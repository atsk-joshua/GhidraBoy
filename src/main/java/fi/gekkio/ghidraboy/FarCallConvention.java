package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Opt-in exact-byte validated inline bank:u8,target:u16 RST convention. */
public record FarCallConvention(
    String trampoline, String expectedBodyHex, List<String> callSites, Integer stackPointer) {
  public FarCallConvention {
    callSites = List.copyOf(callSites);
    if (new HashSet<>(callSites).size() != callSites.size())
      throw new IllegalArgumentException("Duplicate call sites");
  }

  public FarCallConvention(String trampoline, String expectedBodyHex, List<String> callSites) {
    this(trampoline, expectedBodyHex, callSites, null);
  }

  // POP HL; LD A,(HL+); LD (2000),A; LD E,(HL); INC HL; LD D,(HL); INC HL;
  // PUSH HL; PUSH DE; RET. Restores adjusted caller return and transfers via RET.
  public static final String SUPPORTED_BODY = "e12aea00205e235623e5d5c9";

  public List<String> preview(Program p, TaskMonitor monitor) throws Exception {
    if (!SUPPORTED_BODY.equalsIgnoreCase(expectedBodyHex))
      throw new IllegalArgumentException(
          "Unsupported trampoline; only reviewed inline-three-byte convention accepted");
    if (stackPointer == null
        || !((stackPointer >= 0xc004 && stackPointer <= 0xd000)
            || (stackPointer >= 0xff84 && stackPointer <= 0xffff)))
      throw new IllegalArgumentException(
          "Explicit caller SP must keep four stack bytes in fixed WRAM0 or HRAM");
    var c = ProgramMapping.cartridge(p);
    if (c == null || c.mapper() != Cartridge.Mapper.MBC3)
      throw new IllegalArgumentException("Convention requires ordinary MBC3");
    var t = p.getAddressFactory().getAddress(trampoline);
    if (t == null || t.getOffset() > 0x38 || t.getOffset() % 8 != 0)
      throw new IllegalArgumentException("Expected explicit RST vector");
    var trampolineIdentity = ProgramMapping.staticToPhysical(p, t);
    if (trampolineIdentity.size() != 1
        || !trampolineIdentity.get(0).region().equals("ROM")
        || trampolineIdentity.get(0).bank() != 0)
      throw new IllegalArgumentException("Trampoline must execute in fixed physical ROM bank zero");
    byte[] body = HexFormat.of().parseHex(expectedBodyHex), actual = new byte[body.length];
    p.getMemory().getBytes(t, actual);
    if (!Arrays.equals(body, actual))
      throw new IllegalArgumentException("Trampoline bytes do not match reviewed convention");
    var results = new ArrayList<String>();
    var sites = new HashSet<ghidra.program.model.address.Address>();
    for (String site : callSites) {
      monitor.checkCancelled();
      var a = p.getAddressFactory().getAddress(site);
      if (a != null && !sites.add(a))
        throw new IllegalArgumentException("Duplicate resolved call site: " + site);
      var ins = a == null ? null : p.getListing().getInstructionAt(a);
      if (ins == null || (p.getMemory().getByte(a) & 255) != (0xc7 | (int) t.getOffset()))
        throw new IllegalArgumentException("Call site is not the specified RST: " + site);
      var caller = ProgramMapping.staticToPhysical(p, a);
      if (a.getOffset() > 0x3ffb
          || caller.size() != 1
          || !caller.get(0).region().equals("ROM")
          || caller.get(0).bank() != 0)
        throw new IllegalArgumentException(
            "Only fixed-bank callers with payload and return below 4000 are supported; trampoline"
                + " does not restore ROM selection");
      if (ins.getLength() != 1
          || ins.getFlowOverride() != ghidra.program.model.listing.FlowOverride.NONE)
        throw new IllegalArgumentException("Unexpected RST decode or user flow override");
      if (ins.isFallThroughOverridden() && !a.add(4).equals(ins.getFallThrough()))
        throw new IllegalArgumentException("Existing user fallthrough override at " + site);
      for (int off = 1; off <= 3; off++) {
        var payload = a.add(off);
        if (p.getListing().getInstructionContaining(payload) != null
            || p.getListing().getDefinedDataContaining(payload) != null
            || p.getReferenceManager().getReferencesTo(payload).hasNext()
            || p.getSymbolTable().getSymbols(payload).length != 0
            || p.getFunctionManager().getFunctionContaining(payload) != null)
          throw new IllegalArgumentException("Inline payload ownership/boundary conflict at " + payload);
        if (payload.compareTo(t) >= 0 && payload.compareTo(t.add(body.length - 1)) <= 0)
          throw new IllegalArgumentException("Inline payload overlaps helper implementation");
      }
      var continuation = a.add(4);
      var containing = p.getListing().getInstructionContaining(continuation);
      if ((containing != null && !containing.getAddress().equals(continuation))
          || p.getListing().getDefinedDataContaining(continuation) != null)
        throw new IllegalArgumentException("Continuation boundary conflict at " + continuation);
      for (int off = 1; off <= 4; off++) {
        var identity = ProgramMapping.staticToPhysical(p, a.add(off));
        if (identity.size() != 1
            || !identity.get(0).region().equals("ROM")
            || identity.get(0).bank() != 0)
          throw new IllegalArgumentException(
              "Payload or caller return has uncertain physical identity");
      }
      int bank = p.getMemory().getByte(a.add(1)) & 255;
      int cpu =
          (p.getMemory().getByte(a.add(2)) & 255) | ((p.getMemory().getByte(a.add(3)) & 255) << 8);
      if (cpu < 0x4000 || cpu >= 0x8000)
        throw new IllegalArgumentException("Far target must be in switchable ROM");
      var state = MapperState.reset().write(c, 0x2000, bank);
      var physical = MapperState.translate(c, state, cpu, false).physical();
      if (physical == null) throw new IllegalArgumentException("Unresolved far target at " + site);
      var targets =
          ProgramMapping.physicalToStatic(p, physical).stream()
              .filter(x -> x.getOffset() == cpu)
              .toList();
      if (targets.size() != 1)
        throw new IllegalArgumentException("Ambiguous static far target at " + site);
      var targetInstruction = p.getListing().getInstructionContaining(targets.get(0));
      if ((targetInstruction != null && !targetInstruction.getAddress().equals(targets.get(0)))
          || p.getListing().getDefinedDataContaining(targets.get(0)) != null)
        throw new IllegalArgumentException("Target boundary conflict at " + targets.get(0));
      results.add(site + " -> " + targets.get(0) + "; may return " + a.add(4));
    }
    return List.copyOf(results);
  }

  /** Immutable reviewed input; generated annotations do not establish executable semantics. */
  public static final class Preview {
    private final int version;
    private final FarCallConvention convention;
    private final String fingerprint;
    private final List<String> findings;

    private Preview(FarCallConvention convention, String fingerprint, List<String> findings) {
      this.version = 1;
      this.convention = convention;
      this.fingerprint = fingerprint;
      this.findings = List.copyOf(findings);
    }

    public List<String> findings() { return findings; }
    public String fingerprint() { return fingerprint; }
  }

  public Preview previewReviewed(Program p, TaskMonitor monitor) throws Exception {
    long modification = p.getModificationNumber();
    String before = FarCallEvidence.capture(p, monitor);
    var findings = preview(p, monitor);
    if (!before.equals(FarCallEvidence.capture(p, monitor))
        || modification != p.getModificationNumber())
      throw new IllegalStateException("Convention evidence changed during preview");
    monitor.checkCancelled();
    return new Preview(this, before, findings);
  }

  public List<String> apply(Program p, TaskMonitor monitor) throws Exception {
    return apply(p, previewReviewed(p, monitor), monitor);
  }

  public List<String> apply(Program p, Preview reviewed, TaskMonitor monitor) throws Exception {
    if (reviewed == null || reviewed.version != 1 || !equals(reviewed.convention))
      throw new IllegalArgumentException("Preview belongs to a different convention");
    var findings = reviewed.findings;
    // Reject an already-stale review before opening a nested transaction: aborting a nested
    // Ghidra transaction would also abort the caller's surrounding script transaction.
    if (!reviewed.fingerprint.equals(FarCallEvidence.capture(p, monitor)))
      throw new IllegalStateException("Stale convention evidence; preview again");
    int tx = p.startTransaction("Apply explicitly validated far-call convention");
    boolean success = false;
    try {
      if (!reviewed.fingerprint.equals(FarCallEvidence.capture(p, monitor)))
        throw new IllegalStateException("Stale convention evidence; preview again");
      preview(p, monitor);
      AnalysisOwnership.remove(p, "far-call", monitor);
      var owned = new AnalysisOwnership.Group();
      for (String site : callSites) {
        monitor.checkCancelled();
        var a = p.getAddressFactory().getAddress(site);
        var ins = p.getListing().getInstructionAt(a);
        if (ins.isFallThroughOverridden() && !a.add(4).equals(ins.getFallThrough()))
          throw new IllegalArgumentException("Existing user flow override at " + site);
        int bank = p.getMemory().getByte(a.add(1)) & 255;
        int cpu =
            (p.getMemory().getByte(a.add(2)) & 255)
                | ((p.getMemory().getByte(a.add(3)) & 255) << 8);
        var c = ProgramMapping.cartridge(p);
        var resolved =
            ProgramMapping.cpuToStatic(p, MapperState.reset().write(c, 0x2000, bank), cpu, false);
        if (resolved.addresses().size() != 1)
          throw new IllegalArgumentException("Far target changed during apply");
        var target = resolved.addresses().get(0);
        boolean preserve = false;
        for (var ref : p.getReferenceManager().getReferencesFrom(a))
          if (ref.getToAddress().equals(target)
              || (ref.getOperandIndex() == -1 && !ref.isMemoryReference())) preserve = true;
        if (!preserve)
          owned.reference(
              p.getReferenceManager()
                  .addMemoryReference(
                      a, target, RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, -1));
        if (!ins.isFallThroughOverridden()) {
          owned.flows.add(
              new AnalysisOwnership.Flow(
                  AnalysisOwnership.Point.of(a),
                  HexFormat.of().formatHex(ins.getBytes()),
                  ins.getFlowOverride().toString(),
                  AnalysisOwnership.Point.of(a.add(4)),
                  false,
                  null));
          ins.setFallThrough(a.add(4));
        }
        if (p.getBookmarkManager().getBookmark(a, "Analysis", "GhidraBoy Far Call") == null)
          owned.bookmark(
              p.getBookmarkManager()
                  .setBookmark(
                      a,
                      "Analysis",
                      "GhidraBoy Far Call",
                      "Fixed-bank caller; explicit SP="
                          + stackPointer
                          + "; continuation +3; bank is not restored; callee return is not proven."));
      }
      AnalysisOwnership.save(p, "far-call", owned);
      AuthorityOptions.setString(p,ProgramMapping.OPTIONS,"farCallConvention",ProgramMapping.JSON.toJson(this));
      monitor.checkCancelled();
      success = true;
    } finally {
      p.endTransaction(tx, success);
    }
    return findings;
  }
}
