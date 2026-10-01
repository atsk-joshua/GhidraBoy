package fi.gekkio.ghidraboy;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Reversible stock presentation derived only from current matched-return certificates. */
final class OrdinaryCallFlow {
  static final String GROUP = "ordinary-call-flow";
  private static final int VERSION = 1;
  private OrdinaryCallFlow() {}

  record Tuple(AnalysisOwnership.Point from, AnalysisOwnership.Point to, int operand,
      String type, String source, boolean primary, long symbol) {
    static Tuple of(Reference ref) {
      return new Tuple(AnalysisOwnership.Point.of(ref.getFromAddress()),
          AnalysisOwnership.Point.of(ref.getToAddress()), ref.getOperandIndex(),
          ref.getReferenceType().toString(), ref.getSource().toString(), ref.isPrimary(), ref.getSymbolID());
    }
    boolean matches(Reference ref) { return equals(of(ref)); }
  }

  record Receipt(int version, AnalysisResult.OrdinaryCallProof proof, String engine,
      String basis, String bytes, Tuple installed, Tuple displaced) {}

  private record Notification(AddressSet sources, String fingerprint, List<Receipt> receipts) {}
  private static final Map<Program, Notification> notifications = new WeakHashMap<>();

  static List<Receipt> receipts(Program p) {
    return AnalysisOwnership.group(p, GROUP).ordinaryCalls;
  }

  private static boolean valid(Receipt r) {
    return r != null && r.version == VERSION && AnalysisResult.ENGINE_VERSION.equals(r.engine)
        && r.proof != null && r.basis != null && r.bytes != null && r.installed != null
        && r.displaced != null && r.installed.type.equals(RefType.UNCONDITIONAL_CALL.toString())
        && r.installed.source.equals(SourceType.ANALYSIS.toString()) && r.installed.primary
        && r.displaced.type.equals(RefType.UNCONDITIONAL_CALL.toString())
        && r.displaced.source.equals(SourceType.DEFAULT.toString())
        && r.installed.from.equals(r.displaced.from) && r.installed.operand == r.displaced.operand;
  }

  private static Reference installed(Program p, Receipt r) {
    if (!valid(r)) return null;
    var from = r.installed.from.resolve(p);
    if (from == null) return null;
    for (var ref : p.getReferenceManager().getReferencesFrom(from))
      if (r.installed.matches(ref)) return ref;
    return null;
  }

  private static boolean sourceMatches(Instruction ins, Receipt r) throws Exception {
    return ins != null && Objects.equals(ins.getAddress(), r.installed.from.resolve(ins.getProgram()))
        && ins.getLength() == 3 && (ins.getBytes()[0] & 255) == 0xcd
        && HexFormat.of().formatHex(ins.getBytes()).equals(r.bytes)
        && ins.getFlowOverride() == ghidra.program.model.listing.FlowOverride.NONE
        && !ins.isFallThroughOverridden() && !ins.isLengthOverridden()
        && ins.getDefaultFlows().length == 1
        && Objects.equals(ins.getDefaultFlows()[0], r.displaced.to.resolve(ins.getProgram()))
        && Objects.equals(ins.getAddress(), r.installed.from.resolve(ins.getProgram()))
        && Objects.equals(ins.getAddress().toString(), r.proof.source())
        && Objects.equals(r.installed.to.resolve(ins.getProgram()),
            ProgramMapping.staticAddress(ins.getProgram(), r.proof.target()))
        && Objects.equals(ins.getFallThrough(), ProgramMapping.staticAddress(ins.getProgram(), r.proof.continuation()));
  }

  /** Structural correspondence only: basis validation happens after normalized capture. */
  static Receipt exact(Instruction ins) {
    try {
      for (var r : receipts(ins.getProgram())) {
        if (!valid(r) || !sourceMatches(ins, r)) continue;
        var refs = Arrays.stream(ins.getReferencesFrom()).filter(InstructionInterpretation::relevant).toList();
        if (refs.size() == 1 && r.installed.matches(refs.get(0))) return r;
      }
    } catch (Exception invalid) { /* Uncertain receipts confer no authority. */ }
    return null;
  }

  static boolean architecturalExemption(Instruction ins, Reference ref) {
    var r = exact(ins);
    if (r == null || !r.installed.matches(ref)) return false;
    try { return r.basis.equals(ProgramFingerprint.capture(ins.getProgram(), TaskMonitor.DUMMY)); }
    catch (Exception invalid) { return false; }
  }

  static AddressSet publish(Program p, AnalysisResult result, TaskMonitor monitor) throws Exception {
    ProgramFingerprint.requireCurrent(p, result, monitor);
    var changed = new AddressSet();
    if (!result.complete()) return changed;
    var group = AnalysisOwnership.group(p, GROUP);
    for (var proof : result.ordinaryCallProofs()) {
      monitor.checkCancelled();
      var from = ProgramMapping.staticAddress(p, proof.source());
      var to = ProgramMapping.staticAddress(p, proof.target());
      var next = ProgramMapping.staticAddress(p, proof.continuation());
      var ins = p.getListing().getInstructionAt(from);
      var existing = exact(ins);
      if (existing != null && existing.basis.equals(result.fingerprint()) && existing.proof.equals(proof)) continue;
      // Never adopt preexisting/edited artifacts or compete across operand namespaces.
      if (group.ordinaryCalls.stream().anyMatch(r -> valid(r) && Objects.equals(r.installed.from.resolve(p), from))) continue;
      if (ins == null || ins.getLength() != 3 || (ins.getBytes()[0] & 255) != 0xcd
          || InstructionInterpretation.architecturalUnresolved(ins) != null
          || !Objects.equals(ins.getFallThrough(), next)
          || !ProgramMapping.staticToPhysical(p, from).equals(List.of(proof.sourcePhysical()))
          || !ProgramMapping.staticToPhysical(p, to).equals(List.of(proof.targetPhysical()))
          || !ProgramMapping.staticToPhysical(p, next).equals(List.of(proof.continuationPhysical()))
          || !BankAnalysis.ordinaryCallProofStorage(p, from) || !BankAnalysis.ordinaryCallProofStorage(p, to)
          || !BankAnalysis.ordinaryCallProofStorage(p, next)) continue;
      var refs = Arrays.stream(ins.getReferencesFrom()).filter(InstructionInterpretation::relevant).toList();
      if (refs.size() != 1) continue;
      var decoded = refs.get(0);
      if (decoded.getSource() != SourceType.DEFAULT || decoded.getReferenceType() != RefType.UNCONDITIONAL_CALL
          || ins.getDefaultFlows().length != 1 || !decoded.getToAddress().equals(ins.getDefaultFlows()[0])
          || decoded.getSymbolID() != -1) continue;
      // Adding a memory reference can also replace non-flow evidence at the same tuple key.
      if (Arrays.stream(ins.getReferencesFrom()).anyMatch(ref -> ref.getToAddress().equals(to)
          && ref.getOperandIndex() == decoded.getOperandIndex()
          && !Tuple.of(ref).equals(Tuple.of(decoded)))) continue;
      if (Arrays.stream(ins.getReferencesFrom()).anyMatch(ref -> ref.getOperandIndex() == decoded.getOperandIndex()
          && ref.isPrimary() && !Tuple.of(ref).equals(Tuple.of(decoded)))) continue;
      var displaced = Tuple.of(decoded);
      p.getReferenceManager().delete(decoded);
      var physical = p.getReferenceManager().addMemoryReference(from, to,
          RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, displaced.operand);
      p.getReferenceManager().setPrimary(physical, true);
      physical = p.getReferenceManager().getReference(from, to, displaced.operand);
      group.ordinaryCalls.add(new Receipt(VERSION, proof, AnalysisResult.ENGINE_VERSION,
          result.fingerprint(), HexFormat.of().formatHex(ins.getBytes()), Tuple.of(physical), displaced));
      changed.add(from);
    }
    if (!changed.isEmpty()) AnalysisOwnership.save(p, GROUP, group);
    return changed;
  }

  /** Called before any analysis, including incomplete previews, captures its input identity. */
  static void retireStale(Program p, TaskMonitor monitor) throws Exception {
    var group = AnalysisOwnership.group(p, GROUP);
    if (group.ordinaryCalls.isEmpty()) return;
    monitor.checkCancelled();
    var fingerprint = ProgramFingerprint.capture(p, monitor);
    var stale = group.ordinaryCalls.stream().filter(r -> valid(r) && !r.basis.equals(fingerprint)).toList();
    if (stale.isEmpty()) return;
    int tx = p.startTransaction("Retire stale ordinary CALL presentation");
    boolean success = false;
    try {
      for (var r : stale) {
        monitor.checkCancelled();
        if (undo(p, r, new ArrayList<>())) group.ordinaryCalls.remove(r);
      }
      AnalysisOwnership.save(p, GROUP, group);
      success = true;
    } finally { p.endTransaction(tx, success); }
  }

  static boolean undo(Program p, Receipt r, List<String> diagnostics) throws Exception {
    var ref = installed(p, r);
    var from = valid(r) ? r.installed.from.resolve(p) : null;
    var ins = from == null ? null : p.getListing().getInstructionAt(from);
    if (ref == null) {
      diagnostics.add("Preserved edited or uncertain ordinary CALL at " + from);
      return false;
    }
    if (!sourceMatches(ins, r)) {
      p.getReferenceManager().delete(ref);
      diagnostics.add("Retired unchanged ordinary CALL; obsolete DEFAULT not restored at " + from);
      return true;
    }
    var old = r.displaced;
    var to = old.to.resolve(p);
    var present = p.getReferenceManager().getReference(from, to, old.operand);
    if (present != null && r.installed.matches(present)) present = null;
    if (present != null && !old.matches(present)) {
      diagnostics.add("Preserved competing DEFAULT restoration tuple at " + from);
      return false;
    }
    p.getReferenceManager().delete(ref);
    if (present == null) {
      present = p.getReferenceManager().addMemoryReference(from, to, RefType.UNCONDITIONAL_CALL,
          SourceType.DEFAULT, old.operand);
      p.getReferenceManager().setPrimary(present, old.primary);
    }
    return true;
  }

  static void notifyChanged(Program p, AddressSet changed, TaskMonitor monitor) throws Exception {
    if (changed.isEmpty()) return;
    synchronized (notifications) {
      notifications.put(p, new Notification(new AddressSet(changed), ProgramFingerprint.capture(p, monitor),
          List.copyOf(receipts(p))));
    }
    AutoAnalysisManager.getAnalysisManager(p).codeDefined(changed);
  }

  static boolean consumeNotification(Program p, AddressSetView set, TaskMonitor monitor) throws Exception {
    Notification token;
    synchronized (notifications) { token = notifications.remove(p); }
    if (token == null || set.isEmpty() || !token.sources.contains(set)
        || !token.receipts.equals(receipts(p)) || !token.fingerprint.equals(ProgramFingerprint.capture(p, monitor))) return false;
    for (var source : token.sources.getAddresses(true))
      if (exact(p.getListing().getInstructionAt(source)) == null) return false;
    return true;
  }

  static void analysisEnded(Program p) { synchronized (notifications) { notifications.remove(p); } }
}
