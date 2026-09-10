package fi.gekkio.ghidraboy;

import static fi.gekkio.ghidraboy.OrdinaryProofDependencies.fingerprint;

import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Experimental conditional ordinary-entry transport; never specializes the canonical Function. */
public final class OrdinaryEntryAccess {
  private OrdinaryEntryAccess() {}
  public static final String VERSION = "ordinary-entry-access-experiment-5-abstract-joint";
  // Limit expansion to the incumbent producer's 4096-raw-operation work envelope.
  // This is a provider resource policy, not a native protocol limit. A finite payload
  // has at most 4096 raw + 4096 added operations; its real unique-space bound also applies.
  static final int MAX_FINITE_ADDED_OPERATIONS = 4096;
  private static final long UNIQUE_REGION_BYTES = 0x1000000L;
  private static final int SCRATCH_SLOT_BYTES = 16;

  private record FiniteLoweringCost(long rawOperations, long addedOperations, long scratchBytes) {}

  // getOptionsNames exposes root categories; a dot would create a nested category instead.
  public static final String OPTIONS = "GhidraBoyOrdinaryEntryExperiment";
  public static final String PREFIX = "gb_ordinary_";
  private static final Map<Program, String> INSTANCES = Collections.synchronizedMap(new WeakHashMap<>());

  public record Domain(boolean bootBypassed, boolean noAsync, boolean noDMA,
      boolean noUntrackedMutation, int stackMin, int stackMax, String scope) {}
  public static final Domain DOMAIN = new Domain(true, true, true, true, 0xc000, 0xcffd,
      "Conditional synchronous MBC5 fixed-ROM straight-line entry; incoming mapper and CPU registers unknown; "
          + "symbolic return frame in fixed WRAM, SP C000..CFFD. No concrete return destination is proved.");
  public static final Domain BANKED_DOMAIN = new Domain(true, true, true, true, 0xc000, 0xcffd,
      "Conditional synchronous MBC5 straight-line physical invocation proved from a canonical ROM0 driver call; "
          + "incoming mapper and CPU registers unknown; symbolic return frame in fixed WRAM, SP C000..CFFD. "
          + "Execution ranges and mapper successors are production BankAnalysis proof, not display context.");
  public record Invocation(String root, String callSite) {}
  public record SourceByte(int byteIndex, String address, MapperState.Physical physical, int value) {}
  public record Replacement(String instruction, int operation, int operand, int width,
      List<SourceByte> sources, long value) {
    public Replacement { sources = List.copyOf(sources); }
  }
  public record InstructionProof(String address, String bytes, String pcode) {}
  public record Proof(String version, String programInstance, long revision, String entry,
      String end, Domain domain, String dependencies, AnalysisResult analysis,
      List<Replacement> replacements, List<InstructionProof> instructions, Invocation invocation,
      AnalysisResult invocationAnalysis, List<BankAnalysis.FetchStep> fetchSteps,
      List<SoftwareCallExecutionView.Segment> segments, FiniteEntryProducer.Result finite, long elapsedNanos) {
    public Proof {
      replacements = List.copyOf(replacements); instructions = List.copyOf(instructions);
      fetchSteps = List.copyOf(fetchSteps); segments = List.copyOf(segments);
    }
  }
  private record Registration(String version, long programId, String alias, Proof proof, String dependencies,
      String comment, String nativeIdentity, String transport) {}
  public static final String STOCK_OPTIONS = "GhidraBoyStockOrdinaryEntries";
  public static final String STOCK_VERSION = "stock-ordinary-entry-2";

  private static String instance(Program p) {
    return INSTANCES.computeIfAbsent(p, ignored -> UUID.randomUUID().toString());
  }
  private static void require(boolean condition, String reason) {
    if (!condition) throw new IllegalArgumentException(reason);
  }
  /** Read-only, unknown mapper/register entry. Hardware and symbolic stack domain are explicit. */
  public static Proof preview(Program p, Function function, TaskMonitor monitor) throws Exception {
    return preview(p, function, null, monitor);
  }

  public static Proof preview(Program p, Function function, Invocation invocation, TaskMonitor monitor) throws Exception {
    long started = System.nanoTime(), revision = p.getModificationNumber();
    require(function != null && function.getProgram() == p, "Function belongs to another Program");
    var entry = function.getEntryPoint(); var body = function.getBody();
    if (invocation == null)
      require(entry.getAddressSpace().equals(p.getAddressFactory().getDefaultAddressSpace())
          && body.getNumAddressRanges() == 1 && body.getMinAddress().equals(entry)
          && body.getMaxAddress().getOffset() < 0x4000 && body.getNumAddresses() <= 1024,
          "Only a bounded contiguous canonical ROM0 Function is supported without a physical invocation proof");
    else require(entry.getOffset() >= 0x4000 && entry.getOffset() < 0x8000
        && body.getNumAddressRanges() == 1 && body.getMinAddress().equals(entry)
        && body.getMaxAddress().getOffset() < 0x8000 && body.getNumAddresses() <= 1024,
        "Physical invocation requires a bounded canonical ROMX Function");
    require(!function.hasNoReturn() && function.getCallFixup() == null && !function.isThunk(),
        "Unsupported function return, fixup or thunk contract");
    require(SoftwareCallRegistry.configurationIdentity(p).equals("absent"),
        "Ordinary experiment requires absence of the software-call registry");
    var cart = ProgramMapping.cartridge(p);
    require(cart != null && cart.mapper() == Cartridge.Mapper.MBC5
        && cart.declaredRomBanks() > 0 && cart.declaredRomBanks() <= 256
        && cart.addressableLength() == cart.declaredRomBanks() * 0x4000L
        && cart.inputLength() == cart.addressableLength(),
        "Ordinary MBC5 geometry of at most 256 banks required");
    require(!ProgramMapping.inspect(p).inputMode().contains("BOOT"), "Boot image is outside this domain");
    for (String name : List.of("A", "F", "BC", "DE", "HL", "SP")) {
      var value = p.getProgramContext().getRegisterValue(p.getRegister(name), entry);
      require(value == null || !value.hasAnyValue(), "Canonical entry register context must remain unknown: " + name);
    }
    String dependencies = fingerprint(p, monitor);
    var origin = invocation == null ? null : proveInvocation(p, entry, invocation, monitor);
    var fetch = invocation == null ? null
        : BankAnalysis.previewFetch(p, entry, null, AnalysisResult.Configuration.DEFAULT, monitor);
    var analysis = fetch == null ? BankAnalysis.preview(p, entry, null, AnalysisResult.Configuration.DEFAULT, monitor) : fetch.result();
    require(analysis.complete() && analysis.pendingStates() == 0, "Incomplete unknown-entry access analysis");
    var steps = fetch == null ? List.<BankAnalysis.FetchStep>of() : orderedFetch(p, entry, fetch, monitor);
    FiniteEntryProducer.Result finite = null;
    String finiteRefusal = null;
    if (invocation == null) {
      try { finite = FiniteEntryProducer.derive(p, function, monitor); }
      catch (IllegalArgumentException unsupported) { finiteRefusal = unsupported.getMessage(); }
    }
    var replacements = new ArrayList<Replacement>(); var instructions = new ArrayList<InstructionProof>();
    var segments = new ArrayList<SoftwareCallExecutionView.Segment>();
    Address at = entry, end = body.getMaxAddress(); boolean returned = false; int stepIndex = 0;
    while (fetch == null ? body.contains(at) : stepIndex < steps.size()) {
      monitor.checkCancelled();
      var ins = p.getListing().getInstructionAt(at);
      require(ins != null && (fetch != null || body.contains(ins.getMaxAddress())), "Missing or cut instruction at " + at);
      require(InstructionInterpretation.architecturalUnresolved(ins) == null,
          "Overridden instruction interpretation at " + at);
      byte[] bytes = ins.getBytes(); var raw = ins.getPcode(false);
      boolean terminal = bytes.length == 1 && (bytes[0] & 255) == 0xc9;
      require(Arrays.toString(raw).equals(Arrays.toString(ins.getPcode(true))), "Raw/override p-code differs at " + at);
      for (int b = 0; b < bytes.length; b++) immutable(p, at.add(b), fetch == null);
      addSegment(p, segments, at, bytes.length);
      instructions.add(new InstructionProof(at.toString(), HexFormat.of().formatHex(bytes), Arrays.toString(raw)));
      require(!ins.getFlowType().isCall() && !ins.getFlowType().isJump()
          && (terminal || ins.getFlowType().hasFallthrough()), "Unsupported non-straight-line flow at " + at);
      for (int index = 0; index < raw.length; index++) {
        var op = raw[index]; int code = op.getOpcode();
        if (!terminal && op.getOutput() != null && op.getOutput().isRegister()) {
          var sp = p.getRegister("SP"); long offset = op.getOutput().getOffset();
          require(offset + op.getOutput().getSize() <= sp.getAddress().getOffset()
              || offset >= sp.getAddress().getOffset() + sp.getMinimumByteSize(),
              "Stack-domain-changing instruction is unsupported at " + at);
        }
        require(code != PcodeOp.BRANCH && code != PcodeOp.CBRANCH && code != PcodeOp.BRANCHIND
            && code != PcodeOp.CALL && code != PcodeOp.CALLIND, "Unsupported p-code flow at " + at);
        require(code != PcodeOp.RETURN || terminal && index == raw.length - 1,
            "Only actual terminal C9 RETURN is supported");
        if (code == PcodeOp.CALLOTHER) {
          require(CartridgeBus.isDirectWrite(p.getLanguage(), op), "Unsupported userop at " + at);
          require(op.getNumInputs() == 3 && op.getInput(1).isConstant()
              && op.getInput(1).getSize() == 2, "Unsupported bus write operand at " + at);
          long cpu = op.getInput(1).getOffset();
          require(cpu >= 0 && (cpu + op.getInput(2).getSize() <= 0x8000
              || cpu >= 0xc000 && cpu + op.getInput(2).getSize() <= 0xd000),
              "Bus write outside mapper controls/fixed WRAM at " + at);
        } else if (code == PcodeOp.LOAD && !terminal) {
          addReplacement(p, analysis, at, index, -1, op.getOutput().getSize(), finite, finiteRefusal, replacements);
        } else if (code == PcodeOp.STORE) {
          requireFixedWrites(p, analysis, at, index, op.getInput(2).getSize());
        }
        if (code != PcodeOp.RETURN && code != PcodeOp.LOAD && code != PcodeOp.STORE)
          for (int input = 0; input < op.getNumInputs(); input++)
            if (op.getInput(input).isAddress())
              addReplacement(p, analysis, at, index, input, op.getInput(input).getSize(), finite, finiteRefusal, replacements);
        if (op.getOutput() != null && op.getOutput().isAddress())
          requireFixedWrites(p, analysis, at, index, op.getOutput().getSize());
      }
      if (terminal) {
        require((fetch == null ? ins.getMaxAddress().equals(body.getMaxAddress()) : stepIndex == steps.size() - 1)
            && raw.length > 0 && raw[raw.length - 1].getOpcode() == PcodeOp.RETURN, "Body extends beyond actual RET");
        end = ins.getMaxAddress(); returned = true; break;
      }
      require(ins.getFallThrough() != null && ins.getFallThrough().equals(ins.getMaxAddress().next()),
          "Nonsequential fallthrough at " + at);
      at = fetch == null ? ins.getFallThrough() : ProgramMapping.staticAddress(p, steps.get(++stepIndex).source());
    }
    require(returned, "Function lacks a represented terminal RET");
    finiteLoweringCost(p, instructions, replacements, finite);
    OrdinaryProofDependencies.requireUnchanged(p, revision, dependencies, monitor);
    return new Proof(VERSION, instance(p), revision, entry.toString(), end.toString(),
        invocation == null ? DOMAIN : BANKED_DOMAIN, dependencies, analysis, replacements, instructions,
        invocation, origin, steps, segments, finite, System.nanoTime() - started);
  }

  private static AnalysisResult proveInvocation(Program p, Address entry, Invocation invocation,
      TaskMonitor monitor) throws Exception {
    var root = ProgramMapping.staticAddress(p, invocation.root());
    var call = ProgramMapping.staticAddress(p, invocation.callSite());
    require(root != null && call != null && root.getAddressSpace().equals(p.getAddressFactory().getDefaultAddressSpace())
        && call.getAddressSpace().equals(root.getAddressSpace()) && root.getOffset() < 0x4000
        && call.getOffset() < 0x4000, "Invocation must originate from a canonical fixed-ROM driver");
    immutable(p, root, true); immutable(p, call, true);
    var ins = p.getListing().getInstructionAt(call);
    require(ins != null && ins.getFlowType().isCall() && InstructionInterpretation.architecturalUnresolved(ins) == null,
        "Invocation premise is not an architectural driver call");
    var driver = BankAnalysis.previewFetch(p, root, null, AnalysisResult.Configuration.DEFAULT, monitor);
    var calls = driver.result().findings().stream().filter(f -> f.source().equals(call.toString()) && f.access().equals("call")).toList();
    require(driver.result().complete() && driver.result().pendingStates() == 0 && calls.size() == 1
        && calls.get(0).confidence() == AnalysisResult.Confidence.PROVEN
        && calls.get(0).targets().equals(List.of(entry.toString())),
        "Production driver does not prove this unique physical invocation target");
    require(driver.steps().stream().anyMatch(step -> step.source().equals(call.toString())),
        "Invocation call was not fetched by production analysis");
    return driver.result();
  }

  private static List<BankAnalysis.FetchStep> orderedFetch(Program p, Address entry,
      BankAnalysis.FetchPreview fetch, TaskMonitor monitor) throws Exception {
    require(!fetch.steps().isEmpty() && fetch.steps().size() <= 1024, "Missing or unbounded production fetch trace");
    var remaining = new HashMap<String, BankAnalysis.FetchStep>();
    for (var step : fetch.steps())
      require(remaining.put(step.source(), step) == null, "Multiple production states at one instruction");
    var ordered = new ArrayList<BankAnalysis.FetchStep>(); String source = entry.toString(); int totalBytes = 0;
    while (true) {
      monitor.checkCancelled(); var step = remaining.remove(source);
      require(step != null, "Missing or cyclic production fetch successor");
      var at = ProgramMapping.staticAddress(p, source); var ins = p.getListing().getInstructionAt(at);
      require(ins != null && at.getOffset() == step.cpu() && step.cpu() < 0x8000,
          "Production fetch source does not retain CPU identity");
      byte[] bytes = ins.getBytes(); totalBytes += bytes.length;
      require(totalBytes <= 1024 && step.bytes().size() == bytes.length
          && step.rawPcode().equals(Arrays.stream(ins.getPcode(false)).map(PcodeOp::toString).toList()),
          "Production fetch raw instruction differs from canonical source");
      for (int b = 0; b < bytes.length; b++) {
        var octet = step.bytes().get(b); var byteAddress = at.add(b); immutable(p, byteAddress, false);
        require(octet.cpu() == step.cpu() + b && octet.source().equals(byteAddress.toString())
            && octet.value() == (bytes[b] & 255)
            && ProgramMapping.staticToPhysical(p, byteAddress).equals(List.of(octet.physical())),
            "Production fetch physical byte identity mismatch");
      }
      ordered.add(step);
      boolean terminal = bytes.length == 1 && (bytes[0] & 255) == 0xc9;
      if (terminal) {
        require(step.successors().isEmpty() && remaining.isEmpty(), "Terminal fetch has remaining production paths");
        break;
      }
      require(step.successors().size() == 1, "Production fetch does not have a unique successor");
      var successor = remaining.get(step.successors().get(0));
      require(successor != null && successor.cpu() == step.cpu() + bytes.length
          && successor.incoming().equals(step.outgoing()), "Production successor order or mapper knowledge differs");
      source = successor.source();
    }
    // Retain exactly the unresolved device effects and symbolic C9 stack reads admitted by
    // this conditional domain. Missing fetches or other access frontiers are never proof.
    int allowed = 0;
    var terminal = ordered.get(ordered.size() - 1);
    for (var finding : fetch.result().findings()) {
      if (finding.confidence() == AnalysisResult.Confidence.PROVEN) continue;
      var step = ordered.stream().filter(s -> s.source().equals(finding.source())).findFirst().orElse(null);
      require(step != null, "Unresolved finding outside the fetched sequence");
      var ins = p.getListing().getInstructionAt(ProgramMapping.staticAddress(p, step.source()));
      var raw = ins.getPcode(false); int operation = finding.operation();
      boolean stackRead = step == terminal && finding.access().equals("read") && operation >= 0
          && operation < raw.length && raw[operation].getOpcode() == PcodeOp.LOAD;
      boolean device = finding.access().equals("write") && finding.targets().isEmpty()
          && step.writes().stream().anyMatch(w -> w.operation() == operation && w.byteIndex() == finding.byteIndex()
              && w.mapperControl() && w.value() != null);
      require(stackRead || device, "Unresolved production access frontier: " + finding);
      allowed++;
    }
    require(fetch.frontier().size() == allowed, "Unresolved production instruction frontier");
    return List.copyOf(ordered);
  }

  private static void addSegment(Program p, List<SoftwareCallExecutionView.Segment> segments, Address at, int length) {
    if (!segments.isEmpty()) {
      var last = segments.get(segments.size() - 1); var start = ProgramMapping.staticAddress(p, last.source());
      if (start.getAddressSpace().equals(at.getAddressSpace()) && start.add(last.length()).equals(at)
          && last.cpu() + last.length() == at.getOffset()) {
        segments.set(segments.size() - 1, new SoftwareCallExecutionView.Segment(last.cpu(), last.length() + length, last.source()));
        return;
      }
    }
    segments.add(new SoftwareCallExecutionView.Segment((int) at.getOffset(), length, at.toString()));
  }

  private static void immutable(Program p, Address at, boolean fetch) throws Exception {
    var block = p.getMemory().getBlock(at); var physical = ProgramMapping.staticToPhysical(p, at);
    require(block != null && block.isInitialized() && block.isRead() && !block.isWrite()
        && !block.isVolatile() && !block.getName().startsWith(PREFIX)
        && !block.getName().startsWith(SoftwareCallExecutionView.PREFIX) && physical.size() == 1 && physical.get(0).region().equals("ROM")
        && (!fetch || physical.get(0).bank() == 0), "Unproved immutable physical ROM at " + at);
  }
  private static List<BankAnalysis.Finding> findings(AnalysisResult a, Address at, int operation,
      int operand, String kind, int byteIndex) {
    return a.findings().stream().filter(f -> f.source().equals(at.toString())
        && f.operation() == operation && f.operand() == operand && f.access().equals(kind)
        && f.byteIndex() == byteIndex).toList();
  }
  private static void addReplacement(Program p, AnalysisResult analysis, Address at,
      int operation, int operand, int width, FiniteEntryProducer.Result finite, String refusal,
      List<Replacement> replacements) throws Exception {
    try { replacements.add(replacement(p, analysis, at, operation, operand, width)); }
    catch (IllegalArgumentException singletonRefusal) {
      if (finite != null && finite.reads().stream().anyMatch(r -> r.instruction().equals(at.toString())
          && r.operation() == operation && r.operand() == operand && r.width() == width)) return;
      throw new IllegalArgumentException(singletonRefusal.getMessage() + "; finite frontier: " + refusal, singletonRefusal);
    }
  }

  private static Replacement replacement(Program p, AnalysisResult analysis, Address at,
      int operation, int operand, int width) throws Exception {
    require(width > 0 && width <= 8, "Unsupported read width");
    var sources = new ArrayList<SourceByte>(); long value = 0;
    for (int b = 0; b < width; b++) {
      var fs = findings(analysis, at, operation, operand, "read", b);
      require(fs.size() == 1 && fs.get(0).confidence() == AnalysisResult.Confidence.PROVEN
          && fs.get(0).targets().size() == 1, "Missing exact immutable read proof at " + at + ":" + operation);
      var source = ProgramMapping.staticAddress(p, fs.get(0).targets().get(0));
      require(source != null, "Missing physical source"); immutable(p, source, false);
      int octet = p.getMemory().getByte(source) & 255;
      sources.add(new SourceByte(b, source.toString(), ProgramMapping.staticToPhysical(p, source).get(0), octet));
      value |= (long) octet << (8 * b);
    }
    return new Replacement(at.toString(), operation, operand, width, sources, value);
  }
  private static void requireFixedWrites(Program p, AnalysisResult analysis, Address at,
      int operation, int width) throws Exception {
    for (int b = 0; b < width; b++) {
      var fs = findings(analysis, at, operation, -1, "write", b);
      require(fs.size() == 1 && fs.get(0).confidence() == AnalysisResult.Confidence.PROVEN
          && fs.get(0).targets().size() == 1, "Unproved residual write at " + at);
      var target = ProgramMapping.staticAddress(p, fs.get(0).targets().get(0));
      require(target != null && target.getOffset() >= 0xc000 && target.getOffset() < 0xd000,
          "Residual write outside fixed WRAM at " + at);
    }
  }

  private static Registration read(Program p, Address alias) {
    require(!(p.getOptionsNames().contains(STOCK_OPTIONS) && p.getOptions(STOCK_OPTIONS).contains(alias.toString())
        && p.getOptionsNames().contains(OPTIONS) && p.getOptions(OPTIONS).contains(alias.toString())),
        "Conflicting stock and companion authority; records retained");
    boolean stock = p.getOptionsNames().contains(STOCK_OPTIONS) && p.getOptions(STOCK_OPTIONS).contains(alias.toString());
    if (!stock && !p.getOptionsNames().contains(OPTIONS)) return null;
    String json = p.getOptions(stock ? STOCK_OPTIONS : OPTIONS).getString(alias.toString(), null);
    if (json == null) return null;
    // Inspect the version before decoding changed finite-choice record fields. Old records
    // remain intact and cannot be silently reinterpreted under pointer-choice semantics.
    var envelope = com.google.gson.JsonParser.parseString(json).getAsJsonObject();
    require(envelope.has("version") && (stock ? STOCK_VERSION : VERSION).equals(envelope.get("version").getAsString()),
        "Unsupported ordinary registration version; record retained without migration");
    var result = ProgramMapping.JSON.fromJson(json, Registration.class);
    require(result != null && (stock ? StockEntryInjection.VERSION.equals(result.transport()) && result.nativeIdentity() == null : result.transport() == null), "Unsupported ordinary transport authority");
    return result;
  }
  public static boolean registered(Program p, Address alias) {
    if (p.getOptionsNames().contains(STOCK_OPTIONS) && p.getOptions(STOCK_OPTIONS).contains(alias.toString())) return true;
    if (!p.getOptionsNames().contains(OPTIONS)) return false;
    return p.getOptions(OPTIONS).contains(alias.toString());
  }
  public static Proof registeredProof(Program p, Address alias) {
    var registration = read(p, alias);
    require(registration != null, "Missing ordinary-entry registration at " + alias);
    return registration.proof();
  }
  private static void validatePreview(Program p, Proof proof, TaskMonitor monitor) throws Exception {
    require(proof != null && VERSION.equals(proof.version()) && (proof.invocation() == null ? DOMAIN : BANKED_DOMAIN).equals(proof.domain())
        && instance(p).equals(proof.programInstance()) && fingerprint(p, monitor).equals(proof.dependencies()),
        "Stale or foreign ordinary-entry proof");
    var actual = preview(p, p.getFunctionManager().getFunctionAt(ProgramMapping.staticAddress(p, proof.entry())), proof.invocation(), monitor);
    require(actual.entry().equals(proof.entry()) && actual.end().equals(proof.end())
        && sameDerivation(actual, proof),
        "Ordinary-entry proof does not match current production derivation");
  }

  private static boolean sameDerivation(Proof current, Proof proof) {
    return Objects.equals(current.finite(), proof.finite()) && current.instructions().equals(proof.instructions()) && current.replacements().equals(proof.replacements())
        && current.fetchSteps().equals(proof.fetchSteps()) && current.segments().equals(proof.segments())
        && Objects.equals(current.invocation(), proof.invocation())
        && (current.invocation() == null || current.analysis().findings().equals(proof.analysis().findings()))
        && (current.invocationAnalysis() == null ? proof.invocationAnalysis() == null
            : proof.invocationAnalysis() != null && current.invocationAnalysis().findings().equals(proof.invocationAnalysis().findings()));
  }

  private static String domainComment(Proof proof) {
    return VERSION + "\nCanonical entry retained: " + proof.entry() + "\n" + ProgramMapping.JSON.toJson(proof.domain())
        + "\nPhysical invocation premise: " + ProgramMapping.JSON.toJson(proof.invocation());
  }

  // The actual mapped view and visible domain bind the proof to this invocation. A valid proof
  // for some other Function in the same Program cannot authorize this alias via edited JSON.
  private static void requireAliasBinding(Program p, Address alias, Proof proof, TaskMonitor monitor, boolean stock) throws Exception {
    if (stock) {
      StockEntryInjection.validate(p, alias);
      var source = ProgramMapping.staticAddress(p, proof.entry());
      var function = p.getFunctionManager().getFunctionAt(alias);
      require(source != null && alias.getOffset() == source.getOffset()
          && alias.getAddressSpace().getName().startsWith(PREFIX)
          && function != null && function.getBody().equals(new AddressSet(alias, alias))
          && StockEntryInjection.CONVENTION.equals(function.getCallingConventionName())
          && domainComment(proof).equals(function.getComment()), "Changed stock ordinary source/Function binding");
      for (var segment : proof.segments()) for (int i = 0; i < segment.length(); i++)
        immutable(p, ProgramMapping.staticAddress(p, segment.source()).add(i), false);
      return;
    }
    var entry = ProgramMapping.staticAddress(p, proof.entry());
    require(entry != null && alias.getAddressSpace().isOverlaySpace()
        && alias.getAddressSpace().getName().startsWith(PREFIX) && alias.getOffset() == entry.getOffset()
        && !proof.segments().isEmpty(), "Invalid canonical ordinary-entry extent");
    var expectedBody = new AddressSet(); var owned = new HashSet<String>(); int total = 0;
    for (var segment : proof.segments()) {
      var source = ProgramMapping.staticAddress(p, segment.source());
      var destination = alias.getAddressSpace().getAddress(segment.cpu());
      var block = p.getMemory().getBlock(destination); total += segment.length();
      require(source != null && segment.cpu() == source.getOffset() && segment.length() > 0
          && segment.cpu() >= 0 && segment.cpu() + segment.length() <= 0x8000 && total <= 1024
          && block != null && block.getType() == ghidra.program.model.mem.MemoryBlockType.BYTE_MAPPED
          && block.getStart().equals(destination) && block.getSize() == segment.length() && block.isRead()
          && !block.isWrite() && !block.isVolatile() && block.isExecute()
          && owned.add(block.getStart().toString()), "Conditional alias range does not bind this physical proof");
      require(block.getSourceInfos().size() == 1, "Conditional alias has multiple mapped sources");
      var mapped = block.getSourceInfos().get(0).getMappedRange();
      require(mapped.isPresent() && mapped.get().getMinAddress().equals(source)
          && mapped.get().getMaxAddress().equals(source.add(segment.length() - 1)),
          "Conditional alias maps another source extent");
      expectedBody.add(destination, destination.add(segment.length() - 1));
      for (int offset = 0; offset < segment.length(); offset++) {
        monitor.checkCancelled(); immutable(p, source.add(offset), false);
        var physical = ProgramMapping.staticToPhysical(p, source.add(offset));
        require(physical.size() == 1 && physical.equals(ProgramMapping.staticToPhysical(p, destination.add(offset)))
            && p.getMemory().getByte(source.add(offset)) == p.getMemory().getByte(destination.add(offset)),
            "Conditional alias lost physical byte identity");
      }
    }
    for (var block : p.getMemory().getBlocks())
      require(!block.getStart().getAddressSpace().equals(alias.getAddressSpace())
          || owned.contains(block.getStart().toString()), "Conditional alias contains unproved extra ranges");
    var function = p.getFunctionManager().getFunctionAt(alias);
    require(function != null && function.getBody().equals(expectedBody)
        && (stock ? StockEntryInjection.CONVENTION : SoftwareCallStateEntryInjection.CONVENTION).equals(function.getCallingConventionName())
        && domainComment(proof).equals(function.getComment()), "Conditional alias/domain does not bind this canonical proof");
  }

  /** Creates only an explicit conditional alias. Entire operation rolls back on failure. */
  public static Address install(Program p, Proof proof, TaskMonitor monitor) throws Exception {
    return install(p, proof, monitor, true);
  }
  public static Address installLegacyComparison(Program p, Proof proof, TaskMonitor monitor) throws Exception {
    return install(p, proof, monitor, false);
  }
  public static Address installStock(Program p, Proof proof, TaskMonitor monitor) throws Exception {
    return install(p, proof, monitor, true);
  }
  private static Address install(Program p, Proof proof, TaskMonitor monitor, boolean stock) throws Exception {
    validatePreview(p, proof, monitor); String nativeIdentity = stock ? null : SoftwareCallStateEntryInjection.nativeIdentity();
    var entry = ProgramMapping.staticAddress(p, proof.entry());
    String name = PREFIX + Long.toHexString(entry.getOffset());
    require(p.getAddressFactory().getAddressSpace(name) == null, "Ordinary conditional alias already exists");
    int tx = p.startTransaction("Install conditional ordinary-entry experiment"); boolean success = false;
    try {
      var reviewed = SoftwareCallExecutionView.previewOrdinary(p, name, proof.segments(), monitor);
      var created = stock ? StockEntryInjection.carrier(p, name, (int) entry.getOffset(), proof.segments(), monitor)
          : SoftwareCallExecutionView.createOrdinary(p, reviewed, monitor);
      var body = created.body(); var alias = body.getMinAddress();
      if (stock) StockEntryInjection.prepare(p, alias);
      Disassembler.getDisassembler(p, monitor, null).disassemble(alias, body);
      require(p.getListing().getInstructionAt(alias) != null, "Conditional alias failed to decode");
      var function = p.getFunctionManager().createFunction(name + "_conditional", alias, body, SourceType.ANALYSIS);
      function.setCallingConvention(stock ? StockEntryInjection.CONVENTION : SoftwareCallStateEntryInjection.CONVENTION);
      String comment = domainComment(proof);
      function.setComment(comment);
      requireAliasBinding(p, alias, proof, monitor, stock);
      var registration = new Registration(stock ? STOCK_VERSION : VERSION, p.getUniqueProgramID(), alias.toString(), proof,
          fingerprint(p, monitor), comment, nativeIdentity, stock ? StockEntryInjection.VERSION : null);
      p.getOptions(stock ? STOCK_OPTIONS : OPTIONS).setString(alias.toString(), ProgramMapping.JSON.toJson(registration));
      monitor.checkCancelled(); success = true; return alias;
    } finally { p.endTransaction(tx, success); }
  }
  /** Explicit regeneration after a retained stale failure; does not conceal decompiler cache work. */
  public static void refresh(Program p, Address alias, Proof proof, TaskMonitor monitor) throws Exception {
    var old = read(p, alias); require(old != null, "Missing ordinary registration");
    boolean stock = old.transport() != null;
    validatePreview(p, proof, monitor);
    require(old.proof().entry().equals(proof.entry()) && old.proof().end().equals(proof.end())
        && Objects.equals(old.proof().invocation(), proof.invocation()) && old.proof().segments().equals(proof.segments()),
        "Refresh may not change the represented Function extent");
    requireAliasBinding(p, alias, proof, monitor, stock);
    int tx = p.startTransaction("Refresh ordinary-entry access proof"); boolean success = false;
    try {
      String nativeIdentity = stock ? null : SoftwareCallStateEntryInjection.nativeIdentity();
      p.getOptions(stock ? STOCK_OPTIONS : OPTIONS).setString(alias.toString(), ProgramMapping.JSON.toJson(
          new Registration(stock ? STOCK_VERSION : VERSION, p.getUniqueProgramID(), alias.toString(), proof,
              fingerprint(p, monitor), old.comment(), nativeIdentity, old.transport())));
      monitor.checkCancelled(); success = true;
    } finally { p.endTransaction(tx, success); }
  }

  /** Account for the complete expansion before admitting a proof or constructing a payload. */
  private static FiniteLoweringCost finiteLoweringCost(Program p, List<InstructionProof> instructions,
      List<Replacement> replacements, FiniteEntryProducer.Result finite) {
    long raw = 0;
    for (var instruction : instructions) {
      var source = p.getListing().getInstructionAt(ProgramMapping.staticAddress(p, instruction.address()));
      require(source != null, "Missing raw instruction for finite lowering budget");
      raw += source.getPcode(false).length;
    }
    long added = finite == null ? 0 : finite.choices().size(); // actual access-choice snapshots
    if (finite != null) {
      require(FiniteEntryProducer.VERSION.equals(finite.version())
          && new HashSet<>(finite.choices()).size() == finite.choices().size(),
          "Finite frontier: incompatible or duplicate access choices");
      for (var choice : finite.choices()) {
        require(choice.kind() != null && !choice.values().isEmpty()
            && choice.values().size() < FiniteEntryProducer.MAX_VALUES
            && new HashSet<>(choice.values()).size() == choice.values().size(),
            "Finite frontier: incomplete access-choice domain");
        require(choice.kind() == FiniteEntryProducer.Kind.CPU_POINTER
            ? choice.width() == 2 && choice.input() == 1 && choice.mapperCpu() == null
                && choice.values().stream().allMatch(v -> v >= 0 && v <= 65535)
            : choice.width() == 1 && choice.input() == 2 && choice.mapperCpu() != null
                && choice.values().stream().allMatch(v -> v >= 0 && v <= 255),
            "Finite frontier: incompatible access-choice kind or width");
      }
    }
    if (finite != null) for (var read : finite.reads()) {
      if (replacements.stream().anyMatch(r -> r.instruction().equals(read.instruction())
          && r.operation() == read.operation() && r.operand() == read.operand())) continue;
      if (read.joint() != null) {
        var joint = read.joint();
        require(read.width() == 1 && joint.complete() && !joint.reachable().isEmpty()
            && joint.candidateCover().size() <= AbstractValues.MAX_CANDIDATES
            && joint.reachable().size() <= joint.candidateCover().size()
            && finite.choices().contains(joint.selector()) && finite.choices().contains(joint.pointer())
            && joint.selector().kind() == FiniteEntryProducer.Kind.MAPPER_SELECTOR
            && joint.pointer().kind() == FiniteEntryProducer.Kind.CPU_POINTER,
            "Finite frontier: missing complete joint guard coverage");
        var keys = new HashSet<List<Long>>();
        for (var guard : joint.reachable()) {
          var endpoint = guard.endpoint();
          require(joint.candidateCover().contains(endpoint) && keys.add(List.of(endpoint.selector(), endpoint.pointer()))
              && guard.condition().equals(new AbstractValues.Condition(List.of(
                  new AbstractValues.Term(joint.selector().origin(), endpoint.selector()),
                  new AbstractValues.Term(joint.pointer().origin(), endpoint.pointer())))),
              "Finite frontier: forged or duplicate joint guards");
        }
        // Two equality tests, conjunction, byte product and byte sum for each non-first row.
        added += 5L * (joint.reachable().size() - 1);
        continue;
      }
      require(read.width() == 1 && !read.alternatives().isEmpty(),
          "Finite frontier: lowering supports nonempty byte reads only");
      if (read.choice() != null) {
        var values = read.choice().values();
        require(finite.choices().contains(read.choice()), "Finite read has no produced access choice");
        require(!values.isEmpty() && values.size() < FiniteEntryProducer.MAX_VALUES
            && new HashSet<>(values).size() == values.size()
            && read.alternatives().stream().map(FiniteEntryProducer.Alternative::key).toList().equals(values),
            "Finite frontier: alternatives do not cover the produced access-choice domain");
      } else require(read.alternatives().size() == 1, "Finite read has no produced access choice");
      added += 3L * (read.alternatives().size() - 1); // equality, byte product, byte sum
    }
    require(added <= MAX_FINITE_ADDED_OPERATIONS,
        "Finite frontier: finite lowering operation budget exceeded (" + added + " > "
            + MAX_FINITE_ADDED_OPERATIONS + "); complete alternative set refused");
    long scratch = SCRATCH_SLOT_BYTES * added;
    require(scratch <= UNIQUE_REGION_BYTES, "Finite frontier: lowering scratch budget exceeded");
    return new FiniteLoweringCost(raw, added, scratch);
  }

  /** Read-only callback: revalidate dependency snapshot; never run a mutating Program analyzer. */
  public static PcodeOp[] emit(Program p, Address alias, long uniqueBase, TaskMonitor monitor) throws Exception {
    var record = read(p, alias); require(record != null, "Missing ordinary-entry registration");
    return emit(p, alias, uniqueBase, monitor, record.transport() != null);
  }
  public static PcodeOp[] emitLegacyComparison(Program p, Address alias, long uniqueBase, TaskMonitor monitor) throws Exception {
    return emit(p, alias, uniqueBase, monitor, false);
  }
  public static PcodeOp[] emitStock(Program p, Address alias, long uniqueBase, TaskMonitor monitor) throws Exception {
    return emit(p, alias, uniqueBase, monitor, true);
  }
  private static PcodeOp[] emit(Program p, Address alias, long uniqueBase, TaskMonitor monitor, boolean stock) throws Exception {
    long revision = p.getModificationNumber(); var registration = read(p, alias);
    require(registration != null && registration.programId() == p.getUniqueProgramID()
        && alias.toString().equals(registration.alias()), "Missing or foreign ordinary-entry registration");
    require(stock ? StockEntryInjection.VERSION.equals(registration.transport()) : registration.transport() == null, "Entry transport mismatch");
    if (!stock) require(registration.nativeIdentity().equals(SoftwareCallStateEntryInjection.nativeIdentity()), "Native companion changed");
    OrdinaryProofDependencies.requireCurrent(p, registration.dependencies(), monitor);
    requireAliasBinding(p, alias, registration.proof(), monitor, stock);
    // The serialized record is not evidence for its own replacements. Re-derive once at this
    // entry request through the read-only production preview, including after save/reopen.
    // This deliberately pays bounded preview cost rather than trusting mutable option JSON.
    var proof = registration.proof();
    var current = preview(p, p.getFunctionManager().getFunctionAt(ProgramMapping.staticAddress(p, proof.entry())), proof.invocation(), monitor);
    require(VERSION.equals(proof.version()) && (proof.invocation() == null ? DOMAIN : BANKED_DOMAIN).equals(proof.domain())
        && current.entry().equals(proof.entry()) && current.end().equals(proof.end())
        && sameDerivation(current, proof), "Changed ordinary proof record or physical access identity");
    var cost = finiteLoweringCost(p, proof.instructions(), proof.replacements(), proof.finite());
    var result = new ArrayList<PcodeOp>(); long nextUnique = uniqueBase;
    // Reserve scratch after this payload's instruction regions, within the real unique space.
    long scratch = uniqueBase + proof.instructions().size() * UNIQUE_REGION_BYTES;
    require(scratch >= uniqueBase && scratch + UNIQUE_REGION_BYTES <= p.getAddressFactory().getUniqueSpace().getMaxAddress().getOffset(),
        "Ordinary payload exceeds unique-space capacity");
    long scratchStart = scratch;
    require(scratch + cost.scratchBytes() >= scratch
        && scratch + cost.scratchBytes() <= p.getAddressFactory().getUniqueSpace().getMaxAddress().getOffset(),
        "Finite frontier: lowering exceeds actual unique-space capacity");
    var selectors = new HashMap<FiniteEntryProducer.Choice, Varnode>();
    if (proof.finite() != null) for (var selector : proof.finite().choices()) {
      selectors.put(selector, new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(scratch), selector.width()));
      scratch += SCRATCH_SLOT_BYTES;
    }
    for (var instruction : registration.proof().instructions()) {
      monitor.checkCancelled();
      var source = p.getListing().getInstructionAt(ProgramMapping.staticAddress(p, instruction.address()));
      require(source != null && instruction.bytes().equals(HexFormat.of().formatHex(source.getBytes()))
          && instruction.pcode().equals(Arrays.toString(source.getPcode(false))), "Changed raw instruction");
      var temporaries = new HashMap<Long, Long>(); var raw = source.getPcode(false);
      for (int index = 0; index < raw.length; index++) {
        var op = raw[index]; var inputs = op.getInputs().clone();
        for (int i = 0; i < inputs.length; i++) {
          var relocated = relocate(p, inputs[i], temporaries, nextUnique); inputs[i] = relocated;
        }
        var actualInputs = inputs.clone();
        var output = op.getOutput() == null ? null : relocate(p, op.getOutput(), temporaries, nextUnique);
        int code = op.getOpcode();
        for (var replacement : registration.proof().replacements()) {
          if (!replacement.instruction().equals(instruction.address()) || replacement.operation() != index) continue;
          var value = new Varnode(p.getAddressFactory().getConstantSpace().getAddress(replacement.value()), replacement.width());
          if (replacement.operand() == -1) { code = PcodeOp.COPY; inputs = new Varnode[] {value}; }
          else inputs[replacement.operand()] = value;
        }
        if (proof.finite() != null) {
          // Capture the actual raw input before the original mapper write or indexed LOAD.
          // Snapshot relocated raw operands before any read replacements alter their shape.
          for (var selector : proof.finite().choices())
            if (selector.instruction().equals(instruction.address()) && selector.operation() == index)
              result.add(new PcodeOp(alias, result.size(), PcodeOp.COPY,
                  new Varnode[] {actualInputs[selector.input()]}, selectors.get(selector)));
          for (var read : proof.finite().reads()) {
            if (!read.instruction().equals(instruction.address()) || read.operation() != index) continue;
            // Singleton replacements retain the incumbent exact path above.
            boolean singleton = false;
            for (var replacement : proof.replacements())
              if (replacement.instruction().equals(read.instruction()) && replacement.operation() == index
                  && replacement.operand() == read.operand()) singleton = true;
            if (singleton) continue;
            if (read.joint() != null) {
              var joint = read.joint(); var first = joint.reachable().get(0).endpoint();
              var bank = selectors.get(joint.selector()); var pointer = selectors.get(joint.pointer());
              require(bank != null && pointer != null, "Joint read has no actual captured operands");
              Varnode value = constant(p, first.value(), 1);
              for (int row = 1; row < joint.reachable().size(); row++) {
                var endpoint = joint.reachable().get(row).endpoint();
                var bankEqual = new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(scratch), 1); scratch += SCRATCH_SLOT_BYTES;
                var pointerEqual = new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(scratch), 1); scratch += SCRATCH_SLOT_BYTES;
                var condition = new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(scratch), 1); scratch += SCRATCH_SLOT_BYTES;
                var product = new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(scratch), 1); scratch += SCRATCH_SLOT_BYTES;
                var sum = new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(scratch), 1); scratch += SCRATCH_SLOT_BYTES;
                result.add(new PcodeOp(alias, result.size(), PcodeOp.INT_EQUAL,
                    new Varnode[] {bank, constant(p, endpoint.selector(), bank.getSize())}, bankEqual));
                result.add(new PcodeOp(alias, result.size(), PcodeOp.INT_EQUAL,
                    new Varnode[] {pointer, constant(p, endpoint.pointer(), pointer.getSize())}, pointerEqual));
                result.add(new PcodeOp(alias, result.size(), PcodeOp.BOOL_AND,
                    new Varnode[] {bankEqual, pointerEqual}, condition));
                result.add(new PcodeOp(alias, result.size(), PcodeOp.INT_MULT,
                    new Varnode[] {condition, constant(p, (endpoint.value() - first.value()) & 255, 1)}, product));
                result.add(new PcodeOp(alias, result.size(), PcodeOp.INT_ADD, new Varnode[] {value, product}, sum));
                value = sum;
              }
              if (read.operand() == -1) { code = PcodeOp.COPY; inputs = new Varnode[] {value}; }
              else inputs[read.operand()] = value;
              continue;
            }
            var first = read.alternatives().get(0);
            Varnode value = constant(p, first.value(), 1);
            if (read.alternatives().size() > 1) {
              var selector = selectors.get(read.choice());
              require(selector != null, "Finite read has no captured access choice");
              // The producer's complete, distinct access domain makes exactly one equality
              // true (or none for the first member). Each product/sum is modulo 256.
              for (int alternative = 1; alternative < read.alternatives().size(); alternative++) {
                var choice = read.alternatives().get(alternative);
                var condition = new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(scratch), 1); scratch += SCRATCH_SLOT_BYTES;
                var scaled = new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(scratch), 1); scratch += SCRATCH_SLOT_BYTES;
                var selected = new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(scratch), 1); scratch += SCRATCH_SLOT_BYTES;
                result.add(new PcodeOp(alias, result.size(), PcodeOp.INT_EQUAL,
                    new Varnode[] {selector, constant(p, choice.key(), selector.getSize())}, condition));
                result.add(new PcodeOp(alias, result.size(), PcodeOp.INT_MULT,
                    new Varnode[] {condition, constant(p, (choice.value() - first.value()) & 255, 1)}, scaled));
                result.add(new PcodeOp(alias, result.size(), PcodeOp.INT_ADD,
                    new Varnode[] {value, scaled}, selected));
                value = selected;
              }
            }
            if (read.operand() == -1) { code = PcodeOp.COPY; inputs = new Varnode[] {value}; }
            else inputs[read.operand()] = value;
          }
        }
        result.add(new PcodeOp(alias, result.size(), code, inputs, output));
      }
      nextUnique += UNIQUE_REGION_BYTES;
    }
    require(result.size() == cost.rawOperations() + cost.addedOperations()
        && scratch - scratchStart == cost.scratchBytes(), "Finite lowering resource accounting disagrees with payload");
    require(revision == p.getModificationNumber(), "Program changed during ordinary-entry injection");
    return result.toArray(PcodeOp[]::new);
  }
  private static Varnode constant(Program p, long value, int width) {
    return new Varnode(p.getAddressFactory().getConstantSpace().getAddress(value), width);
  }

  private static Varnode relocate(Program p, Varnode value, Map<Long, Long> temporaries, long base) {
    if (!value.isUnique()) return value;
    long original = value.getOffset() & ~0xffffL;
    long replacement = temporaries.computeIfAbsent(original, ignored -> base + temporaries.size() * 0x10000L);
    return new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(replacement + (value.getOffset() & 0xffff)), value.getSize());
  }
}
