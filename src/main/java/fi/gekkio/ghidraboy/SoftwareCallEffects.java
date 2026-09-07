package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/**
 * Bounded, premise-conditional callee proof using architectural p-code and physical bus identity.
 * No function prototype, generated reference, noReturn annotation or observed trace proves an exit.
 * Unknown inputs/effects and exhausted bounds are unresolved, never a returning summary.
 */
public final class SoftwareCallEffects {
  private SoftwareCallEffects() {}
  public static final String VERSION = "software-call-effects-5";
  public record MemoryWrite(int cpu, MapperState.Physical physical, int value) {}
  public record Path(SoftwareCallModel.Returned returned, List<MemoryWrite> writes,
      Set<String> changedRegisters) {
    public Path { writes = List.copyOf(writes); changedRegisters = Set.copyOf(changedRegisters); }
  }
  public record Fetch(String address, MapperState.Physical physical, String nativeFunctionEntry, int callDepth) {}
  public record ReturningCall(String site, String target) {}
  /** A value is attached to a physical access, never to the code view containing the instruction. */
  public record Access(int pcodeIndex, int byteIndex, int cpu, MapperState.Physical physical,
      Integer value, boolean write, boolean mapperControl) {}
  public record MemoryByte(MapperState.Physical physical, int value) {}
  /** An additional typed index into the retained veto list, never an exemption by itself. */
  public record TransportVeto(int step, int callDepth, String kind, String reason) {}
  public record ContinuationState(int cpu, MapperState.Physical physical, MapperState mapper, int sp,
      SoftwareCallModel.Registers registers, List<MemoryByte> memory) {
    public ContinuationState { memory = List.copyOf(memory); }
  }
  /** Expected native resume and current physical stack bytes are separate facts. */
  public record NativeFrame(int returnCpu, int returnSp, int returnWordCpu, Integer liveReturnWord,
      String callerEntry, SoftwareCallModel.Frame softwareCall, int phase) {}
  public record CallOutcome(String exit, ContinuationState state, List<NativeFrame> liveFrames, int terminalStep, Integer resumeStep) {
    public CallOutcome { liveFrames = List.copyOf(liveFrames); }
  }
  public record ContinuationStep(int index, String address, int length, ContinuationState before,
      ContinuationState after, List<Integer> executedPcode, List<Access> accesses, int callDepth,
      String nativeFunctionEntry, String transfer, String physicalTarget, Integer successor,
      SoftwareCallModel.Frame softwareCall, ContinuationState afterCall, CallOutcome callOutcome) {
    public ContinuationStep { executedPcode = List.copyOf(executedPcode); accesses = List.copyOf(accesses); }
  }
  public record ContinuationSummary(String version, String kind, String dependencies, List<ContinuationStep> steps,
      String exit, List<String> unresolved, List<String> nativeIncompatibilities,
      List<String> returningNativeFunctions, List<ReturningCall> returningCalls, List<TransportVeto> transportVetoes,
      ContinuationSummary prerequisiteCallee) {
    public ContinuationSummary {
      steps = List.copyOf(steps); unresolved = List.copyOf(unresolved);
      nativeIncompatibilities = List.copyOf(nativeIncompatibilities);
      returningNativeFunctions = List.copyOf(returningNativeFunctions); returningCalls = List.copyOf(returningCalls);
      transportVetoes = List.copyOf(transportVetoes);
    }
    public boolean complete() { return unresolved.isEmpty() && !steps.isEmpty() && exit != null; }
    public boolean nativeCompatible() { return complete() && nativeIncompatibilities.isEmpty(); }
  }

  /**
   * Trace the continuation under the same exact premises as the callee proof. The supplied path is
   * rederived before use; consumed RAM is carried from execution, not reconstructed from a prototype.
   * An untouched, unknown external return word remains symbolic at the final architectural RET.
   */
  public static ContinuationSummary deriveContinuation(Program program, SoftwareCallModel.Frame frame,
      Path expected, List<SoftwareCallValidation.Configuration> candidates, TaskMonitor monitor) throws Exception {
    return deriveContinuation(program, frame, expected, candidates, monitor, false, false);
  }

  static ContinuationSummary deriveContinuationForReview(Program program, SoftwareCallModel.Frame frame,
      Path expected, List<SoftwareCallValidation.Configuration> candidates, TaskMonitor monitor) throws Exception {
    return deriveContinuation(program, frame, expected, candidates, monitor, true, false);
  }

  static ContinuationSummary deriveContinuationForInstallation(Program program, SoftwareCallModel.Frame frame,
      Path expected, List<SoftwareCallValidation.Configuration> candidates, TaskMonitor monitor) throws Exception {
    return deriveContinuation(program, frame, expected, candidates, monitor, false, true);
  }

  private static ContinuationSummary deriveContinuation(Program program, SoftwareCallModel.Frame frame,
      Path expected, List<SoftwareCallValidation.Configuration> candidates, TaskMonitor monitor,
      boolean reviewRepairs, boolean installationProof) throws Exception {
    long modification = program.getModificationNumber();
    String source = FarCallEvidence.capture(program, monitor);
    var machine = new Machine(program, frame, monitor, List.copyOf(candidates), reviewRepairs, installationProof);
    var unresolved = new ArrayList<String>();
    ContinuationSummary prerequisiteCallee = null;
    try {
      Path actual = machine.run();
      if (!actual.equals(expected)) throw new Unresolved("Continuation input differs from freshly derived callee effects");
      var returned = actual.returned();
      if ((returned.exit() != SoftwareCallModel.Exit.MAY_RETURN && returned.exit() != SoftwareCallModel.Exit.NONLOCAL)
          || returned.physical() == null || returned.registers() == null || returned.sp() == null)
        throw new Unresolved("Continuation requires a proven physical returned state");
      boolean initialIncompatible = !machine.nativeIncompatibilities.isEmpty();
      for (var deferred : machine.returnRepairVetoes.entrySet())
        if (!reviewRepairs || !machine.returningCalls.contains(deferred.getKey())) initialIncompatible = true;
      if (initialIncompatible)
        prerequisiteCallee = deriveCalleeGraph(program, frame, candidates, monitor, reviewRepairs, installationProof);
      machine.startContinuation(returned);
      machine.run();
    } catch (Unresolved failure) { unresolved.add(failure.getMessage()); }
    monitor.checkCancelled();
    if (modification != program.getModificationNumber() || !source.equals(FarCallEvidence.capture(program, monitor)))
      throw new IllegalArgumentException("Program changed during continuation-effect derivation");
    for (var deferred : machine.returnRepairVetoes.entrySet())
      if (!reviewRepairs || !machine.returningCalls.contains(deferred.getKey()))
        machine.nativeIncompatibilities.addAll(deferred.getValue());
    machine.validateBootstrapWitnesses();
    String dependencies = Sha256.of(ProgramMapping.JSON.toJson(List.of(VERSION, "continuation-1", source,
        frame, expected, List.copyOf(candidates), reviewRepairs, installationProof,
        prerequisiteCallee == null ? "none" : prerequisiteCallee.dependencies())).getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString();
    return new ContinuationSummary(VERSION, "CONTINUATION", dependencies, machine.trace.stream().map(TraceStep::freeze).toList(),
        machine.continuationExit, unresolved, List.copyOf(machine.nativeIncompatibilities),
        List.copyOf(machine.returningNativeFunctions), List.copyOf(machine.returningCalls), List.copyOf(machine.transportVetoes), prerequisiteCallee);
  }

  /** Raw callee graph ends at its real RET, before any surrounding software-wrapper epilogue. */
  public static ContinuationSummary deriveCalleeGraph(Program program, SoftwareCallModel.Frame frame,
      List<SoftwareCallValidation.Configuration> candidates, TaskMonitor monitor) throws Exception {
    return deriveCalleeGraph(program, frame, candidates, monitor, false, false);
  }
  static ContinuationSummary deriveCalleeGraphForReview(Program program, SoftwareCallModel.Frame frame,
      List<SoftwareCallValidation.Configuration> candidates, TaskMonitor monitor) throws Exception {
    return deriveCalleeGraph(program, frame, candidates, monitor, true, false);
  }
  static ContinuationSummary deriveCalleeGraphForInstallation(Program program, SoftwareCallModel.Frame frame,
      List<SoftwareCallValidation.Configuration> candidates, TaskMonitor monitor) throws Exception {
    return deriveCalleeGraph(program, frame, candidates, monitor, false, true);
  }
  private static ContinuationSummary deriveCalleeGraph(Program program, SoftwareCallModel.Frame frame,
      List<SoftwareCallValidation.Configuration> candidates, TaskMonitor monitor,
      boolean reviewRepairs, boolean installationProof) throws Exception {
    long modification = program.getModificationNumber();
    String source = FarCallEvidence.capture(program, monitor);
    var machine = new Machine(program, frame, monitor, List.copyOf(candidates), reviewRepairs, installationProof);
    machine.continuationMode = true; machine.calleeGraphMode = true; machine.externalSp = frame.targetSp();
    var unresolved = new ArrayList<String>();
    try { machine.run(); }
    catch (Unresolved failure) { unresolved.add(failure.getMessage()); }
    monitor.checkCancelled();
    if (modification != program.getModificationNumber() || !source.equals(FarCallEvidence.capture(program, monitor)))
      throw new IllegalArgumentException("Program changed during callee-graph derivation");
    for (var deferred : machine.returnRepairVetoes.entrySet())
      if (!reviewRepairs || !machine.returningCalls.contains(deferred.getKey()))
        machine.nativeIncompatibilities.addAll(deferred.getValue());
    machine.validateBootstrapWitnesses();
    String dependencies = Sha256.of(ProgramMapping.JSON.toJson(List.of(VERSION, "callee-graph-1", source,
        frame, List.copyOf(candidates), reviewRepairs, installationProof)).getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString();
    return new ContinuationSummary(VERSION, "CALLEE", dependencies, machine.trace.stream().map(TraceStep::freeze).toList(),
        machine.continuationExit, unresolved, List.copyOf(machine.nativeIncompatibilities),
        List.copyOf(machine.returningNativeFunctions), List.copyOf(machine.returningCalls), List.copyOf(machine.transportVetoes), null);
  }

  public record CalleeInvocation(int callStep, String target, ContinuationSummary graph) {}

  /**
   * Extract actual balanced native invocations from a freshly derived root graph. Global step IDs
   * remain graph labels; only native depth is rebased. Software-wrapper prelude/epilogue operations
   * are outside the callee slice, while calls made by the callee remain inside its dependency graph.
   * A slice consumes the original proof and cannot turn an unmatched frame into a returning call.
   */
  public static List<CalleeInvocation> calleeInvocations(ContinuationSummary source) {
    if (!source.complete()) throw new IllegalArgumentException("Incomplete source graph cannot prove nested invocations");
    var result = new ArrayList<CalleeInvocation>();
    var typedReasons = new HashSet<String>();
    for (var veto : source.transportVetoes()) typedReasons.add(veto.reason());
    for (var call : source.steps()) {
      if ((call.afterCall() == null && call.callOutcome() == null) || call.physicalTarget() == null) continue;
      if (!call.transfer().equals("CALL") && !call.transfer().equals("CALLIND") && call.softwareCall() == null) continue;
      int depth = call.callDepth() + 1, first = -1, last = -1;
      for (int index = 0; index < source.steps().size(); index++) {
        var step = source.steps().get(index);
        if (step.index() <= call.index() || step.callDepth() != depth
            || !step.nativeFunctionEntry().equals(call.physicalTarget())) continue;
        if (first < 0) first = index;
        if (call.callOutcome() != null) continue;
        if (!step.transfer().equals("RETURN") || step.after() == null) continue;
        boolean matched;
        if (call.softwareCall() == null) matched = step.after().equals(call.afterCall());
        else {
          var frame = call.softwareCall();
          int returnCpu = frame.template().epilogueCpu() < 0 ? frame.continuationCpu() : frame.template().epilogueCpu();
          matched = step.after().cpu() == returnCpu && step.after().sp() == ((frame.targetSp() + 2) & 0xffff);
        }
        if (matched) { last = index; break; }
      }
      if (call.callOutcome() != null) {
        for (int index = first; index >= 0 && index < source.steps().size(); index++)
          if (source.steps().get(index).index() == call.callOutcome().terminalStep()) { last = index; break; }
      }
      if (first < 0 || last < first)
        throw new IllegalArgumentException("Proven call lacks its contiguous raw native invocation at step " + call.index());
      var steps = new ArrayList<ContinuationStep>();
      for (int index = first; index <= last; index++) {
        var step = source.steps().get(index);
        if (step.callDepth() < depth)
          throw new IllegalArgumentException("Nested invocation crosses an unmatched outer frame");
        steps.add(new ContinuationStep(step.index(), step.address(), step.length(), step.before(), step.after(),
            step.executedPcode(), step.accesses(), step.callDepth() - depth, step.nativeFunctionEntry(),
            step.transfer(), step.physicalTarget(), index == last && (call.callOutcome() == null
                || !call.callOutcome().exit().equals("NONRETURNING")) ? null : step.successor(),
            step.softwareCall(), step.afterCall(), step.callOutcome()));
      }
      int begin = steps.get(0).index(), end = steps.get(steps.size() - 1).index();
      var vetoes = new ArrayList<TransportVeto>();
      var incompatibilities = new LinkedHashSet<String>();
      // Annotation/contract errors have no transport exemption, including when their exact scope
      // is broader than this invocation. Conservatively retain them for the enclosing proof.
      for (var reason : source.nativeIncompatibilities()) if (!typedReasons.contains(reason)) incompatibilities.add(reason);
      for (var veto : source.transportVetoes()) {
        if (veto.step() < begin || veto.step() > end) continue;
        if (veto.callDepth() < depth) throw new IllegalArgumentException("Transport veto contradicts invocation depth");
        vetoes.add(new TransportVeto(veto.step(), veto.callDepth() - depth, veto.kind(), veto.reason()));
        incompatibilities.add(veto.reason());
      }
      var addresses = new HashSet<String>(); var entries = new HashSet<String>();
      for (var step : steps) { addresses.add(step.address()); entries.add(step.nativeFunctionEntry()); }
      var returning = source.returningNativeFunctions().stream().filter(entries::contains).toList();
      var calls = source.returningCalls().stream().filter(witness -> addresses.contains(witness.site())).toList();
      String dependencies = Sha256.of(ProgramMapping.JSON.toJson(List.of(VERSION, "native-invocation-1",
          source.kind(), source.dependencies(), call.index(), call.before(),
          call.afterCall() == null ? call.callOutcome() : call.afterCall(), begin, end))
          .getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString();
      var graph = new ContinuationSummary(VERSION, "CALLEE", dependencies, steps,
          call.callOutcome() == null ? "RETURN" : call.callOutcome().exit().equals("NONRETURNING") ? "LOOP" : "NONLOCAL", List.of(),
          List.copyOf(incompatibilities), returning, calls, vetoes, null);
      result.add(new CalleeInvocation(call.index(), call.physicalTarget(), graph));
    }
    return List.copyOf(result);
  }

  private static final class TraceStep {
    int index, length, callDepth;
    String address, nativeEntry, transfer = "FALLTHROUGH", physicalTarget;
    ContinuationState before, after, afterCall;
    Integer successor;
    SoftwareCallModel.Frame softwareCall;
    CallOutcome callOutcome;
    final List<Integer> executed = new ArrayList<>();
    final List<Access> accesses = new ArrayList<>();
    ContinuationStep freeze() {
      return new ContinuationStep(index, address, length, before, after, executed, accesses, callDepth,
          nativeEntry, transfer, physicalTarget, successor, softwareCall, afterCall, callOutcome);
    }
  }
  public record Summary(String version, String dependencies, List<Path> paths, List<String> unresolved,
      List<Fetch> fetches, List<String> nativeIncompatibilities, List<String> returningNativeFunctions, List<ReturningCall> returningCalls) {
    public Summary {
      paths = List.copyOf(paths); unresolved = List.copyOf(unresolved);
      fetches = List.copyOf(fetches); nativeIncompatibilities = List.copyOf(nativeIncompatibilities);
      returningNativeFunctions = List.copyOf(returningNativeFunctions); returningCalls = List.copyOf(returningCalls);
    }
    public boolean nativeCompatible() { return complete() && nativeIncompatibilities.isEmpty(); }
    public boolean complete() { return unresolved.isEmpty() && !paths.isEmpty(); }
    public boolean mayReturn() {
      return complete() && paths.stream().anyMatch(p -> p.returned.exit() == SoftwareCallModel.Exit.MAY_RETURN);
    }
  }

  public static Summary derive(Program program, SoftwareCallModel.Frame frame, TaskMonitor monitor) throws Exception {
    return derive(program, frame, monitor, List.of());
  }

  public static Summary derive(Program program, SoftwareCallModel.Frame frame, TaskMonitor monitor,
      List<SoftwareCallValidation.Configuration> candidates) throws Exception {
    return derive(program, frame, monitor, candidates, false, false);
  }

  /** Only matched ordinary RET witnesses can authorize exact noReturn/CALL_RETURN repair. */
  static Summary deriveForReview(Program program, SoftwareCallModel.Frame frame, TaskMonitor monitor,
      List<SoftwareCallValidation.Configuration> candidates) throws Exception {
    return derive(program, frame, monitor, candidates, true, false);
  }

  static Summary deriveForInstallation(Program program, SoftwareCallModel.Frame frame, TaskMonitor monitor,
      List<SoftwareCallValidation.Configuration> candidates) throws Exception {
    return derive(program, frame, monitor, candidates, false, true);
  }

  private static Summary derive(Program program, SoftwareCallModel.Frame frame, TaskMonitor monitor,
      List<SoftwareCallValidation.Configuration> candidates, boolean reviewRepairs, boolean installationProof) throws Exception {
    long modification = program.getModificationNumber();
    String programDependencies = FarCallEvidence.capture(program, monitor);
    var reviewedCandidates = List.copyOf(candidates);
    var frameInputs = List.of(frame.template(), frame.entry(), frame.targetCpu(), frame.target(), frame.continuationCpu(),
        frame.targetSp(), frame.targetRegisters(), frame.targetMapper(), new TreeMap<>(frame.stackBytes()));
    String dependencies = Sha256.of(ProgramMapping.JSON.toJson(List.of(VERSION, programDependencies, frameInputs, reviewedCandidates))
        .getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString();
    var machine = new Machine(program, frame, monitor, reviewedCandidates, reviewRepairs, installationProof);
    var paths = new ArrayList<Path>();
    var unresolved = new ArrayList<String>();
    try { paths.add(machine.run()); }
    catch (Unresolved e) { unresolved.add(e.getMessage()); }
    monitor.checkCancelled();
    if (modification != program.getModificationNumber()
        || !programDependencies.equals(FarCallEvidence.capture(program, monitor)))
      throw new IllegalArgumentException("Program changed during callee-effect derivation");
    for (var deferred : machine.returnRepairVetoes.entrySet())
      if (!reviewRepairs || !machine.returningCalls.contains(deferred.getKey()))
        machine.nativeIncompatibilities.addAll(deferred.getValue());
    machine.validateBootstrapWitnesses();
    return new Summary(VERSION, dependencies, paths, unresolved, machine.fetches, List.copyOf(machine.nativeIncompatibilities),
        List.copyOf(machine.returningNativeFunctions), List.copyOf(machine.returningCalls));
  }

  private static final class Unresolved extends Exception {
    Unresolved(String message) { super(message); }
  }
  private static final class Machine {
    final Program program;
    final Cartridge cartridge;
    final SoftwareCallModel.Frame frame;
    final TaskMonitor monitor;
    final Map<Long, Integer> registers = new HashMap<>();
    final Map<Long, Integer> unique = new HashMap<>();
    final Map<MapperState.Physical, Integer> memory = new HashMap<>();
    final List<MemoryWrite> writes = new ArrayList<>();
    final Set<String> seen = new HashSet<>();
    final List<Fetch> fetches = new ArrayList<>();
    final Set<String> nativeIncompatibilities = new LinkedHashSet<>();
    final Set<String> returningNativeFunctions = new TreeSet<>();
    final Set<ReturningCall> returningCalls = new LinkedHashSet<>();
    final Map<ReturningCall, List<String>> returnRepairVetoes = new LinkedHashMap<>();
    final boolean reviewRepairs, installationProof;
    final Set<String> bootstrapTargets = new TreeSet<>();
    boolean neutralTarget(Address address) {
      if (SoftwareCallRegistry.isNeutralReturningTarget(program, address)) return true;
      if (!installationProof || !AnalysisOwnership.returningMarkerCurrent(program, address)) return false;
      bootstrapTargets.add(address.toString()); return true;
    }
    void validateBootstrapWitnesses() {
      for (var target : bootstrapTargets) if (!returningNativeFunctions.contains(target))
        nativeIncompatibilities.add("Newly installed neutral marker lacks a freshly matched RET witness at " + target);
    }
    private static final class NativeCall {
      final int returnCpu, returnSp;
      final Address callerEntry;
      final SoftwareCallModel.Frame software;
      Address site;
      TraceStep traceCall;
      int phase; // 0: exact helper prelude, 1: target callee, 2: exact helper epilogue
      SoftwareCallModel.Returned expectedReturn;
      NativeCall(int returnCpu, int returnSp, Address callerEntry, SoftwareCallModel.Frame software) {
        this.returnCpu = returnCpu; this.returnSp = returnSp; this.callerEntry = callerEntry; this.software = software;
      }
    }
    final List<SoftwareCallValidation.Configuration> candidates;
    final Deque<NativeCall> nativeCalls = new ArrayDeque<>();
    Address nativeEntry;
    MapperState mapper;
    int cpu;
    boolean continuationMode, calleeGraphMode;
    int externalSp;
    String continuationExit;
    final List<TraceStep> trace = new ArrayList<>();
    final List<TransportVeto> transportVetoes = new ArrayList<>();
    void transportVeto(String kind, String reason) {
      nativeIncompatibilities.add(reason);
      transportVetoes.add(new TransportVeto(
          continuationMode ? (tracing == null ? trace.size() : tracing.index) : -1,
          nativeCalls.size(), kind, reason));
    }
    final Map<String, Integer> traceStates = new HashMap<>();
    TraceStep tracing;
    int pcodeIndex = -1;

    void startContinuation(SoftwareCallModel.Returned returned) throws Exception {
      if (!nativeCalls.isEmpty()) throw new Unresolved("Continuation bypasses an active native frame");
      mapper = returned.mapper(); cpu = returned.cpu(); externalSp = frame.entry().callerSp();
      var r = returned.registers();
      put("A", r.a()); put("F", r.f()); put("BC", r.bc()); put("DE", r.de()); put("HL", r.hl());
      put("SP", returned.sp()); put("PC", cpu);
      nativeEntry = view(cpu); seen.clear(); continuationMode = true;
    }
    ContinuationState state() throws Exception {
      var bytes = memory.entrySet().stream()
          .sorted(Comparator.comparing(entry -> entry.getKey().toString()))
          .map(entry -> new MemoryByte(entry.getKey(), entry.getValue())).toList();
      return new ContinuationState(cpu, physical(cpu, false), mapper, get("SP"), results(), bytes);
    }
    void finishTrace(Integer successor) throws Exception {
      if (tracing == null) return;
      tracing.after = state(); tracing.successor = successor; tracing = null;
    }
    List<NativeFrame> liveFrames() {
      var frames = new ArrayList<NativeFrame>();
      for (var call : nativeCalls) {
        int pointer = (call.returnSp - 2) & 0xffff;
        var lowIdentity = MapperState.translate(cartridge, mapper, pointer, false).physical();
        var highIdentity = MapperState.translate(cartridge, mapper, (pointer + 1) & 0xffff, false).physical();
        Integer low = memory.get(lowIdentity), high = memory.get(highIdentity);
        Integer word = low == null || high == null ? null : low | (high << 8);
        frames.add(new NativeFrame(call.returnCpu, call.returnSp, pointer, word,
            call.callerEntry.toString(), call.software, call.phase));
      }
      return List.copyOf(frames);
    }
    void terminalCalls(String exit) throws Exception {
      if (!continuationMode || nativeCalls.isEmpty()) return;
      int terminalStep = tracing == null ? trace.get(trace.size() - 1).index : tracing.index;
      var outcome = new CallOutcome(exit, state(), liveFrames(), terminalStep, null);
      for (var call : nativeCalls) if (call.traceCall != null) call.traceCall.callOutcome = outcome;
    }
    boolean hasNonlocalBoundary() throws Exception {
      int sp = get("SP"), previous = -1;
      for (var call : nativeCalls) {
        if (call.returnSp <= previous) return false;
        previous = call.returnSp;
        int boundary = call.software != null && call.phase == 1
            ? (call.software.targetSp() + 2) & 0xffff : call.returnSp;
        if (sp == boundary) return true;
        if (sp < boundary) return false;
      }
      return false;
    }
    void retireNonlocal(int destination) throws Exception {
      int sp = get("SP"), previous = -1;
      var departed = new ArrayList<NativeCall>();
      boolean matched = false;
      for (var call : nativeCalls) {
        if (call.returnSp <= previous) throw new Unresolved("Nonlocal native frames have ambiguous stack nesting");
        previous = call.returnSp;
        int boundary = call.software != null && call.phase == 1
            ? (call.software.targetSp() + 2) & 0xffff : call.returnSp;
        departed.add(call);
        if (sp == boundary) { matched = true; break; }
        if (sp < boundary) break;
      }
      if (!matched) throw new Unresolved("Nonlocal RET does not establish exactly departed native frame boundaries");
      cpu = destination;
      var outcome = tracing == null ? null : new CallOutcome("NONLOCAL", state(), liveFrames(), tracing.index, trace.size());
      for (var call : departed) {
        if (call.traceCall != null) call.traceCall.callOutcome = outcome;
        nativeEntry = nativeCalls.pop().callerEntry;
      }
      // Only logical invocation records retire. All current physical RAM, saved wrapper words and
      // registers remain in the machine and are consumed by actual destination instructions.
    }
    void matchedCall(NativeCall call) throws Exception {
      if (continuationMode && call.traceCall != null) {
        int current = cpu; cpu = call.returnCpu;
        try { call.traceCall.afterCall = state(); } finally { cpu = current; }
      }
    }


    Machine(Program program, SoftwareCallModel.Frame frame, TaskMonitor monitor,
        List<SoftwareCallValidation.Configuration> candidates, boolean reviewRepairs, boolean installationProof) throws Exception {
      this.reviewRepairs = reviewRepairs; this.installationProof = installationProof;
      this.program = program; this.frame = frame; this.monitor = monitor;
      this.candidates = List.copyOf(candidates);
      cartridge = ProgramMapping.cartridge(program); mapper = frame.targetMapper(); cpu = frame.targetCpu();
      nativeEntry = view(cpu);
      var r = frame.targetRegisters();
      put("A", r.a()); put("F", r.f()); put("BC", r.bc()); put("DE", r.de()); put("HL", r.hl());
      put("SP", frame.targetSp()); put("PC", cpu);
      for (var b : frame.stackBytes().entrySet()) memory.put(physical(b.getKey(), false), b.getValue());
    }

    Path run() throws Exception {
      for (int step = 0; step < 4096; step++) {
        monitor.checkCancelled();
        put("PC", cpu);
        String frames = nativeCalls.stream().map(call -> call.returnCpu + ":" + call.returnSp + ":"
            + call.callerEntry + ":" + call.phase).toList().toString();
        String key = cpu + ":" + mapper + ":" + new TreeMap<>(registers) + ":" + memory + ":" + frames;
        if (!seen.add(key)) {
          if (continuationMode) {
            continuationExit = "LOOP"; terminalCalls("NONRETURNING"); finishTrace(traceStates.get(key));
          }
          return exit(SoftwareCallModel.Exit.NONRETURNING);
        }
        if (continuationMode) {
          finishTrace(trace.size()); traceStates.put(key, trace.size());
        }
        Address address = view(cpu);
        var fetchIdentity = physical(cpu, false);
        var active = nativeCalls.peek();
        if (active != null && active.software != null && active.phase == 0
            && cpu == active.software.targetCpu() && get("SP") == active.software.targetSp()
            && fetchIdentity.equals(active.software.target())) {
          active.phase = 1; nativeEntry = address;
        }
        boolean transparentHelper = transparentHelper(cpu);
        var boundaryFunction = program.getFunctionManager().getFunctionAt(address);
        if (!transparentHelper && boundaryFunction != null && !address.equals(nativeEntry))
          nativeIncompatibilities.add("Unmodeled native function boundary at " + address + " within " + nativeEntry);
        fetches.add(new Fetch(address.toString(), fetchIdentity, nativeEntry.toString(), nativeCalls.size()));
        if (!transparentHelper && !nativeEntry.getAddressSpace().getAddress(cpu).equals(address))
          transportVeto("FETCH_SPACE", "Callee intrafunction fetch leaves native entry space: " + nativeEntry + " -> " + address);
        var fetchBlock = program.getMemory().getBlock(address);
        if (!fetchIdentity.region().equals("ROM") || fetchBlock == null
            || fetchBlock.isWrite() || fetchBlock.isVolatile() || !fetchBlock.isInitialized())
          throw new Unresolved("Callee instruction source must be immutable initialized ROM at " + address);
        var instruction = SoftwareCallInstructionDiscovery.instructionAt(program, address,
            continuationMode ? "CONTINUATION_FETCH" : "CALLEE_FETCH", monitor);
        if (instruction == null || instruction.isLengthOverridden())
          throw new Unresolved("Missing architectural callee boundary at " + address);
        for (int offset = 0; offset < instruction.getLength(); offset++) {
          int byteCpu = (cpu + offset) & 0xffff;
          var byteAddress = view(byteCpu);
          var byteBlock = program.getMemory().getBlock(byteAddress);
          if (!byteAddress.equals(address.add(offset)))
            throw new Unresolved("Instruction spans distinct physical execution views at " + address);
          if (!physical(byteCpu, false).region().equals("ROM") || byteBlock == null
              || byteBlock.isWrite() || byteBlock.isVolatile() || !byteBlock.isInitialized())
            throw new Unresolved("Instruction byte is not immutable initialized ROM at " + byteAddress);
        }
        if (continuationMode) {
          tracing = new TraceStep(); tracing.index = trace.size(); tracing.address = address.toString();
          tracing.length = instruction.getLength(); tracing.before = state(); tracing.callDepth = nativeCalls.size();
          tracing.nativeEntry = nativeEntry.toString(); trace.add(tracing);
        }
        // Native annotations cannot replace the architectural interpretation proved below.
        String nativeInterpretation = InstructionInterpretation.architecturalUnresolved(instruction);
        boolean neutralCall = false;
        if (instruction.getFlowType().isCall() && instruction.getDefaultFlows().length == 1)
          neutralCall = neutralTarget(instruction.getDefaultFlows()[0]);
        if (nativeInterpretation != null && candidateAt(address) == null
            && !(neutralCall && nativeInterpretation.startsWith("Unsupported instruction interpretation: callfixup "))) {
          if (instruction.getFlowOverride() == ghidra.program.model.listing.FlowOverride.CALL_RETURN
              && instruction.getDefaultFlows().length == 1 && Arrays.stream(instruction.getPcode(false)).anyMatch(op -> op.getOpcode() == PcodeOp.CALL))
            returnRepairVetoes.computeIfAbsent(new ReturningCall(address.toString(), instruction.getDefaultFlows()[0].toString()),
                ignored -> new ArrayList<>()).add(nativeInterpretation + " at " + address);
          else nativeIncompatibilities.add(nativeInterpretation + " at " + address);
        }
        // Source bytes and raw p-code are authoritative; inferred call/noReturn annotations are not.
        var ops = instruction.getPcode(false);
        unique.clear();
        int next = (cpu + instruction.getLength()) & 0xffff;
        for (int index = 0, micro = 0; index < ops.length; index++, micro++) {
          if (micro >= 256) throw new Unresolved("P-code branch budget exceeded at " + address);
          var op = ops[index]; int opcode = op.getOpcode();
          pcodeIndex = index;
          if (tracing != null) tracing.executed.add(index);
          if (opcode == PcodeOp.LOAD) {
            int pointer = integer(op.getInput(1));
            int instructionByte = instruction.getBytes()[0] & 255;
            boolean ordinaryRet = instruction.getLength() == 1
                && (instructionByte == 0xc9 || instructionByte == 0xc0 || instructionByte == 0xc8
                    || instructionByte == 0xd0 || instructionByte == 0xd8);
            if (continuationMode && nativeCalls.isEmpty() && ordinaryRet && pointer == externalSp
                && op.getOutput().getSize() == 1 && get("SP") == externalSp) {
              var low = physical(pointer, false); var high = physical((pointer + 1) & 0xffff, false);
              if (!memory.containsKey(low) && !memory.containsKey(high)) {
                if (!((pointer >= 0xc000 && pointer <= 0xcffe) || (pointer >= 0xff80 && pointer <= 0xfffd)))
                  throw new Unresolved("Symbolic external return requires fixed WRAM0 or HRAM");
                validateNativeMemory(pointer, low); validateNativeMemory((pointer + 1) & 0xffff, high);
                int highLoad = -1;
                for (int remaining = index + 1; remaining < ops.length; remaining++) {
                  var nextOp = ops[remaining];
                  if (nextOp.getOpcode() != PcodeOp.LOAD) continue;
                  Long nextPointer = PcodeConstants.value(nextOp.getInput(1), registers, unique);
                  if (highLoad >= 0 || nextOp.getOutput().getSize() != 1 || nextPointer == null
                      || (nextPointer & 0xffff) != ((pointer + 1) & 0xffff))
                    throw new Unresolved("External RET does not have the architectural ordered byte reads");
                  highLoad = remaining;
                }
                if (highLoad < 0) throw new Unresolved("External RET lacks its architectural high-byte read");
                tracing.accesses.add(new Access(index, 0, pointer, low, null, false, false));
                tracing.accesses.add(new Access(highLoad, 0, (pointer + 1) & 0xffff, high, null, false, false));
                // Retain all remaining raw operations: native execution reads the actual live word.
                for (int remaining = index + 1; remaining < ops.length; remaining++) tracing.executed.add(remaining);
                tracing.transfer = "EXTERNAL_RETURN"; continuationExit = "RETURN";
                put("SP", (externalSp + 2) & 0xffff); finishTrace(null);
                return path(new SoftwareCallModel.Returned(SoftwareCallModel.Exit.MAY_RETURN, null, null,
                    get("SP"), results(), mapper, List.of(), List.of(), List.of()));
              }
              if (memory.containsKey(low) != memory.containsKey(high))
                throw new Unresolved("Partially known external return word requires symbolic byte propagation");
            }
            long value = 0;
            for (int byteIndex = 0; byteIndex < op.getOutput().getSize(); byteIndex++)
              value |= (long) read((pointer + byteIndex) & 0xffff) << (byteIndex * 8);
            PcodeConstants.put(op.getOutput(), value, registers, unique);
          } else if (opcode == PcodeOp.STORE || CartridgeBus.isDirectWrite(program.getLanguage(), op)) {
            int pointer = integer(op.getInput(1)); long value = known(op.getInput(2));
            for (int byteIndex = 0; byteIndex < op.getInput(2).getSize(); byteIndex++)
              write((pointer + byteIndex) & 0xffff, (int) (value >>> (byteIndex * 8)) & 255,
                  CartridgeBus.isDirectWrite(program.getLanguage(), op));
          } else if (opcode == PcodeOp.RETURN) {
            int destination = integer(op.getInput(0));
            if (tracing != null) { tracing.transfer = "RETURN"; tracing.physicalTarget = view(destination).toString(); }
            var softwareCall = nativeCalls.peek();
            if (softwareCall != null && softwareCall.software != null) {
              var nested = softwareCall.software;
              int first = nested.template().epilogueCpu() < 0 ? nested.continuationCpu() : nested.template().epilogueCpu();
              if (softwareCall.phase == 0 && transparentHelper && destination == nested.targetCpu()
                  && get("SP") == nested.targetSp() && physical(destination, false).equals(nested.target())) {
                next = destination; break; // Exact inline helper RET is the emitted physical CALL.
              }
              if (softwareCall.phase == 1 && destination == first && get("SP") == ((nested.targetSp() + 2) & 0xffff)) {
                var live = new HashMap<Integer, Integer>();
                for (int at = nested.targetSp(); at < nested.entry().callerSp(); at++) live.put(at, readProof(at));
                try {
                  softwareCall.expectedReturn = SoftwareCallModel.returnFrom(cartridge, nested, SoftwareCallModel.Exit.MAY_RETURN,
                      nested.targetSp(), results(), mapper, live);
                  returningNativeFunctions.add(nativeEntry.toString());
                } catch (IllegalArgumentException failure) {
                  nativeIncompatibilities.add("Nested software-call live frame differs from contract at " + address);
                }
                nativeEntry = softwareCall.callerEntry;
                if (nested.template().epilogueCpu() >= 0) softwareCall.phase = 2;
                else { verifyNestedReturn(softwareCall); nativeCalls.pop(); matchedCall(softwareCall); }
                next = destination; break;
              }
              if (softwareCall.phase == 2 && destination == softwareCall.returnCpu && get("SP") == softwareCall.returnSp) {
                verifyNestedReturn(softwareCall); nativeEntry = nativeCalls.pop().callerEntry; matchedCall(softwareCall);
                next = destination; break;
              }
            }
            if (continuationMode && !nativeCalls.isEmpty() && nativeCalls.peek().software == null
                && nativeCalls.peek().returnCpu == destination && nativeCalls.peek().returnSp == get("SP")) {
              returningNativeFunctions.add(nativeEntry.toString());
              var matched = nativeCalls.pop();
              if (matched.site != null) returningCalls.add(new ReturningCall(matched.site.toString(), nativeEntry.toString()));
              nativeEntry = matched.callerEntry; matchedCall(matched); next = destination; break;
            }
            if (continuationMode) {
              if (!nativeCalls.isEmpty()) {
                var expectedCall = nativeCalls.peek();
                if (destination == expectedCall.returnCpu)
                  throw new Unresolved("Continuation call returns with an unsupported live-frame stack effect");
                transportVeto("NONLOCAL_CALL", "Callee bypasses an active native call frame at " + address);
                retireNonlocal(destination);
                next = destination; break;
              }
              if (calleeGraphMode && nativeCalls.isEmpty()) {
                int expected = frame.template().epilogueCpu() < 0 ? frame.continuationCpu() : frame.template().epilogueCpu();
                if (destination == expected) {
                  if (get("SP") != ((frame.targetSp() + 2) & 0xffff))
                    throw new Unresolved("Callee graph returns with unsupported live-frame stack effect");
                  validateReturningBoundary(new SoftwareCallModel.Returned(SoftwareCallModel.Exit.MAY_RETURN, destination,
                      physical(destination, false), get("SP"), results(), mapper, List.of(), List.of(), List.of()));
                  returningNativeFunctions.add(nativeEntry.toString());
                  continuationExit = "RETURN"; cpu = destination; finishTrace(null);
                  return path(new SoftwareCallModel.Returned(SoftwareCallModel.Exit.MAY_RETURN, destination,
                      physical(destination, false), get("SP"), results(), mapper, List.of(), List.of(), List.of()));
                }
              }
              continuationExit = "NONLOCAL"; cpu = destination; terminalCalls("NONLOCAL"); finishTrace(null);
              return nonlocal(destination);
            }
            if (!nativeCalls.isEmpty() && destination != nativeCalls.peek().returnCpu && hasNonlocalBoundary()) {
              transportVeto("NONLOCAL_CALL", "Callee bypasses an active native call frame at " + address);
              retireNonlocal(destination); next = destination; break;
            }
            // RET can transfer through a software wrapper's manually pushed epilogue;
            // a Java CALL-depth stack would misclassify that architectural frame as nonlocal.
            if (get("SP") <= frame.targetSp()) {
              if (!nativeCalls.isEmpty() && nativeCalls.peek().returnCpu == destination
                  && nativeCalls.peek().returnSp == get("SP")) {
                returningNativeFunctions.add(nativeEntry.toString());
                var matched = nativeCalls.pop();
                if (matched.site != null) returningCalls.add(new ReturningCall(matched.site.toString(), nativeEntry.toString()));
                nativeEntry = matched.callerEntry;
              } else nativeIncompatibilities.add("Callee RET is an unmodeled native intrafunction transfer at " + address);
              next = destination; break;
            }
            if (!nativeCalls.isEmpty())
              nativeIncompatibilities.add("Callee bypasses an active native call frame at " + address);
            int expected = frame.template().epilogueCpu() < 0 ? frame.continuationCpu() : frame.template().epilogueCpu();
            if (destination != expected) return nonlocal(destination);
            if (get("SP") != ((frame.targetSp() + 2) & 0xffff))
              throw new Unresolved("Callee returns to expected destination with unsupported stack effect");
            var stack = new HashMap<Integer, Integer>();
            for (int p = frame.targetSp(); p < frame.entry().callerSp(); p++) stack.put(p, readProof(p));
            try {
              var returned = SoftwareCallModel.returnFrom(cartridge, frame, SoftwareCallModel.Exit.MAY_RETURN,
                  frame.targetSp(), results(), mapper, stack);
              if (returned.physical() == null) throw new Unresolved("Unresolved physical continuation");
              validateReturningBoundary(returned);
              returningNativeFunctions.add(nativeEntry.toString());
              return path(returned);
            } catch (IllegalArgumentException e) {
              throw new Unresolved("Callee live-frame mutation requires an independent epilogue proof: " + e.getMessage());
            }
          } else if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH
              || opcode == PcodeOp.BRANCHIND || opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
            if (opcode == PcodeOp.CBRANCH && known(op.getInput(1)) == 0) continue;
            var destination = op.getInput(0);
            if (destination.isConstant() && (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH)) {
              index += (int) destination.getOffset() - 1;
              if (index < -1 || index >= ops.length) throw new Unresolved("Invalid p-code relative branch");
              continue;
            }
            next = destination.isAddress() ? (int) destination.getOffset() & 0xffff : integer(destination);
            if (tracing != null) {
              tracing.transfer = PcodeOp.getMnemonic(opcode); tracing.physicalTarget = view(next).toString();
            }
            if (opcode == PcodeOp.BRANCHIND && !transparentHelper)
              transportVeto("INDIRECT_BRANCH", "Indirect native callee branch needs a validated target mechanism at " + address);
            var declaredTransfer = candidateAt(address);
            if ((opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) && !transparentHelper && declaredTransfer == null) {
              var branchFunction = program.getFunctionManager().getFunctionAt(view(next));
              if (branchFunction != null && !branchFunction.getEntryPoint().equals(nativeEntry))
                nativeIncompatibilities.add("Unmodeled native tail-call boundary at " + address + " -> " + branchFunction.getEntryPoint());
            }
            boolean manualSoftwareCall = opcode == PcodeOp.BRANCH && declaredTransfer != null
                && declaredTransfer.transfer() == SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION;
            if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND || manualSoftwareCall) {
              if (nativeCalls.size() >= 32 || frame.targetSp() - get("SP") > 64) throw new Unresolved("Nested frame bound exceeded");
              var declared = declaredTransfer;
              SoftwareCallModel.Frame nested = declared == null ? null : matchingSoftwareFrame(declared);
              if (nested != null) {
                if (next != nested.template().helperCpu())
                  throw new Unresolved("Nested software call does not enter validated helper");
                var call = new NativeCall(nested.continuationCpu(), nested.entry().callerSp(), nativeEntry, nested);
                call.traceCall = tracing; nativeCalls.push(call);
                if (tracing != null) { tracing.softwareCall = nested; tracing.physicalTarget = SoftwareCallValidation.executionAddress(program, nested.targetMapper(), nested.targetCpu()).toString(); }
              } else {
              var actualTarget = view(next);
              if (opcode == PcodeOp.CALLIND || instruction.getDefaultFlows().length != 1
                  || !instruction.getDefaultFlows()[0].equals(actualTarget))
                transportVeto("CALL_TARGET", "Nested call lacks the actual physical native target at " + address + " -> " + actualTarget);
              var repairKey = new ReturningCall(address.toString(), actualTarget.toString());
              if (instruction.getFlowOverride() == ghidra.program.model.listing.FlowOverride.CALL_RETURN
                  && (!instruction.isFallThroughOverridden() || instruction.getFallThrough() == null))
                returnRepairVetoes.computeIfAbsent(repairKey, ignored -> new ArrayList<>())
                    .add("Nested call requires matched-RET flow repair at " + address);
              else if (instruction.getFlowOverride() != ghidra.program.model.listing.FlowOverride.NONE
                  || instruction.isFallThroughOverridden())
                nativeIncompatibilities.add("Nested call has an unvalidated native flow interpretation at " + address);
              for (var reference : instruction.getReferencesFrom())
                if (InstructionInterpretation.relevant(reference)
                    && (!reference.getToAddress().equals(actualTarget) || reference.getReferenceType().isOverride()))
                  nativeIncompatibilities.add("Nested call has a conflicting native target reference at " + address);
              var nativeTarget = program.getFunctionManager().getFunctionAt(actualTarget);
              if (nativeTarget != null && (nativeTarget.isThunk() || nativeTarget.isInline()
                  || (nativeTarget.getCallFixup() != null
                      && !neutralTarget(actualTarget))))
                nativeIncompatibilities.add("Nested call has an unsupported native target contract at " + actualTarget);
              if (nativeTarget != null) {
                if (nativeTarget.hasNoReturn()) returnRepairVetoes.computeIfAbsent(repairKey, ignored -> new ArrayList<>())
                    .add("Nested target requires matched-RET noReturn repair at " + actualTarget);
                int purge = nativeTarget.getStackPurgeSize();
                if (purge != 0 && purge != ghidra.program.model.listing.Function.UNKNOWN_STACK_DEPTH_CHANGE
                    && purge != ghidra.program.model.listing.Function.INVALID_STACK_DEPTH_CHANGE)
                  nativeIncompatibilities.add("Nested call has unsupported native stack purge at " + actualTarget);
              }
              var call = new NativeCall((cpu + instruction.getLength()) & 0xffff, (get("SP") + 2) & 0xffff, nativeEntry, null);
              call.site = address; call.traceCall = tracing;
              nativeCalls.push(call);
              nativeEntry = actualTarget;
              }
            }
            break;
          } else if (opcode == PcodeOp.CALLOTHER || opcode == PcodeOp.UNIMPLEMENTED) {
            throw new Unresolved("Unsupported architectural effect at " + address + ": " + op);
          } else if (op.getOutput() != null) {
            var inputs = new Varnode[op.getNumInputs()];
            for (int inputIndex = 0; inputIndex < inputs.length; inputIndex++) {
              var input = op.getInput(inputIndex);
              inputs[inputIndex] = input.isAddress()
                  ? new Varnode(program.getAddressFactory().getConstantSpace().getAddress(known(input)), input.getSize()) : input;
            }
            var evaluated = new PcodeOp(address, op.getSeqnum().getTime(), opcode, inputs, op.getOutput());
            Long value = PcodeConstants.evaluate(evaluated, registers, unique);
            if (value == null) throw new Unresolved("Unknown architectural value at " + address + ": " + op);
            if (op.getOutput().isAddress()) {
              for (int offset = 0; offset < op.getOutput().getSize(); offset++)
                write(((int) op.getOutput().getOffset() + offset) & 0xffff, (int) (value >>> (8 * offset)) & 255, false);
            } else PcodeConstants.put(op.getOutput(), value, registers, unique);
          } else throw new Unresolved("Unsupported p-code at " + address + ": " + op);
        }
        // Fetch is translated again even after an ordinary mapper-writing instruction.
        cpu = next;
      }
      throw new Unresolved("Callee instruction bound exceeded");
    }

    SoftwareCallValidation.Configuration candidateAt(Address address) throws Exception {
      SoftwareCallValidation.Configuration found = null;
      for (var candidate : candidates) {
        int siteCpu = candidate.callCpu() + (candidate.transfer() == SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION ? 4 : 0);
        if (!SoftwareCallValidation.executionAddress(program, candidate.mapper(), siteCpu).equals(address)) continue;
        if (found != null && !found.equals(candidate)) throw new Unresolved("Ambiguous nested software-call candidate");
        found = candidate;
      }
      return found;
    }
    SoftwareCallModel.Frame matchingSoftwareFrame(SoftwareCallValidation.Configuration candidate) throws Exception {
      if (!mapper.equals(candidate.mapper()) || get("SP") != ((candidate.callerSp() - 2) & 0xffff)
          || !results().equals(candidate.registers()))
        throw new Unresolved("Nested software-call entry premises disagree with actual path");
      return SoftwareCallValidation.preview(program, candidate, monitor).frame();
    }
    boolean transparentHelper(int address) {
      var active = nativeCalls.peek();
      if (active == null || active.software == null || active.phase == 1) return false;
      var template = active.software.template();
      int begin = active.phase == 2 ? template.epilogueCpu() : template.helperCpu();
      int end = active.phase == 0 && template.epilogueCpu() >= 0
          ? template.epilogueCpu() : template.helperCpu() + template.bodyHex().length() / 2;
      return address >= begin && address < end;
    }
    void verifyNestedReturn(NativeCall call) throws Exception {
      var expected = call.expectedReturn;
      if (expected == null || !Objects.equals(expected.registers(), results())
          || !Objects.equals(expected.mapper(), mapper) || !Objects.equals(expected.sp(), get("SP")))
        nativeIncompatibilities.add("Nested software-call epilogue differs from validated effects");
    }

    void validateReturningBoundary(SoftwareCallModel.Returned returned) throws Exception {
      var views = ProgramMapping.physicalToStatic(program, returned.physical()).stream()
          .filter(a -> a.getOffset() == returned.cpu() && SoftwareCallExecutionView.canonical(program, a)).toList();
      if (!returned.physical().region().equals("ROM") || views.size() != 1) {
        nativeIncompatibilities.add("Returning continuation has no unique physical ROM boundary"); return;
      }
      var at = views.get(0); var block = program.getMemory().getBlock(at);
      var instruction = program.getListing().getInstructionContaining(at);
      if (block == null || block.isWrite() || block.isVolatile() || !block.isInitialized()
          || program.getListing().getDefinedDataContaining(at) != null
          || (instruction != null && (!instruction.getAddress().equals(at) || instruction.isLengthOverridden())))
        nativeIncompatibilities.add("Returning continuation boundary conflicts with current Program at " + at);
    }

    Path nonlocal(int destination) throws Exception {
      int sp = get("SP");
      var physical = MapperState.translate(cartridge, mapper, destination, false).physical();
      if (physical == null || !physical.region().equals("ROM"))
        nativeIncompatibilities.add("Nonlocal destination has no supported native ROM execution view");
      else {
        var destinations = ProgramMapping.physicalToStatic(program, physical).stream()
            .filter(a -> a.getOffset() == destination && SoftwareCallExecutionView.canonical(program, a)).toList();
        if (destinations.size() != 1 || SoftwareCallInstructionDiscovery.instructionAt(program, destinations.get(0),
            "NONLOCAL_DESTINATION", monitor) == null)
          nativeIncompatibilities.add("Nonlocal destination lacks an unambiguous decoded boundary");
        else {
          var block = program.getMemory().getBlock(destinations.get(0));
          if (block == null || block.isWrite() || block.isVolatile() || !block.isInitialized())
            nativeIncompatibilities.add("Nonlocal destination code is not immutable initialized ROM");
          var function = program.getFunctionManager().getFunctionAt(destinations.get(0));
          if (function != null) {
            int purge = function.getStackPurgeSize();
            if (function.isThunk() || function.isInline()
                || (function.getCallFixup() != null && !neutralTarget(destinations.get(0))) || function.hasNoReturn()
                || (purge != 0 && purge != ghidra.program.model.listing.Function.UNKNOWN_STACK_DEPTH_CHANGE
                    && purge != ghidra.program.model.listing.Function.INVALID_STACK_DEPTH_CHANGE))
              nativeIncompatibilities.add("Nonlocal destination has an unsupported native function contract");
          }
        }
      }
      var pop = new SoftwareCallModel.Pop((sp - 2) & 0xffff, destination, "callee RET to nonlocal destination");
      var transfer = new SoftwareCallModel.Transfer("RET", destination, "nonlocal callee exit; wrapper epilogue not executed");
      return path(new SoftwareCallModel.Returned(SoftwareCallModel.Exit.NONLOCAL, destination, physical,
          sp, results(), mapper, List.of(), List.of(pop), List.of(pop, transfer)));
    }

    Path exit(SoftwareCallModel.Exit exit) {
      return path(SoftwareCallModel.returnFrom(cartridge, frame, exit, null, null, null, null));
    }
    Path path(SoftwareCallModel.Returned returned) {
      var changed = new HashSet<String>();
      var initial = frame.targetRegisters(); var r = returned.registers();
      if (r != null) {
        if (r.a() != initial.a()) changed.add("A"); if (r.f() != initial.f()) changed.add("F");
        if (r.bc() != initial.bc()) changed.add("BC"); if (r.de() != initial.de()) changed.add("DE");
        if (r.hl() != initial.hl()) changed.add("HL");
      }
      return new Path(returned, writes, changed);
    }
    SoftwareCallModel.Registers results() throws Exception {
      return new SoftwareCallModel.Registers(get("A"), get("F"), get("BC"), get("DE"), get("HL"));
    }
    void put(String name, int value) {
      var r = program.getRegister(name);
      PcodeConstants.put(new Varnode(r.getAddress(), r.getMinimumByteSize()), (long) value, registers, unique);
    }
    int get(String name) throws Exception {
      var r = program.getRegister(name); return integer(new Varnode(r.getAddress(), r.getMinimumByteSize()));
    }
    long known(Varnode value) throws Exception {
      if (value.isAddress()) {
        if (value.getSize() > 8) throw new Unresolved("Unsupported direct memory width");
        long bytes = 0;
        for (int offset = 0; offset < value.getSize(); offset++)
          bytes |= (long) read(((int) value.getOffset() + offset) & 0xffff) << (8 * offset);
        return bytes;
      }
      Long result = PcodeConstants.value(value, registers, unique);
      if (result == null) throw new Unresolved("Unknown required register/memory value");
      return result;
    }
    int integer(Varnode value) throws Exception { return (int) known(value) & 0xffff; }
    MapperState.Physical physical(int address, boolean write) throws Unresolved {
      var resolution = MapperState.translate(cartridge, mapper, address, write);
      if (resolution.physical() == null) throw new Unresolved("Unknown/volatile physical memory at " + Integer.toHexString(address));
      return resolution.physical();
    }
    Address view(int address) throws Exception {
      var identity = physical(address, false);
      var candidates = ProgramMapping.physicalToStatic(program, identity).stream()
          .filter(a -> a.getOffset() == address && SoftwareCallExecutionView.canonical(program, a)).toList();
      if (candidates.size() != 1) throw new Unresolved("Ambiguous physical execution view at " + Integer.toHexString(address));
      return candidates.get(0);
    }
    int readProof(int address) throws Exception {
      var current = tracing; tracing = null;
      try { return read(address); } finally { tracing = current; }
    }
    int read(int address) throws Exception {
      var identity = physical(address, false);
      validateNativeMemory(address, identity);
      for (var physicalView : ProgramMapping.physicalToStatic(program, identity)) {
        var source = program.getMemory().getBlock(physicalView);
        if (source != null && source.isVolatile())
          throw new Unresolved("Volatile physical memory cannot establish a stable read at " + physicalView);
      }
      Integer written = memory.get(identity);
      if (written != null) { recordRead(address, identity, written); return written; }
      if (!identity.region().equals("ROM")) throw new Unresolved("Unknown initial RAM contents at " + Integer.toHexString(address));
      var location = view(address); var block = program.getMemory().getBlock(location);
      if (block == null || block.isWrite() || block.isVolatile() || !block.isInitialized()) throw new Unresolved("Untrusted ROM source");
      int value = program.getMemory().getByte(location) & 255;
      recordRead(address, identity, value); return value;
    }
    void recordRead(int address, MapperState.Physical identity, int value) {
      if (tracing != null) tracing.accesses.add(new Access(pcodeIndex,
          (int) tracing.accesses.stream().filter(a -> a.pcodeIndex() == pcodeIndex && !a.write()).count(),
          address, identity, value, false, false));
    }
    void validateNativeMemory(int cpuAddress, MapperState.Physical actual) throws Exception {
      var active = nativeCalls.peek();
      if (active != null && active.software != null && active.phase == 0 && transparentHelper(cpu)
          && active.software.template().family() == SoftwareCallModel.Family.INLINE_RET
          && cpuAddress >= active.software.entry().encodedContinuation()
          && cpuAddress < active.software.entry().encodedContinuation() + 3)
        return; // Exactly the immutable payload reads specialized by production injection.
      var nativeAddress = nativeEntry.getAddressSpace().getAddress(cpuAddress);
      var identities = ProgramMapping.staticToPhysical(program, nativeAddress);
      // Fixed architectural stack/RAM addresses remain meaningful with hardware blocks omitted;
      // do not extend this fallback to bank-selected RAM or to a conflicting existing block.
      boolean implicitFixedRam = program.getMemory().getBlock(nativeAddress) == null
          && nativeAddress.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())
          && ((cpuAddress >= 0xc000 && cpuAddress < 0xd000 && actual.region().equals("WRAM") && actual.bank() == 0)
              || (cpuAddress >= 0xff80 && cpuAddress < 0xffff && actual.region().equals("HRAM")));
      if (!implicitFixedRam && (identities.size() != 1 || !identities.get(0).equals(actual)))
        transportVeto("DATA_IDENTITY", "Callee memory access lacks native physical identity at CPU "
            + Integer.toHexString(cpuAddress) + " in " + nativeEntry + ": " + actual);
    }

    void write(int address, int value, boolean decoderDirectWrite) throws Exception {
      if (tracing != null) tracing.accesses.add(new Access(pcodeIndex,
          (int) tracing.accesses.stream().filter(a -> a.pcodeIndex() == pcodeIndex && a.write()).count(),
          address, address < 0x8000 || address == 0xff4f || address == 0xff70 ? null : physical(address, true),
          value, true, address < 0x8000 || address == 0xff4f || address == 0xff70));
      if (address < 0x8000) {
        if (!decoderDirectWrite)
          transportVeto("MAPPER_WRITE", "Mapper control write lacks decoder-known native bus lowering at CPU " + Integer.toHexString(address));
        mapper = mapper.write(cartridge, address, value); writes.add(new MemoryWrite(address, null, value)); return;
      }
      if (address == 0xff4f || address == 0xff70) {
        var nativeAddress = nativeEntry.getAddressSpace().getAddress(address);
        var expectedAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
        var block = program.getMemory().getBlock(nativeAddress);
        if (!nativeAddress.equals(expectedAddress) || block == null || !block.isWrite() || !block.isVolatile())
          nativeIncompatibilities.add("Bank-register write lacks its native volatile I/O transport at CPU " + Integer.toHexString(address));
        mapper = mapper.write(cartridge, address, value); writes.add(new MemoryWrite(address, null, value)); return;
      }
      var identity = physical(address, true); validateNativeMemory(address, identity); memory.put(identity, value);
      writes.add(new MemoryWrite(address, identity, MapperState.ramWriteValue(cartridge, value)));
    }
  }
}
