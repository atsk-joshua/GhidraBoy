package fi.gekkio.ghidraboy;

import static fi.gekkio.ghidraboy.PcodeConstants.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Opt-in bounded analysis of existing instructions. Never decodes through marked data. */
public final class BankAnalysis {
  private static final int STATE_DIVERSITY_PER_ADDRESS = 32;

  private BankAnalysis() {}

  public record Finding(
      String source,
      String access,
      List<String> targets,
      String reason,
      AnalysisResult.Confidence confidence,
      int operation,
      int operand,
      int byteIndex) {
    public Finding {
      targets = List.copyOf(targets);
    }
  }

  /** Read-only observations of the production worklist, not a second state evaluator. */
  public record FetchByte(int cpu, String source, MapperState.Physical physical, int value) {}

  public record WriteTransition(
      int operation, int byteIndex, int cpu, Integer value,
      MapperKnowledge before, MapperKnowledge after, boolean mapperControl) {}

  public record FetchStep(
      String source, int cpu, List<FetchByte> bytes, List<String> rawPcode,
      MapperKnowledge incoming, MapperKnowledge outgoing,
      List<WriteTransition> writes, List<String> successors) {
    public FetchStep {
      bytes = List.copyOf(bytes);
      rawPcode = List.copyOf(rawPcode);
      writes = List.copyOf(writes);
      successors = List.copyOf(successors);
    }
  }

  /** Steps are worklist visitation order; callers must prove a unique path before linear emission. */
  public record FetchPreview(AnalysisResult result, List<FetchStep> steps, List<String> frontier) {
    public FetchPreview {
      steps = List.copyOf(steps);
      frontier = List.copyOf(frontier);
    }
  }

  private static final class FetchCollector {
    final List<FetchStep> steps = new ArrayList<>();
    final List<String> frontier = new ArrayList<>();
  }

  record Work(Address address, MapperKnowledge state, Map<Long, Integer> registers,
      Map<MapperState.Physical, AbstractValues.Value> memory) {}

  // Address includes the static execution view; instruction-local uniques are reset on every step.
  record JoinKey(Address address, MapperKnowledge state, Map<Long, Integer> registers) {
    static JoinKey of(Work work) { return new JoinKey(work.address(), work.state(), work.registers()); }
  }

  private record Root(Address address, MapperKnowledge knowledge, AnalysisResult.EntryPremise premise) {}

  /** The physical entry is an external invocation premise, never evidence of a selected display. */
  public static FetchPreview previewFetch(
      Program p, Address start, MapperState assumption,
      AnalysisResult.Configuration configuration, TaskMonitor monitor) throws Exception {
    var diagnostic = new FetchCollector();
    var result = preview(p, List.of(start), assumption, configuration, null, monitor, diagnostic);
    for (var finding : result.findings())
      if (finding.confidence() != AnalysisResult.Confidence.PROVEN)
        diagnostic.frontier.add(finding.source() + " " + finding.access() + ": " + finding.reason());
    return new FetchPreview(result, diagnostic.steps, diagnostic.frontier);
  }

  public static List<Finding> analyze(
      Program p, Address start, MapperState assumption, TaskMonitor monitor, boolean apply)
      throws Exception {
    var result = preview(p, start, assumption, AnalysisResult.Configuration.DEFAULT, monitor);
    if (apply) apply(p, result, monitor);
    return result.findings();
  }

  public static AnalysisResult preview(
      Program p,
      Address start,
      MapperState assumption,
      AnalysisResult.Configuration configuration,
      TaskMonitor monitor)
      throws Exception {
    return preview(p, List.of(start), assumption, configuration, null, monitor, null);
  }

  /** Runs one session-wide worklist for all justified roots. */
  public static AnalysisResult preview(
      Program p,
      Collection<Address> starts,
      AnalysisResult.Configuration configuration,
      AddressSetView restriction,
      TaskMonitor monitor)
      throws Exception {
    return preview(p, starts, null, configuration, restriction, monitor, null);
  }

  private static AnalysisResult preview(
      Program p,
      Collection<Address> starts,
      MapperState assumption,
      AnalysisResult.Configuration configuration,
      AddressSetView restriction,
      TaskMonitor monitor,
      FetchCollector diagnostic)
      throws Exception {
    OrdinaryCallFlow.retireStale(p, monitor);
    // Content hashes alone cannot detect an edit that is restored during exploration.
    long modification = p.getModificationNumber();
    String fingerprint = ProgramFingerprint.capture(p, monitor);
    var cartridge = ProgramMapping.cartridge(p);
    if (cartridge == null) throw new IllegalArgumentException("Cartridge descriptor required");
    var roots = entryRoots(p, cartridge, starts, assumption);
    if (roots.isEmpty()) throw new IllegalArgumentException("At least one justified analysis root is required");
    var primaryStart = roots.get(0).address();
    var entries = new ArrayList<Work>();
    boolean hasSoftwareCalls = !SoftwareCallRegistry.configurationIdentity(p).equals("absent");
    for (var root : roots) {
      var entryRegisters = new HashMap<Long, Integer>();
      // Executable contracts consume only this root's explicitly recorded context as premises.
      // Unknown/partial values are not filled from a template or architectural guess.
      if (hasSoftwareCalls) {
        for (String name : List.of("A", "F", "BC", "DE", "HL", "SP")) {
          var register = p.getRegister(name);
          var contextual = p.getProgramContext().getRegisterValue(register, root.address());
          var value = contextual == null ? null : contextual.getUnsignedValue();
          if (value != null)
            put(new ghidra.program.model.pcode.Varnode(register.getAddress(), register.getMinimumByteSize()),
                value.longValue(), entryRegisters, new HashMap<>());
        }
      }
      entries.add(new Work(root.address(), root.knowledge(), Map.copyOf(entryRegisters), Map.of()));
    }
    var candidates = new AnalysisCandidates();
    var session = new Session();
    explore(p, cartridge, entries, List.of(), configuration, restriction, monitor, diagnostic, candidates, session);
    var completion = session.completion;
    var reasons = candidates.reasons;
    if (completion == AnalysisResult.Completion.STATE_LIMIT)
      reasons.put(
          AnalysisCandidates.Site.control(primaryStart, "limit"),
          configuration.stateLimit() + "-state worklist bound reached");
    if (completion == AnalysisResult.Completion.CANCELLED)
      reasons.put(AnalysisCandidates.Site.control(primaryStart, "cancelled"), "Exploration cancelled");
    if (completion != AnalysisResult.Completion.CANCELLED
        && (!fingerprint.equals(ProgramFingerprint.capture(p, monitor))
            || modification != p.getModificationNumber()))
      completion = AnalysisResult.Completion.INPUT_CHANGED;
    var findings = candidates.finish(completion);
    return new AnalysisResult(
        AnalysisResult.SCHEMA_VERSION,
        AnalysisResult.ENGINE_VERSION,
        roots.stream().map(root -> root.address().toString()).toList(),
        assumption,
        roots.stream().map(Root::premise).toList(),
        configuration,
        completion,
        session.count,
        session.pending,
        fingerprint,
        findings,
        session.callProofs.finish(completion),
        completion == AnalysisResult.Completion.COMPLETE
            ? List.of()
            : List.of("Exploration stopped: " + completion + "; candidates are not proof"));
  }

  private static final int CALLEE_STATE_LIMIT = 128;
  private static final int ORDINARY_CALL_DEPTH = 3;

  private static final class Session {
    int count;
    int pending;
    final OrdinaryCallProofCollector callProofs = new OrdinaryCallProofCollector();
    AnalysisResult.Completion completion = AnalysisResult.Completion.COMPLETE;
  }

  /** Counts all relevant CD encounters, including refusals before composition. */
  private static final class OrdinaryCallProofCollector {
    private boolean incompleteExploration;
    private boolean generatedStorageEncounter;
    private final Map<Address, Integer> encounters = new TreeMap<>();
    private final Map<Address, Integer> successes = new TreeMap<>();
    private final Map<Address, AnalysisResult.OrdinaryCallProof> proofs = new TreeMap<>();
    private final Map<Address, MapperKnowledge> returnedMappers = new TreeMap<>();
    private final Set<Address> conflicts = new HashSet<>();

    void encounter(Program p, Address address) throws Exception {
      var instruction = p.getListing().getInstructionAt(address);
      if (instruction == null) return;
      if ((instruction.getBytes()[0] & 255) == 0xcd) encounters.merge(address, 1, Integer::sum);
      // Prefix state and interior callee bytes are proof dependencies too, not only
      // the three certificate endpoints. Keep generated execution out of all proof inputs.
      for (int i = 0; i < instruction.getLength(); i++)
        if (!ordinaryCallProofStorage(p, address.addWrap(i))) generatedStorageEncounter = true;
    }

    void success(Program p, Cartridge cartridge, Work caller,
        Address target, MapperKnowledge targetState, Work continuation) throws Exception {
      // Generated execution/presentation storage cannot become architectural proof.
      // Check both block and space identity so renaming a block cannot confer authority.
      for (var address : List.of(caller.address(), target, continuation.address()))
        if (!ordinaryCallProofStorage(p, address)) return;
      var sourcePhysical = caller.state().translate(cartridge, (int) caller.address().getOffset(), false).physical();
      var targetPhysical = targetState.translate(cartridge, (int) target.getOffset(), false).physical();
      var continuationPhysical = continuation.state().translate(cartridge, (int) continuation.address().getOffset(), false).physical();
      if (sourcePhysical == null || targetPhysical == null || continuationPhysical == null
          || !sourcePhysical.region().equals("ROM") || !targetPhysical.region().equals("ROM")
          || !continuationPhysical.region().equals("ROM")
          || !ProgramMapping.staticToPhysical(p, caller.address()).equals(List.of(sourcePhysical))
          || !ProgramMapping.staticToPhysical(p, target).equals(List.of(targetPhysical))
          || !ProgramMapping.staticToPhysical(p, continuation.address()).equals(List.of(continuationPhysical))) return;
      var proof = new AnalysisResult.OrdinaryCallProof(caller.address().toString(), sourcePhysical,
          target.toString(), targetPhysical, continuation.address().toString(), continuationPhysical);
      var prior = proofs.putIfAbsent(caller.address(), proof);
      if (prior != null && !prior.equals(proof)) conflicts.add(caller.address());
      var priorMapper = returnedMappers.putIfAbsent(caller.address(), continuation.state());
      if (priorMapper != null && !priorMapper.equals(continuation.state())) conflicts.add(caller.address());
      successes.merge(caller.address(), 1, Integer::sum);
    }

    List<AnalysisResult.OrdinaryCallProof> finish(AnalysisResult.Completion completion) {
      if (completion != AnalysisResult.Completion.COMPLETE || incompleteExploration || generatedStorageEncounter) return List.of();
      return proofs.entrySet().stream()
          .filter(e -> !conflicts.contains(e.getKey())
              && Objects.equals(encounters.get(e.getKey()), successes.get(e.getKey())))
          .map(Map.Entry::getValue).toList();
    }
  }

  // Preview-local, depth-bounded validation frames. Architectural bytes remain in SymbolicMemory.
  private record CallFrame(int cpu, int sp, List<MapperState.Physical> stack,
      MapperState.Physical callee) {}
  private record Exploration(boolean structuralComplete, List<Work> returns) {}

  // Encountered sites are not active invocations. The immutable frame chain is the
  // authority for admission, including while a nested callee is being explored.
  private static boolean hasOrdinaryCallCapacity(List<CallFrame> frames) {
    return frames.size() < ORDINARY_CALL_DEPTH;
  }

  private static Exploration explore(
      Program p, Cartridge cartridge, List<Work> entries, List<CallFrame> frames,
      AnalysisResult.Configuration configuration, AddressSetView restriction,
      TaskMonitor monitor, FetchCollector diagnostic, AnalysisCandidates candidates, Session session)
      throws Exception {
    var frame = frames.isEmpty() ? null : frames.get(frames.size() - 1);
    var queue = new ArrayDeque<Work>();
    var joined = new HashMap<JoinKey, Work>();
    var widened = new HashSet<Address>();
    for (var entry : entries) enqueue(queue, entry, widened, joined);
    var seen = new HashSet<Work>();
    var diversity = new HashMap<Address, Integer>();
    var processedKeys = new HashSet<JoinKey>();
    var targets = candidates.targets;
    var reasons = candidates.reasons;
    int localCount = 0;
    boolean complete = true;
    var returns = new ArrayList<Work>();
    var edges = new HashMap<Address, Set<Address>>();
    var conditionalSites = new HashSet<Address>();
    monitor.setMessage("Exploring bank states");
    try {
      while (!queue.isEmpty() && session.completion == AnalysisResult.Completion.COMPLETE) {
        monitor.checkCancelled();
        var w = queue.removeFirst();
        var top = new Work(w.address(), MapperKnowledge.unknown(), Map.of(), Map.of());
        if (widened.contains(w.address()) && !w.equals(top)) continue;
        // Pending entries may have been weakened again before their turn. Only evaluate
        // the current joined snapshot; a processed key can return with fewer must-facts.
        var joinKey = JoinKey.of(w);
        if (!w.equals(joined.get(joinKey)) || seen.contains(w)) continue;
        int addressStates = diversity.getOrDefault(w.address(), 0);
        if (!widened.contains(w.address())
            && !processedKeys.contains(joinKey)
            && addressStates == STATE_DIVERSITY_PER_ADDRESS) {
          if (frame != null) complete = false;
          widened.add(w.address());
          reasons.put(
              AnalysisCandidates.Site.control(w.address(), "widening"),
              "State diversity widened to unknown after "
                  + STATE_DIVERSITY_PER_ADDRESS
                  + " distinct states at one instruction");
          // The popped item may itself be top but not yet processed. Force it pending:
          // ordinary no-change enqueue would otherwise lose this required evaluation.
          joined.put(JoinKey.of(top), top);
          queue.addFirst(top);
          continue;
        }
        if (session.count == configuration.stateLimit()) {
          queue.addFirst(w);
          session.completion = AnalysisResult.Completion.STATE_LIMIT;
          complete = false;
          break;
        }
        if (frame != null && localCount == CALLEE_STATE_LIMIT) {
          complete = false;
          reasons.put(AnalysisCandidates.Site.control(w.address, "flow"), "Ordinary callee state bound reached");
          break;
        }
        session.callProofs.encounter(p, w.address());
        seen.add(w);
        if (processedKeys.add(joinKey)) diversity.put(w.address(), addressStates + 1);
        session.count++;
        localCount++;
        if (restriction != null && !restriction.contains(w.address)) {
          if (frame != null) complete = false;
          reasons.put(
              AnalysisCandidates.Site.control(w.address, "flow"),
              "Successor is outside the analyzer address restriction");
          continue;
        }
        var ins = p.getListing().getInstructionAt(w.address);
        if (ins == null) {
          if (frame != null) complete = false;
          reasons.put(
              AnalysisCandidates.Site.control(w.address, "flow"),
              "No defined instruction; data/undefined bytes left intact");
          continue;
        }
        if (!fetchEstablished(p, cartridge, w.state, ins, diagnostic != null)
            || (frame != null && !callableInstruction(p, w.state, ins))) {
          if (frame != null) complete = false;
          reasons.put(
              AnalysisCandidates.Site.control(w.address, "flow"),
              "Instruction fetch crosses an unestablished physical execution view");
          continue;
        }
        String interpretation = InstructionInterpretation.unresolved(ins);
        if (interpretation != null) {
          if (frame != null) complete = false;
          reasons.put(AnalysisCandidates.Site.control(w.address, "flow"), interpretation);
          continue;
        }
        var softwareCall = InstructionInterpretation.softwareCall(ins);
        if (softwareCall != null) {
          if (frame != null) {
            complete = false;
            reasons.put(AnalysisCandidates.Site.control(w.address, "flow"), "Nested software call is outside ordinary call composition");
            continue;
          }
          if (diagnostic != null)
            diagnostic.frontier.add(w.address + ": Software-call summary is not an instruction fetch trace");
          var premises = softwareCall.configuration();
          var input = premises.registers();
          int expectedSp = premises.callerSp() -
              (premises.transfer() == SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION ? 2 : 0);
          var expectedRegisters = Map.of("A", input.a(), "F", input.f(), "BC", input.bc(),
              "DE", input.de(), "HL", input.hl(), "SP", expectedSp & 65535);
          boolean established = w.state.equals(MapperKnowledge.from(premises.mapper()));
          for (var expected : expectedRegisters.entrySet()) {
            var register = p.getRegister(expected.getKey());
            Long actual = value(new ghidra.program.model.pcode.Varnode(register.getAddress(), register.getMinimumByteSize()),
                w.registers, Map.of());
            established &= actual != null && actual.intValue() == expected.getValue();
          }
          if (!established) {
            reasons.put(AnalysisCandidates.Site.control(w.address, "flow"),
                "Software-call entry premises are unknown or contradict this incoming path");
            continue;
          }
          var summary = SoftwareCallRegistry.effects(p, softwareCall, monitor);
          if (!summary.complete()) {
            reasons.put(AnalysisCandidates.Site.control(w.address, "flow"),
                "Unresolved callee effects: " + String.join("; ", summary.unresolved()));
            continue;
          }
          var softwareFrame = softwareCall.frame();
          var callKey = AnalysisCandidates.Site.control(w.address, "call");
          for (var target : ProgramMapping.physicalToStatic(p, softwareFrame.target()))
            if (target.getOffset() == softwareFrame.targetCpu() && SoftwareCallExecutionView.canonical(p, target))
              targets.computeIfAbsent(callKey, k -> new TreeSet<>()).add(target);
          for (var path : summary.paths()) {
            var returned = path.returned();
            if (returned.exit() != SoftwareCallModel.Exit.MAY_RETURN) {
              reasons.put(AnalysisCandidates.Site.control(w.address, "flow"),
                  "Validated callee exit: " + returned.exit());
              continue;
            }
            var outputRegisters = new HashMap<Long, Integer>();
            var r = returned.registers();
            var values = Map.of("A", r.a(), "F", r.f(), "BC", r.bc(), "DE", r.de(),
                "HL", r.hl(), "SP", returned.sp());
            for (var value : values.entrySet()) {
              var register = p.getRegister(value.getKey());
              put(new ghidra.program.model.pcode.Varnode(register.getAddress(), register.getMinimumByteSize()),
                  (long) value.getValue(), outputRegisters, new HashMap<>());
            }
            for (var continuation : ProgramMapping.physicalToStatic(p, returned.physical()))
              if (continuation.getOffset() == returned.cpu() && executionCandidate(p, continuation, diagnostic != null))
                enqueue(
                    queue,
                    new Work(
                        continuation,
                        MapperKnowledge.from(returned.mapper()),
                        Map.copyOf(outputRegisters), Map.of()),
                    widened, joined);
          }
          continue;
        }
        int diagnosticIndex = diagnostic == null ? 0 : diagnostic.steps.size();
        var fetchBytes = diagnostic == null ? null : fetchBytes(p, ins);
        var writes = diagnostic == null ? null : new ArrayList<WriteTransition>();
        var raw = ins.getPcode(false);
        var microflow = conditionalMicroflow(p, ins, raw);
        if (microflow != null) {
          conditionalSites.add(w.address);
          if (conditionalSites.size() > 1) {
            complete = false;
            reasons.put(AnalysisCandidates.Site.control(w.address, "flow"),
                "Second conditional CALL/RET site exceeds the one-site microflow bound");
            continue;
          }
          var condition = microflow.condition(registerValue(p, "F", w.registers));
          // The false outcome has no push/pop, frame transition or predicate mutation.
          if (condition != Condition.TRUE) {
            int nextCpu = (int) ((ins.getAddress().getOffset() + ins.getLength()) & 65535);
            var views = resolveWithContext(p, cartridge, w.state, nextCpu, w.address, diagnostic != null);
            if (views.isEmpty()) {
              complete = false;
              reasons.put(AnalysisCandidates.Site.control(w.address, "flow"),
                  "Conditional false fallthrough has no established execution view");
            }
            for (var view : views) {
              var falseWork = new Work(view, w.state, w.registers, w.memory);
              enqueue(queue, falseWork, widened, joined);
              if (frame != null) edges.computeIfAbsent(w.address, k -> new HashSet<>()).add(view);
            }
            if (diagnostic != null) diagnostic.steps.add(new FetchStep(w.address.toString(),
                (int) w.address.getOffset(), fetchBytes, Arrays.stream(raw).map(PcodeOp::toString).toList(),
                w.state, w.state, List.of(), views.stream().map(Address::toString).toList()));
          }
          if (condition == Condition.FALSE) continue;
          // Only the recognized guarded suffix runs through the incumbent evaluator.
        }
        var state = w.state;
        var regs = new HashMap<>(w.registers);
        var unique = new HashMap<Long, Integer>();
        var memory = SymbolicMemory.State.ordinary(w.memory);
        boolean changedMapper = false;
        // Internal p-code branches are not path interpreted by this finite evaluator.
        boolean internal = microflow == null &&
            Arrays.stream(raw)
                .anyMatch(
                    op ->
                        op.getOpcode() == PcodeOp.CBRANCH
                            || (op.getOpcode() == PcodeOp.BRANCH && op.getInput(0).isConstant()));
        Long returnedCpu = null;
        boolean supported = true;
        int operation = 0;
        for (var op : raw) {
          int operationIndex = operation++;
          if (microflow != null && operationIndex <= microflow.gate()) continue;
          if (op.getOpcode() == PcodeOp.RETURN) returnedCpu = value(op.getInput(0), regs, unique);
          if (op.getOpcode() == PcodeOp.CALLOTHER && !CartridgeBus.isDirectWrite(p.getLanguage(), op)) supported = false;
          if (op.getOpcode() != PcodeOp.BRANCH
              && op.getOpcode() != PcodeOp.CBRANCH
              && op.getOpcode() != PcodeOp.CALL
              && op.getOpcode() != PcodeOp.RETURN)
            for (int operand = 0; operand < op.getNumInputs(); operand++) {
              var input = op.getInput(operand);
              if (input.isAddress()) {
                if (frame != null) complete = false;
                readAccess(
                    p,
                    cartridge,
                    state,
                    (int) (input.getOffset() & 65535),
                    input.getSize(),
                    w.address,
                    operationIndex,
                    operand,
                    targets,
                    reasons,
                    diagnostic != null);
              }
            }
          if (op.getOpcode() == PcodeOp.STORE || CartridgeBus.isDirectWrite(p.getLanguage(), op)) {
            Long ptr = value(op.getInput(1), regs, unique),
                val = value(op.getInput(2), regs, unique);
            if (internal || ptr == null) {
              if (frame != null) complete = false;
              state = MapperKnowledge.unknown();
              memory.facts.clear();
              changedMapper = true;
              unknownAccess(
                  w.address,
                  AnalysisCandidates.Access.WRITE,
                  operationIndex,
                  op.getInput(2).getSize(),
                  reasons,
                  "Unknown store may affect mapper state");
            } else {
              int cpu = (int) (ptr & 65535);
              int width = op.getInput(2).getSize();
              state =
                  writeAccess(
                      p,
                      cartridge,
                      state,
                      cpu,
                      width,
                      val,
                      w.address,
                      operationIndex,
                      targets,
                      reasons,
                      writes, memory);
              changedMapper |= touchesMapper(cartridge, cpu, width);
            }
          } else if (op.getOpcode() == PcodeOp.LOAD) {
            Long ptr = value(op.getInput(1), regs, unique);
            if (ptr != null)
              readAccess(
                  p,
                  cartridge,
                  state,
                  (int) (ptr & 65535),
                  op.getOutput().getSize(),
                  w.address,
                  operationIndex,
                  -1,
                  targets,
                  reasons,
                  diagnostic != null);
            else
              unknownAccess(
                  w.address,
                  AnalysisCandidates.Access.READ,
                  operationIndex,
                  op.getOutput().getSize(),
                  reasons,
                  "Unknown load address");
          }
          var output = op.getOutput();
          if (output != null) {
            ReadOutcome read = op.getOpcode() == PcodeOp.LOAD && !internal
                && op.getInput(0).isConstant()
                && (int) op.getInput(0).getOffset() == p.getAddressFactory().getDefaultAddressSpace().getSpaceID()
                ? memoryLoad(p, cartridge, state, memory, value(op.getInput(1), regs, unique), output.getSize())
                : ReadOutcome.UNRESOLVED;
            Long result = internal ? null : op.getOpcode() == PcodeOp.LOAD
                ? read.value() : evaluate(op, regs, unique);
            if (output.isAddress()) {
              int cpu = (int) (output.getOffset() & 65535);
              state =
                  writeAccess(
                      p,
                      cartridge,
                      state,
                      cpu,
                      output.getSize(),
                      result,
                      w.address,
                      operationIndex,
                      targets,
                      reasons,
                      writes, memory);
              changedMapper |= touchesMapper(cartridge, cpu, output.getSize());
            }
            if (frame != null && op.getOpcode() == PcodeOp.LOAD && read.coverage() != ReadCoverage.SUPPORTED) complete = false;
            if (frame != null && !ordinaryOperation(op)) supported = false;
            put(output, result, regs, unique);
          }
        }
        var successors = new ArrayList<Work>();
        var flow = ins.getFlowType();
        if (frame != null) {
          if (!supported || (internal && Arrays.stream(raw).anyMatch(op -> (op.getOutput() != null && !op.getOutput().isUnique())
              || op.getOpcode() == PcodeOp.STORE || CartridgeBus.isDirectWrite(p.getLanguage(), op)))) complete = false;
          if (Arrays.stream(raw).anyMatch(op -> op.getOpcode() == PcodeOp.RETURN)) {
            var sp = registerValue(p, "SP", regs);
            // The actual pop and RETURN operand, not flow metadata, establish this frame.
            if (ins.getBytes().length != 1 || ((ins.getBytes()[0] & 255) != 0xc9 && (microflow == null || microflow.call()))
                || returnedCpu == null || returnedCpu.intValue() != frame.cpu()
                || sp == null || sp.intValue() != frame.sp()
                || !stackIdentity(cartridge, w.state, (frame.sp() - 2) & 65535).equals(frame.stack())) complete = false;
            else {
              var views = resolve(p, cartridge, state, frame.cpu(), diagnostic != null);
              if (views.size() != 1 || p.getListing().getInstructionAt(views.get(0)) == null
                  || !callableInstruction(p, state, p.getListing().getInstructionAt(views.get(0)))
                  || !fetchEstablished(p, cartridge, state, p.getListing().getInstructionAt(views.get(0)), diagnostic != null)) complete = false;
              else returns.add(new Work(views.get(0), state, Map.copyOf(regs), memory.snapshot()));
            }
            if (diagnostic != null) diagnostic.steps.add(new FetchStep(w.address.toString(),
                (int) w.address.getOffset(), fetchBytes, Arrays.stream(raw).map(PcodeOp::toString).toList(),
                w.state, state, writes, List.of()));
            continue;
          }
          if (flow.isCall()) {
            // Only active invocations spend depth. composeCall explores synchronously:
            // a completed nested return resumes this invocation with its original frames
            // and the returned Work, so a later site can establish a fresh physical frame.
            if (!hasOrdinaryCallCapacity(frames) || !supported || internal) {
              complete = false;
              reasons.put(AnalysisCandidates.Site.control(w.address, "flow"),
                  "Ordinary nested call exceeds active depth " + ORDINARY_CALL_DEPTH + " or supported raw effects");
              continue;
            }
          }
        }
        Work composed = null;
        boolean attemptedCall = false;
        boolean pointerSuccessor = false;
        if (flow.isComputed() && exactHlJump(p, ins, raw)) {
          var pointer = value(raw[0].getInput(0), regs, unique);
          var target = pointer == null ? null : exactPointerTarget(p, cartridge, state, pointer.intValue());
          if (target != null) {
            // This is a jump within the current exploration, including its active frame.
            // No push, restoration, new invocation or fallthrough is synthesized.
            successors.add(new Work(target, state, Map.copyOf(regs), memory.snapshot()));
            targets.computeIfAbsent(AnalysisCandidates.Site.control(w.address, "jump"), k -> new TreeSet<>()).add(target);
            pointerSuccessor = true;
          } else reasons.put(AnalysisCandidates.Site.control(w.address, "flow"), pointer == null
              ? "JP HL requires an exact 16-bit architectural pointer"
              : "JP HL target has no unique defined immutable executable ROM source; undefined bytes left intact");
        }
        for (var dest : ins.getDefaultFlows()) {
          var resolved =
              resolveWithContext(
                  p, cartridge, state, (int) dest.getOffset(), changedMapper ? null : w.address, diagnostic != null);
          var key = AnalysisCandidates.Site.control(w.address, flow.isCall() ? "call" : "jump");
          if (resolved.isEmpty()) {
            if (frame != null) complete = false;
            reasons.put(key, "Unknown bank or missing static execution view");
          }
          for (var a : resolved) {
            targets.computeIfAbsent(key, k -> new TreeSet<>()).add(a);
            if (!attemptedCall && flow.isCall()) {
              attemptedCall = true;
              composed = composeCall(p, cartridge, w, ins, raw, microflow, state, regs, memory, resolved,
                  frames, configuration, restriction, monitor, diagnostic, candidates, session);
            }
            // Unsupported calls retain the incumbent unknown continuation.
            if (!flow.isCall()) successors.add(new Work(a, state, Map.copyOf(regs), memory.snapshot()));
          }
        }
        // A partial nested proof cannot authorize the containing invocation's RET,
        // even if another arm returned or a later instruction could reestablish state.
        if (frame != null && flow.isCall() && composed == null) {
          complete = false;
          reasons.put(AnalysisCandidates.Site.control(w.address, "flow"),
              "Nested ordinary call has no complete matched-return proof");
          continue;
        }
        Address next = ins.getFallThrough();
        if (next == null
            && !ins.isFallThroughOverridden()
            && flow.hasFallthrough()
            && ins.getAddress().getOffset() + ins.getLength() > 65535)
          next = ins.getAddress().addWrap(ins.getLength());
        if (next != null) {
          if (flow.isCall() && composed != null) {
            successors.add(composed);
            next = null;
          }
          if (next != null && flow.isCall()) {
            state = MapperKnowledge.unknown();
            regs.clear();
            memory.facts.clear();
            changedMapper = true;
          }
          if (next != null) {
            int nextCpu = (int) ((ins.getAddress().getOffset() + ins.getLength()) & 65535);
            if (ins.isFallThroughOverridden()) nextCpu = (int) next.getOffset();
            var nextViews =
                resolveWithContext(p, cartridge, state, nextCpu, changedMapper ? null : w.address, diagnostic != null);
            if (nextViews.isEmpty()) {
              if (frame != null) complete = false;
              reasons.put(
                  AnalysisCandidates.Site.control(w.address, "flow"),
                  "Fallthrough execution view unresolved after call, mapper write or window"
                      + " transition");
            }
            for (var a : nextViews) successors.add(new Work(a, state, Map.copyOf(regs), memory.snapshot()));
          }
        }
        if (frame != null) {
          if (successors.isEmpty() || (flow.isComputed() && !pointerSuccessor)) complete = false;
          for (var successor : successors)
            edges.computeIfAbsent(w.address, k -> new HashSet<>()).add(successor.address);
        }
        if (configuration.reverseBranches()) Collections.reverse(successors);
        for (var successor : successors) enqueue(queue, successor, widened, joined);
        if (diagnostic != null)
          diagnostic.steps.add(diagnosticIndex, new FetchStep(w.address.toString(), (int) w.address.getOffset(),
              fetchBytes, Arrays.stream(raw).map(PcodeOp::toString).toList(), w.state, state,
              writes, successors.stream().map(work -> work.address.toString()).toList()));
        if (flow.isComputed() && !pointerSuccessor)
          reasons.putIfAbsent(
              AnalysisCandidates.Site.control(w.address, "flow"),
              "Indirect flow requires a validated per-program convention");
      }
    } catch (ghidra.util.exception.CancelledException cancelled) {
      session.completion = AnalysisResult.Completion.CANCELLED;
      complete = false;
    }
    if (frame == null || session.completion != AnalysisResult.Completion.COMPLETE) session.pending += queue.size();
    if (frame != null && cyclic(edges)) complete = false;
    // An unexamined callee frontier can lead back to a previously successful CD
    // under a conflicting state, even when its immediate address is not that site.
    // Do not claim a session-wide must-proof from partial invocation exploration.
    if (frame != null && !complete) session.callProofs.incompleteExploration = true;
    return new Exploration(complete && session.completion == AnalysisResult.Completion.COMPLETE, List.copyOf(returns));
  }

  private enum Condition { TRUE, FALSE, UNKNOWN }

  private record Microflow(boolean call, int gate, int opcode) {
    Condition condition(Long f) {
      if (f == null) return Condition.UNKNOWN;
      int bit = (opcode & 0x10) == 0 ? 7 : 4;
      boolean set = (f & (1L << bit)) != 0;
      boolean taken = (opcode & 8) == 0 ? !set : set;
      return taken ? Condition.TRUE : Condition.FALSE;
    }
  }

  /** Narrow SM83 gate recognition; no arbitrary CBRANCH path interpretation. */
  private static Microflow conditionalMicroflow(Program p,
      ghidra.program.model.listing.Instruction ins, PcodeOp[] raw) throws Exception {
    int opcode = ins.getBytes()[0] & 255;
    boolean call = opcode == 0xc4 || opcode == 0xcc || opcode == 0xd4 || opcode == 0xdc;
    boolean ret = opcode == 0xc0 || opcode == 0xc8 || opcode == 0xd0 || opcode == 0xd8;
    if ((!call && !ret) || ins.getLength() != (call ? 3 : 1) || raw.length == 0
        || ins.isFallThroughOverridden()) return null;
    int gate = -1;
    for (int i = 0; i < raw.length; i++) if (raw[i].getOpcode() == PcodeOp.CBRANCH) {
      if (gate != -1) return null;
      gate = i;
    }
    if (gate < 1 || gate > 8) return null;
    var branch = raw[gate];
    int nextCpu = (int) ((ins.getAddress().getOffset() + ins.getLength()) & 65535);
    if (branch.getNumInputs() != 2 || !branch.getInput(0).isAddress()
        || branch.getInput(0).getOffset() != nextCpu || branch.getInput(1).getSize() != 1) return null;
    var f = p.getRegister("F");
    var sp = p.getRegister("SP");
    var pc = p.getRegister("PC");
    var defined = new HashSet<Long>();
    for (int i = 0; i < gate; i++) {
      var op = raw[i];
      if (!ordinaryOperation(op) || op.getOpcode() == PcodeOp.LOAD
          || op.getOutput() == null || !op.getOutput().isUnique()) return null;
      for (var input : op.getInputs())
        if (!input.isConstant() && !(input.isUnique() && defined.contains(input.getOffset()))
            && !(input.isRegister() && input.getAddress().equals(f.getAddress()) && input.getSize() == 1)) return null;
      defined.add(op.getOutput().getOffset());
    }
    if (!branch.getInput(1).isUnique() || !defined.contains(branch.getInput(1).getOffset())) return null;
    var result = new Microflow(call, gate, opcode);
    // Validate the compiled F-only predicate against the architectural truth table.
    // Reuse PcodeConstants; these local uniques never enter Work or mutate F.
    for (long flags = 0; flags < 256; flags++) {
      var registers = new HashMap<Long, Integer>();
      var unique = new HashMap<Long, Integer>();
      put(new ghidra.program.model.pcode.Varnode(f.getAddress(), 1), flags, registers, unique);
      for (int i = 0; i < gate; i++) put(raw[i].getOutput(), evaluate(raw[i], registers, unique), registers, unique);
      Long skip = value(branch.getInput(1), registers, unique);
      if (skip == null || skip != (result.condition(flags) == Condition.TRUE ? 0L : 1L)) return null;
    }
    int memoryOps = 0, spWrites = 0, pcWrites = 0;
    for (int i = gate + 1; i < raw.length; i++) {
      var op = raw[i];
      if (i == raw.length - 1) {
        if (op.getOpcode() != (call ? PcodeOp.CALL : PcodeOp.RETURN) || op.getNumInputs() != 1) return null;
        if (call && (!op.getInput(0).isAddress() || ins.getDefaultFlows().length != 1
            || !op.getInput(0).getAddress().equals(ins.getDefaultFlows()[0]))) return null;
        if (!call && (!op.getInput(0).isRegister() || !op.getInput(0).getAddress().equals(pc.getAddress())
            || op.getInput(0).getSize() != 2)) return null;
        continue;
      }
      if (op.getOpcode() == (call ? PcodeOp.STORE : PcodeOp.LOAD)) {
        if (!op.getInput(0).isConstant()
            || op.getInput(0).getOffset() != p.getAddressFactory().getDefaultAddressSpace().getSpaceID()
            || op.getInput(1).getSize() != 2
            || (call ? op.getInput(2).getSize() : op.getOutput().getSize()) != 1) return null;
        memoryOps++;
      } else if (!ordinaryOperation(op) || op.getOpcode() == PcodeOp.LOAD) return null;
      var output = op.getOutput();
      if (output != null && !output.isUnique()) {
        if (!output.isRegister() || output.getSize() != 2) return null;
        if (output.getAddress().equals(sp.getAddress())) spWrites++;
        else if (!call && output.getAddress().equals(pc.getAddress())) pcWrites++;
        else return null;
      }
      // The guarded suffix cannot consume a predicate temporary that was skipped.
      for (var input : op.getInputs()) if (input.isUnique() && defined.contains(input.getOffset())) return null;
    }
    return memoryOps == 2 && spWrites == (call ? 2 : 1) && pcWrites == (call ? 0 : 1) ? result : null;
  }

  private static List<MapperState.Physical> stackIdentity(Cartridge cartridge, MapperKnowledge state, int sp) {
    var low = state.translate(cartridge, sp, false).physical();
    var high = state.translate(cartridge, (sp + 1) & 65535, false).physical();
    return low == null || high == null ? List.of() : List.of(low, high);
  }

  private static Long registerValue(Program p, String name, Map<Long, Integer> registers) {
    var register = p.getRegister(name);
    return value(new ghidra.program.model.pcode.Varnode(register.getAddress(), register.getMinimumByteSize()),
        registers, Map.of());
  }

  /** The compiled E9 contract is deliberately one operation, not a BRANCHIND interpreter. */
  static boolean exactHlJump(Program p, ghidra.program.model.listing.Instruction ins,
      PcodeOp[] raw) throws Exception {
    var hl = p.getRegister("HL");
    return ins.getLength() == 1 && (ins.getBytes()[0] & 255) == 0xe9
        && ins.getFlowType().isJump() && ins.getFlowType().isComputed()
        && !ins.getFlowType().isCall() && ins.getFallThrough() == null
        && ins.getDefaultFlows().length == 0
        && InstructionInterpretation.architecturalUnresolved(ins) == null
        && raw.length == 1 && raw[0].getOpcode() == PcodeOp.BRANCHIND
        && raw[0].getOutput() == null && raw[0].getNumInputs() == 1
        && raw[0].getInput(0).isRegister() && raw[0].getInput(0).getSize() == 2
        && hl.getMinimumByteSize() == 2 && raw[0].getInput(0).getAddress().equals(hl.getAddress())
        && Arrays.toString(raw).equals(Arrays.toString(ins.getPcode(true)));
  }

  private static boolean pointerStorage(Program p, Address address) {
    var block = p.getMemory().getBlock(address);
    var space = address.getAddressSpace().getName();
    return block != null && !block.isMapped() && block.isInitialized() && block.isRead()
        && block.isExecute() && !block.isWrite() && !block.isVolatile()
        && !block.getName().startsWith(SoftwareCallExecutionView.PREFIX)
        && !block.getName().startsWith(OrdinaryEntryAccess.PREFIX)
        && !space.startsWith(SoftwareCallExecutionView.PREFIX)
        && !space.startsWith(OrdinaryEntryAccess.PREFIX);
  }

  /** Current Program sources must agree; a CPU pointer never chooses an alias or mapper. */
  private static Map<Address, Integer> pointerSources(Program p, ProgramMapping.Snapshot mapping,
      MapperState.Physical physical) throws Exception {
    var sources = new HashMap<Address, Integer>();
    Integer agreed = null;
    for (var range : mapping.ranges()) {
      if ((range.fileOffset() == null && !"loader-anchor".equals(range.provenance()))
          || !range.region().equals("ROM") || range.bank() != physical.bank()
          || physical.offset() < range.offset() || physical.offset() >= range.offset() + range.length()) continue;
      var space = p.getAddressFactory().getAddressSpace(range.space());
      var at = space.getAddress(range.start() + physical.offset() - range.offset());
      if (!pointerStorage(p, at)) continue;
      if (!ProgramMapping.staticToPhysical(p, at, mapping).equals(List.of(physical))) return Map.of();
      int octet = p.getMemory().getByte(at) & 255;
      if (agreed != null && agreed != octet) return Map.of();
      agreed = octet;
      sources.put(at, octet);
    }
    return sources;
  }

  static Address exactPointerTarget(Program p, Cartridge cartridge, MapperKnowledge state, int cpu)
      throws Exception {
    if (cpu < 0 || cpu > 65535) return null;
    var physical = ScalarAccess.resolve(cartridge, state,
        new ScalarAccess.Request(cpu, ScalarAccess.Kind.FETCH, 1, 0, null, -1, -1, null))
        .resolution().orElseThrow().physical();
    if (physical == null || !physical.region().equals("ROM")) return null;
    var mapping = ProgramMapping.inspect(p);
    var sources = pointerSources(p, mapping, physical);
    var entries = sources.keySet().stream().filter(a -> a.getOffset() == cpu).toList();
    // Agreement does not authorize selecting one of multiple static execution identities.
    if (entries.size() != 1) return null;
    var target = entries.get(0);
    var instruction = p.getListing().getInstructionAt(target);
    if (instruction == null) return null;
    byte[] bytes = instruction.getBytes();
    for (int i = 0; i < bytes.length; i++) {
      int fetchCpu = (cpu + i) & 65535;
      var expected = ScalarAccess.resolve(cartridge, state,
          new ScalarAccess.Request(fetchCpu, ScalarAccess.Kind.FETCH, bytes.length, i, target.toString(), -1, -1, null))
          .resolution().orElseThrow().physical();
      var at = target.addWrap(i);
      if (expected == null || !expected.region().equals("ROM") || !pointerStorage(p, at)
          || !ProgramMapping.staticToPhysical(p, at, mapping).equals(List.of(expected))) return null;
      var octets = pointerSources(p, mapping, expected);
      if (!Objects.equals(octets.get(at), bytes[i] & 255)) return null;
    }
    return target;
  }

  private static boolean ordinaryOperation(PcodeOp op) {
    int opcode = op.getOpcode();
    return opcode == PcodeOp.LOAD || opcode == PcodeOp.COPY
        || (opcode >= PcodeOp.INT_EQUAL && opcode <= PcodeOp.BOOL_OR)
        || opcode == PcodeOp.PIECE || opcode == PcodeOp.SUBPIECE
        || opcode == PcodeOp.POPCOUNT || opcode == PcodeOp.LZCOUNT;
  }

  private static boolean callableInstruction(Program p, MapperKnowledge state,
      ghidra.program.model.listing.Instruction ins) throws Exception {
    for (int i = 0; i < ins.getLength(); i++) {
      var at = ins.getAddress().addWrap(i);
      var block = p.getMemory().getBlock(at);
      var physical = state.translate(ProgramMapping.cartridge(p), (int) (at.getOffset() & 65535), false).physical();
      if (block == null || !block.isExecute() || !block.isRead() || !block.isInitialized()
          || block.isWrite() || physical == null || !physical.region().equals("ROM")
          || !ProgramMapping.staticToPhysical(p, at).equals(List.of(physical))) return false;
    }
    return true;
  }

  private static Work composeCall(
      Program p, Cartridge cartridge, Work caller, ghidra.program.model.listing.Instruction ins,
      PcodeOp[] raw, Microflow microflow, MapperKnowledge state, Map<Long, Integer> registers, SymbolicMemory.State memory,
      List<Address> targets, List<CallFrame> frames,
      AnalysisResult.Configuration configuration, AddressSetView restriction,
      TaskMonitor monitor, FetchCollector diagnostic, AnalysisCandidates candidates, Session session)
      throws Exception {
    // CD or a validated conditional taken suffix has a real push and one direct CALL.
    if (!hasOrdinaryCallCapacity(frames)
        || ins.getLength() != 3 || ((ins.getBytes()[0] & 255) != 0xcd
            && (microflow == null || !microflow.call()))
        || ins.getFallThrough() == null || ins.getDefaultFlows().length != 1
        || targets.size() != 1 || raw.length == 0
        || raw[raw.length - 1].getOpcode() != PcodeOp.CALL) return null;
    var target = targets.get(0);
    int targetCpu = (int) target.getOffset();
    var physical = state.translate(cartridge, targetCpu, false).physical();
    if (physical == null || !ProgramMapping.staticToPhysical(p, target).equals(List.of(physical))) return null;
    if (frames.stream().anyMatch(active -> active.callee().equals(physical))) return null;
    var callee = p.getListing().getInstructionAt(target);
    if (callee == null || !callableInstruction(p, state, callee)) return null;
    var beforeSp = registerValue(p, "SP", caller.registers());
    var entrySp = registerValue(p, "SP", registers);
    int cpu = (int) ((ins.getAddress().getOffset() + ins.getLength()) & 65535);
    if (beforeSp == null || entrySp == null || entrySp.intValue() != ((beforeSp.intValue() - 2) & 65535)) return null;
    // Consume the real CALL stores through the incumbent memory model. No synthesized word.
    var word = memory.ordinaryRead(p, cartridge, state, entrySp, 2);
    if (word == null || word.intValue() != cpu) return null;
    if (diagnostic != null) diagnostic.frontier.add(caller.address() + ": Ordinary call composition is not a linear instruction fetch trace");
    var calleeCandidates = new AnalysisCandidates();
    var nestedFrames = new ArrayList<>(frames);
    nestedFrames.add(new CallFrame(cpu, beforeSp.intValue(),
        stackIdentity(cartridge, state, entrySp.intValue()), physical));
    var summary = explore(p, cartridge,
        List.of(new Work(target, state, Map.copyOf(registers), memory.snapshot())),
        List.copyOf(nestedFrames), configuration, restriction, monitor, diagnostic, calleeCandidates, session);
    for (var entry : calleeCandidates.targets.entrySet()) {
      candidates.targets.computeIfAbsent(entry.getKey(), k -> new TreeSet<>()).addAll(entry.getValue());
      if (!summary.structuralComplete()) candidates.reasons.put(entry.getKey(), "Incomplete ordinary callee exploration: candidates are not proof");
    }
    candidates.reasons.putAll(calleeCandidates.reasons);
    if (!summary.structuralComplete() || summary.returns().isEmpty()) {
      candidates.reasons.put(AnalysisCandidates.Site.control(caller.address(), "flow"),
          "Ordinary call has no complete matched-return proof");
      return null;
    }
    var result = summary.returns().get(0);
    for (var returned : summary.returns().subList(1, summary.returns().size())) {
      // Different physical continuations or mapper identities are incompatible. Fall back
      // to the existing unknown continuation rather than inventing a mapper lattice.
      if (!result.address().equals(returned.address()) || !result.state().equals(returned.state())) return null;
      var commonRegisters = new HashMap<>(result.registers());
      commonRegisters.entrySet().removeIf(e -> !Objects.equals(e.getValue(), returned.registers().get(e.getKey())));
      result = new Work(result.address(), result.state(), Map.copyOf(commonRegisters),
          SymbolicMemory.State.joinOrdinary(result.memory(), returned.memory()));
    }
    if ((ins.getBytes()[0] & 255) == 0xcd && callableInstruction(p, caller.state(), ins))
      session.callProofs.success(p, cartridge, caller, target, state, result);
    return result;
  }

  private static boolean cyclic(Map<Address, Set<Address>> edges) {
    var active = new HashSet<Address>();
    var done = new HashSet<Address>();
    for (var address : edges.keySet()) if (cyclic(address, edges, active, done)) return true;
    return false;
  }

  private static boolean cyclic(Address address, Map<Address, Set<Address>> edges,
      Set<Address> active, Set<Address> done) {
    if (done.contains(address)) return false;
    if (!active.add(address)) return true;
    for (var next : edges.getOrDefault(address, Set.of()))
      if (cyclic(next, edges, active, done)) return true;
    active.remove(address);
    done.add(address);
    return false;
  }

  static void enqueue(ArrayDeque<Work> queue, Work work, Set<Address> widened,
      Map<JoinKey, Work> joined) {
    if (widened.contains(work.address()))
      work = new Work(work.address(), MapperKnowledge.unknown(), Map.of(), Map.of());
    var key = JoinKey.of(work);
    var previous = joined.get(key);
    if (previous != null) {
      var memory = SymbolicMemory.State.joinOrdinary(previous.memory(), work.memory());
      if (memory.equals(previous.memory())) return;
      work = new Work(work.address(), work.state(), work.registers(), memory);
    }
    joined.put(key, work);
    queue.addLast(work);
  }

  private static List<Root> entryRoots(
      Program p, Cartridge cartridge, Collection<Address> starts, MapperState assumption)
      throws Exception {
    var unique = new TreeSet<Address>(starts);
    var result = new ArrayList<Root>();
    for (var start : unique) {
      var identities = ProgramMapping.staticToPhysical(p, start);
      if (identities.size() != 1)
        throw new IllegalArgumentException(
            "Analysis root must have one established physical identity: " + start);
      var physical = identities.get(0);
      var knowledge =
          MapperKnowledge.from(assumption)
              .constrainEntry(cartridge, physical, (int) start.getOffset());
      var resolved = knowledge.translate(cartridge, (int) start.getOffset(), false).physical();
      if (resolved != null && !resolved.equals(physical))
        throw new IllegalArgumentException(
            "Physical analysis root contradicts the alleged mapper state: " + start);
      result.add(
          new Root(
              start,
              knowledge,
              new AnalysisResult.EntryPremise(
                  start.toString(),
                  physical,
                  knowledge,
                  "physical Program topology at the instruction fetch root")));
    }
    return result;
  }

  public static void apply(Program p, AnalysisResult result, TaskMonitor monitor) throws Exception {
    AnalysisApplication.apply(p, result, monitor);
  }

  /** Predicate adapters share the production physical-fetch checks and byte evidence. */
  static List<FetchByte> predicatedFetch(Program p, MapperKnowledge state,
      ghidra.program.model.listing.Instruction instruction) throws Exception {
    if (!fetchEstablished(p, ProgramMapping.cartridge(p), state, instruction, true))
      throw new IllegalArgumentException("Unestablished predicate-qualified physical fetch");
    var bytes = fetchBytes(p, instruction);
    for (var octet : bytes) {
      var at = ProgramMapping.staticAddress(p, octet.source()); var block = p.getMemory().getBlock(at);
      if (block == null || !block.isInitialized() || !block.isRead() || !block.isExecute() || block.isWrite() || block.isVolatile())
        throw new IllegalArgumentException("Predicate fetch requires immutable readable executable ROM");
      var resolution = ScalarAccess.resolve(ProgramMapping.cartridge(p), state,
          new ScalarAccess.Request(octet.cpu(), ScalarAccess.Kind.FETCH, bytes.size(),
              octet.cpu() - (int) instruction.getAddress().getOffset(), instruction.getAddress().toString(), -1, -1, null)).resolution().orElseThrow();
      if (!octet.physical().equals(resolution.physical()))
        throw new IllegalArgumentException("Predicate fetch physical byte mismatch");
    }
    return bytes;
  }

  private static boolean fetchEstablished(
      Program p, Cartridge c, MapperKnowledge state, ghidra.program.model.listing.Instruction ins,
      boolean canonicalOnly)
      throws Exception {
    if (!executionCandidate(p, ins.getAddress(), canonicalOnly)) return false;
    // Ordinary same-window instructions are already supplied by the listing. A
    // boundary-spanning decode must have physical backing for every fetched byte.
    long start = ins.getAddress().getOffset(), end = start + ins.getLength() - 1;
    var source = ProgramMapping.staticToPhysical(p, ins.getAddress());
    var request = new ScalarAccess.Request(
        (int) start, ScalarAccess.Kind.FETCH, ins.getLength(), 0, ins.getAddress().toString(), -1, -1, null);
    var expected = ScalarAccess.resolve(c, state, request).resolution().orElseThrow().physical();
    if (expected != null && (source.size() != 1 || !source.get(0).equals(expected))) return false;
    if (executionWindow((int) start) == executionWindow((int) (end & 65535)) && end <= 65535)
      return true;
    byte[] bytes = ins.getBytes();
    for (int i = 0; i < bytes.length; i++) {
      int cpu = (int) ((start + i) & 65535);
      var views = resolveWithContext(p, c, state, cpu, ins.getAddress(), canonicalOnly);
      if (views.isEmpty()) return false;
      var actual = ProgramMapping.staticToPhysical(p, ins.getAddress().addWrap(i));
      if (actual.size() != 1) return false;
      for (var view : views) {
        if (!ProgramMapping.staticToPhysical(p, view).equals(actual)
            || p.getMemory().getByte(view) != bytes[i]) return false;
      }
    }
    return true;
  }

  private static List<FetchByte> fetchBytes(
      Program p, ghidra.program.model.listing.Instruction ins) throws Exception {
    var result = new ArrayList<FetchByte>();
    byte[] bytes = ins.getBytes();
    for (int i = 0; i < bytes.length; i++) {
      var source = ins.getAddress().addWrap(i);
      var physical = ProgramMapping.staticToPhysical(p, source);
      if (physical.size() != 1)
        throw new IllegalArgumentException("Diagnostic fetch has no unique physical identity: " + source);
      result.add(new FetchByte((int) (source.getOffset() & 65535), source.toString(),
          physical.get(0), bytes[i] & 255));
    }
    return result;
  }

  private static int executionWindow(int cpu) {
    int[] ends = {
      0x4000, 0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xf000, 0xfe00, 0xfea0, 0xff00, 0xff80,
      0xffff, 0x10000
    };
    for (int i = 0; i < ends.length; i++) if (cpu < ends[i]) return i;
    throw new IllegalArgumentException("CPU address out of range");
  }

  private static void unknownAccess(
      Address from,
      AnalysisCandidates.Access access,
      int operation,
      int width,
      Map<AnalysisCandidates.Site, String> reasons,
      String reason) {
    for (int i = 0; i < width; i++)
      reasons.put(new AnalysisCandidates.Site(from, access, operation, -1, i), reason);
  }

  private static boolean mapperControl(Cartridge c, int address) {
    return (address < 0x8000 && c.mapper() != Cartridge.Mapper.ROM_ONLY)
        || (c.color() && (address == 0xff4f || address == 0xff70));
  }

  private static boolean touchesMapper(Cartridge c, int address, int width) {
    for (int i = 0; i < width; i++) if (mapperControl(c, (address + i) & 65535)) return true;
    return false;
  }

  private static MapperKnowledge writeAccess(
      Program p,
      Cartridge c,
      MapperKnowledge state,
      int address,
      int width,
      Long value,
      Address from,
      int operation,
      Map<AnalysisCandidates.Site, Set<Address>> targets,
      Map<AnalysisCandidates.Site, String> reasons,
      List<WriteTransition> writes, SymbolicMemory.State memory)
      throws Exception {
    // P-code operations are ordered. Within a remaining little-endian wide store,
    // bytes use increasing 16-bit addresses. SM83 stack stores explicitly encode
    // their distinct high-byte-first architectural order in SLEIGH.
    for (int i = 0; i < width; i++) {
      int cpu = (address + i) & 65535;
      Integer octet = value == null ? null : (int) (value >>> (i * 8)) & 255;
      var request = new ScalarAccess.Request(
          cpu, ScalarAccess.Kind.WRITE, width, i, from.toString(), operation, -1, octet);
      var before = state;
      var outcome = ScalarAccess.resolve(c, before, request);
      var access = outcome.request();
      var key = new AnalysisCandidates.Site(
          from, AnalysisCandidates.Access.WRITE, access.operation(), access.operand(), access.byteIndex());
      record(p, outcome.resolution().orElseThrow(), access.cpu(), key, targets, reasons, writes != null);
      boolean control = mapperControl(c, cpu);
      memory.ordinaryWrite(p, outcome, control);
      // The adapter proposes a state; this caller retains its mapper-control policy, including CGB gating.
      if (control) state = outcome.after().orElseThrow();
      if (writes != null)
        writes.add(new WriteTransition(operation, i, cpu, octet, before, state, control));
    }
    return state;
  }

  /** Read-effect coverage is independent of byte knowledge; neither is persisted. */
  private enum ReadCoverage { SUPPORTED, UNRESOLVED }
  private record ReadOutcome(Long value, ReadCoverage coverage) {
    private static final ReadOutcome UNRESOLVED = new ReadOutcome(null, ReadCoverage.UNRESOLVED);
  }

  private static ReadOutcome memoryLoad(Program p, Cartridge c, MapperKnowledge state,
      SymbolicMemory.State memory, Long pointer, int width) throws Exception {
    if (pointer == null || width < 1 || width > Long.BYTES) return ReadOutcome.UNRESOLVED;
    var ram = memory.ordinaryRead(p, c, state, pointer, width);
    var value = ram != null ? ram : romLoad(p, c, state, pointer, width);
    if (value != null) return new ReadOutcome(value, ReadCoverage.SUPPORTED);
    for (int i = 0; i < width; i++) {
      int cpu = (int) ((pointer + i) & 65535);
      var request = new ScalarAccess.Request(cpu, ScalarAccess.Kind.READ, width, i, null, -1, -1, null);
      var resolution = ScalarAccess.resolve(c, state, request).resolution().orElseThrow();
      // Canonically backed ordinary RAM reads have no modeled write effects even
      // when a path-written byte is absent. SVBK is the bounded device read from
      // 1B: reading its selector does not change it or RAM; its value stays unknown.
      // Other devices, unavailable ROM and unresolved physical identities refuse.
      if (!SymbolicMemory.State.ordinaryBacking(p, resolution.physical())
          && !(c.color() && cpu == 0xff70 && resolution.status().equals("device")))
        return ReadOutcome.UNRESOLVED;
    }
    return new ReadOutcome(null, ReadCoverage.SUPPORTED);
  }

  /** LOAD alone consumes memory. Mapping observations do not authorize a byte value. */
  static Long romLoad(Program p, Cartridge c, MapperKnowledge state, Long pointer, int width)
      throws Exception {
    if (pointer == null || width < 1 || width > Long.BYTES) return null;
    var mapping = ProgramMapping.inspect(p);
    long value = 0;
    for (int i = 0; i < width; i++) {
      int cpu = (int) ((pointer + i) & 65535);
      var request = new ScalarAccess.Request(cpu, ScalarAccess.Kind.READ, width, i, null, -1, -1, null);
      var physical = ScalarAccess.resolve(c, state, request).resolution().orElseThrow().physical();
      if (physical == null || (!physical.region().equals("ROM") && !physical.region().equals("BOOT")))
        return null;
      Integer octet = null;
      // File sources or explicit loader anchors establish static storage provenance.
      // Neither original FileBytes nor detached/unidentified snapshots supply a value.
      // Aliases and generated snapshots cannot supply an independent source of ROM authority.
      for (var range : mapping.ranges()) {
        if ((range.fileOffset() == null && !"loader-anchor".equals(range.provenance()))
            || !range.region().equals(physical.region())
            || range.bank() != physical.bank() || physical.offset() < range.offset()
            || physical.offset() >= range.offset() + range.length()) continue;
        var space = p.getAddressFactory().getAddressSpace(range.space());
        var address = space.getAddress(range.start() + physical.offset() - range.offset());
        var block = p.getMemory().getBlock(address);
        if (block == null || block.isMapped() || !block.isInitialized() || !block.isRead()
            || block.isWrite() || block.isVolatile()
            || block.getName().startsWith(SoftwareCallExecutionView.PREFIX)
            || block.getName().startsWith(OrdinaryEntryAccess.PREFIX)
            || space.getName().startsWith(SoftwareCallExecutionView.PREFIX)
            || space.getName().startsWith(OrdinaryEntryAccess.PREFIX)) continue;
        var identities = ProgramMapping.staticToPhysical(p, address, mapping);
        if (identities.size() != 1 || !physical.equals(identities.get(0))) return null;
        int current;
        try {
          current = p.getMemory().getByte(address) & 255;
        } catch (ghidra.program.model.mem.MemoryAccessException unavailable) {
          return null;
        }
        if (octet != null && octet != current) return null;
        octet = current;
      }
      if (octet == null) return null;
      value |= (long) octet << (8 * i);
    }
    return value;
  }

  private static void readAccess(
      Program p,
      Cartridge c,
      MapperKnowledge state,
      int address,
      int width,
      Address from,
      int operation,
      int operand,
      Map<AnalysisCandidates.Site, Set<Address>> targets,
      Map<AnalysisCandidates.Site, String> reasons,
      boolean canonicalOnly)
      throws Exception {
    for (int i = 0; i < width; i++) {
      var request = new ScalarAccess.Request(
          (address + i) & 65535, ScalarAccess.Kind.READ, width, i,
          from.toString(), operation, operand, null);
      var outcome = ScalarAccess.resolve(c, state, request);
      var access = outcome.request();
      var key = new AnalysisCandidates.Site(
          from, AnalysisCandidates.Access.READ, access.operation(), access.operand(), access.byteIndex());
      record(p, outcome.resolution().orElseThrow(), access.cpu(), key, targets, reasons, canonicalOnly);
    }
  }

  /** Certificate storage discriminator; fingerprinted independently of navigation annotations. */
  static boolean ordinaryCallProofStorage(Program p, Address address) {
    var block = p.getMemory().getBlock(address);
    var space = address.getAddressSpace().getName();
    return block != null && !block.getName().startsWith(SoftwareCallExecutionView.PREFIX)
        && !block.getName().startsWith(OrdinaryEntryAccess.PREFIX)
        && !space.startsWith(SoftwareCallExecutionView.PREFIX)
        && !space.startsWith(OrdinaryEntryAccess.PREFIX);
  }

  private static boolean executionCandidate(Program p, Address address, boolean canonicalOnly) {
    if (canonicalOnly) {
      var block = p.getMemory().getBlock(address);
      if (block == null || block.getName().startsWith(SoftwareCallExecutionView.PREFIX)
          || block.getName().startsWith(OrdinaryEntryAccess.PREFIX)) return false;
    }
    if (!address.getAddressSpace().getName().startsWith(SoftwareCallExecutionView.PREFIX)) return true;
    var block = p.getMemory().getBlock(address);
    return block != null && block.isExecute();
  }

  private static List<Address> resolveWithContext(
      Program p, Cartridge c, MapperKnowledge s, int cpu, Address context,
      boolean canonicalOnly) throws Exception {
    var result = resolve(p, c, s, cpu, canonicalOnly);
    if (!result.isEmpty()
        || context == null
        || c.mapper() == Cartridge.Mapper.RAW
        || cpu >= 0x8000
        || context.getOffset() >= 0x8000
        || cpu / 0x4000 != context.getOffset() / 0x4000) return result;
    var identities = ProgramMapping.staticToPhysical(p, context);
    if (identities.size() != 1
        || !identities.get(0).region().equals("ROM")
        || !s.allowsExecution(c, cpu, identities.get(0).bank())) return result;
    var physical = new MapperState.Physical("ROM", identities.get(0).bank(), cpu % 0x4000);
    return ProgramMapping.physicalToStatic(p, physical).stream()
        .filter(a -> a.getOffset() == cpu && executionCandidate(p, a, canonicalOnly))
        .toList();
  }

  private static List<Address> resolve(Program p, Cartridge c, MapperKnowledge s, int cpu, boolean canonicalOnly)
      throws Exception {
    var request = new ScalarAccess.Request(cpu, ScalarAccess.Kind.FETCH, 1, 0, null, -1, -1, null);
    var physical = ScalarAccess.resolve(c, s, request).resolution().orElseThrow().physical();
    if (physical == null) return List.of();
    return ProgramMapping.physicalToStatic(p, physical).stream()
        .filter(a -> a.getOffset() == cpu && executionCandidate(p, a, canonicalOnly))
        .toList();
  }

  private static void record(
      Program p,
      MapperState.Resolution result,
      int cpu,
      AnalysisCandidates.Site key,
      Map<AnalysisCandidates.Site, Set<Address>> targets,
      Map<AnalysisCandidates.Site, String> reasons,
      boolean canonicalOnly)
      throws Exception {
    if (result.physical() == null) {
      reasons.put(key, result.status() + ": " + result.reason());
      return;
    }
    var addresses =
        ProgramMapping.physicalToStatic(p, result.physical()).stream()
            .filter(a -> a.getOffset() == cpu && executionCandidate(p, a, canonicalOnly))
            .toList();
    if (addresses.isEmpty()) reasons.put(key, "Physical destination has no static mapping");
    for (var a : addresses) targets.computeIfAbsent(key, k -> new TreeSet<>()).add(a);
  }
}
