package fi.gekkio.ghidraboy;

import static fi.gekkio.ghidraboy.PcodeConstants.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Opt-in bounded analysis of existing instructions. Never decodes through marked data. */
public final class BankAnalysis {
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

  private record Work(Address address, MapperKnowledge state, Map<Long, Integer> registers) {}

  /** The physical entry is an external invocation premise, never evidence of a selected display. */
  public static FetchPreview previewFetch(
      Program p, Address start, MapperState assumption,
      AnalysisResult.Configuration configuration, TaskMonitor monitor) throws Exception {
    var diagnostic = new FetchCollector();
    var result = preview(p, start, assumption, configuration, monitor, diagnostic);
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
    return preview(p, start, assumption, configuration, monitor, null);
  }

  private static AnalysisResult preview(
      Program p, Address start, MapperState assumption,
      AnalysisResult.Configuration configuration, TaskMonitor monitor,
      FetchCollector diagnostic) throws Exception {
    // Content hashes alone cannot detect an edit that is restored during exploration.
    long modification = p.getModificationNumber();
    String fingerprint = ProgramFingerprint.capture(p, monitor);
    var cartridge = ProgramMapping.cartridge(p);
    if (cartridge == null) throw new IllegalArgumentException("Cartridge descriptor required");
    var queue = new ArrayDeque<Work>();
    var entryRegisters = new HashMap<Long, Integer>();
    // Executable contracts consume explicitly recorded context as premises. Unknown/partial
    // values are not filled from a template or architectural guess.
    if (!SoftwareCallRegistry.configurationIdentity(p).equals("absent")) {
      for (String name : List.of("A", "F", "BC", "DE", "HL", "SP")) {
        var register = p.getRegister(name);
        var contextual = p.getProgramContext().getRegisterValue(register, start);
        var value = contextual == null ? null : contextual.getUnsignedValue();
        if (value != null)
          put(new ghidra.program.model.pcode.Varnode(register.getAddress(), register.getMinimumByteSize()),
              value.longValue(), entryRegisters, new HashMap<>());
      }
    }
    queue.add(new Work(start, MapperKnowledge.from(assumption), Map.copyOf(entryRegisters)));
    var seen = new HashSet<Work>();
    var candidates = new AnalysisCandidates();
    var targets = candidates.targets;
    var reasons = candidates.reasons;
    int count = 0;
    var completion = AnalysisResult.Completion.COMPLETE;
    monitor.setMessage("Exploring bank states");
    try {
      while (!queue.isEmpty()) {
        monitor.checkCancelled();
        var w = queue.removeFirst();
        if (seen.contains(w)) continue;
        if (count == configuration.stateLimit()) {
          queue.addFirst(w);
          completion = AnalysisResult.Completion.STATE_LIMIT;
          break;
        }
        seen.add(w);
        count++;
        var ins = p.getListing().getInstructionAt(w.address);
        if (ins == null) {
          reasons.put(
              AnalysisCandidates.Site.control(w.address, "flow"),
              "No defined instruction; data/undefined bytes left intact");
          continue;
        }
        if (!fetchEstablished(p, cartridge, w.state, ins, diagnostic != null)) {
          reasons.put(
              AnalysisCandidates.Site.control(w.address, "flow"),
              "Instruction fetch crosses an unestablished physical execution view");
          continue;
        }
        String interpretation = InstructionInterpretation.unresolved(ins);
        if (interpretation != null) {
          reasons.put(AnalysisCandidates.Site.control(w.address, "flow"), interpretation);
          continue;
        }
        var softwareCall = InstructionInterpretation.softwareCall(ins);
        if (softwareCall != null) {
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
          var frame = softwareCall.frame();
          var callKey = AnalysisCandidates.Site.control(w.address, "call");
          for (var target : ProgramMapping.physicalToStatic(p, frame.target()))
            if (target.getOffset() == frame.targetCpu() && SoftwareCallExecutionView.canonical(p, target))
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
                queue.addLast(new Work(continuation, MapperKnowledge.from(returned.mapper()), Map.copyOf(outputRegisters)));
          }
          continue;
        }
        var fetchBytes = diagnostic == null ? null : fetchBytes(p, ins);
        var writes = diagnostic == null ? null : new ArrayList<WriteTransition>();
        var raw = ins.getPcode(false);
        var state = w.state;
        var regs = new HashMap<>(w.registers);
        var unique = new HashMap<Long, Integer>();
        boolean changedMapper = false;
        // Internal p-code branches are not path interpreted by this finite evaluator.
        boolean internal =
            Arrays.stream(raw)
                .anyMatch(
                    op ->
                        op.getOpcode() == PcodeOp.CBRANCH
                            || (op.getOpcode() == PcodeOp.BRANCH && op.getInput(0).isConstant()));
        int operation = 0;
        for (var op : raw) {
          int operationIndex = operation++;
          if (op.getOpcode() != PcodeOp.BRANCH
              && op.getOpcode() != PcodeOp.CBRANCH
              && op.getOpcode() != PcodeOp.CALL
              && op.getOpcode() != PcodeOp.RETURN)
            for (int operand = 0; operand < op.getNumInputs(); operand++) {
              var input = op.getInput(operand);
              if (input.isAddress())
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
          if (op.getOpcode() == PcodeOp.STORE || CartridgeBus.isDirectWrite(p.getLanguage(), op)) {
            Long ptr = value(op.getInput(1), regs, unique),
                val = value(op.getInput(2), regs, unique);
            if (internal || ptr == null) {
              state = MapperKnowledge.unknown();
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
                      writes);
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
            Long result = internal ? null : evaluate(op, regs, unique);
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
                      writes);
              changedMapper |= touchesMapper(cartridge, cpu, output.getSize());
            }
            put(output, result, regs, unique);
          }
        }
        var successors = new ArrayList<Work>();
        var flow = ins.getFlowType();
        for (var dest : ins.getDefaultFlows()) {
          var resolved =
              resolveWithContext(
                  p, cartridge, state, (int) dest.getOffset(), changedMapper ? null : w.address, diagnostic != null);
          var key = AnalysisCandidates.Site.control(w.address, flow.isCall() ? "call" : "jump");
          if (resolved.isEmpty()) reasons.put(key, "Unknown bank or missing static execution view");
          for (var a : resolved) {
            targets.computeIfAbsent(key, k -> new TreeSet<>()).add(a);
            // No interprocedural return summary: do not propagate assumed state into callees.
            if (!flow.isCall()) successors.add(new Work(a, state, Map.copyOf(regs)));
          }
        }
        Address next = ins.getFallThrough();
        if (next == null
            && !ins.isFallThroughOverridden()
            && flow.hasFallthrough()
            && ins.getAddress().getOffset() + ins.getLength() > 65535)
          next = ins.getAddress().addWrap(ins.getLength());
        if (next != null) {
          if (flow.isCall()) {
            state = MapperKnowledge.unknown();
            regs.clear();
            changedMapper = true;
          }
          int nextCpu = (int) ((ins.getAddress().getOffset() + ins.getLength()) & 65535);
          if (ins.isFallThroughOverridden()) nextCpu = (int) next.getOffset();
          var nextViews =
              resolveWithContext(p, cartridge, state, nextCpu, changedMapper ? null : w.address, diagnostic != null);
          if (nextViews.isEmpty())
            reasons.put(
                AnalysisCandidates.Site.control(w.address, "flow"),
                "Fallthrough execution view unresolved after call, mapper write or window"
                    + " transition");
          for (var a : nextViews) successors.add(new Work(a, state, Map.copyOf(regs)));
        }
        if (configuration.reverseBranches()) Collections.reverse(successors);
        queue.addAll(successors);
        if (diagnostic != null)
          diagnostic.steps.add(new FetchStep(w.address.toString(), (int) w.address.getOffset(),
              fetchBytes, Arrays.stream(raw).map(PcodeOp::toString).toList(), w.state, state,
              writes, successors.stream().map(work -> work.address.toString()).toList()));
        if (flow.isComputed())
          reasons.put(
              AnalysisCandidates.Site.control(w.address, "flow"),
              "Indirect flow requires a validated per-program convention");
      }
    } catch (ghidra.util.exception.CancelledException cancelled) {
      completion = AnalysisResult.Completion.CANCELLED;
    }
    if (completion == AnalysisResult.Completion.STATE_LIMIT)
      reasons.put(
          AnalysisCandidates.Site.control(start, "limit"),
          configuration.stateLimit() + "-state worklist bound reached");
    if (completion == AnalysisResult.Completion.CANCELLED)
      reasons.put(AnalysisCandidates.Site.control(start, "cancelled"), "Exploration cancelled");
    if (completion != AnalysisResult.Completion.CANCELLED
        && (!fingerprint.equals(ProgramFingerprint.capture(p, monitor))
            || modification != p.getModificationNumber()))
      completion = AnalysisResult.Completion.INPUT_CHANGED;
    var findings = candidates.finish(completion);
    return new AnalysisResult(
        2,
        AnalysisResult.ENGINE_VERSION,
        List.of(start.toString()),
        assumption,
        configuration,
        completion,
        count,
        queue.size(),
        fingerprint,
        findings,
        completion == AnalysisResult.Completion.COMPLETE
            ? List.of()
            : List.of("Exploration stopped: " + completion + "; candidates are not proof"));
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
      List<WriteTransition> writes)
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
      // The adapter proposes a state; this caller retains its mapper-control policy, including CGB gating.
      if (control) state = outcome.after().orElseThrow();
      if (writes != null)
        writes.add(new WriteTransition(operation, i, cpu, octet, before, state, control));
    }
    return state;
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
