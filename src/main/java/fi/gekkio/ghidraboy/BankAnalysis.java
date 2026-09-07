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

  private record Work(Address address, MapperKnowledge state, Map<Long, Integer> registers) {}

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
        if (!fetchEstablished(p, cartridge, w.state, ins)) {
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
              if (continuation.getOffset() == returned.cpu() && executionCandidate(p, continuation))
                queue.addLast(new Work(continuation, MapperKnowledge.from(returned.mapper()), Map.copyOf(outputRegisters)));
          }
          continue;
        }
        var state = w.state;
        var regs = new HashMap<>(w.registers);
        var unique = new HashMap<Long, Integer>();
        boolean changedMapper = false;
        // Internal p-code branches are not path interpreted by this finite evaluator.
        boolean internal =
            Arrays.stream(ins.getPcode(false))
                .anyMatch(
                    op ->
                        op.getOpcode() == PcodeOp.CBRANCH
                            || (op.getOpcode() == PcodeOp.BRANCH && op.getInput(0).isConstant()));
        int operation = 0;
        for (var op : ins.getPcode(false)) {
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
                    reasons);
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
                      reasons);
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
                  reasons);
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
                      reasons);
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
                  p, cartridge, state, (int) dest.getOffset(), changedMapper ? null : w.address);
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
              resolveWithContext(p, cartridge, state, nextCpu, changedMapper ? null : w.address);
          if (nextViews.isEmpty())
            reasons.put(
                AnalysisCandidates.Site.control(w.address, "flow"),
                "Fallthrough execution view unresolved after call, mapper write or window"
                    + " transition");
          for (var a : nextViews) successors.add(new Work(a, state, Map.copyOf(regs)));
        }
        if (configuration.reverseBranches()) Collections.reverse(successors);
        queue.addAll(successors);
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

  private static boolean fetchEstablished(
      Program p, Cartridge c, MapperKnowledge state, ghidra.program.model.listing.Instruction ins)
      throws Exception {
    if (!executionCandidate(p, ins.getAddress())) return false;
    // Ordinary same-window instructions are already supplied by the listing. A
    // boundary-spanning decode must have physical backing for every fetched byte.
    long start = ins.getAddress().getOffset(), end = start + ins.getLength() - 1;
    var source = ProgramMapping.staticToPhysical(p, ins.getAddress());
    var expected = state.translate(c, (int) start, false).physical();
    if (expected != null && (source.size() != 1 || !source.get(0).equals(expected))) return false;
    if (executionWindow((int) start) == executionWindow((int) (end & 65535)) && end <= 65535)
      return true;
    byte[] bytes = ins.getBytes();
    for (int i = 0; i < bytes.length; i++) {
      int cpu = (int) ((start + i) & 65535);
      var views = resolveWithContext(p, c, state, cpu, ins.getAddress());
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
      Map<AnalysisCandidates.Site, String> reasons)
      throws Exception {
    // P-code operations are ordered. Within a remaining little-endian wide store,
    // bytes use increasing 16-bit addresses. SM83 stack stores explicitly encode
    // their distinct high-byte-first architectural order in SLEIGH.
    for (int i = 0; i < width; i++) {
      int cpu = (address + i) & 65535;
      record(p, c, state, cpu, true, from, operation, -1, i, targets, reasons);
      if (mapperControl(c, cpu))
        state = state.write(c, cpu, value == null ? null : (int) (value >>> (i * 8)) & 255);
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
      Map<AnalysisCandidates.Site, String> reasons)
      throws Exception {
    for (int i = 0; i < width; i++)
      record(
          p, c, state, (address + i) & 65535, false, from, operation, operand, i, targets, reasons);
  }

  private static boolean executionCandidate(Program p, Address address) {
    if (!address.getAddressSpace().getName().startsWith(SoftwareCallExecutionView.PREFIX)) return true;
    var block = p.getMemory().getBlock(address);
    return block != null && block.isExecute();
  }

  private static List<Address> resolveWithContext(
      Program p, Cartridge c, MapperKnowledge s, int cpu, Address context) throws Exception {
    var result = resolve(p, c, s, cpu);
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
        .filter(a -> a.getOffset() == cpu && executionCandidate(p, a))
        .toList();
  }

  private static List<Address> resolve(Program p, Cartridge c, MapperKnowledge s, int cpu)
      throws Exception {
    var physical = s.translate(c, cpu, false).physical();
    if (physical == null) return List.of();
    return ProgramMapping.physicalToStatic(p, physical).stream()
        .filter(a -> a.getOffset() == cpu && executionCandidate(p, a))
        .toList();
  }

  private static void record(
      Program p,
      Cartridge c,
      MapperKnowledge s,
      int cpu,
      boolean write,
      Address from,
      int operation,
      int operand,
      int byteIndex,
      Map<AnalysisCandidates.Site, Set<Address>> targets,
      Map<AnalysisCandidates.Site, String> reasons)
      throws Exception {
    var key =
        new AnalysisCandidates.Site(
            from,
            write ? AnalysisCandidates.Access.WRITE : AnalysisCandidates.Access.READ,
            operation,
            operand,
            byteIndex);
    var result = s.translate(c, cpu, write);
    if (result.physical() == null) {
      reasons.put(key, result.status() + ": " + result.reason());
      return;
    }
    var addresses =
        ProgramMapping.physicalToStatic(p, result.physical()).stream()
            .filter(a -> a.getOffset() == cpu && executionCandidate(p, a))
            .toList();
    if (addresses.isEmpty()) reasons.put(key, "Physical destination has no static mapping");
    for (var a : addresses) targets.computeIfAbsent(key, k -> new TreeSet<>()).add(a);
  }
}
