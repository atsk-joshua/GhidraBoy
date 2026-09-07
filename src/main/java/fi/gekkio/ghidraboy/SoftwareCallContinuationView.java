package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/**
 * State-qualified continuation transport. Graph labels identify machine states; CPU values,
 * pointers, arithmetic and return words retain their architectural widths. Listing fragments
 * share canonical bytes and retain every fetched physical range, including competing CPU offsets.
 */
public final class SoftwareCallContinuationView {
  private SoftwareCallContinuationView() {}
  public static final String VERSION = "software-call-state-continuation-2";

  /** Detect mapper-sensitive raw branches which native recovery would decode outside the selected path. */
  static boolean requiresEntryContext(Program p, SoftwareCallModel.Frame frame,
      List<SoftwareCallValidation.Configuration> configurations, TaskMonitor monitor) throws Exception {
    var checkpoint = SoftwareCallInstructionDiscovery.checkpoint(p);
    try {
      var pending = new ArrayDeque<Integer>(); pending.add(frame.targetCpu());
      var seen = new HashSet<Integer>();
      boolean conditional = false, mapperWrite = false;
      while (!pending.isEmpty()) {
        monitor.checkCancelled();
        int cpu = pending.removeFirst(); if (!seen.add(cpu)) continue;
        if (seen.size() > 1024) return true;
        var address = SoftwareCallValidation.executionAddress(p, frame.targetMapper(), cpu);
        var instruction = SoftwareCallInstructionDiscovery.instructionAt(p, address, "native conditional mapper exposure", monitor);
        if (instruction == null) return true;
        conditional |= instruction.getFlowType().isConditional();
        var registers = new HashMap<Long, Integer>(); var unique = new HashMap<Long, Integer>();
        for (var op : instruction.getPcode(false)) {
          if (op.getOpcode() == PcodeOp.STORE || CartridgeBus.isDirectWrite(p.getLanguage(), op)) {
            Long pointer = PcodeConstants.value(op.getInput(1), registers, unique);
            if (pointer != null && (pointer < 0x8000 || pointer == 0xff4f || pointer == 0xff70)) mapperWrite = true;
          }
          if (op.getOutput() != null) PcodeConstants.put(op.getOutput(), PcodeConstants.evaluate(op, registers, unique), registers, unique);
        }
        if (conditional && mapperWrite) return true;
        if (instruction.getFlowType().isCall()) {
          // Calls are already proved separately; do not decode software payload as fallthrough.
          boolean configured = configurations.stream().anyMatch(candidate -> candidate.callCpu() == cpu);
          if (configured) continue;
        } else for (var target : instruction.getDefaultFlows()) pending.add((int) target.getOffset() & 0xffff);
        var next = instruction.getDefaultFallThrough(); if (next != null) pending.add((int) next.getOffset() & 0xffff);
      }
      return false;
    } catch (IllegalArgumentException unresolvedNativePath) { return true; }
    finally { SoftwareCallInstructionDiscovery.rollback(p, checkpoint); }
  }

  public static SoftwareCallEffects.ContinuationSummary derive(Program p,
      SoftwareCallValidation.Preview validated, SoftwareCallEffects.Path path,
      List<SoftwareCallValidation.Configuration> configurations, TaskMonitor monitor) throws Exception {
    var graph = SoftwareCallEffects.deriveContinuationForReview(p, validated.frame(), path, configurations, monitor);
    requireTransport(p, graph, monitor);
    return graph;
  }

  public static void requireTransport(Program p, SoftwareCallEffects.ContinuationSummary graph,
      TaskMonitor monitor) throws Exception {
    if (!graph.complete()) throw new IllegalArgumentException("Unresolved continuation effects: " + graph.unresolved());
    if (graph.prerequisiteCallee() != null) requireTransport(p, graph.prerequisiteCallee(), monitor);
    var nestedProofs = SoftwareCallEffects.calleeInvocations(graph);
    for (var nested : nestedProofs) requireTransport(p, nested.graph(), monitor);
    var discharged = new HashSet<String>();
    for (var veto : graph.transportVetoes()) {
      if (veto.step() < 0) {
        if (graph.prerequisiteCallee() != null && graph.prerequisiteCallee().nativeIncompatibilities().contains(veto.reason())) discharged.add(veto.reason());
        continue;
      }
      if (veto.callDepth() != 0) {
        if (nestedProofs.stream().anyMatch(nested -> nested.graph().steps().stream()
            .anyMatch(step -> step.index() == veto.step() && step.callDepth() == 0))) discharged.add(veto.reason());
        continue;
      }
      if (Set.of("FETCH_SPACE", "DATA_IDENTITY", "MAPPER_WRITE", "INDIRECT_BRANCH", "CALL_TARGET").contains(veto.kind())
          || (veto.kind().equals("NONLOCAL_CALL") && graph.kind().equals("CALLEE") && graph.exit().equals("NONLOCAL")
              && graph.steps().get(graph.steps().size() - 1).index() == veto.step()
              && graph.steps().get(graph.steps().size() - 1).transfer().equals("RETURN")))
        discharged.add(veto.reason());
    }
    // A shared diagnostic must not lose a nested occurrence when its root occurrence is discharged.
    for (var veto : graph.transportVetoes())
      if ((veto.step() < 0 && (graph.prerequisiteCallee() == null || !graph.prerequisiteCallee().nativeIncompatibilities().contains(veto.reason()))) || (veto.step() >= 0 && veto.callDepth() != 0 && nestedProofs.stream().noneMatch(nested -> nested.graph().steps().stream()
          .anyMatch(step -> step.index() == veto.step() && step.callDepth() == 0)))) discharged.remove(veto.reason());
    for (String veto : graph.nativeIncompatibilities())
      if (!discharged.contains(veto)) throw new IllegalArgumentException("Continuation native obligation: " + veto);
    for (var step : graph.steps()) {
      monitor.checkCancelled();
      if (step.callDepth() != 0) continue;
      var at = ProgramMapping.staticAddress(p, step.address());
      var instruction = SoftwareCallInstructionDiscovery.instructionAt(p, at, "state-qualified continuation", monitor);
      if (instruction == null || instruction.getLength() != step.length())
        throw new IllegalArgumentException("Changed state-qualified instruction at " + at);
      for (var access : step.accesses()) {
        if (access.mapperControl()) {
          if (!access.write() || access.cpu() >= 0x8000 || access.value() == null
              || !CartridgeBus.supportsControls(ProgramMapping.cartridge(p)))
            throw new IllegalArgumentException("Unsupported state-qualified device effect at " + at);
          continue;
        }
        if (access.physical() == null) throw new IllegalArgumentException("Unknown physical data access at " + at);
        if (access.physical().region().equals("ROM")) {
          if (access.write() || access.value() == null) throw new IllegalArgumentException("Unproved ROM data effect at " + at);
          var source = dataAddress(p, access);
          var block = p.getMemory().getBlock(source);
          if (block == null || !block.isInitialized() || block.isWrite() || block.isVolatile()
              || (p.getMemory().getByte(source) & 255) != access.value())
            throw new IllegalArgumentException("Changed immutable bank-sensitive read at " + source);
        } else {
          if (!((access.cpu() >= 0xc000 && access.cpu() < 0xd000)
              || (access.cpu() >= 0xff80 && access.cpu() < 0xffff)))
            throw new IllegalArgumentException("Continuation data needs additional RAM/device transport proof at " + at);
          dataAddress(p, access);
        }
      }
      if ((step.transfer().equals("CALL") || step.transfer().equals("CALLIND") || step.softwareCall() != null)
          && step.afterCall() == null && step.callOutcome() == null)
        throw new IllegalArgumentException("Continuation call requires a proved return or terminal outcome at " + at);
    }
  }

  private static Address dataAddress(Program p, SoftwareCallEffects.Access access) throws Exception {
    var addresses = ProgramMapping.physicalToStatic(p, access.physical()).stream()
        .filter(a -> a.getOffset() == access.cpu() && SoftwareCallExecutionView.canonical(p, a)).toList();
    if (addresses.isEmpty() && ((access.cpu() >= 0xc000 && access.cpu() < 0xd000
        && access.physical().region().equals("WRAM") && access.physical().bank() == 0)
        || (access.cpu() >= 0xff80 && access.cpu() < 0xffff && access.physical().region().equals("HRAM")))) {
      var fixed = p.getAddressFactory().getDefaultAddressSpace().getAddress(access.cpu());
      if (p.getMemory().getBlock(fixed) == null) return fixed;
    }
    if (addresses.size() != 1) throw new IllegalArgumentException("Ambiguous physical data transport at CPU " + access.cpu());
    return addresses.get(0);
  }

  /** Each physical bank gets an explicit fragment. No overlap is dropped or padded into a bank. */
  public static List<List<SoftwareCallExecutionView.Segment>> fragments(Program p,
      SoftwareCallEffects.ContinuationSummary graph) {
    var spaces = new TreeMap<String, AddressSet>();
    for (var step : graph.steps()) {
      var at = ProgramMapping.staticAddress(p, step.address());
      spaces.computeIfAbsent(at.getAddressSpace().getName(), ignored -> new AddressSet()).add(at, at.add(step.length() - 1));
    }
    var result = new ArrayList<List<SoftwareCallExecutionView.Segment>>();
    for (var body : spaces.values()) {
      var segments = new ArrayList<SoftwareCallExecutionView.Segment>();
      for (var range : body.getAddressRanges()) segments.add(new SoftwareCallExecutionView.Segment(
          (int) range.getMinAddress().getOffset(), (int) range.getLength(), range.getMinAddress().toString()));
      result.add(List.copyOf(segments));
    }
    return List.copyOf(result);
  }

  static PcodeOp[] emit(Program p, Address site, SoftwareCallEffects.ContinuationSummary graph,
      List<SoftwareCallValidation.Configuration> configurations, long uniqueBase) throws Exception {
    requireTransport(p, graph, TaskMonitor.DUMMY);
    return new Lowering(p, site, graph, configurations, uniqueBase).emit();
  }

  static PcodeOp[] emit(Program p, Address site, SoftwareCallEffects.ContinuationSummary graph,
      List<SoftwareCallValidation.Configuration> configurations, long uniqueBase, int entryStep) throws Exception {
    requireTransport(p, graph, TaskMonitor.DUMMY);
    var lowering = new Lowering(p, site, graph, configurations, uniqueBase);
    lowering.entryStep = entryStep;
    return lowering.emit();
  }

  private static final class Lowering {
    final Program p;
    final Address site;
    final SoftwareCallEffects.ContinuationSummary graph;
    final List<SoftwareCallValidation.Configuration> configurations;
    final String sourceSite, originKind;
    final List<PcodeOp> ops = new ArrayList<>();
    final Map<Integer, Integer> entries = new HashMap<>(), edges = new HashMap<>();
    long unique;
    int entryStep;
    Lowering(Program p, Address site, SoftwareCallEffects.ContinuationSummary graph,
        List<SoftwareCallValidation.Configuration> configurations, long unique) {
      this.p = p; this.site = site; this.graph = graph; this.configurations = configurations; this.unique = unique;
      this.entryStep = graph.steps().get(0).index();
      this.sourceSite = SoftwareCallRegistry.graphSourceSite(p, site);
      this.originKind = SoftwareCallRegistry.graphOrigin(p, site, graph.kind());
    }
    Varnode constant(long value, int size) { return new Varnode(p.getAddressFactory().getConstantSpace().getAddress(value), size); }
    Varnode scratch(int size) { var result = new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(unique), size); unique += 0x10000; return result; }
    void add(int code, Varnode out, Varnode... inputs) { ops.add(new PcodeOp(site, ops.size(), code, inputs, out)); }
    void edge(int destination) { edges.put(ops.size(), destination); add(PcodeOp.BRANCH, null, constant(0, 4)); }
    Varnode relocate(Varnode value, Map<Long, Long> temporaries) {
      if (!value.isUnique()) return value;
      long base = value.getOffset() & ~0xffffL;
      long replacement = temporaries.computeIfAbsent(base, ignored -> { long result = unique; unique += 0x10000; return result; });
      return new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(replacement + (value.getOffset() & 0xffff)), value.getSize());
    }
    void results(SoftwareCallEffects.ContinuationState state) {
      var r = state.registers();
      for (var value : Map.of("A", r.a(), "F", r.f(), "BC", r.bc(), "DE", r.de(), "HL", r.hl(), "SP", state.sp()).entrySet()) {
        var register = p.getRegister(value.getKey());
        add(PcodeOp.COPY, new Varnode(register.getAddress(), register.getMinimumByteSize()), constant(value.getValue(), register.getMinimumByteSize()));
      }
    }
    Integer next(SoftwareCallEffects.ContinuationStep step) {
      if (step.transfer().equals("EXTERNAL_RETURN")
          || (step.transfer().equals("RETURN") && step.successor() == null
              && (graph.exit().equals("NONLOCAL") || graph.kind().equals("CALLEE")))
          || (step.callOutcome() != null && step.callOutcome().exit().equals("NONRETURNING"))) return null;
      if (step.afterCall() != null)
        return graph.steps().stream().filter(candidate -> candidate.index() > step.index() && candidate.callDepth() == 0
            && candidate.before().equals(step.afterCall())).map(SoftwareCallEffects.ContinuationStep::index).findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Missing post-call state"));
      if (step.callOutcome() != null && step.callOutcome().exit().equals("NONLOCAL")) {
        int resume = step.callOutcome().resumeStep();
        if (graph.steps().stream().noneMatch(candidate -> candidate.index() == resume)) return null;
        return resume;
      }
      if (step.successor() == null) throw new IllegalArgumentException("Missing graph successor");
      return step.successor();
    }
    PcodeOp[] emit() throws Exception {
      // Follow the already proved local graph from the selected physical fragment entry.
      // Keep the complete proof for nested calls/vetoes; do not emit unreachable prefixes or
      // lose backedges merely because their step IDs precede this selected entry.
      var selected = new ArrayList<SoftwareCallEffects.ContinuationStep>();
      var visited = new HashSet<Integer>();
      for (Integer index = entryStep; index != null && visited.add(index);) {
        int id = index;
        var step = graph.steps().stream().filter(candidate -> candidate.index() == id && candidate.callDepth() == 0)
            .findFirst().orElseThrow(() -> new IllegalArgumentException("Selected entry escapes its native invocation"));
        selected.add(step); index = next(step);
      }
      for (var step : selected) {
        entries.put(step.index(), ops.size());
        add(PcodeOp.COPY, scratch(1), constant(0, 1)); // Stable target survives nested native injection.
        var instruction = p.getListing().getInstructionAt(ProgramMapping.staticAddress(p, step.address()));
        var raw = instruction.getPcode(false);
        var temporaries = new HashMap<Long, Long>();
        boolean propagatedNonlocal = false;
        boolean external = step.transfer().equals("EXTERNAL_RETURN")
            || (step.transfer().equals("RETURN") && step.successor() == null && (graph.exit().equals("NONLOCAL") || graph.kind().equals("CALLEE")));
        for (int index : step.executedPcode()) {
          var op = raw[index]; int code = op.getOpcode();
          boolean softwareTransfer = step.softwareCall() != null && code == PcodeOp.BRANCH && !op.getInput(0).isConstant();
          if (!softwareTransfer && (code == PcodeOp.BRANCH || code == PcodeOp.CBRANCH || code == PcodeOp.BRANCHIND)) continue;
          if (code == PcodeOp.RETURN && !external) continue;
          if (softwareTransfer || code == PcodeOp.CALL || code == PcodeOp.CALLIND) {
            var invocation = SoftwareCallEffects.calleeInvocations(graph).stream().filter(call -> call.callStep() == step.index()).findFirst().orElseThrow();
            var contextual = SoftwareCallRegistry.contextualTarget(p, sourceSite, originKind, invocation.graph().steps().get(0).index());
            if (step.softwareCall() != null) {
              SoftwareCallValidation.Preview validated = null;
              for (var candidate : configurations) {
                var test = SoftwareCallValidation.preview(p, candidate, TaskMonitor.DUMMY);
                if (ProgramMapping.JSON.toJsonTree(test.frame()).equals(ProgramMapping.JSON.toJsonTree(step.softwareCall()))) { validated = test; break; }
              }
              if (validated == null) throw new IllegalArgumentException("Missing current nested call configuration");
              for (var expanded : SoftwareCallInjection.expand(p, validated, site, unique, step.afterCall() != null,
                  step.callOutcome() != null && step.callOutcome().exit().equals("NONLOCAL"), contextual))
                add(expanded.getOpcode(), expanded.getOutput(), expanded.getInputs());
              unique += 0x1000000;
            } else add(PcodeOp.CALL, null, new Varnode(contextual == null ? ProgramMapping.staticAddress(p, step.physicalTarget()) : contextual, 2));
            if (step.afterCall() != null) results(step.afterCall());
            else if (step.callOutcome().exit().equals("NONRETURNING")) {
              if (contextual == null || !p.getFunctionManager().getFunctionAt(contextual).hasNoReturn())
                throw new IllegalArgumentException("Terminal call requires its context-qualified nonreturning native entry");
            } else {
              var outcome = step.callOutcome();
              if (!outcome.exit().equals("NONLOCAL") || outcome.resumeStep() == null)
                throw new IllegalArgumentException("Nonlocal call requires its proved destination continuation graph");
              var resumed = graph.steps().stream().filter(next -> next.index() == outcome.resumeStep()).findFirst().orElse(null);
              if (resumed != null && (!resumed.before().equals(outcome.state()) || resumed.callDepth() != step.callDepth()))
                throw new IllegalArgumentException("Nonlocal continuation does not retain the proved live state");
              if (resumed == null && (!graph.kind().equals("CALLEE") || !graph.exit().equals("NONLOCAL")
                  || graph.steps().get(graph.steps().size() - 1).index() != outcome.terminalStep()))
                throw new IllegalArgumentException("Nonlocal edge leaves its proved invocation boundary");
              results(outcome.state());
              add(PcodeOp.COPY, new Varnode(p.getRegister("PC").getAddress(), 2), constant(outcome.state().cpu(), 2));
              if (resumed == null) {
                // The inner RET already consumed the departed frames. Propagate its actual
                // destination through this native invocation without inventing another stack pop.
                add(PcodeOp.RETURN, null, constant(outcome.state().cpu(), 2));
                propagatedNonlocal = true;
              }
            }
            continue;
          }
          var accesses = step.accesses().stream().filter(a -> a.pcodeIndex() == index).toList();
          var inputs = op.getInputs().clone();
          for (int i = 0; i < inputs.length; i++) inputs[i] = relocate(inputs[i], temporaries);
          var output = op.getOutput() == null ? null : relocate(op.getOutput(), temporaries);
          if (code == PcodeOp.LOAD) {
            if (!accesses.isEmpty() && accesses.stream().allMatch(a -> !a.write() && a.physical().region().equals("ROM"))) {
              long value = 0; for (var access : accesses) value |= (long) access.value() << (8 * access.byteIndex());
              add(PcodeOp.COPY, output, constant(value, output.getSize()));
            } else {
              inputs[0] = constant(p.getAddressFactory().getDefaultAddressSpace().getSpaceID(), 8);
              add(code, output, inputs);
            }
          } else if (code == PcodeOp.STORE || CartridgeBus.isDirectWrite(p.getLanguage(), op)) {
            Varnode value = inputs[2];
            for (var access : accesses) {
              Varnode part = value;
              if (value.getSize() != 1) { part = scratch(1); add(PcodeOp.SUBPIECE, part, value, constant(access.byteIndex(), 4)); }
              if (access.mapperControl()) add(PcodeOp.CALLOTHER, null,
                  constant(CartridgeBus.userop(p.getLanguage(), CartridgeBus.CARTRIDGE_WRITE8), 4), constant(access.cpu(), 2), part);
              else add(PcodeOp.STORE, null, constant(p.getAddressFactory().getDefaultAddressSpace().getSpaceID(), 8), constant(access.cpu(), 2), part);
            }
          } else {
            // SLEIGH also encodes fixed memory reads as address-valued COPY inputs.
            for (int i = 0; i < inputs.length; i++) if (inputs[i].isAddress() && code != PcodeOp.RETURN) {
              long value = 0; boolean immutable = true;
              for (int b = 0; b < inputs[i].getSize(); b++) {
                int cpu = ((int) inputs[i].getOffset() + b) & 0xffff;
                var access = accesses.stream().filter(a -> !a.write() && a.cpu() == cpu).findFirst().orElseThrow();
                if (!access.physical().region().equals("ROM")) immutable = false;
                if (access.value() != null) value |= (long) access.value() << (b * 8);
              }
              inputs[i] = immutable ? constant(value, inputs[i].getSize())
                  : new Varnode(p.getAddressFactory().getDefaultAddressSpace().getAddress(inputs[i].getOffset()), inputs[i].getSize());
            }
            if (output != null && output.isAddress() && accesses.stream().anyMatch(a -> a.write() && a.mapperControl())) {
              var value = scratch(output.getSize());
              add(code, value, inputs);
              for (var access : accesses) if (access.write()) {
                Varnode part = value;
                if (value.getSize() != 1) { part = scratch(1); add(PcodeOp.SUBPIECE, part, value, constant(access.byteIndex(), 4)); }
                if (access.mapperControl()) add(PcodeOp.CALLOTHER, null,
                    constant(CartridgeBus.userop(p.getLanguage(), CartridgeBus.CARTRIDGE_WRITE8), 4), constant(access.cpu(), 2), part);
                else add(PcodeOp.STORE, null, constant(p.getAddressFactory().getDefaultAddressSpace().getSpaceID(), 8), constant(access.cpu(), 2), part);
              }
            } else {
              if (output != null && output.isAddress()) output = new Varnode(p.getAddressFactory().getDefaultAddressSpace().getAddress(output.getOffset()), output.getSize());
              add(code, output, inputs);
            }
          }
        }
        if (!external && !propagatedNonlocal && !(step.callOutcome() != null && step.callOutcome().exit().equals("NONRETURNING"))) {
          Integer successor = step.callOutcome() != null && step.callOutcome().exit().equals("NONLOCAL")
              ? step.callOutcome().resumeStep() : step.successor();
          if (step.afterCall() != null) {
            successor = null;
            for (var next : graph.steps()) if (next.index() > step.index() && next.callDepth() == 0
                && next.before().equals(step.afterCall())) { successor = next.index(); break; }
          }
          if (successor == null) throw new IllegalArgumentException("Continuation graph lacks a represented successor at " + step.address());
          edge(successor);
        }
      }
      for (var edge : edges.entrySet()) {
        var destination = entries.get(edge.getValue());
        if (destination == null) throw new IllegalArgumentException("Continuation edge leaves root native graph");
        var op = ops.get(edge.getKey());
        ops.set(edge.getKey(), new PcodeOp(site, edge.getKey(), PcodeOp.BRANCH,
            new Varnode[] {constant((destination - edge.getKey()) & 0xffffffffL, 4)}));
      }
      return ops.toArray(PcodeOp[]::new);
    }
  }
}
