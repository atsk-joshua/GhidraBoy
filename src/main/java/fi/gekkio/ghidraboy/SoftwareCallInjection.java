package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallfixup;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Installed dynamic helper expansion. Every request resolves current, site-specific evidence. */
public final class SoftwareCallInjection extends InjectPayloadCallfixup {
  public static final String NAME = "ghidraboy_software_call_v1";
  public static final String VERSION = "software-call-injection-5";
  private final long uniqueBase;

  SoftwareCallInjection(String source, long uniqueBase) {
    super(source);
    this.uniqueBase = uniqueBase;
  }

  /**
   * The helper family can return. This metadata prevents the heuristic from declaring the helper
   * universally nonreturning; it does not classify any particular target or authorize unknown sites.
   */
  @Override
  public boolean isFallThru() {
    return true;
  }

  @Override
  public PcodeOp[] getPcode(Program program, InjectContext context) {
    return revalidated(program, () -> currentPcode(program, context));
  }

  /**
   * Stock constant propagation runs parallel function analyses against the same Program. Retry
   * a discarded proof only when that Program changed during the request. Each attempt starts
   * from current persisted dependencies and live paired receipts; stable stale input still fails.
   */
  static PcodeOp[] revalidated(Program program, java.util.function.Supplier<PcodeOp[]> request) {
    for (int attempt = 0; ; attempt++) {
      long before = program.getModificationNumber();
      try { return request.get(); }
      catch (IllegalArgumentException failure) {
        if (attempt == 15 || before == program.getModificationNumber()) throw failure;
      }
    }
  }

  private PcodeOp[] currentPcode(Program program, InjectContext context) {
    try {
      long modification = program.getModificationNumber();
      var preview = SoftwareCallRegistry.resolve(program, context.baseAddr);
      if (preview == null)
        throw new IllegalArgumentException("No validated software-call site at " + context.baseAddr);
      if (context.callAddr != null
          && !context.callAddr.equals(program.getAddressFactory().getDefaultAddressSpace()
              .getAddress(preview.configuration().template().helperCpu())))
        throw new IllegalArgumentException("Software-call helper identity differs from injection context");
      var effects = SoftwareCallRegistry.effects(program, preview, ghidra.util.task.TaskMonitor.DUMMY);
      if (!effects.complete())
        throw new IllegalArgumentException("Callee return/effect obligation is unresolved");
      if (!effects.nativeCompatible())
        SoftwareCallRegistry.requireCalleeTransport(program, preview, ghidra.util.task.TaskMonitor.DUMMY);
      boolean returns = effects.paths().stream().allMatch(path ->
          path.returned().exit() == SoftwareCallModel.Exit.MAY_RETURN);
      boolean nonreturning = effects.paths().stream().allMatch(path ->
          path.returned().exit() == SoftwareCallModel.Exit.NONRETURNING);
      boolean nonlocal = effects.paths().stream().allMatch(path ->
          path.returned().exit() == SoftwareCallModel.Exit.NONLOCAL);
      if (!returns && !nonreturning && !nonlocal)
        throw new IllegalArgumentException("Mixed callee exit is unsupported");
      var executionAlias = SoftwareCallRegistry.executionAlias(program, context.baseAddr);
      boolean stateContinuation = SoftwareCallRegistry.stateContinuation(program, context.baseAddr);
      if (nonlocal) {
        var exit = effects.paths().get(0).returned();
        var instruction = program.getListing().getInstructionAt(executionAlias == null ? context.baseAddr : executionAlias);
        var destination = instruction.getFallThrough();
        if (exit.cpu() == null || exit.physical() == null || exit.sp() == null || exit.registers() == null
            || (!stateContinuation && (destination == null || destination.getOffset() != exit.cpu()
                || instruction.getFlowOverride() == ghidra.program.model.listing.FlowOverride.CALL_RETURN
                || !ProgramMapping.staticToPhysical(program, destination).equals(List.of(exit.physical()))))
            || effects.paths().stream().anyMatch(path -> !java.util.Objects.equals(path.returned().cpu(), exit.cpu())
                || !java.util.Objects.equals(path.returned().physical(), exit.physical())
                || !java.util.Objects.equals(path.returned().sp(), exit.sp()) || path.returned().registers() == null))
          throw new IllegalArgumentException("Known nonlocal exit requires its reviewed physical branch and actual stack state");
      }
      if (nonreturning && program.getListing().getInstructionAt(context.baseAddr).getFlowOverride()
          != ghidra.program.model.listing.FlowOverride.CALL_RETURN)
        throw new IllegalArgumentException("Proven nonreturning site requires reviewed terminal call flow");
      var expanded = new ArrayList<>(List.of(expand(program, preview, context.baseAddr, uniqueBase, returns, nonlocal)));
      // The existing reviewed CALL_RETURN has a terminal operation after the replaced CALL. A
      // proven nonreturning target cannot execute a wrapper epilogue or establish output registers.
      if (nonreturning) return unchanged(program, modification, expanded);
      if (nonlocal) {
        // The callee's RET has already consumed its actual return word. No software-wrapper
        // epilogue runs on this path; the explicit branch below selects its reviewed physical exit.
        var sp = program.getRegister("SP");
        expanded.add(new PcodeOp(context.baseAddr, expanded.size(), PcodeOp.COPY,
            new Varnode[] {new Varnode(program.getAddressFactory().getConstantSpace()
                .getAddress(effects.paths().get(0).returned().sp()), 2)}, new Varnode(sp.getAddress(), 2)));
      }
      // These are site-conditional proven results, not a helper-wide ABI or guessed prototype.
      // In particular F must not inherit its pre-call value merely because a native ABI omits it.
      returnedRegisters(program,effects,context.baseAddr,expanded);
      if (SoftwareCallRegistry.stateContinuation(program, context.baseAddr)) {
        var configurations = SoftwareCallRegistry.configurations(program);
        var graph = SoftwareCallEffects.deriveContinuation(program, preview.frame(), effects.paths().get(0), configurations,
            ghidra.util.task.TaskMonitor.DUMMY);
        for (var op : SoftwareCallContinuationView.emit(program, context.baseAddr, graph, configurations, uniqueBase + 0x20000000L))
          expanded.add(new PcodeOp(context.baseAddr, expanded.size(), op.getOpcode(), op.getInputs(), op.getOutput()));
      } else if (executionAlias != null) {
        // This entry is canonical storage, not the mapped execution alias. Revalidate the
        // complete finite tail and lower its edges locally, so native root-space decoding
        // cannot accidentally read the old bank after the helper changes the selector.
        var tail = new Emitter(program, context.baseAddr, uniqueBase + 0x10000000L);
        tail.continuation(effects.paths().get(0).returned());
        for (var op : tail.ops)
          expanded.add(new PcodeOp(context.baseAddr, expanded.size(), op.getOpcode(), op.getInputs(), op.getOutput()));
      } else if (nonlocal) {
        var destination = program.getListing().getInstructionAt(context.baseAddr).getFallThrough();
        expanded.add(new PcodeOp(context.baseAddr, expanded.size(), PcodeOp.BRANCH,
            new Varnode[] {new Varnode(destination, 2)}));
      }
      return unchanged(program, modification, expanded);
    } catch (Exception failure) {
      throw new IllegalArgumentException("Unresolved software-call injection at " + context.baseAddr
          + ": " + failure.getMessage(), failure);
    }
  }

  /** Shared exact effect contract; a caller may use only results agreed by the actual returned paths. */
  static void returnedRegisters(Program program,SoftwareCallEffects.Summary effects,Address site,List<PcodeOp> operations) {
      var first = effects.paths().get(0).returned().registers();
      Map<String, Integer> results = Map.of("A", first.a(), "F", first.f(), "BC", first.bc(),
          "DE", first.de(), "HL", first.hl());
      for (var result : results.entrySet()) {
        boolean agreed = effects.paths().stream().allMatch(path -> {
          var registers = path.returned().registers();
          int value = switch (result.getKey()) {
            case "A" -> registers.a(); case "F" -> registers.f();
            case "BC" -> registers.bc(); case "DE" -> registers.de(); default -> registers.hl();
          };
          return value == result.getValue();
        });
        if (agreed) {
          var register = program.getRegister(result.getKey());
          operations.add(new PcodeOp(site, operations.size(), PcodeOp.COPY,
              new Varnode[] {new Varnode(program.getAddressFactory().getConstantSpace()
                  .getAddress(result.getValue()), register.getMinimumByteSize())},
              new Varnode(register.getAddress(), register.getMinimumByteSize())));
        }
      }
  }

  private static PcodeOp[] unchanged(Program program, long modification, List<PcodeOp> operations) {
    if (program.getModificationNumber() != modification)
      throw new IllegalArgumentException("Program changed during software-call injection");
    return operations.toArray(PcodeOp[]::new);
  }

  /**
   * Replay architectural helper operations; replace only its terminal transfer with a physical CALL.
   * The original CALL/RST's hardware push remains outside this payload. No host-width CPU arithmetic
   * is introduced. Returning wrappers execute their architectural epilogue after the ordinary call.
   */
  static PcodeOp[] expand(Program program, SoftwareCallValidation.Preview preview, Address site,
      long uniqueBase, boolean returns, boolean nonlocal) throws Exception {
    return expand(program, preview, site, uniqueBase, returns, nonlocal, SoftwareCallRegistry.stateTarget(program, preview));
  }

  static PcodeOp[] expand(Program program, SoftwareCallValidation.Preview preview, Address site,
      long uniqueBase, boolean returns, boolean nonlocal, Address contextualTarget) throws Exception {
    var template = preview.configuration().template();
    var frame = preview.frame();
    var targets = ProgramMapping.physicalToStatic(program, frame.target()).stream()
        .filter(address -> address.getOffset() == frame.targetCpu()
            && SoftwareCallExecutionView.canonical(program, address)).toList();
    if (targets.size() != 1) throw new IllegalArgumentException("Ambiguous physical call target");
    var target = contextualTarget == null ? targets.get(0) : contextualTarget;
    var physicalSource = StockEntryInjection.owned(program, target) ? StockEntries.source(program, target) : target;
    if (target.getOffset() != frame.targetCpu() || !ProgramMapping.staticToPhysical(program, physicalSource).equals(List.of(frame.target())))
      throw new IllegalArgumentException("Contextual call target differs from proven physical identity");
    var callee = program.getFunctionManager().getFunctionAt(target);
    if (callee != null) {
      if (callee.isThunk() || callee.isInline() || (callee.getCallFixup() != null
          && !SoftwareCallMayReturnInjection.NAME.equals(callee.getCallFixup()))
          || ((returns || nonlocal) && callee.hasNoReturn()))
        throw new IllegalArgumentException("Callee native contract conflicts with architectural summary");
      int purge = callee.getStackPurgeSize();
      if (purge != 0 && purge != ghidra.program.model.listing.Function.UNKNOWN_STACK_DEPTH_CHANGE
          && purge != ghidra.program.model.listing.Function.INVALID_STACK_DEPTH_CHANGE)
        throw new IllegalArgumentException("Callee native contract has unsupported stack purge");
    }
    var emitter = new Emitter(program, site, uniqueBase);
    var helper = program.getAddressFactory().getDefaultAddressSpace().getAddress(template.helperCpu());
    int preludeLength = template.epilogueCpu() >= 0
        ? template.epilogueCpu() - template.helperCpu()
        : template.bodyHex().length() / 2;
    if (template.family() == SoftwareCallModel.Family.INLINE_RET) {
      var bytes = frame.entry().payload();
      // Only these three immutable, bus-ordered Program reads are folded. In particular the
      // selector precedes the mapper write, while target bytes follow it. Stack LOADs remain real.
      emitter.payloadReads.put(helper.add(1), bytes[0] & 255);
      emitter.payloadReads.put(helper.add(5), bytes[1] & 255);
      emitter.payloadReads.put(helper.add(7), bytes[2] & 255);
    }
    emitter.instructions(helper, preludeLength, true);
    if (!emitter.payloadReads.isEmpty())
      throw new IllegalArgumentException("Exact helper payload reads were not fully emitted");
    emitter.ops.add(new PcodeOp(site, emitter.ops.size(), PcodeOp.CALL,
        new Varnode[] {new Varnode(target, 2)}));
    if (returns) {
      // This is the proven state after the callee's architectural RET, not another stack pop.
      // A target's native prototype must not shift the wrapper's real frame by a different amount.
      var sp = program.getRegister("SP");
      emitter.ops.add(new PcodeOp(site, emitter.ops.size(), PcodeOp.COPY,
          new Varnode[] {new Varnode(program.getAddressFactory().getConstantSpace()
              .getAddress((frame.targetSp() + 2) & 0xffff), 2)},
          new Varnode(sp.getAddress(), 2)));
    }
    if (returns && template.epilogueCpu() >= 0) {
      emitter.instructions(helper.add(preludeLength),
          template.bodyHex().length() / 2 - preludeLength, true);
    }
    return emitter.ops.toArray(PcodeOp[]::new);
  }

  private static final class Emitter {
    final Program program;
    final Address site;
    final List<PcodeOp> ops = new ArrayList<>();
    final Map<Address, Integer> payloadReads = new HashMap<>();
    long unique;

    Emitter(Program program, Address site, long unique) {
      this.program = program;
      this.site = site;
      this.unique = unique;
    }

    void instructions(Address start, int length, boolean omitTerminalTransfer) {
      int offset = 0;
      boolean terminal = false;
      while (offset < length) {
        var instruction = program.getListing().getInstructionAt(start.add(offset));
        if (instruction == null || offset + instruction.getLength() > length)
          throw new IllegalArgumentException("Changed helper boundary at " + start.add(offset));
        Map<Long, Long> uniques = new HashMap<>();
        for (var op : instruction.getPcode(false)) {
          int code = op.getOpcode();
          boolean transfer = code == PcodeOp.BRANCHIND || code == PcodeOp.RETURN;
          if (transfer && omitTerminalTransfer && offset + instruction.getLength() == length) {
            terminal = true;
            continue;
          }
          if (code == PcodeOp.BRANCH || code == PcodeOp.CBRANCH || transfer
              || code == PcodeOp.CALL || code == PcodeOp.CALLIND)
            throw new IllegalArgumentException("Unsupported control flow inside exact helper");
          if (code == PcodeOp.LOAD && payloadReads.containsKey(instruction.getAddress())) {
            if (op.getOutput() == null || op.getOutput().getSize() != 1)
              throw new IllegalArgumentException("Unexpected helper payload load width");
            int value = payloadReads.remove(instruction.getAddress());
            ops.add(new PcodeOp(site, ops.size(), PcodeOp.COPY,
                new Varnode[] {new Varnode(program.getAddressFactory().getConstantSpace().getAddress(value), 1)},
                relocate(op.getOutput(), uniques)));
            continue;
          }
          Varnode[] inputs = new Varnode[op.getNumInputs()];
          for (int index = 0; index < inputs.length; index++)
            inputs[index] = relocate(op.getInput(index), uniques);
          Varnode output = op.getOutput() == null ? null : relocate(op.getOutput(), uniques);
          ops.add(new PcodeOp(site, ops.size(), code, inputs, output));
        }
        offset += instruction.getLength();
      }
      if (omitTerminalTransfer && !terminal)
        throw new IllegalArgumentException("Exact helper has no terminal transfer");
    }

    void continuation(SoftwareCallModel.Returned returned) throws Exception {
      var segments = SoftwareCallExecutionView.continuationSegments(program, returned, ghidra.util.task.TaskMonitor.DUMMY);
      var instructions = new java.util.TreeMap<Integer, ghidra.program.model.listing.Instruction>();
      for (var segment : segments) {
        var start = ProgramMapping.staticAddress(program, segment.source());
        for (int offset = 0; offset < segment.length();) {
          var instruction = program.getListing().getInstructionAt(start.add(offset));
          instructions.put((int) instruction.getAddress().getOffset(), instruction);
          offset += instruction.getLength();
        }
      }
      var entries = new HashMap<Integer, Integer>();
      var edges = new HashMap<Integer, Integer>();
      edges.put(ops.size(), returned.cpu());
      ops.add(new PcodeOp(site, ops.size(), PcodeOp.BRANCH,
          new Varnode[] {new Varnode(program.getAddressFactory().getConstantSpace().getAddress(0), 4)}));
      for (var entry : instructions.entrySet()) {
        var instruction = entry.getValue();
        entries.put(entry.getKey(), ops.size());
        // Native nested injection deletes/replaces CALLOTHER/CALL sequence identities. A local
        // edge must land on a stable op, not on that deleted sequence number (which Ghidra can
        // interpret as the original instruction's fallthrough). Scratch COPY survives CFG setup.
        ops.add(new PcodeOp(site, ops.size(), PcodeOp.COPY,
            new Varnode[] {new Varnode(program.getAddressFactory().getConstantSpace().getAddress(0), 1)},
            new Varnode(program.getAddressFactory().getUniqueSpace().getAddress(unique), 1)));
        unique += 0x10000;
        Map<Long, Long> uniques = new HashMap<>();
        boolean terminal = false;
        for (var op : instruction.getPcode(false)) {
          var inputs = op.getInputs().clone();
          for (int i = 0; i < inputs.length; i++) inputs[i] = relocate(inputs[i], uniques);
          if ((op.getOpcode() == PcodeOp.BRANCH || op.getOpcode() == PcodeOp.CBRANCH)
              && !inputs[0].isConstant()) {
            edges.put(ops.size(), (int) inputs[0].getOffset() & 0xffff);
            inputs[0] = new Varnode(program.getAddressFactory().getConstantSpace().getAddress(0), 4);
            if (op.getOpcode() == PcodeOp.BRANCH) terminal = true;
          }
          if (op.getOpcode() == PcodeOp.RETURN) terminal = true;
          ops.add(new PcodeOp(site, ops.size(), op.getOpcode(), inputs,
              op.getOutput() == null ? null : relocate(op.getOutput(), uniques)));
        }
        if (!terminal || instruction.getFlowType().isConditional()) {
          edges.put(ops.size(), (entry.getKey() + instruction.getLength()) & 0xffff);
          ops.add(new PcodeOp(site, ops.size(), PcodeOp.BRANCH,
              new Varnode[] {new Varnode(program.getAddressFactory().getConstantSpace().getAddress(0), 4)}));
        }
      }
      for (var edge : edges.entrySet()) {
        var destination = entries.get(edge.getValue());
        if (destination == null) throw new IllegalArgumentException("Continuation edge leaves validated CFG");
        var op = ops.get(edge.getKey());
        var inputs = op.getInputs().clone();
        inputs[0] = new Varnode(program.getAddressFactory().getConstantSpace()
            .getAddress((destination - edge.getKey()) & 0xffffffffL), 4);
        ops.set(edge.getKey(), new PcodeOp(site, edge.getKey(), op.getOpcode(), inputs, op.getOutput()));
      }
    }

    Varnode relocate(Varnode node, Map<Long, Long> uniques) {
      if (!node.isUnique()) return node;
      // Preserve overlapping SLEIGH temporary storage within each instruction. A full page separates
      // instruction namespaces, so temporary addresses never alias a preceding expanded instruction.
      long base = node.getOffset() & ~0xffffL;
      long replacement = uniques.computeIfAbsent(base, ignored -> {
        long allocated = unique;
        unique += 0x10000;
        return allocated;
      });
      return new Varnode(program.getAddressFactory().getUniqueSpace()
          .getAddress(replacement + (node.getOffset() & 0xffffL)), node.getSize());
    }
  }
}
