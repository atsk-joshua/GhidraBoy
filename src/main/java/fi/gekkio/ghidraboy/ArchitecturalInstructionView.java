package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import java.util.Arrays;

/** BankAnalysis hardware view. Stored Ghidra presentation is observed, never rewritten. */
final class ArchitecturalInstructionView {
  private final Instruction instruction;
  private final FlowType flowType;
  private final Address[] targets;
  private final Address fallThrough;
  private final PcodeOp[] pcode;

  private ArchitecturalInstructionView(Instruction instruction) {
    this.instruction = instruction;
    var prototype = instruction.getPrototype();
    var context = instruction.getInstructionContext();
    flowType = prototype.getFlowType(context);
    targets = prototype.getFlows(context);
    fallThrough = prototype.getFallThrough(context);
    pcode = instruction.getPcode(false);
  }

  static ArchitecturalInstructionView of(Instruction instruction) {
    return new ArchitecturalInstructionView(instruction);
  }

  FlowType flowType() { return flowType; }
  Address[] targets() { return targets.clone(); }
  Address fallThrough() { return fallThrough; }
  PcodeOp[] pcode() { return pcode.clone(); }

  /** Stock setFlowOverride retypes ordinary call/jump references without their terminator bit. */
  private RefType presentationReferenceType() {
    var type = FlowOverride.getModifiedFlowType(flowType, instruction.getFlowOverride());
    if (type.isCall()) {
      if (type.isComputed()) return type.isConditional() ? RefType.CONDITIONAL_COMPUTED_CALL : RefType.COMPUTED_CALL;
      return type.isConditional() ? RefType.CONDITIONAL_CALL : RefType.UNCONDITIONAL_CALL;
    }
    if (type.isJump()) {
      if (type.isComputed()) return type.isConditional() ? RefType.CONDITIONAL_COMPUTED_JUMP : RefType.COMPUTED_JUMP;
      return type.isConditional() ? RefType.CONDITIONAL_JUMP : RefType.UNCONDITIONAL_JUMP;
    }
    // RETURN does not necessarily retype a direct reference: stock retains the decoded type.
    return flowType;
  }

  private boolean retainedReturnReference(RefType type) {
    // Stock RETURN can leave the ordinary reference from an earlier CALL/BRANCH override.
    // Conditionality and directness must still match the decoded transfer. Target equality
    // is checked separately; neither reference family supplies hardware transfer authority.
    if (instruction.getFlowOverride() != FlowOverride.RETURN || flowType.isComputed()
        || (!flowType.isCall() && !flowType.isJump())) return false;
    return type.equals(flowType.isConditional() ? RefType.CONDITIONAL_CALL : RefType.UNCONDITIONAL_CALL)
        || type.equals(flowType.isConditional() ? RefType.CONDITIONAL_JUMP : RefType.UNCONDITIONAL_JUMP);
  }

  String architecturalUnresolved() {
    var ins = instruction;
    if (ins.isLengthOverridden() || ins.isFallThroughOverridden()
        || ins.getLength() != ins.getPrototype().getLength())
      return "Unsupported instruction interpretation: length/fallthrough override needs an effect and continuation summary";
    var decoded = Arrays.asList(targets);
    for (var ref : ins.getReferencesFrom()) {
      if (!InstructionInterpretation.relevant(ref)) continue;
      if (OrdinaryCallFlow.architecturalExemption(ins, ref)) continue;
      boolean ordinaryType = ref.getReferenceType().equals(flowType)
          || (ins.getFlowOverride() != FlowOverride.NONE
              && ref.getReferenceType().equals(presentationReferenceType()))
          || retainedReturnReference(ref.getReferenceType());
      if (ref.getReferenceType().isOverride() || !decoded.contains(ref.getToAddress()) || !ordinaryType)
        return "Unsupported instruction interpretation: stored flow annotation differs from decoded flow";
    }
    if (flowType.isCall())
      for (var function : ins.getProgram().getFunctionManager().getFunctions(true))
        if (function.getCallFixup() != null
            && !SoftwareCallMayReturnInjection.NAME.equals(function.getCallFixup())
            && decoded.stream().anyMatch(dest -> dest.getOffset() == function.getEntryPoint().getOffset()))
          return "Unsupported instruction interpretation: callfixup " + function.getCallFixup();
    return null;
  }

  /** Preserve the independently validated software-convention route and its refusal behavior. */
  String unresolved() {
    try {
      if (InstructionInterpretation.softwareCall(instruction) != null) return null;
      var conflict = architecturalUnresolved();
      if (conflict != null) return conflict;
      if (flowType.isCall())
        for (var function : instruction.getProgram().getFunctionManager().getFunctions(true))
          if (SoftwareCallMayReturnInjection.NAME.equals(function.getCallFixup())
              && Arrays.stream(targets).anyMatch(dest -> dest.getOffset() == function.getEntryPoint().getOffset()))
            SoftwareCallRegistry.requireReturningTarget(instruction.getProgram(), function.getEntryPoint());
      return null;
    } catch (Exception failure) {
      return "Unresolved software-call interpretation: " + failure.getMessage();
    }
  }

  String discrepancy() {
    if (instruction.getFlowOverride() == FlowOverride.NONE
        || (flowType.equals(instruction.getFlowType())
            && Arrays.toString(pcode).equals(Arrays.toString(instruction.getPcode(true)))
            && Arrays.equals(targets, instruction.getDefaultFlows())
            && java.util.Objects.equals(fallThrough, instruction.getFallThrough()))) return null;
    return instruction.getAddress() + ": saved flow presentation differs from architectural semantics"
        + " (override=" + instruction.getFlowOverride() + ", raw=" + flowType
        + ", presentation=" + instruction.getFlowType() + "); BankAnalysis used raw architectural semantics";
  }
}
