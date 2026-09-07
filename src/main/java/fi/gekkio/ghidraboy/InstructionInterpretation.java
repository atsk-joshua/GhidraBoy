package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.util.Arrays;

/**
 * Architectural decoding or an independently revalidated software-call contract, otherwise an
 * explicit stop. Callers accepting softwareCall must consume its effects and physical continuation;
 * they must not combine a successful validation with the unexpanded hardware CALL semantics.
 * Stored references and getPcode(true) never independently prove a software-call convention.
 */
final class InstructionInterpretation {
  private InstructionInterpretation() {}

  static boolean relevant(Reference ref) {
    return ref.getReferenceType().isFlow() || ref.getReferenceType().isOverride();
  }

  static SoftwareCallValidation.Preview softwareCall(Instruction ins) throws Exception {
    return SoftwareCallRegistry.resolve(ins.getProgram(), ins.getAddress());
  }

  static String unresolved(Instruction ins) {
    try {
      if (softwareCall(ins) != null) return null;
      var rawConflict = architecturalUnresolved(ins);
      if (rawConflict != null) return rawConflict;
      if (ins.getFlowType().isCall()) {
        for (var function : ins.getProgram().getFunctionManager().getFunctions(true)) {
          if (SoftwareCallMayReturnInjection.NAME.equals(function.getCallFixup())
              && Arrays.stream(ins.getDefaultFlows()).anyMatch(target ->
                  target.getOffset() == function.getEntryPoint().getOffset()))
            SoftwareCallRegistry.requireReturningTarget(ins.getProgram(), function.getEntryPoint());
        }
      }
      return null;
    } catch (Exception failure) {
      return "Unresolved software-call interpretation: " + failure.getMessage();
    }
  }

  /** Architectural validation must not recursively consult generated software-call evidence. */
  static String architecturalUnresolved(Instruction ins) {
    if (ins.getFlowOverride() != FlowOverride.NONE)
      return "Unsupported instruction interpretation: flow override " + ins.getFlowOverride();
    if (ins.isLengthOverridden() || ins.isFallThroughOverridden())
      return "Unsupported instruction interpretation: length/fallthrough override needs an effect"
          + " and continuation summary";
    var decoded = Arrays.asList(ins.getDefaultFlows());
    for (var ref : ins.getReferencesFrom()) {
      if (!relevant(ref)) continue;
      if (ref.getReferenceType().isOverride()
          || !decoded.contains(ref.getToAddress())
          || !ref.getReferenceType().equals(ins.getFlowType()))
        return "Unsupported instruction interpretation: stored flow annotation differs from decoded"
            + " flow";
    }
    if (ins.getFlowType().isCall())
      for (var function : ins.getProgram().getFunctionManager().getFunctions(true))
        if (function.getCallFixup() != null
            && !SoftwareCallMayReturnInjection.NAME.equals(function.getCallFixup())
            && decoded.stream()
                .anyMatch(dest -> dest.getOffset() == function.getEntryPoint().getOffset()))
          // A later mapper resolution may select an overlay at the same CPU address.
          // Until summaries are supported, conservatively reject any such fixup.
          return "Unsupported instruction interpretation: callfixup " + function.getCallFixup();
    return null;
  }
}
