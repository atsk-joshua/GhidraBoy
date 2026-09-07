package fi.gekkio.ghidraboy;

import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallfixup;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Neutral native CALL transport for a target with a current code-derived returning witness.
 * The witness disproves a global noReturn assertion; it does not make every caller return.
 */
public final class SoftwareCallMayReturnInjection extends InjectPayloadCallfixup {
  public static final String NAME = "ghidraboy_may_return_v1";
  public static final String VERSION = "software-call-may-return-injection-2";

  SoftwareCallMayReturnInjection(String source) {
    super(source);
  }

  @Override
  public boolean isFallThru() {
    return true;
  }

  @Override
  public PcodeOp[] getPcode(Program program, InjectContext context) {
    return SoftwareCallInjection.revalidated(program, () -> currentPcode(program, context));
  }

  private PcodeOp[] currentPcode(Program program, InjectContext context) {
    try {
      long modification = program.getModificationNumber();
      if (getParamShift() != 0)
        throw new IllegalArgumentException("Neutral returning metadata cannot shift call parameters");
      if (context.baseAddr == null || context.callAddr == null)
        throw new IllegalArgumentException("A native call site and exact target are required");
      SoftwareCallRegistry.requireReturningTarget(program, context.callAddr);
      if (program.getModificationNumber() != modification)
        throw new IllegalArgumentException("Program changed during returning-target validation");
      // Ghidra FlowInfo::setupCallSpecs cancels re-injection for this exact same target.
      // The original instruction already supplies its architectural push, if any.
      return new PcodeOp[] {new PcodeOp(context.baseAddr, 0, PcodeOp.CALL,
          new Varnode[] {new Varnode(context.callAddr, 2)})};
    } catch (Exception failure) {
      throw new IllegalArgumentException("Unresolved returning-target metadata: " + failure.getMessage(), failure);
    }
  }
}
