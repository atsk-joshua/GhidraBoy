package fi.gekkio.ghidraboy;

import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.InjectPayloadSleigh;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;

/** Late straight-line integrity guard, never a graph transport or architectural entry setup. */
public final class StockEntryGuardInjection extends InjectPayloadSleigh {
  public static final String NAME=StockEntryInjection.CONVENTION+"@@inject_uponentry";
  private final long uniqueBase;
  StockEntryGuardInjection(String source,long uniqueBase) {
    super(NAME,InjectPayload.CALLMECHANISM_TYPE,source);this.uniqueBase=uniqueBase;
  }
  @Override public PcodeOp[] getPcode(Program p,InjectContext context) {
    return SoftwareCallInjection.revalidated(p,()->{
      try {
        StockEntries.current(p,context.baseAddr,TaskMonitor.DUMMY);
        // Stock late injection accepts this dead temporary. No CPU register, memory, PC or SP effect.
        return new PcodeOp[]{new PcodeOp(context.baseAddr,0,PcodeOp.COPY,
            new Varnode[]{new Varnode(p.getAddressFactory().getConstantSpace().getAddress(0),1)},
            new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(uniqueBase),1))};
      }catch(Exception failure){throw new IllegalArgumentException("Unavailable stock entry integrity: "+failure.getMessage(),failure);}
    });
  }
}
