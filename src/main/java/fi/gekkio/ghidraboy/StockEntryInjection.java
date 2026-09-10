package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;
import java.math.BigInteger;

/** Experimental stock flow-time transport. No native-companion identity is substituted. */
public final class StockEntryInjection extends InjectPayloadCallother {
  public static final String NAME = "gb_analysis_entry_v1";
  public static final String CONVENTION = "__ghidraboy_stock_entry_v1";
  public static final String VERSION = "stock-callother-entry-2";
  private final long uniqueBase;

  StockEntryInjection(String source, long uniqueBase) {
    super(source);
    this.uniqueBase = uniqueBase;
  }

  static SoftwareCallExecutionView.Created imageView(Program p, String name, Address source,
      java.util.List<SoftwareCallExecutionView.Segment> pieces, TaskMonitor monitor) throws Exception {
    if (pieces.size() != 1 || p.getCurrentTransactionInfo() == null
        || p.getAddressFactory().getAddressSpace(name) != null)
      throw new IllegalArgumentException("Invalid new image carrier ownership");
    monitor.checkCancelled();
    var block = p.getMemory().createByteMappedBlock(name,
        p.getAddressFactory().getDefaultAddressSpace().getAddress(source.getOffset()), source, pieces.getFirst().length(), true);
    block.setRead(true); block.setWrite(false); block.setExecute(true);
    block.setComment(VERSION + "; presentation of image snapshot " + source);
    return new SoftwareCallExecutionView.Created(VERSION, name, pieces,
        new ghidra.program.model.address.AddressSet(block.getStart(), block.getEnd()));
  }

  static void prepare(Program p, Address entry) throws Exception {
    p.getProgramContext().setValue(p.getRegister("gb_analysis_entry"), entry, entry, BigInteger.ONE);
  }

  static void validate(Program p, Address entry) {
    var instruction = p.getListing().getInstructionAt(entry);
    if (!entry.getAddressSpace().isOverlaySpace() || instruction == null
        || !BigInteger.ONE.equals(p.getProgramContext().getValue(p.getRegister("gb_analysis_entry"), entry, false))
        || instruction.getLength() != 1 || instruction.isFallThroughOverridden()
        || instruction.getFlowOverride() != ghidra.program.model.listing.FlowOverride.NONE)
      throw new IllegalArgumentException("Missing or altered owned stock entry bound at " + entry);
    var ops = instruction.getPcode(false);
    if (ops.length != 2 || ops[0].getOpcode() != PcodeOp.CALLOTHER
        || ops[0].getNumInputs() != 1
        || ops[0].getInput(0).getOffset() != CartridgeBus.userop(p.getLanguage(), NAME)
        || ops[1].getOpcode() != PcodeOp.BRANCH || !ops[1].getInput(0).getAddress().equals(entry))
      throw new IllegalArgumentException("Changed stock entry raw bound at " + entry);
  }

  @Override public PcodeOp[] getPcode(Program p, InjectContext context) {
    return SoftwareCallInjection.revalidated(p, () -> {
      try {
        validate(p, context.baseAddr);
        if (SoftwareCallDomains.registered(p, context.baseAddr))
          return SoftwareCallDomains.emitStock(p, context.baseAddr, uniqueBase, TaskMonitor.DUMMY);
        if (OrdinaryEntryAccess.registered(p, context.baseAddr))
          return OrdinaryEntryAccess.emitStock(p, context.baseAddr, uniqueBase, TaskMonitor.DUMMY);
        if (PredicatedCalls.registered(p, context.baseAddr))
          return PredicatedCalls.emitStock(p, context.baseAddr, uniqueBase, TaskMonitor.DUMMY);
        if (!SoftwareCallRegistry.stockCarrier(p, context.baseAddr))
          throw new IllegalArgumentException("Missing predicated graph registration or stock software carrier");
        long revision = p.getModificationNumber();
        var input = SoftwareCallRegistry.resolveStateEntry(p, context.baseAddr);
        var graph = SoftwareCallRegistry.entryGraph(p, context.baseAddr, input);
        var result = SoftwareCallContinuationView.emit(p, context.baseAddr, graph,
            SoftwareCallRegistry.configurations(p), uniqueBase, SoftwareCallRegistry.entryStep(p, context.baseAddr));
        if (revision != p.getModificationNumber()) throw new IllegalArgumentException("Program changed during stock state-entry injection");
        return result;
      } catch (Exception failure) {
        throw new IllegalArgumentException("Unavailable stock analysis entry: " + failure.getMessage(), failure);
      }
    });
  }
}
