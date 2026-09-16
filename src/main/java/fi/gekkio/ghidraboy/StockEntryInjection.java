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
  public static final String VERSION = "stock-callother-entry-3";
  private final long uniqueBase;

  StockEntryInjection(String source, long uniqueBase) {
    super(source);
    this.uniqueBase = uniqueBase;
  }

  static final String STORAGE = "GhidraBoy stock carrier storage v3";

  /** Presentation storage has no physical-source or executable-image identity. */
  static SoftwareCallExecutionView.Created carrier(Program p, String name, int cpu,
      java.util.List<SoftwareCallExecutionView.Segment> sources, TaskMonitor monitor) throws Exception {
    if (p.getCurrentTransactionInfo() == null || p.getAddressFactory().getAddressSpace(name) != null)
      throw new IllegalArgumentException("Invalid new stock carrier ownership");
    monitor.checkCancelled();
    var block = p.getMemory().createInitializedBlock(name,
        p.getAddressFactory().getDefaultAddressSpace().getAddress(cpu),
        new java.io.ByteArrayInputStream(new byte[] {(byte) 0xc9}), 1, monitor, true);
    block.setRead(true); block.setWrite(false); block.setExecute(true);
    block.setComment(STORAGE);
    return new SoftwareCallExecutionView.Created(VERSION, name, sources,
        new ghidra.program.model.address.AddressSet(block.getStart(), block.getEnd()));
  }

  // Ownership detection must survive removal of context, convention and registration.
  static boolean owned(Program p, Address entry) {
    var block = p.getMemory().getBlock(entry);
    boolean ordinary = OrdinaryEntryAccess.stockRegistered(p, entry);
    boolean predicated = PredicatedCalls.stockRegistered(p, entry);
    return block != null && STORAGE.equals(block.getComment()) || ordinary || predicated;
  }

  /** Export ignores only structurally identified presentation storage, including retired carriers. */
  static boolean presentationStorage(ghidra.program.model.mem.MemoryBlock block) {
    var space = block.getStart().getAddressSpace();
    return STORAGE.equals(block.getComment()) && space.isOverlaySpace()
        && block.getName().equals(space.getName())
        && (space.getName().startsWith(OrdinaryEntryAccess.PREFIX)
            || space.getName().startsWith(SoftwareCallExecutionView.PREFIX))
        && block.isInitialized() && !block.isMapped() && block.getSize() == 1
        && block.isRead() && !block.isWrite() && !block.isVolatile();
  }

  static void validateStorage(Program p, Address entry) {
    var block = p.getMemory().getBlock(entry);
    try {
      if (!entry.getAddressSpace().isOverlaySpace() || block == null || !presentationStorage(block) || block.isMapped()
          || !block.isInitialized() || !block.getStart().equals(entry) || block.getSize() != 1
          || !block.isRead() || block.isWrite() || !block.isExecute() || block.isVolatile()
          || !STORAGE.equals(block.getComment()) || (p.getMemory().getByte(entry) & 255) != 0xc9)
        throw new IllegalArgumentException("Changed stock carrier storage at " + entry);
      for (var other : p.getMemory().getBlocks())
        if (other != block && other.getStart().getAddressSpace().equals(entry.getAddressSpace()))
          throw new IllegalArgumentException("Extra stock carrier range at " + entry);
    } catch (ghidra.program.model.mem.MemoryAccessException failure) {
      throw new IllegalArgumentException("Unreadable stock carrier", failure);
    }
  }

  static void prepare(Program p, Address entry) throws Exception {
    p.getProgramContext().setValue(p.getRegister("gb_analysis_entry"), entry, entry, BigInteger.ONE);
  }

  static void validate(Program p, Address entry) {
    validateStorage(p, entry);
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
        if (SoftwareCallDomains.stockRegistered(p, context.baseAddr))
          return SoftwareCallDomains.emitStock(p, context.baseAddr, uniqueBase, TaskMonitor.DUMMY);
        if (OrdinaryEntryAccess.stockRegistered(p, context.baseAddr))
          return OrdinaryEntryAccess.emitStock(p, context.baseAddr, uniqueBase, TaskMonitor.DUMMY);
        if (PredicatedCalls.stockRegistered(p, context.baseAddr))
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
