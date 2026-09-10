package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/**
 * Scoped SA-02 transport prerequisite: one routine's proven, nonoverlapping CPU ranges may refer
 * to different physical ROM banks in one execution overlay. CPU addresses remain 16-bit and bytes
 * remain shared with canonical storage. A CPU address cannot represent two physical identities in
 * this view; such control flow requires the still-open general SA-02 architecture.
 */
public final class SoftwareCallExecutionView {
  private SoftwareCallExecutionView() {}
  public static final String VERSION = "software-call-execution-view-2";
  public static final String PREFIX = "gb_call_view_";
  public record Segment(int cpu, int length, String source) {}
  public record Preview(String version, String dependencies, String name, List<Segment> segments) {
    public Preview { segments = List.copyOf(segments); }
  }
  public record Created(String version, String name, List<Segment> segments, AddressSet body) {
    public Created { segments = List.copyOf(segments); body = new AddressSet(body); }
    @Override public AddressSet body() { return new AddressSet(body); }
  }

  public static Preview preview(Program program, String name, List<Segment> segments, TaskMonitor monitor) throws Exception {
    return previewOwned(program, name, segments, PREFIX, VERSION, monitor);
  }

  static Preview previewOrdinary(Program program, String name, List<Segment> segments, TaskMonitor monitor) throws Exception {
    return previewOwned(program, name, segments, OrdinaryEntryAccess.PREFIX, OrdinaryEntryAccess.VERSION, monitor);
  }

  private static Preview previewOwned(Program program, String name, List<Segment> segments,
      String prefix, String version, TaskMonitor monitor) throws Exception {
    if (!name.matches("[A-Za-z0-9_]+") || !name.startsWith(prefix))
      throw new IllegalArgumentException("Execution view name must begin " + prefix + " and use identifier characters");
    if (program.getAddressFactory().getAddressSpace(name) != null)
      throw new IllegalArgumentException("Execution view already exists");
    if (segments.isEmpty()) throw new IllegalArgumentException("No execution ranges");
    var occupied = new BitSet(0x8000);
    var ordered = new ArrayList<>(segments); ordered.sort(Comparator.comparingInt(Segment::cpu));
    for (var segment : ordered) {
      monitor.checkCancelled();
      if (segment.cpu < 0 || segment.length <= 0 || segment.cpu + (long) segment.length > 0x8000)
        throw new IllegalArgumentException("Execution segment exceeds 16-bit ROM CPU windows");
      int overlap = occupied.nextSetBit(segment.cpu);
      if (overlap >= 0 && overlap < segment.cpu + segment.length)
        throw new IllegalArgumentException("A CPU address has multiple execution identities");
      occupied.set(segment.cpu, segment.cpu + segment.length);
      var source = ProgramMapping.staticAddress(program, segment.source);
      if (source == null || source.getOffset() != segment.cpu)
        throw new IllegalArgumentException("Execution view must retain the source CPU address");
      var block = program.getMemory().getBlock(source);
      if (block == null || !block.isInitialized() || block.isWrite()
          || block.getName().startsWith(PREFIX) || !block.contains(source.add(segment.length - 1)))
        throw new IllegalArgumentException("Expected immutable canonical ROM source interval");
      for (int offset = 0; offset < segment.length; offset++) {
        monitor.checkCancelled();
        var identity = ProgramMapping.staticToPhysical(program, source.add(offset));
        if (identity.size() != 1 || !identity.get(0).region().equals("ROM"))
          throw new IllegalArgumentException("Unresolved physical source identity");
      }
      var first = program.getListing().getInstructionContaining(source);
      var last = program.getListing().getInstructionContaining(source.add(segment.length - 1));
      if ((first != null && !first.getAddress().equals(source))
          || (last != null && !last.getMaxAddress().equals(source.add(segment.length - 1))))
        throw new IllegalArgumentException("Execution segment cuts an instruction");
    }
    return new Preview(version, FarCallEvidence.capture(program, monitor), name, ordered);
  }

  /** Caller owns the transaction, listing/Function migration and its reviewed rollback receipt. */
  public static Created create(Program program, Preview reviewed, TaskMonitor monitor) throws Exception {
    return createOwned(program, reviewed, PREFIX, VERSION, monitor);
  }

  static Created createOrdinary(Program program, Preview reviewed, TaskMonitor monitor) throws Exception {
    return createOwned(program, reviewed, OrdinaryEntryAccess.PREFIX, OrdinaryEntryAccess.VERSION, monitor);
  }

  private static Created createOwned(Program program, Preview reviewed, String prefix,
      String version, TaskMonitor monitor) throws Exception {
    var current = previewOwned(program, reviewed.name, reviewed.segments, prefix, version, monitor);
    if (!current.equals(reviewed)) throw new IllegalArgumentException("Stale execution-view preview");
    if (program.getCurrentTransactionInfo() == null)
      throw new IllegalArgumentException("Execution view creation requires caller transaction");
    var body = new AddressSet();
    var space = program.getAddressFactory().getDefaultAddressSpace();
    boolean first = true;
    for (var segment : reviewed.segments) {
      monitor.checkCancelled();
      var source = ProgramMapping.staticAddress(program, segment.source);
      var destination = first ? space.getAddress(segment.cpu) : space.getAddressInThisSpaceOnly(segment.cpu);
      var block = program.getMemory().createByteMappedBlock(
          first ? reviewed.name : reviewed.name + "_" + Integer.toHexString(segment.cpu),
          destination, source, segment.length, first);
      block.setRead(true); block.setWrite(false); block.setExecute(true);
      block.setComment(version + "; shared physical source " + segment.source);
      space = block.getStart().getAddressSpace(); first = false;
      body.add(block.getStart(), block.getEnd());
    }
    return new Created(version, reviewed.name, reviewed.segments, body);
  }

  /** Checked physical RAM source; only ExecutableImages calls this inside its establishment transaction. */
  static Created createImage(Program p,String name,int cpu,int length,TaskMonitor monitor) throws Exception {
    if(p.getCurrentTransactionInfo()==null||!name.startsWith(OrdinaryEntryAccess.PREFIX)||p.getAddressFactory().getAddressSpace(name)!=null)
      throw new IllegalArgumentException("Image view requires a new owned transactional space");
    for(int i=0;i<length;i++){monitor.checkCancelled();SymbolicMemory.address(p,MapperKnowledge.unknown(),cpu+i,ScalarAccess.Kind.FETCH);}
    var source=SymbolicMemory.address(p,MapperKnowledge.unknown(),cpu,ScalarAccess.Kind.FETCH);
    byte[] bytes=new byte[length];p.getMemory().getBytes(source,bytes);
    var block=p.getMemory().createInitializedBlock(name,p.getAddressFactory().getDefaultAddressSpace().getAddress(cpu),new java.io.ByteArrayInputStream(bytes),length,monitor,true);
    block.setRead(true);block.setWrite(false);block.setExecute(true);block.setComment(ExecutableImages.VERSION+"; generation snapshot of physical RAM "+source);
    return new Created(ExecutableImages.VERSION,name,List.of(new Segment(cpu,length,source.toString())),new AddressSet(block.getStart(),block.getEnd()));
  }

  /**
   * Derive a finite continuation CFG whose instructions cannot alter bank selection. This scope
   * admits direct conditional branches and terminal RET, rejects indirect flow, nested calls and
   * memory writes. Loads are limited to immutable ROM0 constants and the exact terminal RET
   * stack reads; other data views require additional mapping proof. It never guesses a suffix size.
   */
  public static List<Segment> continuationSegments(Program program, SoftwareCallModel.Returned returned,
      TaskMonitor monitor) throws Exception {
    return continuationSegments(program, returned, monitor, true);
  }

  // The first pass discovers physical instruction ranges even for native same-space tails.
  // Only transported tails require the stronger data/SP policy of local injection/mapped views.
  static List<Segment> continuationSegments(Program program, SoftwareCallModel.Returned returned,
      TaskMonitor monitor, boolean transport) throws Exception {
    if ((returned.exit() != SoftwareCallModel.Exit.MAY_RETURN && returned.exit() != SoftwareCallModel.Exit.NONLOCAL)
        || returned.physical() == null)
      throw new IllegalArgumentException("Proven physical continuation required");
    var pending = new ArrayDeque<Integer>(); pending.add(returned.cpu());
    var visited = new HashSet<Integer>(); var body = new AddressSet();
    while (!pending.isEmpty()) {
      monitor.checkCancelled();
      int cpu = pending.removeFirst();
      if (!visited.add(cpu)) continue;
      if (visited.size() > 1024) throw new IllegalArgumentException("Continuation CFG bound exceeded");
      var address = SoftwareCallValidation.executionAddress(program, returned.mapper(), cpu);
      var fetchBlock = program.getMemory().getBlock(address);
      if (fetchBlock == null || !fetchBlock.isInitialized() || fetchBlock.isWrite() || fetchBlock.isVolatile()
          || !ProgramMapping.staticToPhysical(program, address).equals(List.of(
              MapperState.translate(ProgramMapping.cartridge(program), returned.mapper(), cpu, false).physical())))
        throw new IllegalArgumentException("Continuation source must be immutable initialized physical ROM at " + address);
      var instruction = SoftwareCallInstructionDiscovery.instructionAt(program, address, "proved continuation edge", monitor);
      if (instruction == null || instruction.isLengthOverridden())
        throw new IllegalArgumentException("Continuation requires architectural instruction boundary at " + address);
      var interpretation = InstructionInterpretation.architecturalUnresolved(instruction);
      if (interpretation != null)
        throw new IllegalArgumentException("Continuation has an unvalidated native interpretation at " + address + ": " + interpretation);
      for (int offset = 0; offset < instruction.getLength(); offset++) {
        var byteAddress = SoftwareCallValidation.executionAddress(program, returned.mapper(), (cpu + offset) & 0xffff);
        if (!byteAddress.equals(address.add(offset))) throw new IllegalArgumentException("Continuation instruction crosses physical views");
        var block = program.getMemory().getBlock(byteAddress);
        var identities = ProgramMapping.staticToPhysical(program, byteAddress);
        if (block == null || !block.isInitialized() || block.isWrite() || block.isVolatile()
            || identities.size() != 1 || !identities.get(0).region().equals("ROM"))
          throw new IllegalArgumentException("Continuation source must be immutable initialized physical ROM at " + byteAddress);
      }
      int opcode = instruction.getBytes()[0] & 255;
      boolean architecturalRet = instruction.getLength() == 1
          && (opcode == 0xc9 || opcode == 0xc0 || opcode == 0xc8 || opcode == 0xd0 || opcode == 0xd8);
      boolean terminal = false;
      var instructionRegisters = new HashMap<Long, Integer>();
      var instructionUniques = new HashMap<Long, Integer>();
      for (var op : instruction.getPcode(false)) {
        int code = op.getOpcode();
        var output = op.getOutput();
        if (transport && output != null && output.isAddress())
          validateFixedWrite(program, returned, output.getOffset(), output.getSize());
        boolean flow = code == ghidra.program.model.pcode.PcodeOp.BRANCH || code == ghidra.program.model.pcode.PcodeOp.CBRANCH
            || code == ghidra.program.model.pcode.PcodeOp.BRANCHIND || code == ghidra.program.model.pcode.PcodeOp.CALL
            || code == ghidra.program.model.pcode.PcodeOp.CALLIND || code == ghidra.program.model.pcode.PcodeOp.RETURN;
        if (transport && !flow) for (var input : op.getInputs()) {
          if (!input.isAddress()) continue;
          validateFixedDataRead(program, returned.mapper(), input.getOffset(), input.getSize());
        }
        var sp = program.getRegister("SP");
        if (transport && !architecturalRet && output != null && output.isRegister()
            && output.getOffset() < sp.getOffset() + sp.getMinimumByteSize()
            && sp.getOffset() < output.getOffset() + output.getSize())
          throw new IllegalArgumentException("Continuation changes SP without a stack-view proof");
        if (transport && code == ghidra.program.model.pcode.PcodeOp.LOAD) {
          if (architecturalRet) {
            int stack = returned.sp();
            if (!((stack >= 0xc000 && stack <= 0xcffe) || (stack >= 0xff80 && stack <= 0xfffd)))
              throw new IllegalArgumentException("Continuation RET stack is not in a fixed physical RAM interval");
          } else {
            var pointer = op.getInput(1);
            if (!pointer.isConstant() || pointer.getOffset() < 0
                || pointer.getOffset() + op.getOutput().getSize() > 0x4000)
              throw new IllegalArgumentException("Continuation LOAD requires a proven native physical data view");
            validateFixedDataRead(program, returned.mapper(), pointer.getOffset(), op.getOutput().getSize());
          }
        }
        if (code == ghidra.program.model.pcode.PcodeOp.CALL || code == ghidra.program.model.pcode.PcodeOp.CALLIND
            || code == ghidra.program.model.pcode.PcodeOp.BRANCHIND)
          throw new IllegalArgumentException("Continuation requires further interprocedural or indirect-flow proof");
        if (code == ghidra.program.model.pcode.PcodeOp.STORE || CartridgeBus.isDirectWrite(program.getLanguage(), op)) {
          Long pointer = PcodeConstants.value(op.getInput(1), instructionRegisters, instructionUniques);
          if (pointer == null) throw new IllegalArgumentException("Continuation write has an unknown CPU destination");
          if (transport) validateFixedWrite(program, returned, pointer, op.getInput(2).getSize());
          else if (pointer < 0x8000 || pointer == 0xff4f || pointer == 0xff70)
            throw new IllegalArgumentException("Continuation bank write requires later mapper-state proof");
        } else if (code == ghidra.program.model.pcode.PcodeOp.CALLOTHER)
          throw new IllegalArgumentException("Continuation userop requires further effect proof");
        if (code == ghidra.program.model.pcode.PcodeOp.BRANCH || code == ghidra.program.model.pcode.PcodeOp.CBRANCH) {
          var target = op.getInput(0);
          if (!target.isConstant()) pending.add((int) target.getOffset() & 0xffff);
          if (code == ghidra.program.model.pcode.PcodeOp.BRANCH && !target.isConstant()) terminal = true;
        }
        if (code == ghidra.program.model.pcode.PcodeOp.RETURN) terminal = true;
        if (output != null)
          PcodeConstants.put(output, PcodeConstants.evaluate(op, instructionRegisters, instructionUniques), instructionRegisters, instructionUniques);
      }
      body.add(address, address.add(instruction.getLength() - 1));
      if (!terminal || instruction.getFlowType().isConditional()) pending.add((cpu + instruction.getLength()) & 0xffff);
    }
    var segments = new ArrayList<Segment>();
    for (var range : body.getAddressRanges())
      segments.add(new Segment((int) range.getMinAddress().getOffset(), (int) range.getLength(), range.getMinAddress().toString()));
    return List.copyOf(segments);
  }

  private static void validateFixedWrite(Program program, SoftwareCallModel.Returned returned,
      long pointer, int size) throws Exception {
    if (pointer < 0 || pointer > 0xffff || size < 1 || size > 8)
      throw new IllegalArgumentException("Continuation write has an unsupported CPU address or width");
    for (int offset = 0; offset < size; offset++) {
      int cpu = ((int) pointer + offset) & 0xffff;
      if (!((cpu >= 0xc000 && cpu < 0xd000) || (cpu >= 0xff80 && cpu < 0xffff)))
        throw new IllegalArgumentException("Continuation write requires fixed WRAM0 or HRAM");
      if (cpu == returned.sp() || cpu == ((returned.sp() + 1) & 0xffff))
        throw new IllegalArgumentException("Continuation write overlaps the live return word");
      var actual = MapperState.translate(ProgramMapping.cartridge(program), returned.mapper(), cpu, true).physical();
      var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(cpu);
      var block = program.getMemory().getBlock(address);
      if (block != null) {
        var identities = ProgramMapping.staticToPhysical(program, address);
        if (!block.isWrite() || identities.size() != 1 || !identities.get(0).equals(actual))
          throw new IllegalArgumentException("Continuation write disagrees with native fixed-RAM identity");
      }
    }
  }

  private static void validateFixedDataRead(Program program, MapperState mapper, long pointer, int size) throws Exception {
    if (pointer < 0 || pointer + size > 0x4000)
      throw new IllegalArgumentException("Continuation memory read requires a proven native physical data view");
    for (int offset = 0; offset < size; offset++) {
      var dataAddress = SoftwareCallValidation.executionAddress(program, mapper, (int) pointer + offset);
      var identity = ProgramMapping.staticToPhysical(program, dataAddress);
      var block = program.getMemory().getBlock(dataAddress);
      if (identity.size() != 1 || !identity.get(0).region().equals("ROM")
          || identity.get(0).bank() != 0 || block == null || block.isWrite() || block.isVolatile() || !block.isInitialized())
        throw new IllegalArgumentException("Continuation memory read source is not immutable fixed ROM0");
    }
  }

  /** Exclude derived execution views when selecting canonical validation/proof inputs. */
  public static boolean canonical(Program program, Address address) {
    var block = program.getMemory().getBlock(address);
    return block != null && !block.getName().startsWith(PREFIX);
  }
}
