package fi.gekkio.ghidraboy;

import static fi.gekkio.ghidraboy.AbstractValues.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/**
 * Experimental bounded value projection of compiled straight-line p-code. It does not assign
 * concrete entry registers: an unproved byte denotes all 256 values and a wider unknown is TOP.
 * Cartesian transfer is a sound may-domain, not a claim that its members are unconditional facts.
 * Native lowering retains the raw address/selector computation and snapshots each recorded operand.
 * Program, revision, instruction and physical-byte binding belongs to OrdinaryEntryAccess.
 */
public final class FiniteEntryProducer {
  private FiniteEntryProducer() {}

  public static final String VERSION = "finite-entry-producer-w2g-joint-3";
  public static final int MAX_VALUES = 256;
  // The full byte set is TOP, not useful finite selector precision. This is the
  // enumeration boundary; emitted work is separately budgeted by OrdinaryEntryAccess.
  public static final int MAX_ALTERNATIVES = MAX_VALUES - 1;
  private static final int MAX_OPERATIONS = 4096;

  public enum Kind { MAPPER_SELECTOR, CPU_POINTER }
  public record Choice(Kind kind, String instruction, int operation, int input, Integer mapperCpu,
      String space, long offset, int width, String expression, List<Long> values, AbstractValues.Origin origin) {
    public Choice { values = List.copyOf(values); }
  }
  public record Alternative(long key, List<OrdinaryEntryAccess.SourceByte> sources, long value) {
    public Alternative { sources = List.copyOf(sources); }
  }
  public record Candidate(long selector, long pointer, List<OrdinaryEntryAccess.SourceByte> sources, long value) {
    public Candidate { sources = List.copyOf(sources); }
  }
  public record Guarded(Candidate endpoint, AbstractValues.Condition condition) {}
  public record Joint(Choice selector, Choice pointer, List<Candidate> candidateCover,
      List<Guarded> reachable, boolean complete, String validation) {
    public Joint { candidateCover = List.copyOf(candidateCover); reachable = List.copyOf(reachable); }
  }
  public record Read(String instruction, int operation, int operand, int width,
      Choice choice, List<Alternative> alternatives, Joint joint) {
    public Read { alternatives = List.copyOf(alternatives); }
    public Read(String instruction, int operation, int operand, int width, Choice choice, List<Alternative> alternatives) {
      this(instruction, operation, operand, width, choice, alternatives, null);
    }
  }
  public record Result(String version, List<Read> reads, List<Choice> choices) {
    public Result { reads = List.copyOf(reads); choices = List.copyOf(choices); }
  }

  private static void require(boolean condition, String message) {
    if (!condition) throw new IllegalArgumentException("Finite producer: " + message);
  }

  static OrdinaryEntryAccess.SourceByte source(Program p, MapperKnowledge state,
      Cartridge cartridge, int cpu, int byteIndex, int width, Address instruction,
      int operation, int operand) throws Exception {
    var access = ScalarAccess.resolve(cartridge, state, new ScalarAccess.Request(cpu,
        ScalarAccess.Kind.READ, width, byteIndex, instruction.toString(), operation, operand, null));
    var mapped = access.resolution().orElseThrow();
    require(mapped.physical() != null && mapped.physical().region().equals("ROM"),
        "read has unknown/non-ROM physical source at CPU " + Integer.toHexString(cpu));
    Address chosen = null;
    for (var address : ProgramMapping.physicalToStatic(p, mapped.physical())) {
      var block = p.getMemory().getBlock(address);
      if (block != null && block.isInitialized() && block.isRead() && !block.isWrite()
          && !block.isVolatile() && !block.getName().startsWith(OrdinaryEntryAccess.PREFIX)
          && !block.getName().startsWith(SoftwareCallExecutionView.PREFIX)
          && ProgramMapping.staticToPhysical(p, address).equals(List.of(mapped.physical()))) {
        chosen = address; break;
      }
    }
    require(chosen != null, "missing immutable physical byte " + mapped.physical());
    return new OrdinaryEntryAccess.SourceByte(access.request().byteIndex(), chosen.toString(), mapped.physical(),
        p.getMemory().getByte(chosen) & 255);
  }

  private static Read read(Program p, Cartridge cartridge, MapperKnowledge mapper, Choice selector,
      Address instruction, int operation, int operand, int width, Value pointer,
      Varnode pointerNode) throws Exception {
    require(width > 0 && width <= 8 && pointer.width() == 2 && pointer.values() != null
        && !pointer.values().isEmpty() && pointer.values().size() <= MAX_ALTERNATIVES,
        "unproved finite 16-bit read pointer or enumeration capacity exceeded at " + instruction);
    boolean indexed = pointer.values().size() > 1;
    Choice choice = selector;
    if (indexed) {
      require(width == 1 && pointerNode != null
          && (pointerNode.isRegister() || pointerNode.isUnique()),
          "finite pointer requires byte LOAD with register/unique source at " + instruction);
      choice = new Choice(Kind.CPU_POINTER, instruction.toString(), operation, 1, null,
          pointerNode.getAddress().getAddressSpace().getName(), pointerNode.getOffset(),
          pointerNode.getSize(), pointer.as(Role.CPU_POINTER).expression(), new ArrayList<>(pointer.values()), pointer.origin());
    }
    if (indexed && selector != null) {
      // Candidate mapping is a conservative cover, never claimed to be the reachable relation.
      require((long) selector.values().size() * pointer.values().size() <= AbstractValues.MAX_CANDIDATES,
          "joint physical candidate budget exhausted before construction");
      var candidates = new ArrayList<Candidate>();
      for (long bank : selector.values()) for (long cpu : pointer.values()) {
        var state = mapper.write(cartridge, selector.mapperCpu(), (int) bank);
        var octet = source(p, state, cartridge, (int) cpu, 0, 1, instruction, operation, operand);
        candidates.add(new Candidate(bank, cpu, List.of(octet), octet.value()));
      }
      var relation = AbstractValues.relation(List.of(selector.origin(), pointer.origin()));
      require(relation.complete(), "joint guard coverage unproved: " + relation.reason());
      var reachable = new ArrayList<Guarded>();
      for (var tuple : relation.reachable()) {
        var endpoint = candidates.stream().filter(c -> c.selector() == tuple.values().get(0)
            && c.pointer() == tuple.values().get(1)).findFirst().orElseThrow(
                () -> new IllegalArgumentException("Finite producer: joint guard escapes candidate cover"));
        reachable.add(new Guarded(endpoint, tuple.condition()));
      }
      require(!reachable.isEmpty(), "empty joint guard coverage");
      return new Read(instruction.toString(), operation, operand, width, choice, List.of(),
          new Joint(selector, choice, candidates, reachable, true, relation.reason()));
    }
    var alternatives = new ArrayList<Alternative>();
    for (long key : choice == null ? List.of(0L) : choice.values()) {
      int cpu = indexed ? (int) key : pointer.values().first().intValue();
      var state = selector == null ? mapper : mapper.write(cartridge, selector.mapperCpu(), (int) key);
      var sources = new ArrayList<OrdinaryEntryAccess.SourceByte>(); long value = 0;
      for (int b = 0; b < width; b++) {
        var octet = source(p, state, cartridge, (cpu + b) & 65535, b, width, instruction, operation, operand);
        sources.add(octet); value |= (long) octet.value() << (8 * b);
      }
      alternatives.add(new Alternative(key, sources, value));
    }
    // Pointer coverage survives equal bytes and physical aliases. Only a selector-independent
    // fixed-address read may discard a pending mapper choice.
    if (!indexed && alternatives.stream().allMatch(a -> a.sources().equals(alternatives.get(0).sources())))
      return new Read(instruction.toString(), operation, operand, width, null,
          List.of(new Alternative(0, alternatives.get(0).sources(), alternatives.get(0).value())));
    return new Read(instruction.toString(), operation, operand, width, choice, alternatives);
  }

  private static MapperKnowledge write(Cartridge cartridge, MapperKnowledge before,
      int cpu, Integer value, Address instruction, int operation, int width) {
    return ScalarAccess.resolve(cartridge, before, new ScalarAccess.Request(cpu,
        ScalarAccess.Kind.WRITE, width, 0, instruction.toString(), operation, 2, value))
        .after().orElseThrow();
  }

  private static Value readValue(Read read) {
    var rows = new ArrayList<AbstractValues.TableRow>();
    List<AbstractValues.Origin> inputs;
    if (read.joint() != null) {
      inputs = List.of(read.joint().selector().origin(), read.joint().pointer().origin());
      for (var guard : read.joint().reachable()) {
        var c = guard.endpoint();
        rows.add(new AbstractValues.TableRow(List.of(c.selector(), c.pointer()), c.value(), c.sources().toString()));
      }
    } else {
      inputs = read.choice() == null ? List.of() : List.of(read.choice().origin());
      for (var alternative : read.alternatives()) rows.add(new AbstractValues.TableRow(
          read.choice() == null ? List.of() : List.of(alternative.key()), alternative.value(), alternative.sources().toString()));
    }
    return AbstractValues.table(read.width(), inputs, rows, read.instruction() + ":" + read.operation());
  }

  /** No fixture identifiers, masks, banks or output constants enter this derivation. */
  public static Result derive(Program p, Function function, TaskMonitor monitor) throws Exception {
    require(function != null && function.getProgram() == p, "foreign Function");
    var body = function.getBody(); var entry = function.getEntryPoint();
    require(body.getNumAddressRanges() == 1 && body.getMinAddress().equals(entry)
        && entry.getAddressSpace().equals(p.getAddressFactory().getDefaultAddressSpace())
        && body.getMaxAddress().getOffset() < 0x4000 && body.getNumAddresses() <= 1024,
        "requires bounded canonical ROM0 body");
    var cartridge = ProgramMapping.cartridge(p);
    require(cartridge != null && cartridge.mapper() == Cartridge.Mapper.MBC5
        && cartridge.actualRomBanks() <= 256, "requires bounded MBC5 geometry");
    var storage = new AbstractValues.Storage(p.getUniqueProgramID() + ":" + entry); var reads = new ArrayList<Read>();
    var choices = new ArrayList<Choice>();
    MapperKnowledge mapper = MapperKnowledge.unknown(); Choice active = null;
    int operations = 0; Address at = entry; boolean returned = false;
    while (body.contains(at)) {
      monitor.checkCancelled(); var instruction = p.getListing().getInstructionAt(at);
      require(instruction != null && body.contains(instruction.getMaxAddress()), "missing instruction at " + at);
      require(InstructionInterpretation.architecturalUnresolved(instruction) == null
          && Arrays.toString(instruction.getPcode(false)).equals(Arrays.toString(instruction.getPcode(true))),
          "overridden instruction at " + at);
      var raw = instruction.getPcode(false); var bytes = instruction.getBytes();
      boolean terminal = bytes.length == 1 && (bytes[0] & 255) == 0xc9;
      require(!instruction.getFlowType().isCall() && !instruction.getFlowType().isJump()
          && (terminal || instruction.getFlowType().hasFallthrough()), "non-straight-line flow");
      storage.instruction(at.toString());
      for (int index = 0; index < raw.length; index++) {
        require(++operations <= MAX_OPERATIONS, "operation budget exhausted");
        var op = raw[index]; int code = op.getOpcode();
        require(code != PcodeOp.BRANCH && code != PcodeOp.CBRANCH && code != PcodeOp.BRANCHIND
            && code != PcodeOp.CALL && code != PcodeOp.CALLIND, "unsupported raw p-code flow");
        if (terminal) continue; // Existing ordinary entry domain owns symbolic stack and RETURN.
        var inputs = new ArrayList<Value>();
        for (int operand = 0; operand < op.getNumInputs(); operand++) {
          var node = op.getInput(operand);
          if (node.isAddress()) {
            var proof = read(p, cartridge, mapper, active, at, index, operand, node.getSize(),
                constant(node.getOffset(), 2), null);
            reads.add(proof); inputs.add(readValue(proof));
          } else inputs.add(storage.get(node));
        }
        if (code == PcodeOp.CALLOTHER) {
          require(CartridgeBus.isDirectWrite(p.getLanguage(), op) && op.getNumInputs() == 3
              && op.getInput(1).isConstant() && op.getInput(1).getSize() == 2,
              "unsupported userop/bus pointer");
          int cpu = (int) op.getInput(1).getOffset(); var value = inputs.get(2);
          if (cpu >= 0x2000 && cpu < 0x3000) {
            require(value.width() == 1 && value.values() != null
                && value.values().size() <= MAX_ALTERNATIVES,
                "selector is unknown/full-byte TOP or exceeds enumeration capacity at " + at + ":" + index);
            if (value.values().size() == 1) {
              mapper = write(cartridge, mapper, cpu, value.values().first().intValue(), at, index, value.width()); active = null;
            } else {
              var node = op.getInput(2);
              require(node.isRegister() || node.isUnique(), "selector snapshot requires register/unique source");
              active = new Choice(Kind.MAPPER_SELECTOR, at.toString(), index, 2, cpu, node.getAddress().getAddressSpace().getName(),
                  node.getOffset(), node.getSize(), value.as(Role.MAPPER_SELECTOR).expression(), new ArrayList<>(value.values()), value.origin());
              choices.add(active); mapper = write(cartridge, mapper, cpu, null, at, index, value.width());
            }
          } else {
            Integer known = value.values() != null && value.values().size() == 1
                ? value.values().first().intValue() : null;
            mapper = write(cartridge, mapper, cpu, known, at, index, value.width());
          }
        } else if (code == PcodeOp.LOAD) {
          require(op.getNumInputs() == 2 && op.getInput(0).isConstant()
              && op.getInput(0).getOffset() == p.getAddressFactory().getDefaultAddressSpace().getSpaceID(),
              "unsupported LOAD address space");
          var proof = read(p, cartridge, mapper, active, at, index, -1, op.getOutput().getSize(), inputs.get(1), op.getInput(1));
          reads.add(proof);
          if (proof.choice() != null && proof.choice().kind() == Kind.CPU_POINTER) choices.add(proof.choice());
          storage.put(op.getOutput(), readValue(proof));
        } else if (op.getOutput() != null) {
          storage.put(op.getOutput(), AbstractValues.evaluate(op.getOpcode(), op.getOutput().getSize(), inputs, at + ":" + index));
        }
      }
      if (terminal) {
        require(instruction.getMaxAddress().equals(body.getMaxAddress()), "body extends beyond RET");
        returned = true; break;
      }
      require(instruction.getFallThrough() != null && instruction.getFallThrough().equals(instruction.getMaxAddress().next()),
          "nonsequential fallthrough");
      at = instruction.getFallThrough();
    }
    require(returned, "missing terminal RET");
    return new Result(VERSION, reads, choices);
  }
}
