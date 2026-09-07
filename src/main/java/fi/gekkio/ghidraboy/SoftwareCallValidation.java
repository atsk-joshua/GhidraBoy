package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Read-only Program-backed validation of the finite effect templates; installs no interpretation. */
public final class SoftwareCallValidation {
  private SoftwareCallValidation() {}
  public static final String VERSION = "software-call-preview-3";

  /** Registers/mapper are explicit helper-entry premises, not facts inferred from a RAM shadow. */
  public record Configuration(int callCpu, SoftwareCallModel.Template template,
      SoftwareCallModel.EntryTransfer transfer, int callerSp,
      SoftwareCallModel.Registers registers, MapperState mapper) {
    public Configuration {
      Objects.requireNonNull(template); Objects.requireNonNull(transfer); Objects.requireNonNull(registers);
      if (callCpu < 0 || callCpu >= 0x8000) throw new IllegalArgumentException("Caller must be ROM");
      Objects.requireNonNull(mapper);
    }
  }

  public record Preview(String version, Configuration configuration, String dependencies,
      SoftwareCallModel.Frame frame) {
    public void requireCurrent(Program program, TaskMonitor monitor) throws Exception {
      Preview current = preview(program, configuration, monitor);
      if (!VERSION.equals(version) || !ProgramMapping.JSON.toJson(this).equals(ProgramMapping.JSON.toJson(current)))
        throw new IllegalArgumentException("Stale or incompatible software-call preview");
    }
  }

  public static Preview preview(Program program, Configuration config, TaskMonitor monitor) throws Exception {
    long beforeModification = program.getModificationNumber();
    String before = FarCallEvidence.capture(program, monitor);
    var cartridge = ProgramMapping.cartridge(program);
    if (cartridge == null) throw new IllegalArgumentException("Cartridge mapping required");
    var helper = cpu(program, config.template.helperCpu());
    byte[] body = HexFormat.of().parseHex(config.template.bodyHex());
    byte[] actual = new byte[body.length];
    program.getMemory().getBytes(helper, actual);
    config.template.validateBytes(actual);
    validateInstructions(program, helper, body.length, monitor);
    for (int offset = 0; offset < body.length; offset++) {
      requireFixed(program, helper.add(offset));
      if (!executionAddress(program, config.mapper, config.template.helperCpu() + offset).equals(helper.add(offset)))
        throw new IllegalArgumentException("Helper is not the physical fixed-ROM execution view");
      var instruction = program.getListing().getInstructionAt(helper.add(offset));
      if (instruction != null) {
        var conflict = InstructionInterpretation.architecturalUnresolved(instruction);
        if (conflict != null) throw new IllegalArgumentException("Conflicting helper interpretation: " + conflict);
      }
    }
    validateContext(program, helper, config);
    var site = executionAddress(program, config.mapper, config.callCpu);
    int length;
    switch (config.transfer) {
      case HARDWARE_CALL -> {
        length = 3;
        requireBytes(program, site, new byte[] {(byte) 0xcd, (byte) config.template.helperCpu(), (byte) (config.template.helperCpu() >>> 8)});
      }
      case HARDWARE_RST -> {
        length = 1;
        int vector = config.template.helperCpu();
        if (vector > 0x38 || vector % 8 != 0) throw new IllegalArgumentException("Hardware RST does not encode helper");
        requireBytes(program, site, new byte[] {(byte) (0xc7 | vector)});
      }
      case PUSHED_CONTINUATION -> {
        if (config.template.payloadLength() != 0) throw new IllegalArgumentException("Manual prefix cannot supply inline payload");
        // Exact supported prelude: LD BC,next; PUSH BC; JP helper. BC's entry premise must
        // agree with that architectural clobber. Other manual constructions remain unresolved.
        length = 7;
        int next = config.callCpu + length;
        if (config.registers.bc() != next) throw new IllegalArgumentException("Manual prefix BC effect disagrees with entry premise");
        requireBytes(program, site, new byte[] {1, (byte) next, (byte) (next >>> 8), (byte) 0xc5, (byte) 0xc3,
            (byte) config.template.helperCpu(), (byte) (config.template.helperCpu() >>> 8)});
      }
      default -> throw new IllegalArgumentException("Unsupported entry transfer");
    }
    validateInstructions(program, site, length, monitor);
    int encodedContinuation = config.callCpu + length;
    int continuation = encodedContinuation + config.template.payloadLength();
    if (continuation >= 0x8000 || config.callCpu / 0x4000 != continuation / 0x4000)
      throw new IllegalArgumentException("Payload/continuation crosses ROM CPU window");
    byte[] payload = new byte[config.template.payloadLength()];
    for (var segment : payloadSegments(program, config, monitor)) {
      var address = ProgramMapping.staticAddress(program, segment.address);
      SoftwareCallApplication.inspectPayload(program, address, segment.length, site, monitor);
      program.getMemory().getBytes(address, payload, segment.logicalOffset, segment.length);
    }
    // The actual return destination (including a known nonlocal exit) is checked by application
    // after callee derivation. The encoded continuation is a frame value, not a proved code edge.
    var frame = SoftwareCallModel.enter(cartridge, config.template, actual,
        new SoftwareCallModel.Entry(config.transfer, config.callerSp, encodedContinuation,
            config.registers, config.mapper, payload));
    var targetViews = ProgramMapping.physicalToStatic(program, frame.target()).stream()
        .filter(address -> address.getOffset() == frame.targetCpu() && SoftwareCallExecutionView.canonical(program, address)).toList();
    if (targetViews.size() != 1) throw new IllegalArgumentException("Ambiguous target execution view");
    rejectInterior(program, targetViews.get(0));
    String after = FarCallEvidence.capture(program, monitor);
    monitor.checkCancelled();
    if (beforeModification != program.getModificationNumber() || !before.equals(after))
      throw new IllegalArgumentException("Program changed during software-call preview");
    return new Preview(VERSION, config, before, frame);
  }

  /** A physical payload reservation; readLength distinguishes actual reads from skipped tail. */
  public record PayloadSegment(String address, int length, int logicalOffset, int readLength) {}

  public static List<PayloadSegment> payloadSegments(Program program, Configuration config,
      TaskMonitor monitor) throws Exception {
    int size = config.template.payloadLength();
    if (size == 0) return List.of();
    if (config.template.family() != SoftwareCallModel.Family.INLINE_RET)
      throw new IllegalArgumentException("Payload unsupported for helper family");
    int encoded = config.callCpu + (config.transfer == SoftwareCallModel.EntryTransfer.HARDWARE_CALL ? 3 : 1);
    if (encoded >= 0x8000 || encoded + size >= 0x8000 || encoded / 0x4000 != (encoded + size) / 0x4000)
      throw new IllegalArgumentException("Payload/continuation crosses ROM CPU window");
    var first = executionAddress(program, config.mapper, encoded);
    requireImmutableRom(program, first);
    int selector = program.getMemory().getByte(first) & 255;
    var selected = config.mapper.write(ProgramMapping.cartridge(program), 0x2000, selector);
    var remaining = executionAddress(program, selected, encoded + 1);
    for (int offset = 0; offset < size - 1; offset++) {
      monitor.checkCancelled();
      var physical = executionAddress(program, selected, encoded + 1 + offset);
      requireImmutableRom(program, physical);
      if (!physical.equals(remaining.add(offset)))
        throw new IllegalArgumentException("Payload range spans physical execution views");
    }
    if (first.add(1).equals(remaining))
      return List.of(new PayloadSegment(first.toString(), size, 0, 3));
    return List.of(new PayloadSegment(first.toString(), 1, 0, 1),
        new PayloadSegment(remaining.toString(), size - 1, 1, 2));
  }

  private static void requireImmutableRom(Program program, Address address) throws Exception {
    var identities = ProgramMapping.staticToPhysical(program, address);
    var block = program.getMemory().getBlock(address);
    if (identities.size() != 1 || !identities.get(0).region().equals("ROM") || block == null
        || block.isWrite() || block.isVolatile() || !block.isInitialized())
      throw new IllegalArgumentException("Payload requires immutable initialized physical ROM");
  }

  private static void validateContext(Program p, Address helper, Configuration config) {
    var expected = Map.of("A", config.registers.a(), "F", config.registers.f(),
        "BC", config.registers.bc(), "DE", config.registers.de(), "HL", config.registers.hl(),
        "SP", (config.callerSp - 2) & 0xffff);
    for (var entry : expected.entrySet()) {
      var register = p.getRegister(entry.getKey());
      if (register == null) throw new IllegalArgumentException("Missing SM83 register " + entry.getKey());
      var value = p.getProgramContext().getRegisterValue(register, helper);
      if (value != null && value.hasAnyValue()) {
        var mask = value.getValueMask();
        var actual = value.getUnsignedValueIgnoreMask();
        if (!actual.and(mask).equals(java.math.BigInteger.valueOf(entry.getValue()).and(mask)))
          throw new IllegalArgumentException("Entry premise contradicts Program context for " + entry.getKey());
      }
    }
  }

  private static void validateInstructions(Program p, Address start, int length, TaskMonitor monitor) throws Exception {
    int offset = 0;
    while (offset < length) {
      monitor.checkCancelled();
      var address = start.add(offset);
      var instruction = SoftwareCallInstructionDiscovery.instructionAt(p, address, "exact validated helper/caller bytes", monitor);
      if (instruction == null || offset + instruction.getLength() > length)
        throw new IllegalArgumentException("Missing or conflicting helper/caller instruction boundary at " + address);
      if (instruction.isLengthOverridden())
        throw new IllegalArgumentException("Overridden instruction length at " + address);
      // Exact bytes plus unmodified raw decoding establish this finite template. Generated
      // annotations (including a false CALL_RETURN pending reviewed repair) are not evidence.
      instruction.getPcode(false);
      for (int byteOffset = 0; byteOffset < instruction.getLength(); byteOffset++) {
        var identities = ProgramMapping.staticToPhysical(p, address.add(byteOffset));
        if (identities.size() != 1 || !identities.get(0).region().equals("ROM"))
          throw new IllegalArgumentException("Expected unique physical ROM at " + address);
      }
      offset += instruction.getLength();
    }
  }

  private static void requireFixed(Program p, Address address) throws Exception {
    var identity = ProgramMapping.staticToPhysical(p, address);
    var block = p.getMemory().getBlock(address);
    if (block == null || block.isWrite() || block.isVolatile() || !block.isInitialized()
        || address.getOffset() >= 0x4000 || identity.size() != 1
        || !identity.get(0).region().equals("ROM") || identity.get(0).bank() != 0)
      throw new IllegalArgumentException("Expected unique physical ROM0 at " + address);
  }

  private static void rejectInterior(Program p, Address address) {
    var instruction = p.getListing().getInstructionContaining(address);
    if ((instruction != null && !instruction.getAddress().equals(address))
        || p.getListing().getDefinedDataContaining(address) != null)
      throw new IllegalArgumentException("Target/continuation boundary conflict at " + address);
  }

  private static void requireBytes(Program p, Address address, byte[] expected) throws Exception {
    byte[] actual = new byte[expected.length];
    p.getMemory().getBytes(address, actual);
    if (!Arrays.equals(expected, actual)) throw new IllegalArgumentException("Caller bytes do not implement specified transfer");
  }

  public static Address executionAddress(Program p, MapperState mapper, int value) throws java.io.IOException {
    var physical = MapperState.translate(ProgramMapping.cartridge(p), mapper, value, false).physical();
    if (physical == null) throw new IllegalArgumentException("Unresolved execution identity");
    var addresses = ProgramMapping.physicalToStatic(p, physical).stream().filter(a -> a.getOffset() == value && SoftwareCallExecutionView.canonical(p, a)).toList();
    if (addresses.size() != 1) throw new IllegalArgumentException("Ambiguous execution view");
    return addresses.get(0);
  }

  private static Address cpu(Program p, int value) {
    return p.getAddressFactory().getDefaultAddressSpace().getAddress(value);
  }
}
