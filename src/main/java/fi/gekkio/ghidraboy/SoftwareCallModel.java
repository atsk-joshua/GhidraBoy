package fi.gekkio.ghidraboy;

import java.util.*;

/**
 * Finite, versioned software-call templates. This is an effect contract, not an opcode evaluator,
 * recognizer based on symbols, or permission to install a flow override. Program callers must verify
 * the implementation, context, payload ownership and all consumed dependencies before using it.
 */
public final class SoftwareCallModel {
  private SoftwareCallModel() {}

  public static final String VERSION = "software-call-templates-3";

  public enum Family { INLINE_RET, REGISTER_JP, RESTORING_REGISTER_JP, CONSTANT_REGISTER_JP }
  public enum EntryTransfer { HARDWARE_CALL, HARDWARE_RST, PUSHED_CONTINUATION }
  public enum ReturnPolicy { NONRESTORING, RESTORING, CONSTANT }
  public enum Exit { MAY_RETURN, NONRETURNING, NONLOCAL, UNKNOWN }

  /** Every write is a real bus write; stack addresses and values are CPU quantities. */
  public sealed interface Event permits Write, Pop, Read, Transfer {}
  public record Write(int cpuAddress, int value, String purpose) implements Event {}
  public record Pop(int cpuAddress, int value, String purpose) implements Event {}
  public record Read(int cpuAddress, int value, String purpose, MapperState.Physical physical) implements Event {
    public Read(int cpuAddress, int value, String purpose) { this(cpuAddress, value, purpose, null); }
  }
  public record Transfer(String mechanism, int targetCpu, String purpose) implements Event {}
  public record Selector(int raw, int effectiveBank) {}
  public record Registers(int a, int f, int bc, int de, int hl) {
    public Registers {
      byteValue(a); byteValue(f); word(bc); word(de); word(hl);
      if ((f & 15) != 0) throw new IllegalArgumentException("Architectural F low bits must be zero");
    }
  }

  /** Immutable exact implementation at a fixed CPU location; no title/vector-based recognition. */
  public record Template(Family family, int helperCpu, int payloadLength, Integer constantRaw) {
    public Template {
      Objects.requireNonNull(family); word(helperCpu);
      if (helperCpu >= 0x3f00) throw new IllegalArgumentException("Helper must fit fixed ROM0");
      if (family == Family.INLINE_RET ? payloadLength < 3 || payloadLength > 16 : payloadLength != 0)
        throw new IllegalArgumentException("Unsupported payload length");
      if (family == Family.CONSTANT_REGISTER_JP) {
        if (constantRaw == null) throw new IllegalArgumentException("Constant selector required");
        byteValue(constantRaw);
      } else if (constantRaw != null) throw new IllegalArgumentException("Unexpected constant selector");
    }

    public ReturnPolicy returnPolicy() {
      return switch (family) {
        case RESTORING_REGISTER_JP -> ReturnPolicy.RESTORING;
        case CONSTANT_REGISTER_JP -> ReturnPolicy.CONSTANT;
        default -> ReturnPolicy.NONRESTORING;
      };
    }

    public int epilogueCpu() {
      return switch (family) {
        case RESTORING_REGISTER_JP -> helperCpu + 10;
        case CONSTANT_REGISTER_JP -> helperCpu + 8;
        default -> -1;
      };
    }

    public String bodyHex() {
      return switch (family) {
        case INLINE_RET -> "e12aea00205e235623" + "23".repeat(payloadLength - 3) + "e5d5c9";
        case REGISTER_JP -> "ea0020e9";
        case RESTORING_REGISTER_JP -> "f579ea002001" + little(epilogueCpu()) + "c5e9c178ea0020c9";
        case CONSTANT_REGISTER_JP -> "ea002001" + little(epilogueCpu()) + "c5e93e"
            + String.format("%02x", constantRaw) + "ea0020c9";
      };
    }

    public void validateBytes(byte[] actual) {
      if (!Arrays.equals(HexFormat.of().parseHex(bodyHex()), actual))
        throw new IllegalArgumentException("Helper implementation differs from " + VERSION);
    }
  }

  /** SP is before the real caller push. Registers and mapper describe helper entry. */
  public record Entry(EntryTransfer transfer, int callerSp, int encodedContinuation,
      Registers registers, MapperState mapper, byte[] payload) {
    public Entry {
      Objects.requireNonNull(transfer); Objects.requireNonNull(registers);
      word(callerSp); word(encodedContinuation); payload = payload.clone();
    }
    @Override public byte[] payload() { return payload.clone(); }
  }

  /** Target-entry frame and effects; no assertion that this target actually returns. */
  public record Frame(Template template, Entry entry, int targetCpu, MapperState.Physical target,
      int continuationCpu, MapperState.Physical continuation, int targetSp,
      Registers targetRegisters, MapperState targetMapper, Selector targetSelector,
      List<Write> writes, List<Pop> pops, List<Read> reads, List<Event> events, Map<Integer, Integer> stackBytes) {
    public Frame {
      writes = List.copyOf(writes); pops = List.copyOf(pops); reads = List.copyOf(reads); events = List.copyOf(events); stackBytes = Map.copyOf(stackBytes);
    }
  }

  /** A conditional result: only the MAY_RETURN path executes the wrapper's return epilogue. */
  public record Returned(Exit exit, Integer cpu, MapperState.Physical physical, Integer sp,
      Registers registers, MapperState mapper, List<Write> writes, List<Pop> pops, List<Event> events) {
    public Returned { writes = List.copyOf(writes); pops = List.copyOf(pops); events = List.copyOf(events); }
  }

  public static Frame enter(Cartridge cartridge, Template template, byte[] actualBody, Entry entry) {
    requireMbc3(cartridge);
    template.validateBytes(actualBody);
    if (entry.mapper == null) throw new IllegalArgumentException("Explicit mapper entry state required");
    if (entry.payload.length != template.payloadLength)
      throw new IllegalArgumentException("Payload length differs from validated template");
    if (template.family == Family.INLINE_RET && entry.transfer == EntryTransfer.PUSHED_CONTINUATION)
      throw new IllegalArgumentException("Inline template consumes a hardware return address");
    int continuation = (entry.encodedContinuation + template.payloadLength) & 0xffff;
    if (entry.encodedContinuation >= 0x8000 || continuation >= 0x8000
        || continuation < entry.encodedContinuation
        || entry.encodedContinuation / 0x4000 != continuation / 0x4000)
      throw new IllegalArgumentException("Continuation/payload must remain in one ROM CPU window");
    int depth = switch (template.family) {
      case RESTORING_REGISTER_JP -> 6;
      case REGISTER_JP -> 2;
      default -> 4;
    };
    if (!((entry.callerSp >= 0xc000 + depth && entry.callerSp <= 0xd000)
        || (entry.callerSp >= 0xff80 + depth && entry.callerSp <= 0xffff)))
      throw new IllegalArgumentException("Real frame must fit fixed WRAM0 or HRAM");
    var events = new ArrayList<Event>();
    var writes = new ArrayList<Write>();
    var pops = new ArrayList<Pop>();
    var stack = new HashMap<Integer, Integer>();
    var reads = new ArrayList<Read>();
    int sp = push(entry.callerSp, entry.encodedContinuation, "caller continuation", writes, events, stack);
    events.add(new Transfer(entry.transfer.name(), template.helperCpu, "enter helper"));
    var r = entry.registers;
    int raw = r.a, target = r.hl;
    if (template.family == Family.INLINE_RET) {
      add(pops, events, new Pop(sp, entry.encodedContinuation, "helper consumes inline pointer"));
      sp = (sp + 2) & 0xffff;
      add(reads, events, new Read(entry.encodedContinuation, entry.payload[0] & 255, "inline raw selector",
          MapperState.translate(cartridge, entry.mapper, entry.encodedContinuation, false).physical()));
      raw = entry.payload[0] & 255;
      target = (entry.payload[1] & 255) | ((entry.payload[2] & 255) << 8);
      add(writes, events, new Write(0x2000, raw, "target ROM selector"));
      add(reads, events, new Read(entry.encodedContinuation + 1, entry.payload[1] & 255, "inline target low",
          MapperState.translate(cartridge, entry.mapper.write(cartridge, 0x2000, raw), entry.encodedContinuation + 1, false).physical()));
      add(reads, events, new Read(entry.encodedContinuation + 2, entry.payload[2] & 255, "inline target high",
          MapperState.translate(cartridge, entry.mapper.write(cartridge, 0x2000, raw), entry.encodedContinuation + 2, false).physical()));
      sp = push(sp, continuation, "adjusted continuation", writes, events, stack);
      sp = push(sp, target, "RET target", writes, events, stack);
      add(pops, events, new Pop(sp, target, "RET transfer to callee"));
      sp = (sp + 2) & 0xffff;
      r = new Registers(raw, r.f, r.bc, target, continuation);
    } else if (template.family == Family.RESTORING_REGISTER_JP) {
      if ((r.a & 127) != entry.mapper.romLow())
        throw new IllegalArgumentException("Saved A selector is not proven to match entry mapper register");
      sp = push(sp, (r.a << 8) | r.f, "saved AF selector", writes, events, stack);
      raw = r.bc & 255;
      add(writes, events, new Write(0x2000, raw, "target ROM selector"));
      sp = push(sp, template.epilogueCpu(), "wrapper epilogue", writes, events, stack);
      r = new Registers(raw, r.f, template.epilogueCpu(), r.de, r.hl);
    } else if (template.family == Family.CONSTANT_REGISTER_JP) {
      add(writes, events, new Write(0x2000, raw, "target ROM selector"));
      sp = push(sp, template.epilogueCpu(), "wrapper epilogue", writes, events, stack);
      r = new Registers(r.a, r.f, template.epilogueCpu(), r.de, r.hl);
    }
    if (target < 0x4000 || target >= 0x8000)
      throw new IllegalArgumentException("Template target must be switchable ROM");
    var mapper = entry.mapper.write(cartridge, 0x2000, raw);
    if (template.family == Family.REGISTER_JP)
      add(writes, events, new Write(0x2000, raw, "target ROM selector"));
    var physical = MapperState.translate(cartridge, mapper, target, false).physical();
    if (physical == null) throw new IllegalArgumentException("Unresolved physical target");
    events.add(new Transfer(template.family == Family.INLINE_RET ? "RET" : "JP_HL", target, "enter callee"));
    return new Frame(template, entry, target, physical, continuation,
        MapperState.translate(cartridge, null, continuation, false).physical(), sp, r, mapper,
        new Selector(raw, physical.bank()), writes, pops, reads, events, stack);
  }

  /**
   * Apply the epilogue conditional on an independently established balanced callee RET. A null or
   * changed SP, nonlocal exit or nonreturn cannot fabricate a continuation. Unknown mapper state
   * stays unknown; a banked continuation requires a resolved physical mapper state. Caller
   * supplies callee output registers/state; this method never assumes a callee preserves them.
   */
  public static Returned returnFrom(Cartridge cartridge, Frame frame, Exit exit,
      Integer calleeSp, Registers results, MapperState calleeMapper, Map<Integer, Integer> calleeStack) {
    requireMbc3(cartridge); Objects.requireNonNull(exit);
    if (exit != Exit.MAY_RETURN)
      return new Returned(exit, null, null, null, null, null, List.of(), List.of(), List.of());
    if (calleeSp == null || calleeSp != frame.targetSp || results == null)
      throw new IllegalArgumentException("Balanced callee RET and register results required");
    if (calleeStack == null) throw new IllegalArgumentException("Callee stack contents required");
    for (int address = calleeSp; address < frame.entry.callerSp; address++) {
      if (!Objects.equals(frame.stackBytes.get(address), calleeStack.get(address)))
        throw new IllegalArgumentException("Callee changed or invalidated a live frame byte");
    }
    var events = new ArrayList<Event>();
    var writes = new ArrayList<Write>();
    var pops = new ArrayList<Pop>();
    int sp = calleeSp;
    int firstReturn = frame.template.epilogueCpu() < 0 ? frame.continuationCpu : frame.template.epilogueCpu();
    add(pops, events, new Pop(sp, firstReturn, "callee RET")); sp = (sp + 2) & 0xffff;
    events.add(new Transfer("RET", firstReturn, "callee return"));
    var mapper = calleeMapper;
    if (frame.template.returnPolicy() == ReturnPolicy.RESTORING) {
      int saved = (frame.entry.registers.a << 8) | frame.entry.registers.f;
      add(pops, events, new Pop(sp, saved, "POP BC restores saved selector, not callee F"));
      sp = (sp + 2) & 0xffff;
      results = new Registers(frame.entry.registers.a, results.f, saved, results.de, results.hl);
    } else if (frame.template.returnPolicy() == ReturnPolicy.CONSTANT) {
      results = new Registers(frame.template.constantRaw, results.f, results.bc, results.de, results.hl);
    }
    if (frame.template.returnPolicy() != ReturnPolicy.NONRESTORING) {
      // Unknown unrelated mapper registers stay unknown; no reset state is substituted.
      mapper = mapper == null ? null : mapper.write(cartridge, 0x2000, results.a);
      add(writes, events, new Write(0x2000, results.a, "return ROM selector"));
      add(pops, events, new Pop(sp, frame.continuationCpu, "wrapper RET")); sp = (sp + 2) & 0xffff;
      events.add(new Transfer("RET", frame.continuationCpu, "wrapper return"));
    }
    return new Returned(exit, frame.continuationCpu,
        MapperState.translate(cartridge, mapper, frame.continuationCpu, false).physical(),
        sp, results, mapper, writes, pops, events);
  }

  private static int push(int sp, int value, String purpose, List<Write> writes, List<Event> events, Map<Integer, Integer> bytes) {
    sp = (sp - 1) & 0xffff; add(writes, events, new Write(sp, value >>> 8, purpose + " high")); bytes.put(sp, value >>> 8);
    sp = (sp - 1) & 0xffff; add(writes, events, new Write(sp, value & 255, purpose + " low")); bytes.put(sp, value & 255);
    return sp;
  }
  private static <T extends Event> void add(List<T> typed, List<Event> events, T event) {
    typed.add(event); events.add(event);
  }
  private static void requireMbc3(Cartridge c) {
    if (c.mapper() != Cartridge.Mapper.MBC3) throw new IllegalArgumentException("Reviewed templates require ordinary MBC3");
  }
  private static String little(int value) { return String.format("%02x%02x", value & 255, value >>> 8); }
  private static void byteValue(int value) { if (value < 0 || value > 255) throw new IllegalArgumentException("Byte out of range"); }
  private static void word(int value) { if (value < 0 || value > 65535) throw new IllegalArgumentException("CPU word out of range"); }
}
