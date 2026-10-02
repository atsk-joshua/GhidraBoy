package fi.gekkio.ghidraboy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Transient synchronous control facts. No button, IF, IME, DIV or timing values. */
record ControlRegisterFacts(Boolean cgb, Boolean doubleSpeed, Boolean armed,
    AbstractValues.PartialBits ie, AbstractValues.PartialBits joyp) {
  static ControlRegisterFacts unknown() {
    return new ControlRegisterFacts(null, null, null, FlagBitState.unknown(), FlagBitState.unknown());
  }

  ControlRegisterFacts onHardware(Cartridge cartridge) {
    // A conservative execution-state fallback cannot turn a GB hardware premise into CGB.
    return cartridge.hardwareKnown() && !cartridge.color()
        ? new ControlRegisterFacts(false, null, null, ie, joyp) : this;
  }

  AbstractValues.PartialBits key1() {
    if (Boolean.FALSE.equals(cgb)) return FlagBitState.exact(255L, 1);
    if (cgb == null) return FlagBitState.unknown();
    return new AbstractValues.PartialBits((doubleSpeed == null ? 0 : 128) | (armed == null ? 0 : 1),
        (Boolean.TRUE.equals(doubleSpeed) ? 128 : 0) | (Boolean.TRUE.equals(armed) ? 1 : 0));
  }

  // Disjoint hardware alternatives, never a global selection of an unknown speed.
  List<ControlRegisterFacts> readAlternatives() { return readAlternatives(128); }

  List<ControlRegisterFacts> readAlternatives(int testedMask) {
    var result = new ArrayList<ControlRegisterFacts>();
    if (!Boolean.TRUE.equals(cgb)) result.add(new ControlRegisterFacts(false, null, null, ie, joyp));
    if (!Boolean.FALSE.equals(cgb)) {
      var speeds = doubleSpeed == null && (testedMask & 128) != 0 ? List.of(false, true) : Arrays.asList(doubleSpeed);
      var arms = armed == null && (testedMask & 1) != 0 ? List.of(false, true) : Arrays.asList(armed);
      for (var speed : speeds) for (var arm : arms)
        result.add(new ControlRegisterFacts(true, speed, arm, ie, joyp));
    }
    return List.copyOf(result);
  }

  ControlRegisterFacts write(int cpu, AbstractValues.PartialBits bits) {
    return switch (cpu) {
      case 0xff4d -> new ControlRegisterFacts(cgb, doubleSpeed,
          Boolean.FALSE.equals(cgb) || (bits.knownMask() & 1) == 0 ? null : (bits.knownValue() & 1) != 0, ie, joyp);
      case 0xffff -> new ControlRegisterFacts(cgb, doubleSpeed, armed, bits, joyp);
      case 0xff00 -> new ControlRegisterFacts(cgb, doubleSpeed, armed, ie,
          new AbstractValues.PartialBits(bits.knownMask() & 0x30, bits.knownValue() & 0x30));
      default -> this;
    };
  }

  boolean canSwitch() {
    return Boolean.TRUE.equals(cgb) && doubleSpeed != null && Boolean.TRUE.equals(armed)
        && (ie.knownMask() & 255) == 255 && ie.knownValue() == 0
        && (joyp.knownMask() & 0x30) == 0x30 && (joyp.knownValue() & 0x30) == 0x30;
  }

  ControlRegisterFacts switched() {
    if (!canSwitch()) throw new IllegalStateException("Unproved speed switch");
    return new ControlRegisterFacts(true, !doubleSpeed, false, ie, joyp);
  }

  static ControlRegisterFacts meet(ControlRegisterFacts a, ControlRegisterFacts b) {
    return new ControlRegisterFacts(Objects.equals(a.cgb, b.cgb) ? a.cgb : null,
        Objects.equals(a.doubleSpeed, b.doubleSpeed) ? a.doubleSpeed : null,
        Objects.equals(a.armed, b.armed) ? a.armed : null,
        FlagBitState.meet(a.ie, b.ie), FlagBitState.meet(a.joyp, b.joyp));
  }
}
