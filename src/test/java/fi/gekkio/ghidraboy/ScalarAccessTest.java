package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Differential parity is separate from the independent ordered-access expectations below. */
class ScalarAccessTest {
  private static Cartridge cartridge(int banks, int type, GameBoyKind hardware) {
    byte[] bytes = new byte[banks * 0x4000];
    bytes[0x147] = (byte) type;
    bytes[0x148] = (byte) Integer.numberOfTrailingZeros(banks / 2);
    bytes[0x149] = (byte) (type == 6 || type == 0 ? 0 : 3);
    return Cartridge.parse(bytes, "AUTO").withHardware(hardware);
  }

  private static ScalarAccess.Request request(Integer cpu, ScalarAccess.Kind kind, Integer value) {
    return new ScalarAccess.Request(cpu, kind, 1, 0, "0150", 2, 1, value);
  }

  @Test
  void differentialMappingAndTransitionParityRetainsLegacyStatusesAndReasons() {
    for (int type : new int[] {0, 3, 6, 0x10, 0x1b}) {
      var cart = cartridge(4, type, GameBoyKind.CGB);
      var exact = MapperKnowledge.from(MapperState.reset());
      for (var before : List.of(exact, MapperKnowledge.unknown(), exact.write(cart, 0x0000, 10))) {
        for (int cpu : new int[] {0, 0x2000, 0x2fff, 0x3000, 0x4000, 0x7fff, 0xa000,
            0xc100, 0xe100, 0xff4f, 0xff70, 0xffff}) {
          for (var kind : ScalarAccess.Kind.values()) {
            Integer value = kind == ScalarAccess.Kind.WRITE ? 2 : null;
            var req = request(cpu, kind, value);
            var actual = ScalarAccess.resolve(cart, before, req);
            assertSame(req, actual.request());
            assertEquals(before, actual.before());
            assertEquals(before.translate(cart, cpu, kind == ScalarAccess.Kind.WRITE), actual.resolution().orElseThrow());
            assertEquals(kind == ScalarAccess.Kind.WRITE ? before.write(cart, cpu, value) : before,
                actual.after().orElseThrow());
          }
        }
      }
    }
  }

  @Test
  void unknownPointerUnknownSelectorDisabledAndDeviceAreDifferentOutcomes() {
    var cart = cartridge(4, 0x1b, GameBoyKind.GB);
    var unknown = MapperKnowledge.unknown();
    var pointer = ScalarAccess.resolve(cart, unknown, request(null, ScalarAccess.Kind.READ, null));
    assertFalse(pointer.request().pointerKnown());
    assertTrue(pointer.resolution().isEmpty());
    assertEquals(unknown, pointer.after().orElseThrow());
    var bank = ScalarAccess.resolve(cart, unknown, request(0x6000, ScalarAccess.Kind.READ, null));
    assertTrue(bank.request().pointerKnown());
    assertEquals("unknown", bank.resolution().orElseThrow().status());
    assertEquals("Required mapper register is unknown", bank.resolution().orElseThrow().reason());
    assertNull(bank.resolution().orElseThrow().physical());
    var unknownWrite = ScalarAccess.resolve(cart, unknown, request(null, ScalarAccess.Kind.WRITE, 2));
    assertTrue(unknownWrite.after().isEmpty());
    assertTrue(unknownWrite.resolution().isEmpty());
    var exact = MapperKnowledge.from(MapperState.reset());
    var disabled = ScalarAccess.resolve(cart, exact, request(0xa000, ScalarAccess.Kind.READ, null)).resolution().orElseThrow();
    assertEquals("unmapped", disabled.status());
    assertEquals("RAM/RTC disabled", disabled.reason());
    assertNull(disabled.physical());
    var device = ScalarAccess.resolve(cart, exact, request(0x2000, ScalarAccess.Kind.WRITE, null));
    assertEquals("device", device.resolution().orElseThrow().status());
    assertNull(device.resolution().orElseThrow().physical());
    assertNull(device.after().orElseThrow().low());
    assertEquals(exact.high(), device.after().orElseThrow().high());
  }

  @Test
  void orderedLowThenHighControlsRetainIntermediatePhysicalIdentityAndCatchFinalStateMutant() {
    // Existing MBC5 2fff/3000 boundary: written high byte 12 means effective high bit 0.
    var cart = cartridge(512, 0x1b, GameBoyKind.GB);
    var initial = MapperKnowledge.from(new MapperState(0x44, 1, 0, 0, true, 0, 1, 0));
    var low = ScalarAccess.resolve(cart, initial, request(0x2fff, ScalarAccess.Kind.WRITE, 0x34));
    var firstRead = ScalarAccess.resolve(cart, low.after().orElseThrow(), request(0x4000, ScalarAccess.Kind.READ, null));
    var high = ScalarAccess.resolve(cart, firstRead.after().orElseThrow(), request(0x3000, ScalarAccess.Kind.WRITE, 0x12));
    var secondRead = ScalarAccess.resolve(cart, high.after().orElseThrow(), request(0x4000, ScalarAccess.Kind.READ, null));
    assertEquals(new MapperState.Physical("ROM", 0x134, 0), firstRead.resolution().orElseThrow().physical());
    assertEquals(new MapperState.Physical("ROM", 0x34, 0), secondRead.resolution().orElseThrow().physical());
    assertEquals(0x12, high.request().writtenValue());
    assertEquals(0, high.after().orElseThrow().high());
    assertEquals(low.after(), firstRead.after());
    assertEquals(firstRead.after().orElseThrow(), high.before());
    var wrongFirst = ScalarAccess.resolve(cart, high.after().orElseThrow(), firstRead.request());
    assertNotEquals(firstRead.resolution(), wrongFirst.resolution(), "Final-state-only resolution loses the first physical source");
    var highFirst = ScalarAccess.resolve(cart, initial, high.request());
    var wrongOrder = ScalarAccess.resolve(cart, highFirst.after().orElseThrow(), firstRead.request());
    assertNotEquals(firstRead.resolution(), wrongOrder.resolution(), "Reordered controls change the intermediate source");
  }

  @Test
  void alreadySequencedWordBytesPreserveWrapStateAndAccessProvenance() {
    var cart = cartridge(4, 0x1b, GameBoyKind.GB);
    var initial = MapperKnowledge.from(MapperState.reset().write(cart, 0, 10));
    var lowRequest = new ScalarAccess.Request(0xffff, ScalarAccess.Kind.WRITE, 2, 0, "0150", 3, -1, 0x34);
    var highRequest = new ScalarAccess.Request(0, ScalarAccess.Kind.WRITE, 2, 1, "0150", 3, -1, 0x12);
    var low = ScalarAccess.resolve(cart, initial, lowRequest);
    var high = ScalarAccess.resolve(cart, low.after().orElseThrow(), highRequest);
    assertEquals(initial, low.after().orElseThrow());
    assertEquals(low.after().orElseThrow(), high.before());
    assertFalse(high.after().orElseThrow().enabled());
    assertEquals(List.of(0xffff, 0), List.of(low.request().cpu(), high.request().cpu()));
    assertEquals(2, high.request().width());
    assertEquals(1, high.request().byteIndex());
    assertEquals("0150", high.request().source());
    assertEquals(3, high.request().operation());
    assertEquals(-1, high.request().operand());
    assertEquals(new MapperState.Physical("ROM", 0, 0),
        ScalarAccess.resolve(cart, high.after().orElseThrow(), request(0, ScalarAccess.Kind.READ, null)).resolution().orElseThrow().physical());
  }

  @Test
  void splitReadAliasesAndFetchIntentDoNotClaimByteValuesOrExecutableBacking() {
    var cart = cartridge(4, 0x1b, GameBoyKind.GB);
    var before = MapperKnowledge.from(MapperState.reset());
    var first = ScalarAccess.resolve(cart, before, new ScalarAccess.Request(0x7fff, ScalarAccess.Kind.READ, 2, 0, "0150", 0, -1, null));
    var second = ScalarAccess.resolve(cart, first.after().orElseThrow(), new ScalarAccess.Request(0x8000, ScalarAccess.Kind.READ, 2, 1, "0150", 0, -1, null));
    assertEquals(new MapperState.Physical("ROM", 1, 0x3fff), first.resolution().orElseThrow().physical());
    assertEquals(new MapperState.Physical("VRAM", 0, 0), second.resolution().orElseThrow().physical());
    var ram = ScalarAccess.resolve(cart, before, request(0xc100, ScalarAccess.Kind.READ, null));
    var echo = ScalarAccess.resolve(cart, before, request(0xe100, ScalarAccess.Kind.READ, null));
    var fetch = ScalarAccess.resolve(cart, before, request(0xc100, ScalarAccess.Kind.FETCH, null));
    assertEquals(ram.resolution(), echo.resolution());
    assertEquals(ram.resolution(), fetch.resolution());
    assertEquals(ScalarAccess.Kind.FETCH, fetch.request().kind());
    assertNull(fetch.request().writtenValue());
    assertEquals(before, fetch.after().orElseThrow());
    // This resolver has no Program or memory reader: mapped RAM carries no imported byte value,
    // and FETCH intent grants neither initialized/executable bytes nor a decoding proof.
  }
}
