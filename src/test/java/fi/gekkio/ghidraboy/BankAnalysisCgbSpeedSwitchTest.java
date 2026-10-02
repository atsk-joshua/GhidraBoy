package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/** Source-authored control premises; no execution state or private game bytes are seeded. */
class BankAnalysisCgbSpeedSwitchTest extends IntegrationTest {
  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("Synchronous CGB control fixture", getLanguage(),
        getLanguage().getDefaultCompilerSpec(), owner);
    final int call;
    final int continuation;

    Fixture(String hardware, String setup, String body) throws Exception {
      // Establish device writes before the frame: JOYP/IE retain their existing memory policy.
      String caller = setup + "3e5aea00c13e6be0803100d0cd0003"
          + "0802c1fa00c1ea04c1f080ea05c176";
      call = 0x150 + setup.length() / 2 + 12;
      continuation = call + 3;
      byte[] bytes = new byte[0x10000];
      bytes[0x143] = (byte) 0x80; // Capability header cannot substitute for hardware selection.
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      byte[] main = HexFormat.of().parseHex(caller);
      byte[] callee = HexFormat.of().parseHex(body);
      System.arraycopy(main, 0, bytes, 0x150, main.length);
      System.arraycopy(callee, 0, bytes, 0x300, callee.length);
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.CGB,
            true, true, TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("Define generic control flow and hardware premise");
      try {
        var cartridge = ProgramMapping.cartridge(p).withHardwareChoice(hardware);
        p.getOptions(ProgramMapping.OPTIONS).setString("cartridge", ProgramMapping.JSON.toJson(cartridge));
        define("0150", main.length);
        define("0300", callee.length);
      } finally { p.endTransaction(tx, true); }
    }

    void define(String address, int length) throws Exception {
      var at = ProgramMapping.staticAddress(p, address);
      Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(at,
          new AddressSet(at, at.add(length - 1)));
    }

    BankAnalysis.FetchPreview preview(boolean reverse) throws Exception {
      return BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
          new AnalysisResult.Configuration(4096, reverse), TaskMonitor.DUMMY);
    }

    @Override public void close() { p.release(owner); }
  }

  private static final String SETUP = "3e00e0ff3e30e000";
  // Unknown speed branches either to a direct RET or to an independently refined switch.
  // Post-STOP BIT checks reject the wrong toggled speed or an uncleared arm via unsupported HALT.
  private static String switching(boolean doubleToNormal) {
    if (doubleToNormal) {
      // First prove active CGB by bit7-clear, switch to double, then rearm and switch back.
      return "214dffcb7e201acbc61000cb7e2811cb46200dcbc61000cb7e2005cb462001c976c9";
    }
    return "214dffcb7e200ecbc61000cb7e2805cb462001c976c9";
  }

  private static List<Integer> valuesAt(BankAnalysis.FetchPreview preview, int cpu) {
    return preview.steps().stream().flatMap(s -> s.writes().stream())
        .filter(w -> w.cpu() == cpu).map(BankAnalysis.WriteTransition::value).toList();
  }

  static List<Boolean> speeds() { return List.of(false, true); }

  @ParameterizedTest @MethodSource("speeds")
  void bothSpeedsToggleAndClearArmWithoutChangingFrameMemoryOrMapper(boolean doubleToNormal) throws Exception {
    try (var f = new Fixture("CGB", SETUP, switching(doubleToNormal))) {
      BankAnalysis.FetchPreview previous = null;
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        assertEquals(1, preview.result().ordinaryCallProofs().size(), preview.result().findings().toString());
        var proof = preview.result().ordinaryCallProofs().get(0);
        assertEquals(String.format("%04X", f.call), proof.source());
        assertTrue(preview.steps().stream().anyMatch(s -> s.cpu() == 0x30b));
        assertFalse(preview.steps().stream().anyMatch(s -> s.cpu() == 0x30a),
            "STOP's second byte is consumed, not visited as NOP");
        assertFalse(preview.steps().stream().anyMatch(s -> s.cpu() == (doubleToNormal ? 0x320 : 0x314)),
            "Neither opposite speed nor uncleared arm reaches refusal marker");
        if (doubleToNormal) {
          assertTrue(preview.steps().stream().anyMatch(s -> s.cpu() == 0x317));
          assertFalse(preview.steps().stream().anyMatch(s -> s.cpu() == 0x316));
        }
        var stop = preview.steps().stream().filter(s -> s.cpu() == 0x309).findFirst().orElseThrow();
        assertEquals(stop.incoming(), stop.outgoing(), "Speed never changes physical storage selectors");
        assertTrue(stop.writes().isEmpty(), "Hardware switch creates no software timer or interrupt writes");
        assertEquals(List.of(0x00), valuesAt(preview, 0xc102));
        assertEquals(List.of(0xd0), valuesAt(preview, 0xc103));
        assertEquals(List.of(0x5a), valuesAt(preview, 0xc104));
        assertEquals(List.of(0x6b), valuesAt(preview, 0xc105));
        assertTrue(valuesAt(preview, 0xcfff).contains(f.continuation >>> 8));
        assertTrue(valuesAt(preview, 0xcffe).contains(f.continuation & 255));
        if (previous != null) {
          assertEquals(previous.result().ordinaryCallProofs(), preview.result().ordinaryCallProofs());
          assertEquals(previous.result().findings(), preview.result().findings());
          assertEquals(previous.steps().stream().map(BankAnalysis.FetchStep::cpu).collect(java.util.stream.Collectors.toSet()),
              preview.steps().stream().map(BankAnalysis.FetchStep::cpu).collect(java.util.stream.Collectors.toSet()));
        }
        previous = preview;
      }
    }
  }

  record Refusal(String name, String hardware, String setup, String body) {
    @Override public String toString() { return name; }
  }

  static List<Refusal> refusals() {
    String normal = switching(false);
    return List.of(
        new Refusal("unknown arm", "CGB", SETUP, normal.replace("cbc6", "0000")),
        new Refusal("unarmed", "CGB", SETUP, normal.replace("cbc6", "cb86")),
        new Refusal("unknown write weakens arm", "CGB", SETUP,
            "214dffcb7e200acbc6fa00c2771000c976c9"),
        new Refusal("unknown speed", "CGB", SETUP, "214dffcbc61000c9"),
        new Refusal("unknown hardware direct STOP", "UNKNOWN", SETUP, "214dffcbc61000c9"),
        new Refusal("non-CGB direct STOP", "GB", SETUP, "214dffcbc61000c9"),
        new Refusal("enabled interrupt with unresolved IF", "CGB", "3e01e0ff3e30e000", normal),
        new Refusal("unknown IE", "CGB", "3e30e000", normal),
        new Refusal("selected input group", "CGB", "3e00e0ff3e20e000", normal),
        new Refusal("unknown JOYP", "CGB", "3e00e0ff", normal),
        new Refusal("noncanonical second STOP byte", "CGB", SETUP, normal.replace("1000", "1001")),
        new Refusal("unsupported HALT", "CGB", SETUP, normal.replace("1000", "7600")));
  }

  @ParameterizedTest(name = "{0}") @MethodSource("refusals")
  void unresolvedOrDifferentStopModesDoNotAuthorizeReturningCall(Refusal refusal) throws Exception {
    try (var f = new Fixture(refusal.hardware, refusal.setup, refusal.body)) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        assertTrue(preview.result().ordinaryCallProofs().isEmpty(), refusal.name + ": " + preview.result().findings());
        assertTrue(preview.result().findings().stream().anyMatch(finding ->
            finding.source().equals(String.format("%04X", f.call)) && finding.access().equals("flow")
                && finding.reason().contains("no complete matched-return proof")));
        assertTrue(valuesAt(preview, 0xc102).stream().allMatch(Objects::isNull),
            "Incumbent fallback continuation retains unknown SP");
        assertTrue(valuesAt(preview, 0xc104).stream().allMatch(Objects::isNull),
            "Fallback cannot retain the callee's ordinary memory authority");
      }
    }
  }

  @Test void nonCgbKey1ReadCannotTakeBitSevenClearPathDespiteColorCapableHeader() throws Exception {
    try (var f = new Fixture("GB", SETUP, switching(false))) {
      var preview = f.preview(false);
      assertEquals(1, preview.result().ordinaryCallProofs().size());
      assertFalse(preview.steps().stream().anyMatch(s -> s.cpu() == 0x307));
      assertFalse(preview.steps().stream().anyMatch(s -> s.cpu() == 0x309));
      assertTrue(preview.steps().stream().anyMatch(s -> s.cpu() == 0x315));
    }
  }

  @Test void softwareSpeedBitWriteDoesNotResolveUnknownReadOnlySpeed() throws Exception {
    try (var f = new Fixture("CGB", SETUP, "3e81e04d1000c9")) {
      assertTrue(f.preview(false).result().ordinaryCallProofs().isEmpty());
    }
  }

  @Test void bitZeroRefinesBothArmPathsWithoutSeedingOrInventingSpeed() throws Exception {
    String body = "214dffcb7e2012cb462002cbc61000cb7e2805cb462001c976c9";
    try (var f = new Fixture("CGB", SETUP, body)) {
      var forward = f.preview(false);
      var reverse = f.preview(true);
      assertEquals(1, forward.result().ordinaryCallProofs().size(), forward.result().findings().toString());
      assertEquals(forward.result().ordinaryCallProofs(), reverse.result().ordinaryCallProofs());
      assertEquals(forward.result().findings(), reverse.result().findings());
      assertTrue(forward.steps().stream().anyMatch(s -> s.cpu() == 0x30b));
      assertTrue(forward.steps().stream().anyMatch(s -> s.cpu() == 0x30d));
      assertFalse(forward.steps().stream().anyMatch(s -> s.cpu() == 0x318));
      assertEquals(List.of(0xd0), valuesAt(forward, 0xc103));
    }
  }

  record GuardedWrite(int cpu, Integer value, boolean preserves) {
    @Override public String toString() { return String.format("%04X <- %s preserves=%s", cpu, value, preserves); }
  }
  static List<GuardedWrite> guardedWrites() {
    return List.of(new GuardedWrite(0xff0f, 0, true), new GuardedWrite(0xffff, 0, true),
        new GuardedWrite(0xff00, 0x30, true), new GuardedWrite(0xff4d, 1, true),
        new GuardedWrite(0xff4d, null, true), new GuardedWrite(0xff0f, 1, false),
        new GuardedWrite(0xff0f, null, false), new GuardedWrite(0xffff, 1, false),
        new GuardedWrite(0xffff, null, false), new GuardedWrite(0xff00, 0x20, false),
        new GuardedWrite(0xff00, null, false), new GuardedWrite(0xff46, 0, false),
        new GuardedWrite(0xff55, 0, false));
  }

  @ParameterizedTest(name = "{0}") @MethodSource("guardedWrites")
  void guardedControlWritesAfterFramePreserveOnlyQualifiedOrdinaryMemory(GuardedWrite write) throws Exception {
    String value = write.value == null ? "fa00c2" : String.format("3e%02x", write.value);
    try (var f = new Fixture("CGB", SETUP, value + String.format("e0%02xc9", write.cpu & 255))) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        assertEquals(write.preserves ? 1 : 0, preview.result().ordinaryCallProofs().size(),
            preview.result().findings().toString());
        assertFalse(valuesAt(preview, 0xc102).isEmpty());
        if (write.preserves) {
          assertEquals(List.of(0), valuesAt(preview, 0xc102));
          assertEquals(List.of(0xd0), valuesAt(preview, 0xc103));
          assertEquals(List.of(0x5a), valuesAt(preview, 0xc104));
          assertEquals(List.of(0x6b), valuesAt(preview, 0xc105));
        } else {
          assertTrue(valuesAt(preview, 0xc102).stream().allMatch(Objects::isNull));
          assertTrue(valuesAt(preview, 0xc104).stream().allMatch(Objects::isNull));
        }
      }
    }
  }

  record Key1(Boolean speed, Boolean arm, long mask, long value) {}
  static List<Key1> key1Matrix() {
    return List.of(new Key1(false, false, 0x81, 0), new Key1(false, true, 0x81, 1),
        new Key1(true, false, 0x81, 0x80), new Key1(true, true, 0x81, 0x81),
        new Key1(null, false, 1, 0), new Key1(null, true, 1, 1),
        new Key1(false, null, 0x80, 0), new Key1(true, null, 0x80, 0x80),
        new Key1(null, null, 0, 0));
  }

  @ParameterizedTest @MethodSource("key1Matrix")
  void key1ArchitecturalMatrixExposesOnlyProvedBits(Key1 row) {
    var controls = new ControlRegisterFacts(true, row.speed, row.arm,
        FlagBitState.unknown(), FlagBitState.unknown());
    assertEquals(new AbstractValues.PartialBits(row.mask, row.value), controls.key1());
    assertEquals(0, controls.key1().knownMask() & 0x7e, "Reserved bits remain unknown");
  }

  @Test void nonCgbAndUnknownModeReadRelationsRemainDistinct() {
    var gb = new ControlRegisterFacts(false, null, null, FlagBitState.unknown(), FlagBitState.unknown());
    assertEquals(new AbstractValues.PartialBits(255, 255), gb.key1());
    var unknown = ControlRegisterFacts.unknown();
    assertEquals(new AbstractValues.PartialBits(0, 0), unknown.key1());
    var alternatives = unknown.readAlternatives();
    assertEquals(3, alternatives.size());
    assertEquals(1, alternatives.stream().filter(c -> (c.key1().knownValue() & 128) == 0).count());
    var normal = alternatives.stream().filter(c -> (c.key1().knownValue() & 128) == 0).findFirst().orElseThrow();
    assertEquals(Boolean.TRUE, normal.cgb());
    assertEquals(Boolean.FALSE, normal.doubleSpeed());
    assertNull(normal.armed());
    assertNull(unknown.cgb());
    assertNull(unknown.doubleSpeed(), "Read refinement never overwrites the sibling or original relation");
    var arms = unknown.readAlternatives(1);
    assertEquals(3, arms.size());
    assertTrue(arms.stream().allMatch(c -> c.doubleSpeed() == null),
        "Testing arm does not invent current speed");
    assertEquals(1, arms.stream().filter(c -> Boolean.FALSE.equals(c.armed())).count());
    var readModifyWrite = unknown.readAlternatives(0);
    assertEquals(2, readModifyWrite.size());
    assertTrue(readModifyWrite.stream().allMatch(c -> c.doubleSpeed() == null && c.armed() == null),
        "An untested read preserves both unknown control bits");
  }

  @Test void key1WritableBitUpdatesNeverModifyReadOnlySpeedOrInventReservedBits() {
    for (Boolean speed : Arrays.asList(false, true, null)) {
      var controls = new ControlRegisterFacts(true, speed, null, FlagBitState.unknown(), FlagBitState.unknown());
      var armed = controls.write(0xff4d, new AbstractValues.PartialBits(1, 1));
      assertEquals(Boolean.TRUE, armed.armed());
      assertEquals(speed, armed.doubleSpeed());
      assertEquals(Boolean.FALSE, armed.write(0xff4d, new AbstractValues.PartialBits(1, 0)).armed());
      var unknown = armed.write(0xff4d, FlagBitState.unknown());
      assertNull(unknown.armed());
      assertEquals(speed, unknown.doubleSpeed());
      var attempted = armed.write(0xff4d, FlagBitState.exact(0x81L, 1));
      assertEquals(speed, attempted.doubleSpeed());
      assertEquals(0, attempted.key1().knownMask() & 0x7e);
    }
  }

  @Test void gbHardwarePremiseSurvivesUnknownExecutionFallback() throws Exception {
    try (var fixture = new Fixture("GB", SETUP, "c9")) {
      var controls = ControlRegisterFacts.unknown().onHardware(ProgramMapping.cartridge(fixture.p));
      assertEquals(Boolean.FALSE, controls.cgb());
      assertEquals(new AbstractValues.PartialBits(255, 255), controls.key1());
      assertEquals(1, controls.readAlternatives(0x81).size());
      assertFalse(controls.write(0xff4d, FlagBitState.exact(1L, 1))
          .write(0xffff, FlagBitState.exact(0L, 1)).write(0xff00, FlagBitState.exact(0x30L, 1)).canSwitch());
    }
  }

  @Test void synchronousSwitchRequiresEveryControlPremiseAndRetainsOnlyConsumedFacts() {
    for (boolean speed : List.of(false, true)) {
      var eligible = new ControlRegisterFacts(true, speed, true,
          FlagBitState.exact(0L, 1), new AbstractValues.PartialBits(0x30, 0x30));
      assertTrue(eligible.canSwitch());
      var switched = eligible.switched();
      assertEquals(!speed, switched.doubleSpeed());
      assertEquals(Boolean.FALSE, switched.armed());
      assertEquals(eligible.ie(), switched.ie());
      assertEquals(eligible.joyp(), switched.joyp());
      for (var refused : List.of(
          new ControlRegisterFacts(null, speed, true, eligible.ie(), eligible.joyp()),
          new ControlRegisterFacts(false, speed, true, eligible.ie(), eligible.joyp()),
          new ControlRegisterFacts(true, null, true, eligible.ie(), eligible.joyp()),
          new ControlRegisterFacts(true, speed, null, eligible.ie(), eligible.joyp()),
          new ControlRegisterFacts(true, speed, false, eligible.ie(), eligible.joyp()),
          eligible.write(0xffff, FlagBitState.unknown()),
          eligible.write(0xffff, FlagBitState.exact(1L, 1)),
          eligible.write(0xff00, FlagBitState.unknown()),
          eligible.write(0xff00, FlagBitState.exact(0x20L, 1)))) {
        assertFalse(refused.canSwitch());
        assertThrows(IllegalStateException.class, refused::switched);
      }
      assertEquals(eligible, eligible.write(0xff04, FlagBitState.exact(0x55L, 1)),
          "DIV and timer values are not part of this transient relation");
      assertEquals(eligible, eligible.write(0xff0f, FlagBitState.exact(0L, 1)),
          "No exact IF or asynchronous interrupt state is created");
    }
  }
}
