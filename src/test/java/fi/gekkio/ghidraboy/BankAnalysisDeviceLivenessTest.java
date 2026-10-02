package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/** Finite 2E ordinary-memory contract; no device-value or hardware-state oracle is implied. */
class BankAnalysisDeviceLivenessTest extends IntegrationTest {
  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("Qualified local device fixture", getLanguage(),
        getLanguage().getDefaultCompilerSpec(), owner);

    Fixture(String caller, String callee) throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      byte[] main = HexFormat.of().parseHex(caller);
      byte[] body = HexFormat.of().parseHex(callee);
      System.arraycopy(main, 0, bytes, 0x150, main.length);
      System.arraycopy(body, 0, bytes, 0x300, body.length);
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.CGB, true, true,
            TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("Define self-authored ordinary call");
      try {
        define("0150", main.length);
        define("0300", body.length);
      } finally { p.endTransaction(tx, true); }
    }
    void define(String at, int length) throws Exception {
      var first = ProgramMapping.staticAddress(p, at);
      Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first,
          new AddressSet(first, first.add(length - 1)));
    }
    BankAnalysis.FetchPreview preview(boolean reverse) throws Exception {
      return BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
          new AnalysisResult.Configuration(4096, reverse), TaskMonitor.DUMMY);
    }
    @Override public void close() { p.release(owner); }
  }

  record Device(int cpu, Long value) {
    @Override public String toString() { return String.format("%04X <- %s", cpu, value); }
  }
  static List<Device> devices() {
    var cases = new ArrayList<Device>();
    for (int cpu : List.of(0xff26, 0xff40, 0xff42, 0xff43, 0xff4a, 0xff4b)) {
      cases.add(new Device(cpu, null));
      cases.add(new Device(cpu, 2L));
    }
    for (Long value : Arrays.asList(0L, 0xffL, 0x77L, null)) cases.add(new Device(0xff24, value));
    // LCDC: bit 7 unchanged, disabling, enabling, and other control bits changing.
    for (long value : List.of(0x91L, 0L, 0x80L, 0x93L)) cases.add(new Device(0xff40, value));
    for (long value : List.of(0L, 0x80L)) cases.add(new Device(0xff26, value));
    return cases;
  }
  private static MapperKnowledge write(Fixture f, SymbolicMemory.State memory,
      MapperKnowledge mapper, int cpu, int width, Long value) throws Exception {
    return write(f, memory, mapper, cpu, width, value, new ArrayList<>());
  }
  private static MapperKnowledge write(Fixture f, SymbolicMemory.State memory,
      MapperKnowledge mapper, int cpu, int width, Long value,
      List<BankAnalysis.WriteTransition> writes) throws Exception {
    var method = Arrays.stream(BankAnalysis.class.getDeclaredMethods())
        .filter(m -> m.getName().equals("writeAccess")).findFirst().orElseThrow();
    method.setAccessible(true);
    return (MapperKnowledge) method.invoke(null, f.p, ProgramMapping.cartridge(f.p), mapper,
        cpu, width, value, ProgramMapping.staticAddress(f.p, "0150"), 0,
        new HashMap<>(), new HashMap<>(), writes, memory);
  }
  private static SymbolicMemory.State frame(Fixture f, MapperKnowledge mapper) throws Exception {
    var memory = SymbolicMemory.State.ordinary(Map.of());
    write(f, memory, mapper, 0xfffe, 1, 1L);
    write(f, memory, mapper, 0xfffd, 1, 0x56L);
    write(f, memory, mapper, 0xc123, 1, 0x5aL);
    assertEquals(Set.of(new MapperState.Physical("HRAM", 0, 0x7d),
        new MapperState.Physical("HRAM", 0, 0x7e), new MapperState.Physical("WRAM", 0, 0x123)), memory.snapshot().keySet());
    return memory;
  }
  private static List<BankAnalysis.WriteTransition> writes(BankAnalysis.FetchPreview preview, int cpu) {
    return preview.steps().stream().filter(s -> s.cpu() == cpu).flatMap(s -> s.writes().stream()).toList();
  }

  @ParameterizedTest(name = "{0}") @MethodSource("devices")
  void ordinaryBytesAndActualReturnSurviveWithoutDeviceFacts(Device device) throws Exception {
    String effect = (device.value == null ? "" : String.format("3e%02x", device.value))
        + String.format("e0%02x", device.cpu & 255);
    // Continuation stores restored SP; callee stores frame SP immediately before real RET.
    try (var f = new Fixture("31ffffcd00030802c176", effect + "0800c1c9")) {
      var mapper = MapperKnowledge.from(MapperState.reset());
      var memory = frame(f, mapper);
      var before = memory.snapshot();
      assertEquals(mapper, write(f, memory, mapper, device.cpu, 1, device.value));
      assertEquals(before, memory.snapshot(), "No device or PPU/APU premise is added");
      assertEquals(0x156L, memory.ordinaryRead(f.p, ProgramMapping.cartridge(f.p), mapper, 0xfffdL, 2));
      assertNull(memory.ordinaryRead(f.p, ProgramMapping.cartridge(f.p), mapper, (long) device.cpu, 1));
      assertEquals(new MapperState.Physical("HRAM", 0, 0x7d),
          mapper.translate(ProgramMapping.cartridge(f.p), 0xfffd, false).physical());
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        assertEquals(List.of(new AnalysisResult.OrdinaryCallProof("0153",
            new MapperState.Physical("ROM", 0, 0x153), "0300", new MapperState.Physical("ROM", 0, 0x300),
            "0156", new MapperState.Physical("ROM", 0, 0x156))), preview.result().ordinaryCallProofs(),
            preview.result().findings().toString());
        assertEquals(List.of(0xfffe, 0xfffd), writes(preview, 0x153).stream().map(BankAnalysis.WriteTransition::cpu).toList());
        assertEquals(List.of(1, 0x56), writes(preview, 0x153).stream().map(BankAnalysis.WriteTransition::value).toList());
        var deviceWrites = writes(preview, device.value == null ? 0x300 : 0x302);
        assertEquals(1, deviceWrites.size());
        assertEquals(device.cpu, deviceWrites.get(0).cpu());
        assertEquals(device.value == null ? null : device.value.intValue(), deviceWrites.get(0).value());
        assertEquals(new MapperState.Physical("HRAM", 0, 0x7e),
            mapper.translate(ProgramMapping.cartridge(f.p), 0xfffe, true).physical());
        int witness = 0x300 + effect.length() / 2;
        assertEquals(List.of(0xfd, 0xff), writes(preview, witness).stream().map(BankAnalysis.WriteTransition::value).toList());
        assertEquals(List.of(0xff, 0xff), writes(preview, 0x156).stream().map(BankAnalysis.WriteTransition::value).toList());
        var ret = preview.steps().stream().filter(s -> s.cpu() == witness + 3).findFirst().orElseThrow();
        assertTrue(ret.successors().isEmpty(), "Matched RET is consumed by ordinary-call composition");
        assertEquals(mapper, ret.incoming());
        assertEquals(mapper, ret.outgoing());
        var raw = f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, String.format("%04x", witness + 3))).getPcode(false);
        assertEquals(2, Arrays.stream(raw).filter(op -> op.getOpcode() == PcodeOp.LOAD).count());
        assertEquals(1, Arrays.stream(raw).filter(op -> op.getOpcode() == PcodeOp.RETURN).count());
      }
    }
  }

  static List<Integer> unqualified() { return List.of(0xff25, 0xff41, 0xff0f, 0xffff, 0xff46, 0xff55, 0xff44); }
  @ParameterizedTest @MethodSource("unqualified")
  void unqualifiedExactDeviceStillDestroysReturnFacts(int cpu) throws Exception {
    try (var f = new Fixture("31ffffcd000376", String.format("3e00ea%02x%02xc9", cpu & 255, cpu >>> 8))) {
      var mapper = MapperKnowledge.from(MapperState.reset());
      var memory = frame(f, mapper);
      assertEquals(mapper, write(f, memory, mapper, cpu, 1, 0L));
      assertTrue(memory.facts.isEmpty());
      assertNull(memory.ordinaryRead(f.p, ProgramMapping.cartridge(f.p), mapper, 0xfffdL, 2));
      assertTrue(f.preview(false).result().ordinaryCallProofs().isEmpty());
    }
  }

  @Test void constituentBytesDoNotInheritQualificationAndWrappingStillChangesMapper() throws Exception {
    try (var f = new Fixture("00", "c9")) {
      var mapper = MapperKnowledge.from(MapperState.reset());
      for (int start : List.of(0xff24, 0xff25, 0xff26, 0xff3f, 0xff40, 0xff43, 0xff4b)) {
        var memory = frame(f, mapper);
        var transitions = new ArrayList<BankAnalysis.WriteTransition>();
        assertEquals(mapper, write(f, memory, mapper, start, 2, 0x1200L, transitions));
        assertEquals(List.of(start, start + 1), transitions.stream().map(BankAnalysis.WriteTransition::cpu).toList());
        assertEquals(List.of(0, 1), transitions.stream().map(BankAnalysis.WriteTransition::byteIndex).toList());
        assertEquals(List.of(0, 0x12), transitions.stream().map(BankAnalysis.WriteTransition::value).toList());
        assertTrue(memory.facts.isEmpty(), String.format("Unqualified constituent at %04x", start));
      }
      for (int start : List.of(0xff42, 0xff4a)) {
        var memory = frame(f, mapper);
        var before = memory.snapshot();
        var transitions = new ArrayList<BankAnalysis.WriteTransition>();
        assertEquals(mapper, write(f, memory, mapper, start, 2, null, transitions));
        assertEquals(List.of(start, start + 1), transitions.stream().map(BankAnalysis.WriteTransition::cpu).toList());
        assertEquals(List.of(0, 1), transitions.stream().map(BankAnalysis.WriteTransition::byteIndex).toList());
        assertTrue(transitions.stream().allMatch(w -> w.value() == null));
        assertEquals(before, memory.snapshot());
      }
      var memory = frame(f, mapper);
      var transitions = new ArrayList<BankAnalysis.WriteTransition>();
      var wrapped = write(f, memory, mapper, 0xffff, 2, 0x1200L, transitions);
      assertEquals(List.of(0xffff, 0), transitions.stream().map(BankAnalysis.WriteTransition::cpu).toList());
      assertEquals(List.of(0, 1), transitions.stream().map(BankAnalysis.WriteTransition::byteIndex).toList());
      assertEquals(List.of(0, 0x12), transitions.stream().map(BankAnalysis.WriteTransition::value).toList());
      assertEquals(transitions.get(0).after(), transitions.get(1).before());
      assertTrue(memory.facts.isEmpty());
      assertEquals(Boolean.FALSE, wrapped.enabled(), "Second architectural byte wraps to mapper enable at 0000");
      assertEquals(1, wrapped.low());
      assertEquals(1, wrapped.svbk());
    }
  }

  @Test void finiteSetStillRequiresEstablishedHardware() throws Exception {
    for (String hardware : List.of("GB", "CGB", "UNKNOWN")) {
      try (var f = new Fixture("00", "c9")) {
        int tx = f.p.startTransaction("Hardware identity control");
        try {
          var cartridge = ProgramMapping.cartridge(f.p).withHardwareChoice(hardware);
          f.p.getOptions(ProgramMapping.OPTIONS).setString("cartridge", ProgramMapping.JSON.toJson(cartridge));
        } finally { f.p.endTransaction(tx, true); }
        for (int cpu : List.of(0xff24, 0xff26, 0xff40, 0xff42, 0xff43, 0xff4a, 0xff4b)) {
          var mapper = MapperKnowledge.from(MapperState.reset());
          var memory = frame(f, mapper);
          var before = memory.snapshot();
          assertEquals(mapper, write(f, memory, mapper, cpu, 1, null));
          assertEquals(hardware.equals("UNKNOWN") ? Map.of() : before, memory.snapshot());
          assertNull(memory.ordinaryRead(f.p, ProgramMapping.cartridge(f.p), mapper, (long) cpu, 1));
        }
      }
    }
  }

  @Test void qualifiedWriteDoesNotAdmitDeviceRead() throws Exception {
    for (int cpu : List.of(0xff24, 0xff40, 0xff26)) {
      try (var f = new Fixture("31ffffcd000376", String.format("e0%02xf0%02xc9", cpu & 255, cpu & 255))) {
        var mapper = MapperKnowledge.from(MapperState.reset());
        var memory = frame(f, mapper);
        var before = memory.snapshot();
        assertEquals(mapper, write(f, memory, mapper, cpu, 1, null));
        assertEquals(before, memory.snapshot());
        assertNull(memory.ordinaryRead(f.p, ProgramMapping.cartridge(f.p), mapper, (long) cpu, 1));
        for (boolean reverse : List.of(false, true)) {
          var preview = f.preview(reverse);
          assertTrue(preview.result().ordinaryCallProofs().isEmpty());
          var read = preview.steps().stream().filter(step -> step.cpu() == 0x302).findFirst().orElseThrow();
          assertEquals(mapper, read.incoming());
          assertEquals(mapper, read.outgoing());
        }
      }
    }
  }

  @Test void supportedUnknownReadRemainsUnknownAndUnsafeReadStillRefuses() throws Exception {
    for (String read : List.of("f070", "2100c17e", "21a0fe7e")) {
      try (var f = new Fixture("31ffffcd0003ea01c176", read + "e040c9")) {
        var preview = f.preview(false);
        boolean supported = !read.equals("21a0fe7e");
        assertEquals(supported ? 1 : 0, preview.result().ordinaryCallProofs().size());
        if (supported) {
          var effects = preview.steps().stream().flatMap(s -> s.writes().stream())
              .filter(w -> w.cpu() == 0xff40 || w.cpu() == 0xc101).toList();
          assertEquals(2, effects.size());
          assertTrue(effects.stream().allMatch(w -> w.value() == null));
        }
      }
    }
  }
}
