package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/** Promoted 1A controls: independently predicted physical bytes, mapper state and composition. */
class BankAnalysisScxLivenessTest extends IntegrationTest {
  @TempDir Path temporary;
  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("Call coverage and unknown values", getLanguage(),
        getLanguage().getDefaultCompilerSpec(), owner);
    final String root;
    final int site;

    Fixture(String caller, String callee) throws Exception { this(caller, callee, false, 0x153); }

    Fixture(String caller, String callee, boolean banked, int site) throws Exception {
      root = banked ? "rom1::4000" : "0150";
      this.site = site;
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      byte[] main = HexFormat.of().parseHex(caller);
      byte[] body = HexFormat.of().parseHex(callee);
      System.arraycopy(main, 0, bytes, banked ? 0x4000 : 0x150, main.length);
      System.arraycopy(body, 0, bytes, 0x300, body.length);
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.CGB, true, true,
            TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("Define self-authored coverage fixture");
      try {
        define(root, main.length);
        if (body.length != 0) define("0300", body.length);
      } finally { p.endTransaction(tx, true); }
    }

    void define(String at, int length) throws Exception {
      var first = ProgramMapping.staticAddress(p, at);
      Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first,
          new AddressSet(first, first.add(length - 1)));
    }

    BankAnalysis.FetchPreview preview(boolean reverse, int limit) throws Exception {
      return BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, root), MapperState.reset(),
          new AnalysisResult.Configuration(limit, reverse), TaskMonitor.DUMMY);
    }

    @Override public void close() { p.release(owner); }
  }


  record Case(String id, int sp, String effect, int target, Long value,
      Long word, boolean proof, Integer low, Integer svbk, boolean clear) {
    @Override public String toString() { return id; }
  }
  static List<Case> cases() {
    return List.of(
        new Case("WRAM-disjoint", 0xffff, "3e02ea00c1", 0xc100, 2L, 0x156L, true, 1, 1, false),
        new Case("HRAM-disjoint", 0xffff, "3e02e090", 0xff90, 2L, 0x156L, true, 1, 1, false),
        new Case("SCX", 0xffff, "3e02e043", 0xff43, 2L, 0x156L, true, 1, 1, false),
        new Case("SCX-unknown-value", 0xffff, "e043", 0xff43, null, 0x156L, true, 1, 1, false),
        new Case("mapper-disjoint", 0xffff, "3e02ea0020", 0x2000, 2L, 0x156L, true, 2, 1, false),
        new Case("HRAM-SVBK", 0xffff, "3e02e070", 0xff70, 2L, 0x156L, true, 1, 2, false),
        new Case("same-value", 0xffff, "21fdff3656", 0xfffd, 0x56L, 0x156L, true, 1, 1, false),
        new Case("CFFF-D000", 0xd001, "3e02e090", 0xff90, 2L, 0x156L, true, 1, 1, false),
        new Case("alias", 0xffff, "21fdff3600", 0xfffd, 0L, 0x100L, false, 1, 1, false),
        new Case("unknown-slot", 0xffff, "21fdff70", 0xfffd, null, null, false, 1, 1, false),
        new Case("FF46", 0xffff, "3ec0e046", 0xff46, 0xc0L, null, false, 1, 1, true),
        new Case("FF55", 0xffff, "3e00e055", 0xff55, 0L, null, false, 1, 1, true),
        new Case("FF26-unclassified", 0xffff, "3e00e026", 0xff26, 0L, null, false, 1, 1, true),
        new Case("WRAM-SVBK", 0xd100, "3e02e070", 0xff70, 2L, null, false, 1, 2, false),
        new Case("CFFF-D000-SVBK", 0xd001, "3e02e070", 0xff70, 2L, null, false, 1, 2, false),
        new Case("device-boundary", 0xff81, "3e02ea00c1", 0xc100, 2L, null, false, 1, 1, false),
        new Case("IE-boundary", 0, "3e02ea00c1", 0xc100, 2L, null, false, 1, 1, false),
        new Case("full-wrap", 1, "3e02ea00c1", 0xc100, 2L, null, false, 1, 1, false));
  }

  // These explicit physical oracles are independent of MapperKnowledge.translate.
  private static MapperState.Physical byteIdentity(int cpu, int bank) {
    if (cpu >= 0xc000 && cpu <= 0xcfff) return new MapperState.Physical("WRAM", 0, cpu - 0xc000);
    if (cpu >= 0xd000 && cpu <= 0xdfff) return new MapperState.Physical("WRAM", bank, cpu - 0xd000);
    if (cpu >= 0xff80 && cpu <= 0xfffe) return new MapperState.Physical("HRAM", 0, cpu - 0xff80);
    return null;
  }

  private static MapperState.Physical resolvedIdentity(int cpu, int bank) {
    return cpu == 0 ? new MapperState.Physical("ROM", 0, 0) : byteIdentity(cpu, bank);
  }

  private static MapperKnowledge write(Fixture f, SymbolicMemory.State memory,
      MapperKnowledge mapper, int cpu, int width, Long value) throws Exception {
    // Exercise the actual adapter, including ordered/wrapped mapper transitions.
    var method = Arrays.stream(BankAnalysis.class.getDeclaredMethods())
        .filter(m -> m.getName().equals("writeAccess")).findFirst().orElseThrow();
    method.setAccessible(true);
    return (MapperKnowledge) method.invoke(null, f.p, ProgramMapping.cartridge(f.p), mapper,
        cpu, width, value, ProgramMapping.staticAddress(f.p, "0150"), 0,
        new HashMap<>(), new HashMap<>(), new ArrayList<>(), memory);
  }

  @ParameterizedTest(name = "{0}") @MethodSource("cases")
  void exactPhysicalEffectsAndCallComposition(Case c) throws Exception {
    String caller = "31" + String.format("%02x%02x", c.sp & 255, c.sp >>> 8) + "cd0003ea002076";
    try (var f = new Fixture(caller, c.effect + "3e02c9")) {
      var initial = MapperKnowledge.from(MapperState.reset());
      var mapper = initial;
      var memory = SymbolicMemory.State.ordinary(Map.of());
      int slot = (c.sp - 2) & 65535;
      int high = (slot + 1) & 65535;
      var lowPhysical = byteIdentity(slot, 1);
      var highPhysical = byteIdentity(high, 1);
      assertEquals(resolvedIdentity(slot, 1), mapper.translate(ProgramMapping.cartridge(f.p), slot, false).physical());
      assertEquals(resolvedIdentity(high, 1), mapper.translate(ProgramMapping.cartridge(f.p), high, false).physical());
      mapper = write(f, memory, mapper, high, 1, 1L);
      mapper = write(f, memory, mapper, slot, 1, 0x56L);
      boolean ordinaryPair = lowPhysical != null && highPhysical != null;
      assertEquals(ordinaryPair ? 0x156L : null,
          memory.ordinaryRead(f.p, ProgramMapping.cartridge(f.p), mapper, (long) slot, 2));
      var before = memory.snapshot();
      mapper = write(f, memory, mapper, c.target, 1, c.value);
      assertEquals(new MapperKnowledge(c.low, initial.high(), initial.mode(), initial.ram(),
          initial.enabled(), initial.vbk(), c.svbk, initial.latch()), mapper);
      assertEquals(resolvedIdentity(slot, c.svbk), mapper.translate(ProgramMapping.cartridge(f.p), slot, false).physical());
      assertEquals(resolvedIdentity(high, c.svbk), mapper.translate(ProgramMapping.cartridge(f.p), high, false).physical());
      assertEquals(c.word, memory.ordinaryRead(f.p, ProgramMapping.cartridge(f.p), mapper, (long) slot, 2));
      if (c.clear) assertTrue(memory.facts.isEmpty());
      else for (var entry : before.entrySet()) {
        if (entry.getKey().equals(byteIdentity(c.target, 1))) {
          if (c.value == null) assertFalse(memory.facts.containsKey(entry.getKey()));
          else assertEquals(c.value.longValue(), ((AbstractValues.Exact) memory.facts.get(entry.getKey()).domain()).value());
        } else assertEquals(entry.getValue(), memory.facts.get(entry.getKey()));
      }
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse, 4096);
        assertEquals(c.proof ? 1 : 0, preview.result().ordinaryCallProofs().size(), preview.result().findings().toString());
        if (c.proof) {
          var proof = preview.result().ordinaryCallProofs().get(0);
          assertEquals(new MapperState.Physical("ROM", 0, 0x153), proof.sourcePhysical());
          assertEquals(new MapperState.Physical("ROM", 0, 0x300), proof.targetPhysical());
          assertEquals("0156", proof.continuation());
          assertEquals(new MapperState.Physical("ROM", 0, 0x156), proof.continuationPhysical());
          var output = preview.steps().stream().filter(s -> s.source().equals("0156"))
              .flatMap(s -> s.writes().stream()).findFirst().orElseThrow();
          assertEquals(2, output.value());
          assertEquals(mapper, output.before());
        }
      }
    }
  }

  @Test void unknownAddressAndAmbiguousExecutableContinuationRemainRefused() throws Exception {
    for (boolean banked : List.of(false, true)) {
      try (var f = new Fixture("31ffffcd000376", banked ? "ea0020c9" : "3e0212c9",
          banked, banked ? 0x4003 : 0x153)) {
        if (banked) {
          var memory = SymbolicMemory.State.ordinary(Map.of());
          var mapper = MapperKnowledge.from(MapperState.reset());
          mapper = write(f, memory, mapper, 0xfffe, 1, 0x40L);
          mapper = write(f, memory, mapper, 0xfffd, 1, 6L);
          mapper = write(f, memory, mapper, 0x2000, 1, null);
          assertNull(mapper.low());
          assertEquals(0x4006L, memory.ordinaryRead(f.p, ProgramMapping.cartridge(f.p), mapper, 0xfffdL, 2));
          assertNull(mapper.translate(ProgramMapping.cartridge(f.p), 0x4006, false).physical());
        }
        for (boolean reverse : List.of(false, true)) {
          var preview = f.preview(reverse, 4096);
          assertTrue(preview.result().ordinaryCallProofs().isEmpty());
          if (!banked) {
            var store = preview.steps().stream().filter(step -> step.source().equals("0302")).findFirst().orElseThrow();
            assertEquals(MapperKnowledge.unknown(), store.outgoing());
            assertTrue(store.writes().isEmpty(), "No exact target may be fabricated for unknown DE");
          }
        }
      }
    }
  }

  @Test void wideWrapAndEchoAliasRetainConservativePhysicalEffects() throws Exception {
    try (var f = new Fixture("00", "c9")) {
      var mapper = MapperKnowledge.from(MapperState.reset());
      var memory = SymbolicMemory.State.ordinary(Map.of());
      mapper = write(f, memory, mapper, 0xc101, 1, 1L);
      mapper = write(f, memory, mapper, 0xc100, 1, 0x56L);
      assertEquals(new MapperState.Physical("WRAM", 0, 0x100),
          mapper.translate(ProgramMapping.cartridge(f.p), 0xe100, true).physical());
      mapper = write(f, memory, mapper, 0xe100, 1, 0L);
      assertEquals(0x100L, memory.ordinaryRead(f.p, ProgramMapping.cartridge(f.p), mapper, 0xc100L, 2));
      mapper = write(f, memory, mapper, 0xffff, 2, 0L);
      assertTrue(memory.facts.isEmpty());
      assertEquals(Boolean.FALSE, mapper.enabled());
      assertEquals(1, mapper.low());
    }
  }

  @Test void onlyEstablishedHardwareAndExactScxByteReceiveException() throws Exception {
    for (String hardware : List.of("GB", "CGB", "UNKNOWN")) {
      try (var f = new Fixture("00", "c9")) {
        int tx = f.p.startTransaction("Explicit hardware qualification");
        try {
          var cartridge = ProgramMapping.cartridge(f.p).withHardwareChoice(hardware);
          f.p.getOptions(ProgramMapping.OPTIONS).setString("cartridge", ProgramMapping.JSON.toJson(cartridge));
        } finally { f.p.endTransaction(tx, true); }
        var mapper = MapperKnowledge.from(MapperState.reset());
        var memory = SymbolicMemory.State.ordinary(Map.of());
        mapper = write(f, memory, mapper, 0xfffe, 1, 1L);
        mapper = write(f, memory, mapper, 0xfffd, 1, 0x56L);
        mapper = write(f, memory, mapper, 0xc123, 1, 0x5aL);
        assertEquals(0x5aL, memory.ordinaryRead(f.p, ProgramMapping.cartridge(f.p), mapper, 0xc123L, 1));
        var before = memory.snapshot();
        var after = write(f, memory, mapper, 0xff43, 1, null);
        assertEquals(mapper, after);
        assertEquals(hardware.equals("UNKNOWN") ? Map.of() : before, memory.snapshot());
        // A wide STORE includes FF44, whose unclassified effect must still clear.
        write(f, memory, mapper, 0xff43, 2, 0L);
        assertTrue(memory.facts.isEmpty());
      }
    }
  }

  @Test void supportedUnknownLoadAcrossScxPreservesOnlyIndependentBytes() throws Exception {
    for (String read : List.of("f070", "2100c17e")) {
      try (var f = new Fixture("31ffffcd0003ea01c176", read + "e043c9")) {
        var preview = f.preview(false, 4096);
        assertEquals(1, preview.result().ordinaryCallProofs().size());
        for (int target : List.of(0xff43, 0xc101)) {
          var writes = preview.steps().stream().flatMap(s -> s.writes().stream())
              .filter(w -> w.cpu() == target).toList();
          assertFalse(writes.isEmpty());
          assertTrue(writes.stream().allMatch(w -> w.value() == null));
        }
      }
    }
  }

  @Test void scxProofSurvivesPackedReopenAndOldEngineCannotAuthorizeIt() throws Exception {
    try (var f = new Fixture("31ffffcd000376", "3e02e043c9")) {
      var current = f.preview(false, 4096).result();
      assertEquals(1, current.ordinaryCallProofs().size());
      var oldJson = ProgramMapping.JSON.toJson(current).replace(AnalysisResult.ENGINE_VERSION,
          "20261001-call-stack-liveness-2a-1");
      var old = ProgramMapping.JSON.fromJson(oldJson, AnalysisResult.class);
      assertEquals(current.fingerprint(), old.fingerprint());
      assertTrue(old.ordinaryCallProofs().isEmpty());
      assertThrows(IllegalArgumentException.class, () -> AnalysisResult.read(oldJson));
      assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(f.p, old, TaskMonitor.DUMMY));
      assertThrows(IllegalStateException.class, () -> AnalysisApplication.apply(f.p, old, TaskMonitor.DUMMY));
      BankAnalysis.apply(f.p, current, TaskMonitor.DUMMY);
      var packed = temporary.resolve("scx.gzf").toFile();
      f.p.saveToPackedFile(packed, TaskMonitor.DUMMY);
      var database = PackedDatabase.getPackedDatabase(packed, true, TaskMonitor.DUMMY);
      Object owner = new Object();
      ProgramDB reopened = null;
      try {
        reopened = new ProgramDB(database.open(TaskMonitor.DUMMY), OpenMode.IMMUTABLE, TaskMonitor.DUMMY, owner);
        var saved = AnalysisResult.read(reopened.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", null));
        ProgramFingerprint.requireCurrent(reopened, saved, TaskMonitor.DUMMY);
        var fresh = BankAnalysis.preview(reopened, ProgramMapping.staticAddress(reopened, "0150"),
            MapperState.reset(), AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
        assertEquals(saved.ordinaryCallProofs(), fresh.ordinaryCallProofs());
        assertEquals(1, fresh.ordinaryCallProofs().size());
      } finally {
        if (reopened != null) reopened.release(owner);
        database.dispose();
      }
    }
  }
}
