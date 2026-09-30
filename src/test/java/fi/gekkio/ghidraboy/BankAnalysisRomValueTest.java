package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.framework.store.db.PackedDatabase;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Independent N1 ROM selector oracle: file 0200 = 02, MBC5 bank 2, ROM2:4000. */
class BankAnalysisRomValueTest extends IntegrationTest {
  @TempDir Path temporary;

  private final class Fixture implements AutoCloseable {
    final Object consumer = new Object();
    final ProgramDB p = new ProgramDB("N1 ROM selector", getLanguage(), getLanguage().getDefaultCompilerSpec(), consumer);
    final byte[] bytes = new byte[0x10000];
    final Cartridge c;

    Fixture() throws Exception {
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      bytes[0x200] = 2;
      bytes[0x201] = 0x34;
      byte[] code = {0x21, 0, 2, 0x7e, (byte) 0xea, 0, 0x20, (byte) 0xc3, 0, 0x40};
      System.arraycopy(code, 0, bytes, 0x150, code.length);
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true,
            TaskMonitor.DUMMY, new MessageLog());
      }
      c = ProgramMapping.cartridge(p);
      edit(() -> Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
          .disassemble(at("0150"), new AddressSet(at("0150"), at("0159"))));
    }

    Address at(String text) { return Objects.requireNonNull(ProgramMapping.staticAddress(p, text)); }
    void edit(Checked action) throws Exception {
      int tx = p.startTransaction("N1 self-authored fixture");
      try { action.run(); } finally { p.endTransaction(tx, true); }
    }
    Long load(Long cpu, int width, MapperKnowledge state) throws Exception {
      return BankAnalysis.romLoad(p, c, state, cpu, width);
    }
    BankAnalysis.FetchPreview preview(MapperState assumption) throws Exception {
      return BankAnalysis.previewFetch(p, at("0150"), assumption, AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
    }
    MemoryBlock duplicate(String name, int value) throws Exception {
      MemoryBlock[] block = new MemoryBlock[1];
      edit(() -> {
        block[0] = p.getMemory().createInitializedBlock(name, at("0000"),
            new java.io.ByteArrayInputStream(Arrays.copyOf(bytes, 0x202)), 0x202, TaskMonitor.DUMMY, true);
        ProgramMapping.anchor(p, block[0], "ROM", 0);
        block[0].setRead(true);
        block[0].setWrite(false);
        p.getMemory().setByte(block[0].getStart().add(0x200), (byte) value);
      });
      return block[0];
    }
    @Override public void close() { p.release(consumer); }
  }
  @FunctionalInterface private interface Checked { void run() throws Exception; }
  private static final MapperKnowledge EXACT = MapperKnowledge.from(MapperState.reset());

  private static void selector(BankAnalysis.FetchPreview preview, int value, String target) {
    var write = preview.steps().stream().flatMap(step -> step.writes().stream())
        .filter(item -> item.cpu() == 0x2000).findFirst().orElseThrow();
    assertEquals(value, write.value());
    assertEquals(Integer.valueOf(value), write.after().low());
    assertEquals(List.of(target), preview.result().findings().stream()
        .filter(item -> item.source().equals("0157") && item.access().equals("jump"))
        .findFirst().orElseThrow().targets());
    assertTrue(preview.result().findings().stream().anyMatch(item -> item.source().equals("0153")
        && item.access().equals("read") && item.targets().equals(List.of("0200"))));
  }

  @Test void compiledLoadDrivesOrdinaryMapperWriteAndPhysicalSuccessor() throws Exception {
    try (var f = new Fixture()) {
      var raw = f.p.getListing().getInstructionAt(f.at("0153")).getPcode(false);
      var load = Arrays.stream(raw).filter(op -> op.getOpcode() == PcodeOp.LOAD).findFirst().orElseThrow();
      assertEquals(1, load.getOutput().getSize());
      assertEquals(f.p.getRegister("HL").getAddress(), load.getInput(1).getAddress());
      assertNull(PcodeConstants.evaluate(load, Map.of(), Map.of()), "Memory stays outside PcodeConstants");
      selector(f.preview(MapperState.reset()), 2, "rom2::4000");
      var ordinary = BankAnalysis.preview(f.p, f.at("0150"), MapperState.reset(),
          AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
      assertEquals(List.of("rom2::4000"), ordinary.findings().stream()
          .filter(item -> item.source().equals("0157") && item.access().equals("jump"))
          .findFirst().orElseThrow().targets());
      assertTrue(load.getInput(0).isConstant());
      assertEquals(f.p.getAddressFactory().getDefaultAddressSpace().getSpaceID(), (int) load.getInput(0).getOffset());
    }
  }

  @Test void unknownPointerMapperAndNonRomBytesStayUnknown() throws Exception {
    try (var f = new Fixture()) {
      assertNull(f.load(null, 1, EXACT));
      assertNull(f.load(0x4010L, 1, MapperKnowledge.unknown()));
      assertNull(f.load(0xc100L, 1, EXACT));
      assertNull(f.load(0xff00L, 1, EXACT));
      assertNull(f.load(0xffffL, 2, EXACT));
      assertNull(f.load(0x200L, 9, EXACT));
      var unknown = BankAnalysis.preview(f.p, f.at("0153"), MapperState.reset(),
          AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
      assertTrue(unknown.findings().stream().anyMatch(item -> item.access().equals("read") && item.reason().equals("Unknown load address")));
      assertTrue(unknown.findings().stream().filter(item -> item.access().equals("jump")).allMatch(item -> item.targets().isEmpty()));
      f.edit(() -> {
        f.p.getListing().clearCodeUnits(f.at("0150"), f.at("0152"), false);
        f.p.getMemory().setBytes(f.at("0151"), new byte[] {0x10, 0x40});
        Disassembler.getDisassembler(f.p, TaskMonitor.DUMMY, null).disassemble(f.at("0150"), new AddressSet(f.at("0150"), f.at("0152")));
      });
      var mapperUnknown = f.preview(null);
      assertTrue(mapperUnknown.result().findings().stream().anyMatch(item -> item.access().equals("read") && item.targets().isEmpty()
          && item.reason().contains("unknown")));
    }
  }

  @Test void writableVolatileUnreadableAndUninitializedStorageCannotAuthorizeValues() throws Exception {
    try (var f = new Fixture()) {
      var block = f.p.getMemory().getBlock(f.at("0200"));
      var original = f.preview(MapperState.reset()).result();
      f.edit(() -> block.setWrite(true));
      assertNull(f.load(0x200L, 1, EXACT));
      assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(f.p, original, TaskMonitor.DUMMY));
      assertUnknownWithReadMapping(f);
      f.edit(() -> { block.setWrite(false); block.setVolatile(true); });
      assertNull(f.load(0x200L, 1, EXACT));
      assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(f.p, original, TaskMonitor.DUMMY));
      assertUnknownWithReadMapping(f);
      f.edit(() -> { block.setVolatile(false); block.setRead(false); });
      assertNull(f.load(0x200L, 1, EXACT));
      assertUnknownWithReadMapping(f);
      // RAM initialization must never become a ROM premise.
      var ram = f.p.getMemory().getBlock(f.at("c100"));
      f.edit(() -> f.p.getMemory().convertToInitialized(ram, (byte) 2));
      assertNull(f.load(0xc100L, 1, EXACT));
    }
  }

  private static void assertUnknownWithReadMapping(Fixture f) throws Exception {
    var preview = f.preview(MapperState.reset());
    assertTrue(preview.result().findings().stream().anyMatch(item -> item.source().equals("0153") && item.access().equals("read")
        && item.targets().contains("0200")));
    assertNull(preview.steps().stream().flatMap(step -> step.writes().stream()).filter(item -> item.cpu() == 0x2000).findFirst().orElseThrow().value());
    assertTrue(preview.result().findings().stream().filter(item -> item.access().equals("jump")).allMatch(item -> item.targets().isEmpty()));
  }

  @Test void allCurrentPhysicalSourcesMustAgreeAndGeneratedViewsCannotSupplyAuthority() throws Exception {
    try (var f = new Fixture()) {
      assertEquals(0x3402L, f.load(0x200L, 2, EXACT));
      assertEquals(0x3402L, f.load(0x10200L, 2, EXACT), "16-bit CPU pointer");
      var copy = f.duplicate("second_source", 2);
      assertEquals(2L, f.load(0x200L, 1, EXACT));
      f.edit(() -> f.p.getMemory().setByte(copy.getStart().add(0x200), (byte) 3));
      assertNull(f.load(0x200L, 1, EXACT));
      assertNull(f.load(0x200L, 2, EXACT));
      assertUnknownWithReadMapping(f);
      var conflict = f.preview(MapperState.reset()).result();
      f.edit(() -> copy.setName(SoftwareCallExecutionView.PREFIX + "snapshot"));
      assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(f.p, conflict, TaskMonitor.DUMMY));
      assertEquals(2L, f.load(0x200L, 1, EXACT));
      f.edit(() -> f.p.getMemory().getBlock(f.at("0200")).setWrite(true));
      assertNull(f.load(0x200L, 1, EXACT), "Generated source cannot rescue ineligible canonical storage");
    }
  }

  @Test void bytePositionsCrossRomWindowsAndIneligibleAliasesDoNotRescueBacking() throws Exception {
    try (var f = new Fixture()) {
      f.edit(() -> {
        f.p.getMemory().setByte(f.at("3fff"), (byte) 0x78);
        f.p.getMemory().setByte(f.at("rom1::4000"), (byte) 0x56);
      });
      assertEquals(0x5678L, f.load(0x3fffL, 2, EXACT));
      assertNull(f.load(0x3fffL, 2, MapperKnowledge.unknown()), "One unknown byte invalidates scalar");
      f.edit(() -> {
        var alias = f.p.getMemory().createByteMappedBlock("read_only_alias", f.at("0200"), f.at("0200"), 2, true);
        alias.setRead(true);
        alias.setWrite(false);
        f.p.getMemory().getBlock(f.at("0200")).setWrite(true);
      });
      assertNull(f.load(0x200L, 1, EXACT), "Read-only alias cannot mask writable backing");
    }
  }

  @Test void addressValuedCopyIsOnlyAnObservationAndNeverAnImplicitLoad() throws Exception {
    try (var f = new Fixture()) {
      var a = f.p.getRegister("A");
      var output = new Varnode(a.getAddress(), 1);
      var copy = new PcodeOp(f.at("0150"), 0, PcodeOp.COPY, new Varnode[] {new Varnode(f.at("0200"), 1)}, output);
      assertNull(PcodeConstants.evaluate(copy, Map.of(), Map.of()));
      var literal = new Varnode(f.p.getAddressFactory().getConstantSpace().getAddress(0x200), 2);
      var hl = f.p.getRegister("HL");
      var addressCopy = new PcodeOp(f.at("0150"), 0, PcodeOp.COPY, new Varnode[] {literal}, new Varnode(hl.getAddress(), 2));
      assertEquals(0x200L, PcodeConstants.evaluate(addressCopy, Map.of(), Map.of()));
    }
  }

  @Test void ordinaryRenamesAndRamVolatilityAreNotRomValueDependencies() throws Exception {
    try (var f = new Fixture()) {
      var original = f.preview(MapperState.reset()).result();
      f.edit(() -> {
        f.p.getMemory().getBlock(f.at("0200")).setName("renamed_rom");
        f.p.getMemory().getBlock(f.at("c100")).setVolatile(true);
      });
      ProgramFingerprint.requireCurrent(f.p, original, TaskMonitor.DUMMY);
      selector(f.preview(MapperState.reset()), 2, "rom2::4000");
      f.edit(() -> f.p.getMemory().getBlock(f.at("0200"))
          .setName(OrdinaryEntryAccess.PREFIX + "excluded"));
      assertThrows(IllegalStateException.class,
          () -> ProgramFingerprint.requireCurrent(f.p, original, TaskMonitor.DUMMY));
      assertNull(f.load(0x200L, 1, EXACT));
    }
  }

  @Test void currentMutationAndPersistedEngineStalenessSurvivePackedReopen() throws Exception {
    try (var f = new Fixture()) {
      var original = f.preview(MapperState.reset()).result();
      BankAnalysis.apply(f.p, original, TaskMonitor.DUMMY);
      var packed = temporary.resolve("n1.gzf").toFile();
      f.p.saveToPackedFile(packed, TaskMonitor.DUMMY);
      var database = PackedDatabase.getPackedDatabase(packed, true, TaskMonitor.DUMMY);
      var consumer = new Object();
      ProgramDB reopened = null;
      try {
        reopened = new ProgramDB(database.open(TaskMonitor.DUMMY), OpenMode.UPDATE, TaskMonitor.DUMMY, consumer);
        var p = reopened;
        var stored = AnalysisResult.read(p.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", null));
        assertEquals(original, stored);
        ProgramFingerprint.requireCurrent(p, stored, TaskMonitor.DUMMY);
        assertTrue(stored.findings().stream().anyMatch(item -> item.access().equals("jump") && item.targets().equals(List.of("rom2::4000"))));
        var old = ProgramMapping.JSON.toJson(stored).replace(AnalysisResult.ENGINE_VERSION, "20260930-m2-native-analysis-3");
        assertThrows(IllegalArgumentException.class, () -> AnalysisResult.read(old));
        var oldResult = ProgramMapping.JSON.fromJson(old, AnalysisResult.class);
        assertThrows(IllegalStateException.class, () -> BankAnalysis.apply(p, oldResult, TaskMonitor.DUMMY));
        int tx = p.startTransaction("Current ROM selector mutation");
        try { p.getMemory().setByte(ProgramMapping.staticAddress(p, "0200"), (byte) 3); }
        finally { p.endTransaction(tx, true); }
        assertThrows(IllegalStateException.class, () -> BankAnalysis.apply(p, stored, TaskMonitor.DUMMY));
        assertEquals(2, ProgramMapping.originalFile(p).getOriginalByte(0x200));
        var changed = BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(), AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
        selector(changed, 3, "rom3::4000");
        BankAnalysis.apply(p, changed.result(), TaskMonitor.DUMMY);
        var changedFile = temporary.resolve("n1-changed.gzf").toFile();
        p.saveToPackedFile(changedFile, TaskMonitor.DUMMY);
        var secondDb = PackedDatabase.getPackedDatabase(changedFile, true, TaskMonitor.DUMMY);
        ProgramDB second = null;
        try {
          second = new ProgramDB(secondDb.open(TaskMonitor.DUMMY), OpenMode.IMMUTABLE, TaskMonitor.DUMMY, consumer);
          var current = AnalysisResult.read(second.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", null));
          ProgramFingerprint.requireCurrent(second, current, TaskMonitor.DUMMY);
          selector(BankAnalysis.previewFetch(second, ProgramMapping.staticAddress(second, "0150"), MapperState.reset(), AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY), 3, "rom3::4000");
        } finally { if (second != null) second.release(consumer); secondDb.dispose(); }
      } finally { if (reopened != null) reopened.release(consumer); database.dispose(); }
    }
  }
}
