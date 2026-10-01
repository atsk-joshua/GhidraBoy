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

/** Self-authored instruction oracle: a RAM-carried selector 2 must select physical ROM2. */
class BankAnalysisRamValueTest extends IntegrationTest {
  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("N2 RAM selector", getLanguage(), getLanguage().getDefaultCompilerSpec(), owner);
    Fixture(String hex, GameBoyKind hardware) throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19; bytes[0x148] = 1;
      byte[] code = HexFormat.of().parseHex(hex + "ea0020c30040");
      System.arraycopy(code, 0, bytes, 0x150, code.length);
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", hardware, true, true, TaskMonitor.DUMMY, new MessageLog());
      }
      edit(() -> Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(
          ProgramMapping.staticAddress(p, "0150"), new AddressSet(
              ProgramMapping.staticAddress(p, "0150"), ProgramMapping.staticAddress(p, String.format("%04x", 0x150 + code.length - 1)))));
    }
    void edit(Checked action) throws Exception {
      int tx = p.startTransaction("N2 fixture");
      try { action.run(); } finally { p.endTransaction(tx, true); }
    }
    BankAnalysis.FetchPreview preview(MapperState assumption) throws Exception {
      return BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, "0150"), assumption,
          AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
    }
    @Override public void close() { p.release(owner); }
  }
  @FunctionalInterface private interface Checked { void run() throws Exception; }
  private static void selector(BankAnalysis.FetchPreview preview, Integer expected) {
    var write = preview.steps().stream().flatMap(s -> s.writes().stream())
        .filter(w -> w.cpu() == 0x2000).findFirst().orElseThrow();
    assertEquals(expected, write.value());
    var jump = preview.result().findings().stream().filter(f -> f.access().equals("jump")).findFirst().orElseThrow();
    assertEquals(expected == null ? List.of() : List.of("rom" + expected + "::4000"), jump.targets());
  }
  private void check(String code, Integer expected) throws Exception {
    try (var f = new Fixture(code, GameBoyKind.GB)) { selector(f.preview(MapperState.reset()), expected); }
  }

  @Test void compiledStoreLoadFeedsRegisterAndOrdinaryPhysicalFlow() throws Exception {
    // LD HL,C000; LD (HL),02; LD A,(HL); LD (2000),A; JP 4000.
    try (var f = new Fixture("2100c036027e", GameBoyKind.GB)) {
      var store = f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, "0153")).getPcode(false);
      var load = f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, "0155")).getPcode(false);
      assertTrue(Arrays.stream(store).anyMatch(op -> op.getOpcode() == PcodeOp.STORE));
      assertTrue(Arrays.stream(load).anyMatch(op -> op.getOpcode() == PcodeOp.LOAD));
      assertEquals(List.of(new MapperState.Physical("WRAM", 0, 0)), ProgramMapping.staticToPhysical(f.p, ProgramMapping.staticAddress(f.p, "c000")));
      selector(f.preview(MapperState.reset()), 2);
      var result = BankAnalysis.preview(f.p, ProgramMapping.staticAddress(f.p, "0150"), MapperState.reset(), AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
      assertTrue(result.findings().stream().anyMatch(x -> x.access().equals("jump") && x.targets().equals(List.of("rom2::4000"))));
    }
  }
  @Test void canonicalAndEchoStoresSharePhysicalFactsInBothDirections() throws Exception {
    check("2100c036022100e07e", 2);
    check("2100e036022100c07e", 2);
  }
  @Test void unknownOverwriteKillsCanonicalAndAliasFacts() throws Exception {
    // B is an unknown entry byte, and cannot preserve the previous constant.
    check("2100c036027e702100c07e", null);
    check("2100c036022100e0702100c07e", null);
    check("2100e036022100c0702100e07e", null);
  }
  @Test void disjointUnknownWritePreservesTheOtherPhysicalByte() throws Exception {
    check("2100c036022101c0702100e07e", 2);
  }
  @Test void initializedRamIsNeverRuntimeAuthority() throws Exception {
    try (var f = new Fixture("2100c07e", GameBoyKind.GB)) {
      f.edit(() -> {
        var block = f.p.getMemory().getBlock(ProgramMapping.staticAddress(f.p, "c000"));
        if (!block.isInitialized()) f.p.getMemory().convertToInitialized(block, (byte) 2);
        else f.p.getMemory().setByte(ProgramMapping.staticAddress(f.p, "c000"), (byte) 2);
      });
      selector(f.preview(MapperState.reset()), null);
    }
  }
  @Test void unknownPointerStoreInvalidatesPossibleAliases() throws Exception {
    // DE has no entry value.
    check("2100c03602122100c07e", null);
  }
  @Test void existingOrderedWordStoreAndStackLoadUseLittleEndianBytes() throws Exception {
    // LD SP,0202; LD (C000),SP; LD SP,E000; POP BC; LD A,B.
    check("3102020800c03100e0c178", 2);
    // Only one POP byte is established: the entire BC result must be unknown.
    check("2100c036023100e0c178", null);
  }
  @Test void hramUsesPathWritesAndDeviceBoundaryRemainsUnknown() throws Exception {
    check("21feff36027e", 2);
    // LD (FFFE),SP wraps the second byte into IE, which has no synchronous RAM fact.
    check("31020208feff31feffc178", null);
  }
  @Test void unknownBankAndDistinctEstablishedWramBanksStaySeparate() throws Exception {
    try (var f = new Fixture("2100d036027e", GameBoyKind.CGB)) { selector(f.preview(null), null); }
    // Existing FF70 semantics select bank 2 after writing bank 1; bank 2 is unwritten.
    try (var f = new Fixture("2100d036023e02e0707e", GameBoyKind.CGB)) { selector(f.preview(MapperState.reset()), null); }
    // Conversely, writing bank 2 cannot establish the same CPU byte in bank 1.
    try (var f = new Fixture("3e02e0702100d036023e01e0707e", GameBoyKind.CGB)) { selector(f.preview(MapperState.reset()), null); }
    // Write bank 2, select bank 1, then return to bank 2: identity survives selection changes.
    try (var f = new Fixture("3e02e0702100d036023e01e0703e02e0707e", GameBoyKind.CGB)) { selector(f.preview(MapperState.reset()), 2); }
  }
  @Test void branchesRetainSeparateFactsAndDoNotProveOnePathValue() throws Exception {
    // Unknown Z chooses C000=1 or C000=2, with distinct B values retaining path correlation.
    try (var f = new Fixture("2100c02806060136011804060236027e", GameBoyKind.GB)) {
      var preview = f.preview(MapperState.reset());
      var values = new HashSet<Integer>();
      preview.steps().stream().flatMap(step -> step.writes().stream())
          .filter(write -> write.cpu() == 0x2000).forEach(write -> values.add(write.value()));
      assertEquals(Set.of(1, 2), values);
      assertTrue(preview.result().findings().stream().filter(x -> x.access().equals("jump") && x.targets().stream().anyMatch(t -> t.endsWith("::4000")))
          .allMatch(x -> x.confidence() != AnalysisResult.Confidence.PROVEN));
      var reversed = BankAnalysis.preview(f.p, ProgramMapping.staticAddress(f.p, "0150"), MapperState.reset(),
          new AnalysisResult.Configuration(4096, true), TaskMonitor.DUMMY);
      assertEquals(preview.result().findings(), reversed.findings());
    }
  }
  @Test void callsAndDiversityFallbackCannotRetainAnObservedRamConstant() throws Exception {
    check("2100c03602cd00037e", null);
    // A changing independent BC counter keeps register states incompatible; diversity drops facts.
    try (var f = new Fixture("0100002100c036027e3c770320fa7e", GameBoyKind.GB)) {
      var preview = f.preview(MapperState.reset());
      assertTrue(preview.result().findings().stream().anyMatch(x -> x.access().equals("widening")));
      assertTrue(preview.steps().stream().flatMap(x -> x.writes().stream())
          .anyMatch(x -> x.cpu() == 0x2000 && x.value() == null));
      assertTrue(preview.result().findings().stream().filter(x -> x.access().equals("jump") && x.targets().stream().anyMatch(t -> t.endsWith("::4000")))
          .allMatch(x -> x.confidence() != AnalysisResult.Confidence.PROVEN));
    }
  }
  @Test void ramVolatilityIsAStaleDependencyButStoredBytesAreNotFacts() throws Exception {
    try (var f = new Fixture("2100c036027e", GameBoyKind.GB)) {
      var result = f.preview(MapperState.reset()).result();
      f.edit(() -> f.p.getMemory().getBlock(ProgramMapping.staticAddress(f.p, "c000")).setVolatile(true));
      assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(f.p, result, TaskMonitor.DUMMY));
      selector(f.preview(MapperState.reset()), null);
      String old = ProgramMapping.JSON.toJson(result).replace(AnalysisResult.ENGINE_VERSION, "20260930-n1-rom-value-4");
      assertThrows(IllegalArgumentException.class, () -> AnalysisResult.read(old));
    }
  }
}
