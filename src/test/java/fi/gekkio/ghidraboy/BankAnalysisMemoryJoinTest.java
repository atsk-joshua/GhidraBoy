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

/** Compiled instruction counterexamples for compatible physical-byte must joins. */
class BankAnalysisMemoryJoinTest extends IntegrationTest {
  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("N3 memory join", getLanguage(), getLanguage().getDefaultCompilerSpec(), owner);
    Fixture(String hex) throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19; bytes[0x148] = 1;
      byte[] code = HexFormat.of().parseHex(hex + "ea0020c30040");
      System.arraycopy(code, 0, bytes, 0x150, code.length);
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true,
            TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("N3 instructions");
      try {
        Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(
            ProgramMapping.staticAddress(p, "0150"), new AddressSet(
                ProgramMapping.staticAddress(p, "0150"),
                ProgramMapping.staticAddress(p, String.format("%04x", 0x150 + code.length - 1))));
      } finally { p.endTransaction(tx, true); }
    }
    BankAnalysis.FetchPreview preview(boolean reverse) throws Exception {
      return BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
          new AnalysisResult.Configuration(4096, reverse), TaskMonitor.DUMMY);
    }
    @Override public void close() { p.release(owner); }
  }

  // Unknown Z enters either arm. Both arms end in JR, including JR +0 for the second.
  private static String diamond(String left, String right) {
    return "28" + String.format("%02x", left.length() / 2 + 2) + left
        + "18" + String.format("%02x", right.length() / 2 + 2) + right + "1800";
  }

  private static List<BankAnalysis.WriteTransition> selectors(BankAnalysis.FetchPreview preview) {
    return preview.steps().stream().flatMap(s -> s.writes().stream())
        .filter(w -> w.cpu() == 0x2000).toList();
  }

  private static void selected(BankAnalysis.FetchPreview preview, Integer expected) {
    assertEquals(AnalysisResult.Completion.COMPLETE, preview.result().completion());
    assertFalse(selectors(preview).isEmpty());
    assertTrue(selectors(preview).stream().allMatch(w -> Objects.equals(expected, w.value())));
    var jumps = preview.result().findings().stream().filter(f -> f.access().equals("jump") && (f.targets().isEmpty() || f.targets().stream().anyMatch(t -> t.endsWith("::4000")))).toList();
    assertFalse(jumps.isEmpty());
    if (expected != null) {
      assertTrue(jumps.stream().anyMatch(f -> f.confidence() == AnalysisResult.Confidence.PROVEN
          && f.targets().equals(List.of("rom" + expected + "::4000"))));
    } else {
      assertTrue(jumps.stream().allMatch(f -> f.confidence() != AnalysisResult.Confidence.PROVEN));
    }
  }

  private void check(String code, Integer expected) throws Exception {
    try (var f = new Fixture(code)) {
      var forward = f.preview(false);
      selected(forward, expected);
      var reverse = f.preview(true);
      selected(reverse, expected);
      assertEquals(forward.result().findings(), reverse.result().findings());
      assertTrue(forward.result().findings().stream().noneMatch(x -> x.access().equals("widening")));
    }
  }

  @Test void identicalCompatibleFactsRetainExactSelector() throws Exception {
    check("2100c0" + diamond("3602", "3602") + "7e", 2);
  }

  @Test void conflictingCompatibleFactsCannotSelectEitherBank() throws Exception {
    check("2100c0" + diamond("3601", "3602") + "7e", null);
  }

  @Test void missingPathFactIsUnknown() throws Exception {
    check("2100c0" + diamond("3602", "00") + "7e", null);
  }

  @Test void commonByteSurvivesWhileDifferentByteBecomesUnknown() throws Exception {
    String paths = "2100c0" + diamond("36022336032100c0", "36022336042100c0");
    check(paths + "7e", 2);
    check(paths + "2101c07e", null);
  }

  @Test void disjointFactsSurviveOnlyForBytesWrittenOnBothArms() throws Exception {
    String paths = "2100c0" + diamond("36022101c036032100c0", "36022102c036042100c0");
    check(paths + "7e", 2);
    check(paths + "2101c07e", null);
    check(paths + "2102c07e", null);
  }

  @Test void echoAliasSpellingsUseOnePhysicalFact() throws Exception {
    check(diamond("2100c036022100c0", "2100e036022100c0") + "7e", 2);
  }

  @Test void differentRegistersRetainSeparateSelectorValues() throws Exception {
    try (var f = new Fixture("2100c03602" + diamond("3e01", "3e02"))) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        var values = new HashSet<Integer>();
        selectors(preview).forEach(w -> values.add(w.value()));
        assertEquals(Set.of(1, 2), values);
      }
    }
  }

  @Test void differentMapperStatesRetainBothPhysicalSuccessors() throws Exception {
    // Select banks in each arm, then normalize A before the shared JP 4000.
    String code = "2100c03602" + diamond("3e01ea00203e00", "3e02ea00203e00") + "c30040";
    try (var f = new Fixture(code)) {
      var preview = f.preview(false);
      var targets = new HashSet<String>();
      preview.result().findings().stream().filter(x -> x.access().equals("jump") && (x.targets().isEmpty() || x.targets().stream().anyMatch(t -> t.endsWith("::4000"))))
          .forEach(x -> targets.addAll(x.targets()));
      assertEquals(Set.of("rom1::4000", "rom2::4000"), targets);
      assertEquals(preview.result().findings(), f.preview(true).result().findings());
    }
  }

  @Test void compatibleLoopReprocessesWeakenedFactsWithoutDiversityFallback() throws Exception {
    // C000=2 is invariant; C001 starts as 3 and becomes 4 on a backedge.
    // LD/16-bit pointer setup preserves flags, so every loop header has identical registers.
    String loop = "2100c036022101c036032100c0280a2101c036042100c018f4";
    check(loop + "7e", 2);
    try (var f = new Fixture(loop + "2101c07e")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        assertEquals(AnalysisResult.Completion.COMPLETE, preview.result().completion());
        assertTrue(preview.steps().size() < 100);
        assertTrue(preview.result().findings().stream().noneMatch(x -> x.access().equals("widening")));
        assertTrue(selectors(preview).stream().anyMatch(w -> w.value() == null));
        assertTrue(preview.result().findings().stream().filter(x -> x.access().equals("jump") && (x.targets().isEmpty() || x.targets().stream().anyMatch(t -> t.endsWith("::4000"))))
            .allMatch(x -> x.confidence() != AnalysisResult.Confidence.PROVEN));
      }
    }
  }
  @Test void n3RoundTripRejectsN2WithoutSerializingTransientMemory() throws Exception {
    try (var f = new Fixture("2100c036027e")) {
      var result = f.preview(false).result();
      String json = ProgramMapping.JSON.toJson(result);
      assertEquals(result, AnalysisResult.read(json));
      assertEquals(3, result.schemaVersion());
      assertThrows(IllegalArgumentException.class, () -> AnalysisResult.read(
          json.replace(AnalysisResult.ENGINE_VERSION, "20260930-n2-ram-value-1")));
      var fields = com.google.gson.JsonParser.parseString(json).getAsJsonObject().keySet();
      assertEquals(Set.of("schemaVersion", "engineVersion", "starts", "assumption", "entryPremises",
          "configuration", "completion", "exploredStates", "pendingStates", "fingerprint",
          "findings", "diagnostics"), fields);
    }
  }

}
