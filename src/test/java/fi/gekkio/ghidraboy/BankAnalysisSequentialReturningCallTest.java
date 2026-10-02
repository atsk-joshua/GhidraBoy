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

/** Self-authored N7 bytes distinguish successive returned states and physical invocation frames. */
class BankAnalysisSequentialReturningCallTest extends IntegrationTest {
  private static final String CALL_A = "3100d0cd0003";
  private static final String CALL_B = "cd2003";
  private static final String CALL_C = "cd4003";
  private static final String SELECT = "ea0020c30040";

  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("N7 sequential calls", getLanguage(), getLanguage().getDefaultCompilerSpec(), owner);

    Fixture(String caller, String a, String b, String c) throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      bytes[0x4000] = 1;
      bytes[0x8000] = 2;
      bytes[0xc000] = 3;
      String[] code = {caller, a, b, c};
      int[] starts = {0x150, 0x300, 0x320, 0x340};
      for (int i = 0; i < code.length; i++) {
        byte[] part = HexFormat.of().parseHex(code[i]);
        System.arraycopy(part, 0, bytes, starts[i], part.length);
      }
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true,
            TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("Defined N7 fixture bytes");
      try {
        for (int i = 0; i < code.length; i++) if (!code[i].isEmpty()) {
          define(String.format("%04x", starts[i]), code[i].length() / 2);
        }
      } finally { p.endTransaction(tx, true); }
    }

    private void define(String address, int length) throws Exception {
      var first = ProgramMapping.staticAddress(p, address);
      Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first,
          new AddressSet(first, first.add(length - 1)));
    }

    void code(String address, String hex) throws Exception {
      int tx = p.startTransaction("Defined physical N7 callee");
      try {
        byte[] bytes = HexFormat.of().parseHex(hex);
        p.getMemory().setBytes(ProgramMapping.staticAddress(p, address), bytes);
        define(address, bytes.length);
      } finally { p.endTransaction(tx, true); }
    }

    BankAnalysis.FetchPreview preview(boolean reverse) throws Exception { return preview(reverse, 4096); }

    BankAnalysis.FetchPreview preview(boolean reverse, int limit) throws Exception {
      return BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
          new AnalysisResult.Configuration(limit, reverse), TaskMonitor.DUMMY);
    }

    @Override public void close() { p.release(owner); }
  }

  private static boolean visited(BankAnalysis.FetchPreview preview, int cpu) {
    return preview.steps().stream().anyMatch(s -> s.cpu() == cpu);
  }

  private static List<BankAnalysis.WriteTransition> writes(BankAnalysis.FetchPreview preview, int source, int cpu) {
    return preview.steps().stream().filter(s -> s.cpu() == source).flatMap(s -> s.writes().stream())
        .filter(w -> w.cpu() == cpu).toList();
  }

  private static void store(BankAnalysis.FetchPreview preview, int source, int cpu, Integer expected) {
    var actual = writes(preview, source, cpu);
    assertFalse(actual.isEmpty(), "Missing store at " + Integer.toHexString(source));
    assertTrue(actual.stream().allMatch(w -> Objects.equals(expected, w.value())), actual.toString());
  }

  private static void selects(BankAnalysis.FetchPreview preview, Integer expected) {
    store(preview, 0x156, 0x2000, expected);
    // Callee-local jumps may be covered even when returned data stays unknown.
    // Only the caller banked jump can demonstrate selector certainty.
    var proven = preview.result().findings().stream().filter(f -> f.source().equals("0159")
        && f.access().equals("jump") && f.confidence() == AnalysisResult.Confidence.PROVEN).toList();
    if (expected == null) assertTrue(proven.isEmpty());
    else assertTrue(proven.stream().anyMatch(f -> f.targets().equals(List.of("rom" + expected + "::4000"))));
  }

  @Test void sequentialRegisterStatesPassThroughBothContinuationsAndCaller() throws Exception {
    // B supplies A=1; A observes and increments it; C consumes A=2 into B and
    // produces D=3; A consumes D and the original B, then returns final A=3.
    try (var f = new Fixture(CALL_A + SELECT,
        CALL_B + "ea10c03c" + CALL_C + "7aea12c078ea13c07ac9",
        "3e01c9", "471603c9")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        store(preview, 0x303, 0xc010, 1);
        store(preview, 0x30b, 0xc012, 3);
        store(preview, 0x30f, 0xc013, 2);
        selects(preview, 3);
        assertTrue(visited(preview, 0x320));
        assertTrue(visited(preview, 0x340));
      }
    }
  }

  @Test void returnedRamFeedsSecondCalleeThenOuterAndCallerLoads() throws Exception {
    try (var f = new Fixture(CALL_A + "2102c07e" + SELECT,
        CALL_B + CALL_C + "2101c07e3c2102c077c9",
        "2100c03601c9", "2100c07e3c2101c077c9")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        store(preview, 0x323, 0xc000, 1);
        store(preview, 0x348, 0xc001, 2);
        store(preview, 0x30e, 0xc002, 3);
        store(preview, 0x15a, 0x2000, 3);
      }
    }
  }

  @Test void conflictingFirstReturnRamCannotManufactureSecondCallCertainty() throws Exception {
    // Ordinary JR remains a conservative diamond. Its returning RAM facts disagree.
    try (var f = new Fixture(CALL_A + SELECT, CALL_B + CALL_C + "c9",
        "28072100c0360118072100c036021800c9", "2100c07e3cc9")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        assertTrue(visited(preview, 0x340));
        selects(preview, null);
      }
    }
  }

  @Test void secondCalleeFetchUsesFirstReturnedPhysicalRomBankAndReturnsNewMapper() throws Exception {
    try (var f = new Fixture(CALL_A + "2100407e" + SELECT,
        CALL_B + "cd0041" + "2100407eea10c0c9", "3e02ea0020c9", "3cea0020c9")) {
      f.code("rom2::4100", "2100407eea11c0c34003");
      f.code("rom1::4100", "d3");
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        var entry = preview.steps().stream().filter(s -> s.source().equals("rom2::4100")).findFirst().orElseThrow();
        assertEquals(new MapperState.Physical("ROM", 2, 0x100), entry.bytes().get(0).physical());
        assertTrue(preview.steps().stream().noneMatch(s -> s.source().equals("rom1::4100")));
        store(preview, 0x4104, 0xc011, 2);
        store(preview, 0x30a, 0xc010, 3);
        store(preview, 0x15a, 0x2000, 3);
      }
    }
  }

  @Test void flagsProducedByFirstCalleeAreConsumedBySecondAndFinalFlagsReachCaller() throws Exception {
    try (var f = new Fixture(CALL_A + "f5c179ea12c078" + SELECT,
        CALL_B + CALL_C + "f5c179ea11c078c9", "012002c5f1c9",
        "f5c179ea10c0013003c5f1c9")) {
      var preview = f.preview(false);
      store(preview, 0x343, 0xc010, 0x20);
      store(preview, 0x309, 0xc011, 0x30);
      store(preview, 0x159, 0xc012, 0x30);
      store(preview, 0x15d, 0x2000, 3);
    }
  }

  @Test void sequentialFramesUseCurrentSpAndKeepOriginalOuterPhysicalFrame() throws Exception {
    // B's frame is CFFC/CFFD. A moves its current SP before C, whose frame is
    // CFEC/CFED, then restores CFFE to consume the untouched A frame.
    try (var f = new Fixture(CALL_A + "0810c0" + SELECT,
        CALL_B + "31eecf" + CALL_C + "0812c031fecfc9", "3e01c9", "3e02c9")) {
      var preview = f.preview(false);
      int[] sites = {0x153, 0x300, 0x306};
      int[][] stack = {{0xcfff, 0xcffe}, {0xcffd, 0xcffc}, {0xcfed, 0xcfec}};
      int[][] words = {{1, 0x56}, {3, 3}, {3, 9}};
      var identities = new HashSet<MapperState.Physical>();
      for (int i = 0; i < sites.length; i++) {
        final int source = sites[i];
        var ins = f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, String.format("%04x", source)));
        assertEquals(0xcd, ins.getBytes()[0] & 255);
        assertEquals(2, Arrays.stream(ins.getPcode(false)).filter(op -> op.getOpcode() == PcodeOp.STORE).count());
        var stores = preview.steps().stream().filter(s -> s.cpu() == source).flatMap(s -> s.writes().stream()).toList();
        assertEquals(Arrays.stream(stack[i]).boxed().toList(), stores.stream().map(BankAnalysis.WriteTransition::cpu).toList());
        assertEquals(Arrays.stream(words[i]).boxed().toList(), stores.stream().map(BankAnalysis.WriteTransition::value).toList());
        for (int cpu : stack[i]) identities.add(MapperState.translate(ProgramMapping.cartridge(f.p), MapperState.reset(), cpu, false).physical());
      }
      assertEquals(6, identities.size());
      assertFalse(identities.contains(null));
      store(preview, 0x309, 0xc012, 0xee);
      store(preview, 0x309, 0xc013, 0xcf);
      store(preview, 0x156, 0xc010, 0);
      store(preview, 0x156, 0xc011, 0xd0);
      store(preview, 0x159, 0x2000, 2);
    }
  }

  @Test void incompleteFirstReturnBlocksSecondCallAndOuterResult() throws Exception {
    try (var f = new Fixture(CALL_A + SELECT, CALL_B + CALL_C + "c9", "28033e02c9e9", "3e03c9")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        assertFalse(visited(preview, 0x303));
        assertFalse(visited(preview, 0x340));
        selects(preview, null);
        assertTrue(preview.result().findings().stream().anyMatch(x -> x.reason().contains("complete matched-return")));
      }
    }
  }

  @Test void incompleteSecondReturnCannotPublishSuccessfulFirstReturnAsOuterProof() throws Exception {
    try (var f = new Fixture(CALL_A + SELECT, CALL_B + "ea10c0" + CALL_C + "3e03c9",
        "3e01c9", "28033e02c9e9")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        store(preview, 0x303, 0xc010, 1);
        assertTrue(visited(preview, 0x340));
        assertFalse(visited(preview, 0x309));
        selects(preview, null);
        assertTrue(preview.result().findings().stream().anyMatch(x -> x.reason().contains("complete matched-return")));
      }
    }
  }

  @Test void secondSequentialCalleeCannotCreateFourthActiveFrame() throws Exception {
    try (var f = new Fixture(CALL_A + SELECT, CALL_B + CALL_C + "c9", "cd60033e01c9", CALL_B + "c9")) {
      f.code("0360", "c9");
      var preview = f.preview(false);
      // The admitted visit is traced; depth refusal exits before a second FetchStep.
      assertEquals(1, preview.steps().stream().filter(s -> s.cpu() == 0x320).count());
      assertFalse(visited(preview, 0x306));
      selects(preview, null);
      assertTrue(preview.result().findings().stream().anyMatch(x -> x.source().equals("0320") && x.reason().contains("depth")));
    }
  }

  @Test void sequentialMutualRecursionStillRefusesActiveAncestor() throws Exception {
    try (var f = new Fixture(CALL_A + SELECT, CALL_B + CALL_C + "c9", "3e01c9", "cd0003c9")) {
      var preview = f.preview(false);
      assertEquals(1, preview.steps().stream().filter(s -> s.cpu() == 0x300).count());
      assertFalse(visited(preview, 0x306));
      selects(preview, null);
    }
  }

  @Test void knownFalseRecursiveCallInSecondCalleeDoesNotExecute() throws Exception {
    try (var f = new Fixture(CALL_A + SELECT, CALL_B + CALL_C + "c9", "3e01c9",
        "018002c5f1c400033e03c9")) {
      var preview = f.preview(false);
      assertEquals(1, preview.steps().stream().filter(s -> s.cpu() == 0x300).count());
      selects(preview, 3);
    }
  }

  @Test void sequentialCallsSpendOneSharedGlobalBudget() throws Exception {
    try (var f = new Fixture(CALL_A + SELECT, CALL_B + CALL_C + "c9", "3e01c9", "3e03c9")) {
      var full = f.preview(false);
      selects(full, 3);
      for (boolean reverse : List.of(false, true)) {
        var limited = f.preview(reverse, 8);
        assertEquals(AnalysisResult.Completion.STATE_LIMIT, limited.result().completion());
        assertEquals(8, limited.result().exploredStates());
        assertTrue(visited(limited, 0x340));
        assertFalse(visited(limited, 0x306));
        assertTrue(limited.result().findings().stream().noneMatch(x -> x.confidence() == AnalysisResult.Confidence.PROVEN));
      }
    }
  }

  @Test void n7RoundTripRejectsImmediatelyPrecedingEngineWithoutPersistingFrames() throws Exception {
    try (var f = new Fixture(CALL_A + SELECT, CALL_B + CALL_C + "c9", "3e01c9", "3e03c9")) {
      var result = f.preview(false).result();
      assertEquals("20261001-call-stack-liveness-2d-1", result.engineVersion());
      assertEquals(4, result.schemaVersion());
      String json = ProgramMapping.JSON.toJson(result);
      assertEquals(result, AnalysisResult.read(json));
      assertThrows(IllegalArgumentException.class, () -> AnalysisResult.read(
          json.replace(AnalysisResult.ENGINE_VERSION, "20260930-n6-conditional-call-ret-1")));
      assertEquals(Set.of("schemaVersion", "engineVersion", "starts", "assumption", "entryPremises",
          "configuration", "completion", "exploredStates", "pendingStates", "fingerprint",
          "findings", "ordinaryCallProofs", "diagnostics"), com.google.gson.JsonParser.parseString(json).getAsJsonObject().keySet());
    }
  }
}
