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

/** Independent byte, raw-pcode and physical-topology oracles for the bounded N5 chain. */
class BankAnalysisNestedReturningCallTest extends IntegrationTest {
  private static final String CALL_A = "3100d0cd0003";
  private static final String CALL_B = "cd2003";
  private static final String SELECT = "ea0020c30040";

  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("N5 nested call", getLanguage(), getLanguage().getDefaultCompilerSpec(), owner);

    Fixture(String caller, String a, String b) throws Exception {
      this(caller, a, b, "", GameBoyKind.GB);
    }

    Fixture(String caller, String a, String b, String c, GameBoyKind hardware) throws Exception {
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
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", hardware, true, true,
            TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("Defined fixture bytes");
      try {
        for (int i = 0; i < code.length; i++) if (!code[i].isEmpty()) define(String.format("%04x", starts[i]), code[i].length() / 2);
      } finally { p.endTransaction(tx, true); }
    }

    private void define(String address, int length) throws Exception {
      var first = ProgramMapping.staticAddress(p, address);
      Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first,
          new AddressSet(first, first.add(length - 1)));
    }

    void code(String address, String hex) throws Exception {
      int tx = p.startTransaction("Defined banked fixture");
      try {
        byte[] bytes = HexFormat.of().parseHex(hex);
        p.getMemory().setBytes(ProgramMapping.staticAddress(p, address), bytes);
        define(address, bytes.length);
      } finally { p.endTransaction(tx, true); }
    }

    BankAnalysis.FetchPreview preview(boolean reverse, int limit) throws Exception {
      return BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
          new AnalysisResult.Configuration(limit, reverse), TaskMonitor.DUMMY);
    }

    @Override public void close() { p.release(owner); }
  }

  private static String diamond(String left, String right) {
    return "28" + String.format("%02x", left.length() / 2 + 2) + left
        + "18" + String.format("%02x", right.length() / 2 + 2) + right + "1800";
  }

  private static List<BankAnalysis.WriteTransition> writes(BankAnalysis.FetchPreview preview, int source, int cpu) {
    return preview.steps().stream().filter(s -> s.cpu() == source).flatMap(s -> s.writes().stream())
        .filter(w -> w.cpu() == cpu).toList();
  }

  private static boolean provesBank(BankAnalysis.FetchPreview preview, int bank) {
    return preview.result().findings().stream().anyMatch(f -> f.access().equals("jump")
        && f.confidence() == AnalysisResult.Confidence.PROVEN
        && f.targets().equals(List.of("rom" + bank + "::4000")));
  }

  private void chain(String caller, String a, String b, int selector, Integer expected) throws Exception {
    try (var f = new Fixture(caller + SELECT, a, b)) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse, 4096);
        var actual = writes(preview, selector, 0x2000);
        assertFalse(actual.isEmpty());
        assertTrue(actual.stream().allMatch(w -> Objects.equals(expected, w.value())));
        if (expected == null) assertFalse(provesBank(preview, 2));
        else if (expected <= 3) assertTrue(provesBank(preview, expected));
      }
    }
  }

  private void refused(String a, String b) throws Exception {
    chain(CALL_A, a, b, 0x156, null);
  }

  @Test void returnedRegisterTraversesBothBoundaries() throws Exception {
    chain(CALL_A, CALL_B + "c9", "3e02c9", 0x156, 2);
  }

  @Test void returnedRamTraversesBothBoundariesAndCallerLoad() throws Exception {
    chain(CALL_A + "2100c07e", CALL_B + "c9", "2100c03602c9", 0x15a, 2);
  }

  @Test void nestedEntryUsesActualOuterCalleeRegistersAndRam() throws Exception {
    chain(CALL_A + "2100c07e", "3e022100c077" + CALL_B + "c9", "2100c07e3c77c9", 0x15a, 3);
  }

  @Test void nestedMapperFeedsOuterReadAndCallerReadWithoutRestoration() throws Exception {
    try (var f = new Fixture(CALL_A + "2100407e" + SELECT,
        CALL_B + "2100407e2100c077c9", "3e03ea0020c9")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse, 4096);
        assertTrue(writes(preview, 0x30a, 0xc000).stream().anyMatch(w -> Objects.equals(3, w.value())));
        assertTrue(writes(preview, 0x15a, 0x2000).stream().allMatch(w -> Objects.equals(3, w.value())));
        assertTrue(provesBank(preview, 3));
      }
    }
  }

  @Test void outerContinuationModifiesNestedReturnedRegister() throws Exception {
    chain(CALL_A, CALL_B + "3cc9", "3e02c9", 0x156, 3);
  }

  @Test void nestedWriteReplacesOuterCallerFact() throws Exception {
    chain("2100c03607" + CALL_A + "2100c07e", CALL_B + "c9", "2100c03602c9", 0x15f, 2);
  }

  @Test void twoRawArchitecturalFramesUseSeparatePhysicalBytes() throws Exception {
    try (var f = new Fixture(CALL_A + SELECT, CALL_B + "c9", "3e02c9")) {
      String[] sites = {"0153", "0300", "0322", "0303"};
      for (int i = 0; i < sites.length; i++) {
        var ins = f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, sites[i]));
        var ops = Arrays.asList(ins.getPcode(false));
        assertEquals(i < 2 ? 0xcd : 0xc9, ins.getBytes()[0] & 255);
        int memoryOpcode = i < 2 ? PcodeOp.STORE : PcodeOp.LOAD;
        int flowOpcode = i < 2 ? PcodeOp.CALL : PcodeOp.RETURN;
        assertEquals(2, ops.stream().filter(op -> op.getOpcode() == memoryOpcode).count());
        assertEquals(1, ops.stream().filter(op -> op.getOpcode() == flowOpcode).count());
      }
      assertEquals(ProgramMapping.staticAddress(f.p, "0156"), f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, "0153")).getFallThrough());
      assertEquals(ProgramMapping.staticAddress(f.p, "0303"), f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, "0300")).getFallThrough());
      var preview = f.preview(false, 4096);
      int[] sources = {0x153, 0x300};
      int[][] stack = {{0xcfff, 0xcffe}, {0xcffd, 0xcffc}};
      int[][] values = {{1, 0x56}, {3, 3}};
      var identities = new HashSet<MapperState.Physical>();
      for (int i = 0; i < 2; i++) {
        final int source = sources[i];
        var stores = preview.steps().stream().filter(s -> s.cpu() == source).flatMap(s -> s.writes().stream()).toList();
        assertEquals(Arrays.stream(stack[i]).boxed().toList(), stores.stream().map(BankAnalysis.WriteTransition::cpu).toList());
        assertEquals(Arrays.stream(values[i]).boxed().toList(), stores.stream().map(BankAnalysis.WriteTransition::value).toList());
        for (int cpu : stack[i]) identities.add(MapperState.translate(ProgramMapping.cartridge(f.p), MapperState.reset(), cpu, false).physical());
      }
      assertEquals(4, identities.size());
      assertFalse(identities.contains(null));
      assertTrue(preview.steps().stream().anyMatch(s -> s.cpu() == 0x322));
      assertTrue(preview.steps().stream().anyMatch(s -> s.cpu() == 0x303));
      assertTrue(provesBank(preview, 2));
    }
  }

  @Test void conflictingNestedRegistersRemainUnknown() throws Exception {
    chain(CALL_A, CALL_B + "c9", diamond("3e01", "3e02") + "c9", 0x156, null);
  }

  @Test void conflictingNestedRamCannotRestoreOuterCallerSnapshot() throws Exception {
    chain("2100c03607" + CALL_A + "2100c07e", CALL_B + "c9",
        diamond("2100c03601", "2100c03602") + "c9", 0x15f, null);
  }

  @Test void conflictingNestedMapperCannotAuthorizeOuterContinuation() throws Exception {
    refused(CALL_B + "c9", diamond("3e01ea0020", "3e02ea0020") + "3e02c9");
  }

  @Test void missingLoopingComputedAndUnsupportedLeafDoNotReturn() throws Exception {
    for (String b : List.of("", "3e02", "3e0218fe", "3e02e9", "3e02d3")) refused(CALL_B + "c9", b);
  }

  @Test void successfulLeafReturnArmCannotHideIncompleteSibling() throws Exception {
    refused(CALL_B + "c9", "28033e02c9e9");
  }

  @Test void incompleteNestedInvocationCannotBeRepairedByOuterContinuation() throws Exception {
    // A could forge the outer return word and reestablish mapper/register facts after B.
    // An incomplete B still has no architectural return authorizing those instructions.
    try (var f = new Fixture(CALL_A + SELECT,
        CALL_B + "31560108fecf31fecf3e00ea00303e02ea0020c9", "3e02e9")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse, 4096);
        assertTrue(preview.steps().stream().noneMatch(s -> s.cpu() == 0x303));
        assertFalse(provesBank(preview, 2));
        var callerWrites = writes(preview, 0x156, 0x2000);
        assertFalse(callerWrites.isEmpty());
        assertTrue(callerWrites.stream().allMatch(w -> w.value() == null));
      }
    }
  }

  @Test void cancellationInsideNestedInvocationCannotPublishPartialReturns() throws Exception {
    try (var f = new Fixture(CALL_A + SELECT, CALL_B + "c9", "3e02c9")) {
      var monitor = new ghidra.util.task.TaskMonitorAdapter(true) {
        int invocations;
        @Override public void setMessage(String message) {
          if (message.equals("Exploring bank states") && ++invocations == 3) cancel();
        }
      };
      var result = BankAnalysis.preview(f.p, ProgramMapping.staticAddress(f.p, "0150"), MapperState.reset(),
          AnalysisResult.Configuration.DEFAULT, monitor);
      assertEquals(AnalysisResult.Completion.CANCELLED, result.completion());
      assertTrue(result.findings().stream().noneMatch(x -> x.confidence() == AnalysisResult.Confidence.PROVEN));
    }
  }

  @Test void successfulNestedReturnCannotReplaceMissingOuterReturn() throws Exception {
    for (String a : List.of(CALL_B, CALL_B + "18fe", CALL_B + "e9")) refused(a, "3e02c9");
  }

  @Test void directAndMutualRecursionRefuse() throws Exception {
    refused("cd0003c9", "3e02c9");
    refused(CALL_B + "c9", "cd0003c9");
  }

  @Test void thirdActiveCallLevelRefusesWithoutPartialLeafEffects() throws Exception {
    try (var f = new Fixture(CALL_A + SELECT, CALL_B + "c9", "cd4003c9", "3e02c9", GameBoyKind.GB)) {
      var preview = f.preview(false, 4096);
      assertFalse(provesBank(preview, 2));
      assertTrue(writes(preview, 0x156, 0x2000).stream().allMatch(w -> w.value() == null));
      assertTrue(preview.steps().stream().noneMatch(s -> s.cpu() == 0x340));
    }
  }

  @Test void sequentialReentryOfReturnedCalleeComposes() throws Exception {
    chain(CALL_A, CALL_B + "cd2003c9", "3e02c9", 0x156, 2);
  }

  @Test void unknownIndirectNestedTransferCannotRecoverCall() throws Exception {
    refused("e9", "3e02c9");
  }

  @Test void exactHlJumpRetainsContainingFrameWithoutCreatingNestedCall() throws Exception {
    chain(CALL_A, "212003e9", "3e02c9", 0x156, 2);
  }

  @Test void nestedConditionalStateConflictIncompleteReturnRetiAndRstRemainExcluded() throws Exception {
    refused("cc2003c9", "3e02c9");
    for (String b : List.of("3e02c8e9", "3e02d9", "3e02ffc9")) refused(CALL_B + "c9", b);
  }

  @Test void sameNumericNestedReturnInDifferentPhysicalWramBankRefuses() throws Exception {
    // Outer frame D0FE/D0FF, nested frame D0FC/D0FD in bank 1. Forge 0303 in bank 2.
    try (var f = new Fixture("3100d1cd0003" + SELECT, CALL_B + "c9",
        "3e02e07031030308fcd031fcd03e02c9", "", GameBoyKind.CGB)) {
      assertNotEquals(MapperState.translate(ProgramMapping.cartridge(f.p), MapperState.reset(), 0xd0fc, false).physical(),
          MapperState.translate(ProgramMapping.cartridge(f.p), MapperState.reset().write(ProgramMapping.cartridge(f.p), 0xff70, 2), 0xd0fc, false).physical());
      var preview = f.preview(false, 4096);
      assertFalse(provesBank(preview, 2));
      assertTrue(writes(preview, 0x156, 0x2000).stream().allMatch(w -> w.value() == null));
    }
  }

  @Test void nestedRetCannotPopOuterFrameEvenWithExactNumericReturn() throws Exception {
    refused(CALL_B + "c9", "31fecf31030308fecf31fecf3e02c9");
  }

  @Test void mapperInvalidatesNestedReturnToBankedOuterContinuation() throws Exception {
    try (var f = new Fixture("3100d0cd0040" + SELECT, "", "3e02ea0020c9")) {
      f.code("rom1::4000", CALL_B + "c9");
      var preview = f.preview(false, 4096);
      assertFalse(provesBank(preview, 2));
      assertTrue(writes(preview, 0x156, 0x2000).stream().allMatch(w -> w.value() == null));
      assertTrue(preview.steps().stream().noneMatch(s -> s.source().equals("rom1::4003")));
    }
  }

  @Test void nestedLocalAndSharedGlobalBudgetRemainBounded() throws Exception {
    try (var f = new Fixture(CALL_A + SELECT, CALL_B + "c9", "3e00".repeat(129) + "3e02c9")) {
      var local = f.preview(false, 4096);
      assertFalse(provesBank(local, 2));
      assertTrue(local.result().exploredStates() < 150);
      assertTrue(local.result().findings().stream().anyMatch(x -> x.reason().contains("callee state bound")));
      var global = f.preview(false, 8);
      assertEquals(AnalysisResult.Completion.STATE_LIMIT, global.result().completion());
      assertEquals(8, global.result().exploredStates());
      assertTrue(global.result().findings().stream().noneMatch(x -> x.confidence() == AnalysisResult.Confidence.PROVEN));
    }
  }

  @Test void returnedFlagsTraverseBothBoundariesAndMeetConflicts() throws Exception {
    chain(CALL_A + "f5c179", CALL_B + "c9", "012002c5f1c9", 0x159, 0x20);
    chain(CALL_A + "f5c179", CALL_B + "c9", diamond("012002c5f1", "013002c5f1") + "c9", 0x159, null);
  }

  @Test void currentRoundTripRetainsSchemaAndRejectsN4WithoutTransientState() throws Exception {
    try (var f = new Fixture(CALL_A + SELECT, CALL_B + "c9", "3e02c9")) {
      var result = f.preview(false, 4096).result();
      assertEquals("20260930-n8-finite-pointer-successor-1", result.engineVersion());
      assertEquals(3, result.schemaVersion());
      String json = ProgramMapping.JSON.toJson(result);
      assertEquals(result, AnalysisResult.read(json));
      assertThrows(IllegalArgumentException.class, () -> AnalysisResult.read(
          json.replace(AnalysisResult.ENGINE_VERSION, "20260930-n4-returning-call-1")));
      assertEquals(Set.of("schemaVersion", "engineVersion", "starts", "assumption", "entryPremises",
          "configuration", "completion", "exploredStates", "pendingStates", "fingerprint",
          "findings", "diagnostics"), com.google.gson.JsonParser.parseString(json).getAsJsonObject().keySet());
    }
  }
}
