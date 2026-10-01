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

/** Self-authored SM83 encodings, architectural flag meanings and physical frame oracles. */
class BankAnalysisConditionalCallRetTest extends IntegrationTest {
  private static final String SP = "3100d0";
  private static final String CALL_A = "cd0003";
  private static final String CALL_B = "cd2003";
  private static final String SELECT = "ea0020c30040";
  private static final int[] CALLS = {0xc4, 0xcc, 0xd4, 0xdc};
  private static final int[] RETS = {0xc0, 0xc8, 0xd0, 0xd8};

  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("N6 conditional microflow", getLanguage(), getLanguage().getDefaultCompilerSpec(), owner);

    Fixture(String caller, String a) throws Exception { this(caller, a, "", ""); }

    Fixture(String caller, String a, String b, String c) throws Exception {
      this(caller, a, b, c, GameBoyKind.GB);
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
      int tx = p.startTransaction("Defined N6 fixture bytes");
      try {
        for (int i = 0; i < code.length; i++) if (!code[i].isEmpty()) {
          var first = ProgramMapping.staticAddress(p, String.format("%04x", starts[i]));
          Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first,
              new AddressSet(first, first.add(code[i].length() / 2 - 1)));
        }
      } finally { p.endTransaction(tx, true); }
    }

    BankAnalysis.FetchPreview preview(boolean reverse) throws Exception { return preview(reverse, 4096); }

    BankAnalysis.FetchPreview preview(boolean reverse, int limit) throws Exception {
      return BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
          new AnalysisResult.Configuration(limit, reverse), TaskMonitor.DUMMY);
    }

    void code(String address, String hex) throws Exception {
      int tx = p.startTransaction("Defined physical banked N6 bytes");
      try {
        var first = ProgramMapping.staticAddress(p, address);
        byte[] bytes = HexFormat.of().parseHex(hex);
        p.getMemory().setBytes(first, bytes);
        Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first,
            new AddressSet(first, first.add(bytes.length - 1)));
      } finally { p.endTransaction(tx, true); }
    }

    @Override public void close() { p.release(owner); }
  }

  // LD BC,01ff / PUSH BC / POP AF establishes A=1 and exactly the authored F byte.
  // This avoids relying on reset flags or on an unrelated instruction's inferred predicate.
  private static String flags(int f) { return "01" + String.format("%02x", f) + "01c5f1"; }
  private static String opcode(int op) { return String.format("%02x", op); }
  private static boolean taken(int condition, int f) {
    return switch (condition) {
      case 0 -> (f & 0x80) == 0;
      case 1 -> (f & 0x80) != 0;
      case 2 -> (f & 0x10) == 0;
      default -> (f & 0x10) != 0;
    };
  }

  private static List<BankAnalysis.WriteTransition> writes(BankAnalysis.FetchPreview preview, int source, int cpu) {
    return preview.steps().stream().filter(s -> s.cpu() == source).flatMap(s -> s.writes().stream())
        .filter(w -> w.cpu() == cpu).toList();
  }

  private static List<BankAnalysis.WriteTransition> selectors(BankAnalysis.FetchPreview preview) {
    return preview.steps().stream().filter(s -> s.cpu() < 0x300).flatMap(s -> s.writes().stream())
        .filter(w -> w.cpu() == 0x2000).toList();
  }

  private static void selects(BankAnalysis.FetchPreview preview, Integer expected) {
    var stores = selectors(preview);
    assertFalse(stores.isEmpty());
    assertTrue(stores.stream().allMatch(w -> Objects.equals(expected, w.value())), stores.toString());
    if (expected != null) assertTrue(preview.result().findings().stream().anyMatch(f -> f.access().equals("jump")
        && f.confidence() == AnalysisResult.Confidence.PROVEN && f.targets().equals(List.of("rom" + expected + "::4000"))));
    else assertFalse(preview.result().findings().stream().anyMatch(f -> f.access().equals("jump")
        && f.confidence() == AnalysisResult.Confidence.PROVEN && f.targets().equals(List.of("rom2::4000"))));
  }

  private static boolean visited(BankAnalysis.FetchPreview preview, int cpu) {
    return preview.steps().stream().anyMatch(s -> s.cpu() == cpu);
  }

  @Test void allFourCompiledGuardsPrecedeActualArchitecturalEffects() throws Exception {
    for (int i = 0; i < 4; i++) try (var f = new Fixture(SP + opcode(CALLS[i]) + "0003" + SELECT, opcode(RETS[i]) + "c9")) {
      for (int site : new int[] {0x153, 0x300}) {
        var ins = f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, String.format("%04x", site)));
        var ops = Arrays.asList(ins.getPcode(false));
        var guards = ops.stream().filter(op -> op.getOpcode() == PcodeOp.CBRANCH).toList();
        assertEquals(1, guards.size());
        var guard = guards.get(0);
        assertEquals(site + ins.getLength(), guard.getInput(0).getOffset());
        assertTrue(guard.getInput(0).isAddress());
        assertEquals(1, guard.getInput(1).getSize());
        assertTrue(guard.getInput(1).isUnique());
        int gate = ops.indexOf(guard);
        assertTrue(ops.subList(0, gate).stream().flatMap(op -> Arrays.stream(op.getInputs()))
            .anyMatch(v -> v.isRegister() && v.getAddress().equals(f.p.getRegister("F").getAddress())));
        int memoryOpcode = site == 0x153 ? PcodeOp.STORE : PcodeOp.LOAD;
        int flowOpcode = site == 0x153 ? PcodeOp.CALL : PcodeOp.RETURN;
        assertEquals(2, ops.stream().filter(op -> op.getOpcode() == memoryOpcode).count());
        assertEquals(1, ops.stream().filter(op -> op.getOpcode() == flowOpcode).count());
        assertTrue(ops.subList(0, gate).stream().noneMatch(op -> op.getOpcode() == memoryOpcode));
        assertEquals(flowOpcode, ops.get(ops.size() - 1).getOpcode());
        assertTrue(ops.subList(gate + 1, ops.size()).stream().anyMatch(op -> op.getOutput() != null
            && op.getOutput().getAddress().equals(f.p.getRegister("SP").getAddress())));
      }
    }
  }

  @Test void allFourCallConditionsUseIndependentArchitecturalZAndC() throws Exception {
    for (int condition = 0; condition < 4; condition++) for (int fbits : new int[] {0, 0x10, 0x80, 0x90}) {
      String caller = SP + flags(fbits) + opcode(CALLS[condition]) + "0003" + SELECT;
      try (var f = new Fixture(caller, "3e02c9")) {
        for (boolean reverse : List.of(false, true)) {
          var preview = f.preview(reverse);
          boolean executes = taken(condition, fbits);
          selects(preview, executes ? 2 : 1);
          assertEquals(executes, visited(preview, 0x300));
          assertEquals(executes ? List.of(1) : List.of(), writes(preview, 0x158, 0xcfff).stream().map(BankAnalysis.WriteTransition::value).toList());
          assertEquals(executes ? List.of(0x5b) : List.of(), writes(preview, 0x158, 0xcffe).stream().map(BankAnalysis.WriteTransition::value).toList());
        }
      }
    }
  }

  @Test void allFourRetConditionsPreserveOrConsumeTheActualFrame() throws Exception {
    for (int condition = 0; condition < 4; condition++) for (int fbits : new int[] {0, 0x10, 0x80, 0x90}) {
      try (var f = new Fixture(SP + flags(fbits) + CALL_A + "0810c0" + SELECT,
          "3e02" + opcode(RETS[condition]) + "0812c03e03c9")) {
        for (boolean reverse : List.of(false, true)) {
          var preview = f.preview(reverse);
          boolean returns = taken(condition, fbits);
          selects(preview, returns ? 2 : 3);
          assertEquals(!returns, visited(preview, 0x303));
          assertEquals(List.of(0), writes(preview, 0x15b, 0xc010).stream().map(BankAnalysis.WriteTransition::value).toList());
          assertEquals(List.of(0xd0), writes(preview, 0x15b, 0xc011).stream().map(BankAnalysis.WriteTransition::value).toList());
          if (!returns) {
            assertEquals(List.of(0xfe), writes(preview, 0x303, 0xc012).stream().map(BankAnalysis.WriteTransition::value).toList());
            assertEquals(List.of(0xcf), writes(preview, 0x303, 0xc013).stream().map(BankAnalysis.WriteTransition::value).toList());
          }
        }
      }
    }
  }

  @Test void falseCallPreservesSpRamAndFlagsAndNeverExecutesInvalidCallee() throws Exception {
    // Z=1 rejects CALL NZ. The callee is invalid; no taken frame may be required.
    try (var f = new Fixture(SP + "2100c03602" + flags(0x80) + "c400030810c0f5c179ea11c02100c07e" + SELECT, "d3")) {
      var preview = f.preview(false);
      selects(preview, 2);
      assertFalse(visited(preview, 0x300));
      assertEquals(List.of(0), writes(preview, 0x160, 0xc010).stream().map(BankAnalysis.WriteTransition::value).toList());
      assertEquals(List.of(0xd0), writes(preview, 0x160, 0xc011).stream().map(BankAnalysis.WriteTransition::value).toList());
      assertEquals(List.of(0x80), writes(preview, 0x166, 0xc011).stream().map(BankAnalysis.WriteTransition::value).toList());
    }
  }

  @Test void unknownCallSplitsRealPushFromUntakenStateAndMeetsReturnedRegister() throws Exception {
    try (var f = new Fixture(SP + "3e01c40003" + SELECT, "3e02c9")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        assertTrue(visited(preview, 0x300));
        assertTrue(visited(preview, 0x158));
        var callSteps = preview.steps().stream().filter(s -> s.cpu() == 0x155).toList();
        assertTrue(callSteps.stream().anyMatch(s -> s.writes().size() == 2));
        assertTrue(callSteps.stream().anyMatch(s -> s.writes().isEmpty()));
        assertEquals(List.of(1), writes(preview, 0x155, 0xcfff).stream().map(BankAnalysis.WriteTransition::value).toList());
        assertEquals(List.of(0x58), writes(preview, 0x155, 0xcffe).stream().map(BankAnalysis.WriteTransition::value).toList());
        assertEquals(Set.of(1, 2), new HashSet<>(selectors(preview).stream().map(BankAnalysis.WriteTransition::value).toList()));
        assertFalse(preview.result().findings().stream().anyMatch(x -> x.access().equals("jump") && x.confidence() == AnalysisResult.Confidence.PROVEN));
      }
    }
  }

  @Test void unknownRetSplitsReturnAndFallthroughWithoutPoppingTheFalseFrame() throws Exception {
    try (var f = new Fixture(SP + CALL_A + "0810c0" + SELECT, "3e02c00812c0c9")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        selects(preview, 2);
        assertTrue(visited(preview, 0x302));
        assertTrue(visited(preview, 0x303));
        assertTrue(visited(preview, 0x306));
        assertEquals(List.of(0xfe), writes(preview, 0x303, 0xc012).stream().map(BankAnalysis.WriteTransition::value).toList());
        assertEquals(List.of(0xcf), writes(preview, 0x303, 0xc013).stream().map(BankAnalysis.WriteTransition::value).toList());
        assertEquals(List.of(0), writes(preview, 0x156, 0xc010).stream().map(BankAnalysis.WriteTransition::value).toList());
        assertEquals(List.of(0xd0), writes(preview, 0x156, 0xc011).stream().map(BankAnalysis.WriteTransition::value).toList());
      }
    }
  }

  @Test void unknownZAndCProduceBothOutcomesForEveryEncoding() throws Exception {
    for (int i = 0; i < 4; i++) {
      try (var f = new Fixture(SP + "3e02" + opcode(CALLS[i]) + "0003" + SELECT, "3e02c9")) {
        var preview = f.preview(false);
        selects(preview, 2);
        assertTrue(visited(preview, 0x300));
        assertTrue(preview.steps().stream().anyMatch(s -> s.cpu() == 0x155 && s.writes().isEmpty()));
        assertTrue(preview.steps().stream().anyMatch(s -> s.cpu() == 0x155 && s.writes().size() == 2));
      }
      try (var f = new Fixture(SP + CALL_A + SELECT, "3e02" + opcode(RETS[i]) + "c9")) {
        var preview = f.preview(false);
        selects(preview, 2);
        assertTrue(visited(preview, 0x303));
      }
    }
  }

  @Test void conditionalCallAndRetPreserveActualReturnedFlags() throws Exception {
    // Z=0 makes both CALL NZ and RET NZ taken. Callee changes F to C=1,Z=0.
    try (var f = new Fixture(SP + flags(0) + "c40003f5c179ea10c03e02" + SELECT, flags(0x10) + "c0")) {
      var preview = f.preview(false);
      selects(preview, 2);
      assertEquals(List.of(0x10), writes(preview, 0x15e, 0xc010).stream().map(BankAnalysis.WriteTransition::value).toList());
    }
  }

  @Test void nestedTakenCallPropagatesActualRegisterRamMapperAndSeparateStackBytes() throws Exception {
    try (var f = new Fixture(SP + flags(0) + CALL_A + "2100c07e" + SELECT,
        "c420032100407eea01c078ea02c0c9", "3e03ea00202100c036020602c9", "")) {
      var preview = f.preview(false);
      selects(preview, 2);
      assertEquals(List.of(3), writes(preview, 0x307, 0xc001).stream().map(BankAnalysis.WriteTransition::value).toList());
      assertEquals(List.of(2), writes(preview, 0x30b, 0xc002).stream().map(BankAnalysis.WriteTransition::value).toList());
      assertEquals(List.of(0xcfff, 0xcffe), preview.steps().stream().filter(s -> s.cpu() == 0x158)
          .flatMap(s -> s.writes().stream()).map(BankAnalysis.WriteTransition::cpu).toList());
      assertEquals(List.of(0xcffd, 0xcffc), preview.steps().stream().filter(s -> s.cpu() == 0x300)
          .flatMap(s -> s.writes().stream()).map(BankAnalysis.WriteTransition::cpu).toList());
    }
  }

  @Test void conditionalRetAtBothNestedDepthsKeepsTheTopFrame() throws Exception {
    for (boolean inner : List.of(false, true)) try (var f = new Fixture(SP + CALL_A + SELECT,
        inner ? CALL_B + "c9" : "3e02c0" + CALL_B + "c9",
        inner ? "3e02c0c9" : "3e02c9", "")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        selects(preview, 2);
        assertTrue(visited(preview, inner ? 0x323 : 0x303));
      }
    }
  }

  @Test void conditionalCallTargetsEstablishedPhysicalBankAndConditionalRetReturns() throws Exception {
    try (var f = new Fixture(SP + flags(0) + "c40040" + SELECT, "")) {
      f.code("rom1::4000", "3e02c0");
      var preview = f.preview(false);
      selects(preview, 2);
      assertTrue(preview.steps().stream().anyMatch(s -> s.source().equals("rom1::4000")));
      assertTrue(preview.result().findings().stream().anyMatch(x -> x.access().equals("call")
          && x.targets().equals(List.of("rom1::4000")) && x.confidence() == AnalysisResult.Confidence.PROVEN));
    }
  }

  @Test void conditionalCallFromOverlayUsesActualPhysicalContinuationMapper() throws Exception {
    for (boolean remaps : List.of(false, true)) try (var f = new Fixture(SP + flags(0) + "cd0040" + SELECT,
        "", remaps ? "3e02ea0020c0" : "3e02c0", "")) {
      f.code("rom1::4000", "c42003c9");
      var ins = f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, "rom1::4000"));
      var call = Arrays.stream(ins.getPcode(false)).filter(op -> op.getOpcode() == PcodeOp.CALL).findFirst().orElseThrow();
      assertEquals(0x320, call.getInput(0).getOffset());
      assertEquals(0x320, ins.getDefaultFlows()[0].getOffset());
      assertEquals(0x4003, ins.getFallThrough().getOffset());
      var preview = f.preview(false);
      selects(preview, remaps ? null : 2);
      assertEquals(!remaps, preview.steps().stream().anyMatch(s -> s.source().equals("rom1::4003")));
    }
  }

  @Test void knownFalseDepthThreeCallContinuesButReachableThirdFrameRefuses() throws Exception {
    for (Integer fbits : Arrays.asList(0x80, 0, null)) {
      String prefix = fbits == null ? "3e02" : flags(fbits) + "3e02";
      try (var f = new Fixture(SP + CALL_A + SELECT, CALL_B + "c9", prefix + "c44003c9", "3e03c9")) {
        var preview = f.preview(false);
        selects(preview, Objects.equals(0x80, fbits) ? 2 : null);
        assertFalse(visited(preview, 0x340));
        if (!Objects.equals(0x80, fbits)) assertTrue(preview.result().findings().stream().anyMatch(x -> x.reason().contains("depth")));
      }
    }
  }

  @Test void knownFalseSelfAndMutualRecursionDoNotExecuteButReachableRecursionRefuses() throws Exception {
    for (boolean mutual : List.of(false, true)) for (Integer fbits : Arrays.asList(0x80, 0, null)) {
      String prefix = fbits == null ? "3e02" : flags(fbits) + "3e02";
      try (var f = new Fixture(SP + CALL_A + SELECT,
          mutual ? CALL_B + "c9" : prefix + "c40003c9",
          mutual ? prefix + "c40003c9" : "", "")) {
        var preview = f.preview(false);
        selects(preview, Objects.equals(0x80, fbits) ? 2 : null);
      }
    }
  }

  @Test void conflictingConditionalRetRegistersAndRamBecomeUnknown() throws Exception {
    for (String continuation : List.of("", "2100c07e")) {
      try (var f = new Fixture(SP + CALL_A + continuation + SELECT,
          "2100c036023e02c036033e03c9")) {
        selects(f.preview(false), null);
        selects(f.preview(true), null);
      }
    }
  }

  @Test void conflictingConditionalRetMapperCannotSelectOneReturningPath() throws Exception {
    try (var f = new Fixture(SP + CALL_A + SELECT, "3e02c03e03ea00203e02c9")) {
      selects(f.preview(false), null);
      selects(f.preview(true), null);
    }
  }

  @Test void unknownNestedCallCannotChooseCalleeMapperOrDiscardFalseRamState() throws Exception {
    // Taken arm replaces caller RAM and selects bank 3; false arm retains RAM=1, bank 1.
    try (var f = new Fixture(SP + "2100c03601" + CALL_A + "2100c07e" + SELECT,
        "c42003c9", "3e03ea00202100c03602c9", "")) {
      selects(f.preview(false), null);
      selects(f.preview(true), null);
    }
  }

  @Test void incompleteConditionalRetFallthroughCannotPublishSuccessfulReturn() throws Exception {
    for (String tail : List.of("e9", "d3", "18fe", "")) try (var f = new Fixture(SP + CALL_A + SELECT, "3e02c0" + tail)) {
      var preview = f.preview(false);
      selects(preview, null);
      assertFalse(preview.frontier().isEmpty());
    }
  }

  @Test void incompleteConditionalTakenCallCannotEscapeThroughItsFalseBranch() throws Exception {
    try (var f = new Fixture(SP + CALL_A + SELECT, "3e02c42003c9", "e9", "")) {
      selects(f.preview(false), null);
      selects(f.preview(true), null);
    }
  }

  @Test void successfulTakenCallCannotHideIncompleteContainingFallthrough() throws Exception {
    try (var f = new Fixture(SP + CALL_A + SELECT, "3e02c42003e9", "3e02c9", "")) {
      selects(f.preview(false), null);
      selects(f.preview(true), null);
    }
  }

  @Test void secondDistinctConditionalTransferSiteMakesInvocationIncomplete() throws Exception {
    for (String a : List.of("3e02c0c8c9", "c42003c8c9")) try (var f = new Fixture(SP + CALL_A + SELECT, a, "3e02c9", "")) {
      var preview = f.preview(false);
      selects(preview, null);
      assertTrue(preview.result().findings().stream().anyMatch(x -> x.reason().contains("conditional")));
    }
  }

  @Test void conditionalPathsShareTheExistingGlobalStateBudget() throws Exception {
    try (var f = new Fixture(SP + CALL_A + SELECT, "3e02c0c9")) {
      var preview = f.preview(false, 4);
      assertEquals(AnalysisResult.Completion.STATE_LIMIT, preview.result().completion());
      assertEquals(4, preview.result().exploredStates());
      assertTrue(preview.result().findings().stream().noneMatch(x -> x.confidence() == AnalysisResult.Confidence.PROVEN));
    }
  }

  @Test void trueConditionalRetCannotConsumeCorruptedOrNumericallyForgedFrame() throws Exception {
    for (String a : List.of("21fecf3600c0", "315b0108fccf31fccf3e02c0")) {
      try (var f = new Fixture(SP + flags(0) + "c40003" + SELECT, a)) {
        selects(f.preview(false), null);
      }
    }
  }

  @Test void conditionalRetCannotImpersonatePhysicalStackBytesInAnotherWramBank() throws Exception {
    // The numeric return 015B and restored SP D100 match, but the forged word is bank 2.
    try (var f = new Fixture("3100d1" + flags(0) + "c40003" + SELECT,
        "3e02e070315b0108fed031fed03e02c0", "", "", GameBoyKind.CGB)) {
      var cartridge = ProgramMapping.cartridge(f.p);
      assertNotEquals(MapperState.translate(cartridge, MapperState.reset(), 0xd0fe, false).physical(),
          MapperState.translate(cartridge, MapperState.reset().write(cartridge, 0xff70, 2), 0xd0fe, false).physical());
      selects(f.preview(false), null);
    }
  }

  @Test void conditionalInvocationRetainsTheExistingLocalCalleeCap() throws Exception {
    try (var f = new Fixture(SP + flags(0) + "c40003" + SELECT, "3e00".repeat(129) + "3e02c9")) {
      var preview = f.preview(false);
      selects(preview, null);
      assertTrue(preview.result().exploredStates() < 150);
      assertTrue(preview.result().findings().stream().anyMatch(x -> x.reason().contains("callee state bound")));
    }
  }

  @Test void reprocessingOneConditionalSiteAfterRamJoinDoesNotSpendAnotherSite() throws Exception {
    // The ordinary JR diamond supplies different physical RAM facts to the same source site.
    String diamond = "28072100c0360118072100c036021800";
    try (var f = new Fixture(SP + "3e02" + CALL_A + SELECT, diamond + "c42003c9", "3e02c9", "")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse);
        selects(preview, 2);
        assertTrue(preview.steps().stream().filter(s -> s.cpu() == 0x310).count() > 1);
        assertTrue(preview.result().findings().stream().noneMatch(x -> x.reason().contains("second conditional")));
      }
    }
  }

  @Test void knownFlagsDoNotTurnOrdinaryConditionalJrIntoANewPredicateInterpreter() throws Exception {
    try (var f = new Fixture(SP + flags(0) + CALL_A + SELECT, "28043e0118043e021800c9")) {
      selects(f.preview(false), null);
      selects(f.preview(true), null);
    }
  }

  @Test void n6RoundTripRejectsN5AndRetainsSchemaWithoutTransientMicroflow() throws Exception {
    try (var f = new Fixture(SP + flags(0) + "c40003" + SELECT, "3e02c9")) {
      var result = f.preview(false).result();
      assertEquals("20260930-n6-conditional-call-ret-1", result.engineVersion());
      assertEquals(3, result.schemaVersion());
      String json = ProgramMapping.JSON.toJson(result);
      assertEquals(result, AnalysisResult.read(json));
      assertThrows(IllegalArgumentException.class, () -> AnalysisResult.read(
          json.replace(AnalysisResult.ENGINE_VERSION, "20260930-n5-nested-returning-call-1")));
      assertEquals(Set.of("schemaVersion", "engineVersion", "starts", "assumption", "entryPremises",
          "configuration", "completion", "exploredStates", "pendingStates", "fingerprint",
          "findings", "diagnostics"), com.google.gson.JsonParser.parseString(json).getAsJsonObject().keySet());
    }
  }
}
