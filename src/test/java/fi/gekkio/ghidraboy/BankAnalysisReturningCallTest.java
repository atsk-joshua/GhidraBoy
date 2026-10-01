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

/** Self-authored architectural CALL/RET and physical-state composition counterexamples. */
class BankAnalysisReturningCallTest extends IntegrationTest {
  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("N4 returning call", getLanguage(), getLanguage().getDefaultCompilerSpec(), owner);

    Fixture(String caller, String callee) throws Exception {
      this(caller, callee, "");
    }

    Fixture(String caller, String callee, String nested) throws Exception {
      this(caller, callee, nested, GameBoyKind.GB);
    }

    Fixture(String caller, String callee, String nested, GameBoyKind hardware) throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      bytes[0x4000] = 1;
      bytes[0x8000] = 2;
      byte[] callerBytes = HexFormat.of().parseHex(caller);
      byte[] calleeBytes = HexFormat.of().parseHex(callee);
      byte[] nestedBytes = HexFormat.of().parseHex(nested);
      System.arraycopy(callerBytes, 0, bytes, 0x150, callerBytes.length);
      System.arraycopy(calleeBytes, 0, bytes, 0x300, calleeBytes.length);
      System.arraycopy(nestedBytes, 0, bytes, 0x320, nestedBytes.length);
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", hardware, true, true,
            TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("N4 defined instructions");
      try {
        define(0x150, callerBytes.length);
        if (calleeBytes.length != 0) define(0x300, calleeBytes.length);
        if (nestedBytes.length != 0) define(0x320, nestedBytes.length);
      } finally { p.endTransaction(tx, true); }
    }

    private void define(int start, int length) throws Exception {
      var first = ProgramMapping.staticAddress(p, String.format("%04x", start));
      var last = ProgramMapping.staticAddress(p, String.format("%04x", start + length - 1));
      Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first, new AddressSet(first, last));
    }

    BankAnalysis.FetchPreview preview(boolean reverse, int limit) throws Exception {
      return BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
          new AnalysisResult.Configuration(limit, reverse), TaskMonitor.DUMMY);
    }

    @Override public void close() { p.release(owner); }
  }

  private static final String CALL = "3100d0cd0003";
  private static final String SELECT = "ea0020c30040";

  private static String diamond(String left, String right) {
    return "28" + String.format("%02x", left.length() / 2 + 2) + left
        + "18" + String.format("%02x", right.length() / 2 + 2) + right + "1800";
  }

  private static List<BankAnalysis.WriteTransition> selectors(BankAnalysis.FetchPreview preview) {
    return preview.steps().stream().flatMap(s -> s.writes().stream())
        .filter(w -> w.cpu() == 0x2000).toList();
  }

  private static boolean provesRom2(BankAnalysis.FetchPreview preview) {
    return preview.result().findings().stream().anyMatch(f -> f.access().equals("jump")
        && f.confidence() == AnalysisResult.Confidence.PROVEN
        && f.targets().equals(List.of("rom2::4000")));
  }

  private void check(String callee, String continuation, Integer expected) throws Exception {
    try (var f = new Fixture(CALL + continuation + SELECT, callee)) {
      var forward = f.preview(false, 4096);
      var reverse = f.preview(true, 4096);
      assertEquals(AnalysisResult.Completion.COMPLETE, forward.result().completion());
      assertFalse(selectors(forward).isEmpty());
      assertTrue(selectors(forward).stream().allMatch(w -> Objects.equals(expected, w.value())));
      assertEquals(expected != null, provesRom2(forward));
      assertEquals(forward.result().findings(), reverse.result().findings());
    }
  }

  private void refused(String caller, String callee) throws Exception {
    try (var f = new Fixture(caller + SELECT, callee)) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse, 4096);
        assertFalse(provesRom2(preview));
        assertTrue(selectors(preview).stream().allMatch(w -> w.value() == null));
      }
    }
  }

  @Test void rawCallPushAndRetPopEstablishArchitecturalFrame() throws Exception {
    try (var f = new Fixture(CALL + SELECT, "3e02c9")) {
      var call = f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, "0153"));
      var ret = f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, "0302"));
      var callOps = Arrays.asList(call.getPcode(false));
      var retOps = Arrays.asList(ret.getPcode(false));
      assertEquals(2, callOps.stream().filter(op -> op.getOpcode() == PcodeOp.STORE).count());
      assertEquals(1, callOps.stream().filter(op -> op.getOpcode() == PcodeOp.CALL).count());
      assertEquals(2, retOps.stream().filter(op -> op.getOpcode() == PcodeOp.LOAD).count());
      assertEquals(1, retOps.stream().filter(op -> op.getOpcode() == PcodeOp.RETURN).count());
      assertTrue(callOps.stream().anyMatch(op -> op.getOutput() != null
          && op.getOutput().isRegister() && op.getOutput().getAddress().equals(f.p.getRegister("SP").getAddress())));
      assertTrue(retOps.stream().anyMatch(op -> op.getOutput() != null
          && op.getOutput().isRegister() && op.getOutput().getAddress().equals(f.p.getRegister("SP").getAddress())));
      assertTrue(retOps.stream().anyMatch(op -> op.getOutput() != null
          && op.getOutput().isRegister() && op.getOutput().getAddress().equals(f.p.getRegister("PC").getAddress())));
      assertArrayEquals(new ghidra.program.model.address.Address[] {ProgramMapping.staticAddress(f.p, "0300")}, call.getDefaultFlows());
      assertEquals(ProgramMapping.staticAddress(f.p, "0156"), call.getFallThrough());
      var preview = f.preview(false, 4096);
      var writes = preview.steps().stream().filter(s -> s.cpu() == 0x153).flatMap(s -> s.writes().stream()).toList();
      assertEquals(List.of(0xcfff, 0xcffe), writes.stream().map(BankAnalysis.WriteTransition::cpu).toList());
      assertEquals(List.of(1, 0x56), writes.stream().map(BankAnalysis.WriteTransition::value).toList());
      assertTrue(preview.steps().stream().anyMatch(s -> s.cpu() == 0x302));
      assertTrue(provesRom2(preview));
    }
  }

  @Test void returnedRegisterSelectsPhysicalBank() throws Exception { check("3e02c9", "", 2); }

  @Test void returnedRamFeedsCallerLoad() throws Exception { check("2100c03602c9", "2100c07e", 2); }

  @Test void returnedMapperSelectsCallerRomRead() throws Exception {
    check("3e02ea0020c9", "2100407e", 2);
  }

  @Test void differingReturnedRegistersDoNotSelectAnObservedValue() throws Exception {
    check(diamond("3e01", "3e02") + "c9", "", null);
  }

  @Test void differingReturnedMappersCannotChooseOneReturnPath() throws Exception {
    String callee = diamond("3e01ea00203e02", "3e02ea00203e02") + "c9";
    try (var f = new Fixture(CALL + SELECT, callee)) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse, 4096);
        assertFalse(provesRom2(preview));
        var callerWrites = preview.steps().stream().filter(s -> s.cpu() == 0x156)
            .flatMap(s -> s.writes().stream()).toList();
        assertFalse(callerWrites.isEmpty());
        assertTrue(callerWrites.stream().allMatch(w -> w.value() == null));
      }
    }
  }

  @Test void commonReturnedMemoryRetainsExactFact() throws Exception {
    check(diamond("2100c03602", "2100c03602") + "c9", "2100c07e", 2);
  }

  @Test void conflictingReturnedMemoryIsUnknown() throws Exception {
    check(diamond("2100c03601", "2100c03602") + "c9", "2100c07e", null);
  }

  @Test void missingReturnedMemoryIsUnknown() throws Exception {
    check(diamond("2100c03602", "2100c000") + "c9", "2100c07e", null);
  }

  @Test void sharedByteSurvivesIndependentConflict() throws Exception {
    String callee = diamond("2100c03602233603", "2100c03602233604") + "c9";
    check(callee, "2100c07e", 2);
    check(callee, "2101c07e", null);
  }

  @Test void returnedEchoFactsUsePhysicalIdentity() throws Exception {
    check(diamond("2100c03602", "2100e03602") + "2100c0c9", "2100e07e", 2);
  }

  @Test void callerFactMustSurviveActualCalleeInstructions() throws Exception {
    try (var f = new Fixture("2100c03602" + CALL + "2100c07e" + SELECT, "00c9")) {
      assertTrue(provesRom2(f.preview(false, 4096)));
    }
  }

  @Test void unknownOverwriteDoesNotPreserveCallerFact() throws Exception {
    refused("2100c03602" + CALL + "2100c07e", "2100c070c9");
  }

  @Test void unknownPointerWriteCannotProveReturnFrame() throws Exception {
    refused(CALL + "2100c07e", "2100c0360212c9");
  }

  @Test void deviceWriteCannotPreserveRamOrReturnFrame() throws Exception {
    refused(CALL + "2100c07e", "2100c036023e02e000c9");
  }

  @Test void exhaustedAndNonreturningPathsAreNotReturns() throws Exception {
    refused(CALL, "3e02");
    refused(CALL, "3e0218fe");
    refused(CALL, "3e02e9");
    refused(CALL, "");
  }

  @Test void nestedAndRecursiveOrdinaryCallsFailClosed() throws Exception {
    try (var f = new Fixture(CALL + SELECT, "cd20033e02c9", "3e02c9")) {
      var preview = f.preview(false, 4096);
      assertNotNull(f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, "0320")));
      assertFalse(provesRom2(preview));
      assertTrue(selectors(preview).stream().allMatch(w -> w.value() == null));
    }
    refused(CALL, "cd00033e02c9");
  }

  @Test void corruptedReturnWordCannotCompose() throws Exception {
    refused(CALL, "21fecf3600c9");
  }

  @Test void wrongRestoredStackPointerCannotComposeEvenMatchingWord() throws Exception {
    // The same return PC is at CFFC, but RET would restore CFFE rather than the caller's D000.
    refused(CALL, "31560108fccf31fccf3e02c9");
  }

  @Test void conditionalReturnAndUnknownEntrySpRemainExcluded() throws Exception {
    refused(CALL, "3e02c8c9");
    refused("cd0003", "3e02c9");
  }

  @Test void calleeStateLimitCannotProduceProvenContinuation() throws Exception {
    try (var f = new Fixture(CALL + SELECT, "000000003e02c9")) {
      var preview = f.preview(false, 3);
      assertEquals(AnalysisResult.Completion.STATE_LIMIT, preview.result().completion());
      assertFalse(provesRom2(preview));
      assertTrue(preview.result().findings().stream().noneMatch(x -> x.confidence() == AnalysisResult.Confidence.PROVEN));
    }
  }

  @Test void n4RoundTripRejectsN3WithoutSerializingFramesOrMemory() throws Exception {
    try (var f = new Fixture(CALL + SELECT, "3e02c9")) {
      var result = f.preview(false, 4096).result();
      assertEquals("20260930-n4-returning-call-1", result.engineVersion());
      String json = ProgramMapping.JSON.toJson(result);
      assertEquals(result, AnalysisResult.read(json));
      assertEquals(3, result.schemaVersion());
      assertThrows(IllegalArgumentException.class, () -> AnalysisResult.read(
          json.replace(AnalysisResult.ENGINE_VERSION, "20260930-n3-memory-join-1")));
      assertEquals(Set.of("schemaVersion", "engineVersion", "starts", "assumption", "entryPremises",
          "configuration", "completion", "exploredStates", "pendingStates", "fingerprint",
          "findings", "diagnostics"), com.google.gson.JsonParser.parseString(json).getAsJsonObject().keySet());
    }
  }
  @Test void differentPhysicalStackBankCannotImpersonateCallFrame() throws Exception {
    // CALL writes bank-1 D0FE/D0FF. Callee selects WRAM bank 2 and forges identical numeric PC/SP.
    try (var f = new Fixture("3100d1cd0003" + SELECT,
        "3e02e07031560108fed031fed03e02c9", "", GameBoyKind.CGB)) {
      var preview = f.preview(false, 4096);
      var callerWrites = preview.steps().stream().filter(s -> s.cpu() == 0x156)
          .flatMap(s -> s.writes().stream()).toList();
      assertFalse(callerWrites.isEmpty());
      assertTrue(callerWrites.stream().allMatch(w -> w.value() == null));
      assertFalse(provesRom2(preview));
    }
  }

  @Test void localCalleeBudgetRefusesWithoutMultiplyingGlobalBound() throws Exception {
    try (var f = new Fixture(CALL + SELECT, "3e00".repeat(129) + "3e02c9")) {
      var preview = f.preview(false, 4096);
      assertFalse(provesRom2(preview));
      assertTrue(preview.result().exploredStates() < 150);
      assertTrue(preview.result().findings().stream().anyMatch(x -> x.reason().contains("callee state bound")));
    }
  }

  @Test void returnedFlagsAreActualRegisterFactsAndConflictsBecomeUnknown() throws Exception {
    // PUSH BC / POP AF establishes A=2,F=20 independently of any ABI.
    try (var f = new Fixture(CALL + "f5c179" + SELECT, "012002c5f1c9")) {
      assertTrue(selectors(f.preview(false, 4096)).stream().allMatch(w -> Objects.equals(0x20, w.value())));
    }
    check(diamond("012002c5f1", "013002c5f1") + "c9", "f5c179", null);
  }

  @Test void rawCallFlowOverrideCannotAcquireArchitecturalProof() throws Exception {
    try (var f = new Fixture(CALL + SELECT, "3e02c9")) {
      int tx = f.p.startTransaction("Unsupported override");
      try { f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, "0153"))
          .setFlowOverride(ghidra.program.model.listing.FlowOverride.CALL_RETURN); }
      finally { f.p.endTransaction(tx, true); }
      var preview = f.preview(false, 4096);
      assertFalse(provesRom2(preview));
      assertTrue(preview.result().findings().stream().anyMatch(x -> x.reason().contains("flow override")));
    }
  }

  @Test void unknownPhysicalCallTargetStaysConservative() throws Exception {
    try (var f = new Fixture("3100d0cd0040" + SELECT, "3e02c9")) {
      var preview = BankAnalysis.previewFetch(f.p, ProgramMapping.staticAddress(f.p, "0150"), null,
          AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
      assertFalse(provesRom2(preview));
      assertTrue(preview.result().findings().stream().anyMatch(x -> x.access().equals("call") && x.targets().isEmpty()));
    }
  }

  @Test void missingDefinedContinuationCannotConsumeReturnedValue() throws Exception {
    try (var f = new Fixture(CALL + SELECT, "3e02c9")) {
      int tx = f.p.startTransaction("Unavailable continuation");
      try { f.p.getListing().clearCodeUnits(ProgramMapping.staticAddress(f.p, "0156"),
          ProgramMapping.staticAddress(f.p, "0158"), false); }
      finally { f.p.endTransaction(tx, true); }
      assertFalse(provesRom2(f.preview(false, 4096)));
    }
  }

  @Test void cancellationDuringCalleeCannotPublishReturnedProof() throws Exception {
    try (var f = new Fixture(CALL + SELECT, "3e02c9")) {
      var monitor = new ghidra.util.task.TaskMonitorAdapter(true) {
        int explorations;
        @Override public void setMessage(String message) {
          if (message.equals("Exploring bank states") && ++explorations == 2) cancel();
        }
      };
      var result = BankAnalysis.preview(f.p, ProgramMapping.staticAddress(f.p, "0150"), MapperState.reset(),
          AnalysisResult.Configuration.DEFAULT, monitor);
      assertEquals(AnalysisResult.Completion.CANCELLED, result.completion());
      assertTrue(result.findings().stream().noneMatch(x -> x.confidence() == AnalysisResult.Confidence.PROVEN));
    }
  }

  @Test void unresolvedAddressValuedCopyCannotAuthorizeReturnedSummary() throws Exception {
    // FA is an address-valued COPY, deliberately outside incumbent LOAD value propagation.
    refused(CALL, "fa00c03e02c9");
  }

  @Test void multipleStaticTargetViewsCannotSelectOneCallee() throws Exception {
    try (var f = new Fixture(CALL + SELECT, "3e02c9")) {
      int tx = f.p.startTransaction("Ambiguous target view");
      try {
        var address = ProgramMapping.staticAddress(f.p, "0300");
        var alias = f.p.getMemory().createByteMappedBlock("callee_alias", address, address, 3, true);
        alias.setExecute(true);
      } finally { f.p.endTransaction(tx, true); }
      var preview = f.preview(false, 4096);
      assertFalse(provesRom2(preview));
      assertTrue(selectors(preview).stream().allMatch(w -> w.value() == null));
    }
  }

}
