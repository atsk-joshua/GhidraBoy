package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Independent CPU-byte and physical-frame oracles for CALL-STACK-LIVENESS-2B. */
class BankAnalysisCallCoverageTest extends IntegrationTest {
  @TempDir Path temporary;

  private static final String CALL = "31feffcd0003";

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

  private static MapperState.Physical rom(int bank, int offset) {
    return new MapperState.Physical("ROM", bank, offset);
  }

  private static void proof(Fixture f, BankAnalysis.FetchPreview preview) {
    var proofs = preview.result().ordinaryCallProofs();
    assertEquals(1, proofs.size(), preview.result().findings().toString());
    var proof = proofs.get(0);
    assertEquals(String.format("%04x", f.site), proof.source());
    assertEquals(rom(0, f.site), proof.sourcePhysical());
    assertEquals("0300", proof.target());
    assertEquals(rom(0, 0x300), proof.targetPhysical());
    assertEquals(String.format("%04x", f.site + 3), proof.continuation());
    assertEquals(rom(0, f.site + 3), proof.continuationPhysical());
  }

  private static void unknownWrite(BankAnalysis.FetchPreview preview, int cpu) {
    var writes = preview.steps().stream().flatMap(s -> s.writes().stream())
        .filter(w -> w.cpu() == cpu).toList();
    assertFalse(writes.isEmpty(), "The continuation must actually execute its observed write");
    assertTrue(writes.stream().allMatch(w -> w.value() == null),
        "Unknown data must never become a loader-fill byte or inferred register value: " + writes);
  }

  private void admitted(String callee, String continuation, int unknownDestination) throws Exception {
    try (var f = new Fixture(CALL + continuation + "76", callee)) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse, 4096);
        proof(f, preview);
        if (unknownDestination >= 0) unknownWrite(preview, unknownDestination);
      }
    }
  }

  private void refused(String callee) throws Exception {
    try (var f = new Fixture(CALL + "76", callee)) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse, 4096);
        assertTrue(preview.result().findings().stream().anyMatch(x -> x.source().equals("0153")
            && x.access().equals("call") && x.targets().equals(List.of("0300"))));
        assertTrue(preview.result().ordinaryCallProofs().isEmpty(), callee);
      }
    }
  }

  @Test void immediateRetBaselineA() throws Exception { admitted("c9", "", -1); }

  @Test void supportedSvbkReadBReturnsWithUnknownA() throws Exception {
    // FF70 is a read of the CGB bank selector. Reset mapper knowledge is not a sampled byte.
    admitted("f070c9", "ea00c1", 0xc100);
  }

  @Test void unknownAfPushPopCRetainsExactReturnSlotsAndUnknownFlags() throws Exception {
    // PUSH AF writes FFFA/FFFB, below CALL's FFFC/FFFD; POP restores SP=FFFC.
    // Caller PUSH AF / POP BC / LD A,C exposes returned F without a register ABI premise.
    admitted("f5f1c9", "ea01c1f5c179ea00c1", 0xc100);
    try (var f = new Fixture(CALL + "ea01c1f5c179ea00c176", "f5f1c9")) {
      var preview = f.preview(false, 4096);
      var push = preview.steps().stream().filter(s -> s.source().equals("0300"))
          .flatMap(s -> s.writes().stream()).toList();
      assertEquals(List.of(0xfffb, 0xfffa), push.stream().map(BankAnalysis.WriteTransition::cpu).toList());
      assertTrue(push.stream().allMatch(w -> w.value() == null));
      proof(f, preview);
      unknownWrite(preview, 0xc100);
      unknownWrite(preview, 0xc101);
    }
  }

  @Test void knownWramUnknownStoreDKillsPriorDataButPreservesFrame() throws Exception {
    String prefix = "2100c1365a";
    try (var f = new Fixture(prefix + CALL + "2100c17eea01c176", "ea00c1c9", false, 0x158)) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse, 4096);
        proof(f, preview);
        unknownWrite(preview, 0xc101);
        assertTrue(preview.steps().stream().filter(s -> s.source().equals("0300"))
            .flatMap(s -> s.writes().stream()).anyMatch(w -> w.cpu() == 0xc100 && w.value() == null));
      }
    }
  }

  @Test void unknownMapperSelectorEAllowsFixedRomContinuation() throws Exception {
    // MBC5 low bank selection cannot change ROM0's 0156 continuation or HRAM frame.
    admitted("ea0020c9", "ea00c1", 0xc100);
  }

  @Test void exhaustiveConditionalReturnGMatchesOneContinuation() throws Exception {
    // F is initially unknown: RET NZ and fallthrough RET both consume the same exact word.
    admitted("c0c9", "", -1);
  }

  @Test void unknownNonControlOutputRegisterHStaysUnknown() throws Exception {
    admitted("47c9", "78ea00c1", 0xc100);
  }

  @Test void supportedUnwrittenWramReadHasUnknownValueAndExactReturn() throws Exception {
    admitted("2100c17ec9", "ea01c1", 0xc101);
  }

  @Test void deviceReadReallyUsesRawLoadAndNeverSamplesResetValue() throws Exception {
    try (var f = new Fixture(CALL + "ea00c176", "3e5af070c9")) {
      var ops = Arrays.asList(f.p.getListing().getInstructionAt(
          ProgramMapping.staticAddress(f.p, "0302")).getPcode(false));
      assertTrue(ops.stream().anyMatch(op -> op.getOpcode() == PcodeOp.LOAD));
      var preview = f.preview(false, 4096);
      proof(f, preview);
      unknownWrite(preview, 0xc100);
    }
  }

  @Test void unknownAddressStoreStillRefuses() throws Exception { refused("77c9"); }

  @Test void overwrittenReturnSlotStillRefuses() throws Exception { refused("eafcffc9"); }

  @Test void unknownValueUsedAsPointerStillRefuses() throws Exception {
    refused("f0706f260077c9");
  }

  @Test void unsupportedOrUnresolvedReadsStillRefuseDespiteExactRet() throws Exception {
    for (String callee : List.of("7ec9", "21a0fe7ec9", "f000c9", "ea00202100407ec9"))
      refused(callee);
  }

  @Test void ambiguousBankedContinuationStillRefuses() throws Exception {
    try (var f = new Fixture(CALL + "76", "ea0020c9", true, 0x4003)) {
      assertTrue(f.preview(false, 4096).result().ordinaryCallProofs().isEmpty());
      assertTrue(f.preview(true, 4096).result().ordinaryCallProofs().isEmpty());
    }
  }

  @Test void oneNonreturningConditionalArmStillRefuses() throws Exception { refused("c076"); }

  @Test void wrongRestoredSpStillRefusesMatchingPc() throws Exception {
    // Forge 0156 at FFFA, then RET restores FFFC instead of the pre-CALL FFFE.
    refused("31560108faff31faffc9");
  }

  @Test void wrongPhysicalSlotIdentityStillRefusesMatchingPcAndSp() throws Exception {
    // CALL owns bank-1 D0FE/D0FF; selecting bank 2 and forging the same word is no return.
    try (var f = new Fixture("3100d1cd000376", "3e02e07031560108fed031fed0c9")) {
      assertTrue(f.preview(false, 4096).result().ordinaryCallProofs().isEmpty());
      assertTrue(f.preview(true, 4096).result().ordinaryCallProofs().isEmpty());
    }
  }

  @Test void missingRetCycleRecursionAndIncompleteExplorationStillRefuse() throws Exception {
    for (String callee : List.of("", "00", "18fe", "cd0003c9", "c0e9",
        "3e00".repeat(179) + "c9")) refused(callee);
  }

  @Test void globalStateLimitClearsEarlierMatchedReturnProof() throws Exception {
    try (var f = new Fixture(CALL + "000000000076", "f070c9")) {
      var preview = f.preview(false, 5);
      assertEquals(AnalysisResult.Completion.STATE_LIMIT, preview.result().completion());
      assertTrue(preview.result().ordinaryCallProofs().isEmpty());
    }
  }

  @Test void supportedUnknownReadAndAfStackRoundTripSurvivePackedReopen() throws Exception {
    for (String callee : List.of("f070c9", "f5f1c9")) {
      try (var f = new Fixture(CALL + "ea01c1f5c179ea00c176", callee)) {
        var original = f.preview(false, 4096);
        proof(f, original);
        unknownWrite(original, 0xc100);
        unknownWrite(original, 0xc101);
        BankAnalysis.apply(f.p, original.result(), TaskMonitor.DUMMY);
        var packed = temporary.resolve(callee + ".gzf").toFile();
        f.p.saveToPackedFile(packed, TaskMonitor.DUMMY);
        var database = PackedDatabase.getPackedDatabase(packed, true, TaskMonitor.DUMMY);
        Object owner = new Object();
        ProgramDB reopened = null;
        try {
          reopened = new ProgramDB(database.open(TaskMonitor.DUMMY), OpenMode.IMMUTABLE,
              TaskMonitor.DUMMY, owner);
          var stored = AnalysisResult.read(reopened.getOptions(ProgramMapping.OPTIONS)
              .getString("analysis.latest", null));
          assertEquals(original.result(), stored);
          ProgramFingerprint.requireCurrent(reopened, stored, TaskMonitor.DUMMY);
          var fresh = BankAnalysis.previewFetch(reopened, ProgramMapping.staticAddress(reopened, "0150"),
              MapperState.reset(), new AnalysisResult.Configuration(4096, false), TaskMonitor.DUMMY);
          assertEquals(stored, fresh.result());
          assertEquals(original.result().ordinaryCallProofs(), fresh.result().ordinaryCallProofs());
          unknownWrite(fresh, 0xc100);
          unknownWrite(fresh, 0xc101);
        } finally {
          if (reopened != null) reopened.release(owner);
          database.dispose();
        }
      }
    }
  }

  @Test void cancellationDuringSupportedUnknownReadCannotPublishProof() throws Exception {
    try (var f = new Fixture(CALL + "76", "f070c9")) {
      var monitor = new TaskMonitorAdapter(true) {
        int explorations;
        @Override public void setMessage(String message) {
          if (message.equals("Exploring bank states") && ++explorations == 2) cancel();
        }
      };
      var result = BankAnalysis.preview(f.p, ProgramMapping.staticAddress(f.p, "0150"), MapperState.reset(),
          AnalysisResult.Configuration.DEFAULT, monitor);
      assertEquals(AnalysisResult.Completion.CANCELLED, result.completion());
      assertTrue(result.ordinaryCallProofs().isEmpty());
    }
  }

  @Test void unavailableMutableBackingIsNotSupportedUnknownRead() throws Exception {
    try (var f = new Fixture(CALL + "76", "2100c17ec9")) {
      int tx = f.p.startTransaction("Remove canonical read eligibility");
      try { f.p.getMemory().getBlock(ProgramMapping.staticAddress(f.p, "c100")).setVolatile(true); }
      finally { f.p.endTransaction(tx, true); }
      assertTrue(f.preview(false, 4096).result().ordinaryCallProofs().isEmpty());
    }
  }
}
