package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.util.*;
import org.junit.jupiter.api.Test;

/** Independent self-authored byte/physical oracles for WUX-1P producer authority. */
class BankAnalysisOrdinaryCallProofTest extends IntegrationTest {
  private static final String CALL = "3100d0cd0003";
  private static final String STOP = "76";

  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("Ordinary call proof", getLanguage(), getLanguage().getDefaultCompilerSpec(), owner);

    Fixture(String caller, String a, String b, String c, GameBoyKind hardware) throws Exception {
      this(caller, a, b, c, hardware, 0x19);
    }

    Fixture(String caller, String a, String b, String c, GameBoyKind hardware, int mapper) throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = (byte) mapper;
      bytes[0x148] = 1;
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
      int tx = p.startTransaction("Define proof fixture");
      try {
        for (int i = 0; i < code.length; i++) if (!code[i].isEmpty())
          define(String.format("%04x", starts[i]), code[i].length() / 2);
      } finally { p.endTransaction(tx, true); }
    }

    Fixture(String caller, String a) throws Exception { this(caller, a, "", "", GameBoyKind.GB); }

    void define(String at, int length) throws Exception {
      var start = ProgramMapping.staticAddress(p, at);
      Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(start,
          new AddressSet(start, start.add(length - 1)));
    }

    void code(String at, String hex) throws Exception {
      int tx = p.startTransaction("Change physical proof dependency");
      try {
        var start = ProgramMapping.staticAddress(p, at);
        byte[] bytes = HexFormat.of().parseHex(hex);
        p.getListing().clearCodeUnits(start, start.add(bytes.length - 1), false);
        p.getMemory().setBytes(start, bytes);
        define(at, bytes.length);
      } finally { p.endTransaction(tx, true); }
    }

    BankAnalysis.FetchPreview preview(boolean reverse, int limit) throws Exception {
      return BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
          new AnalysisResult.Configuration(limit, reverse), TaskMonitor.DUMMY);
    }

    AnalysisResult result() throws Exception { return preview(false, 4096).result(); }
    @Override public void close() { p.release(owner); }
  }

  private static MapperState.Physical rom(int bank, int offset) {
    return new MapperState.Physical("ROM", bank, offset);
  }

  private static void exact(AnalysisResult.OrdinaryCallProof proof,
      String source, MapperState.Physical sourcePhysical, String target,
      MapperState.Physical targetPhysical, String continuation, MapperState.Physical continuationPhysical) {
    assertEquals(source, proof.source());
    assertEquals(sourcePhysical, proof.sourcePhysical());
    assertEquals(target, proof.target());
    assertEquals(targetPhysical, proof.targetPhysical());
    assertEquals(continuation, proof.continuation());
    assertEquals(continuationPhysical, proof.continuationPhysical());
  }

  private static BankAnalysis.Finding call(AnalysisResult result, String source) {
    return result.findings().stream().filter(f -> f.source().equals(source) && f.access().equals("call")
        && !f.targets().isEmpty()).findFirst().orElseThrow();
  }

  private static String diamond(String left, String right) {
    return "28" + String.format("%02x", left.length() / 2 + 2) + left
        + "18" + String.format("%02x", right.length() / 2 + 2) + right + "1800";
  }

  @Test void matchedReturnCarriesAllSixExactIdentities() throws Exception {
    try (var f = new Fixture(CALL + STOP, "3e02c9")) {
      var result = f.result();
      assertEquals(AnalysisResult.Completion.COMPLETE, result.completion());
      assertEquals(List.of("0300"), call(result, "0153").targets());
      assertEquals(1, result.ordinaryCallProofs().size());
      exact(result.ordinaryCallProofs().get(0), "0153", rom(0, 0x153), "0300", rom(0, 0x300),
          "0156", rom(0, 0x156));
    }
  }

  @Test void selectedBankRetainsPhysicalTargetRatherThanCpuOffset() throws Exception {
    for (int bank : List.of(1, 2)) try (var f = new Fixture("3100d03e0" + bank + "ea0020cd0040" + STOP, "")) {
      f.code("rom1::4000", "3e01c9");
      f.code("rom2::4000", "3e02c9");
      var result = f.result();
      assertEquals(1, result.ordinaryCallProofs().size());
      exact(result.ordinaryCallProofs().get(0), "0158", rom(0, 0x158), "rom" + bank + "::4000",
          rom(bank, 0), "015b", rom(0, 0x15b));
    }
  }

  @Test void nestedSitesHaveIndependentFrameAndContinuationIdentities() throws Exception {
    try (var f = new Fixture(CALL + STOP, "cd2003c9", "3e02c9", "", GameBoyKind.GB)) {
      var proofs = f.result().ordinaryCallProofs();
      assertEquals(2, proofs.size());
      exact(proofs.get(0), "0153", rom(0, 0x153), "0300", rom(0, 0x300), "0156", rom(0, 0x156));
      exact(proofs.get(1), "0300", rom(0, 0x300), "0320", rom(0, 0x320), "0303", rom(0, 0x303));
    }
  }

  @Test void overlaySourceAndContinuationRetainExecutionViewAndPhysicalBank() throws Exception {
    try (var f = new Fixture("3100d0cd0040" + STOP, "", "3e02c9", "", GameBoyKind.GB)) {
      f.code("rom1::4000", "cd2003c9");
      var proofs = f.result().ordinaryCallProofs();
      assertEquals(2, proofs.size());
      var inner = proofs.stream().filter(x -> x.source().equals("rom1::4000")).findFirst().orElseThrow();
      exact(inner, "rom1::4000", rom(1, 0), "0320", rom(0, 0x320), "rom1::4003", rom(1, 3));
    }
  }

  @Test void sequentialSitesRetainSeparateDeterministicCertificates() throws Exception {
    try (var f = new Fixture(CALL + STOP, "cd2003cd4003c9", "3e01c9", "3e02c9", GameBoyKind.GB)) {
      var forward = f.preview(false, 4096).result().ordinaryCallProofs();
      var reverse = f.preview(true, 4096).result().ordinaryCallProofs();
      assertEquals(3, forward.size());
      assertEquals(List.of("0153", "0300", "0303"), forward.stream().map(AnalysisResult.OrdinaryCallProof::source).toList());
      assertEquals(List.of("0156", "0303", "0306"), forward.stream().map(AnalysisResult.OrdinaryCallProof::continuation).toList());
      assertEquals(forward, reverse);
      assertEquals(ProgramMapping.JSON.toJson(forward), ProgramMapping.JSON.toJson(f.result().ordinaryCallProofs()));
    }
  }

  @Test void genericSingletonProvenCallCannotAuthorizeFailedComposition() throws Exception {
    try (var f = new Fixture("cd0003" + STOP, "3e02c9")) {
      var result = f.result();
      assertEquals(AnalysisResult.Completion.COMPLETE, result.completion());
      var observation = call(result, "0150");
      assertEquals(List.of("0300"), observation.targets());
      assertEquals(AnalysisResult.Confidence.PROVEN, observation.confidence());
      assertTrue(result.ordinaryCallProofs().isEmpty());
    }
  }

  @Test void realFrameAndCompletenessFailuresHaveNoCertificate() throws Exception {
    for (String callee : List.of("21fecf3600c9", "31560108fccf31fccf3e02c9",
        "3e02", "3e0218fe", "3e02e9", "3e02c8e9", "")) {
      try (var f = new Fixture(CALL + STOP, callee)) {
        for (boolean reverse : List.of(false, true)) {
          var result = f.preview(reverse, 4096).result();
          assertEquals(List.of("0300"), call(result, "0153").targets());
          assertTrue(result.ordinaryCallProofs().isEmpty(), callee);
        }
      }
    }
  }

  @Test void numericallyMatchingFrameInWrongPhysicalWramBankIsRefused() throws Exception {
    try (var f = new Fixture("3100d1cd0003" + STOP,
        "3e02e07031560108fed031fed03e02c9", "", "", GameBoyKind.CGB)) {
      assertTrue(f.result().ordinaryCallProofs().isEmpty());
    }
  }

  @Test void missingContinuationVetoesProofWhilePresentationOverridePreservesRawProof() throws Exception {
    for (boolean override : List.of(false, true)) try (var f = new Fixture(CALL + STOP, "c9")) {
      int tx = f.p.startTransaction("Unavailable architectural dependency");
      try {
        if (override) f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, "0153"))
            .setFlowOverride(ghidra.program.model.listing.FlowOverride.CALL_RETURN);
        else f.p.getListing().clearCodeUnits(ProgramMapping.staticAddress(f.p, "0156"),
            ProgramMapping.staticAddress(f.p, "0156"), false);
      } finally { f.p.endTransaction(tx, true); }
      var result = f.result();
      if (override) {
        assertEquals(1, result.ordinaryCallProofs().size());
        assertTrue(OrdinaryCallFlow.publish(f.p, result, TaskMonitor.DUMMY).isEmpty());
      } else assertTrue(result.ordinaryCallProofs().isEmpty());
    }
  }

  @Test void recursionAndFourthDepthDoNotCertifyDependentInvocations() throws Exception {
    try (var f = new Fixture(CALL + STOP, "cd0003c9")) {
      assertTrue(f.result().ordinaryCallProofs().isEmpty());
    }
    try (var f = new Fixture(CALL + STOP, "cd2003c9", "cd4003c9", "cd6003c9", GameBoyKind.GB)) {
      f.code("0360", "3e02c9");
      assertTrue(f.result().ordinaryCallProofs().isEmpty());
      assertTrue(f.result().findings().stream().anyMatch(x -> x.reason().contains("depth")));
    }
  }

  @Test void successfulInnerCallCannotCertifyOuterIncompleteReturn() throws Exception {
    try (var f = new Fixture(CALL + STOP, "cd2003e9", "3e02c9", "", GameBoyKind.GB)) {
      var proofs = f.result().ordinaryCallProofs();
      assertTrue(proofs.stream().noneMatch(x -> x.source().equals("0153")));
      assertTrue(proofs.isEmpty(), "Incomplete containing exploration cannot publish session authority");
    }
  }

  @Test void localBoundAfterSuccessfulInnerCallVetoesUnexaminedReachableAlternatives() throws Exception {
    // B returns successfully before A reaches its local cap. The unseen tail can
    // revisit that same CD source; an immediate non-CD frontier is no proof of safety.
    try (var f = new Fixture(CALL + STOP, "cd0008" + "3e00".repeat(179) + "c30003")) {
      f.code("0800", "c9");
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse, 4096);
        assertEquals(AnalysisResult.Completion.COMPLETE, preview.result().completion());
        assertTrue(preview.steps().stream().anyMatch(s -> s.source().equals("0800")), preview.toString());
        assertTrue(preview.result().findings().stream().anyMatch(x -> x.reason().contains("callee state bound")), preview.result().findings().toString());
        assertTrue(preview.result().ordinaryCallProofs().isEmpty());
      }
    }
  }

  @Test void allConditionalEncodingsRemainExcludedEvenWithTakenProof() throws Exception {
    for (String opcode : List.of("c4", "cc", "d4", "dc")) {
      String flags = opcode.equals("cc") ? "80" : opcode.equals("dc") ? "10" : "00";
      try (var f = new Fixture("3100d001" + flags + "00c5f1" + opcode + "0003" + STOP, "3e02c9")) {
        var result = f.result();
        assertFalse(result.findings().stream().filter(x -> x.access().equals("call")).toList().isEmpty());
        assertTrue(result.ordinaryCallProofs().isEmpty());
      }
    }
  }

  @Test void oneSuccessfulStateCannotHideFailedStateAtSameSource() throws Exception {
    String prefix = diamond("3100d0", "310080");
    try (var f = new Fixture(prefix + "cd0003" + STOP, "3e02c9")) {
      String source = String.format("%04x", 0x150 + prefix.length() / 2);
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse, 4096);
        assertTrue(preview.steps().stream().filter(s -> s.source().equals(source)).count() >= 2);
        assertEquals(List.of("0300"), call(preview.result(), source).targets());
        assertTrue(preview.result().ordinaryCallProofs().isEmpty());
      }
    }
  }

  @Test void sameCpuTargetWithIncompatiblePhysicalBanksCannotCollapse() throws Exception {
    String prefix = "3100d0" + diamond("3e01ea0020", "3e02ea0020");
    try (var f = new Fixture(prefix + "cd0040" + STOP, "")) {
      f.code("rom1::4000", "3e01c9");
      f.code("rom2::4000", "3e02c9");
      for (boolean reverse : List.of(false, true)) {
        var result = f.preview(reverse, 4096).result();
        assertEquals(List.of("rom1::4000", "rom2::4000"), call(result,
            String.format("%04x", 0x150 + prefix.length() / 2)).targets());
        assertTrue(result.ordinaryCallProofs().isEmpty());
      }
    }
  }

  @Test void repeatedExactIdentitiesWithIncompatibleReturnedMapperDoNotCertify() throws Exception {
    String prefix = "3100d0" + diamond("3e01ea0020", "3e02ea0020");
    String source = String.format("%04x", 0x150 + prefix.length() / 2);
    try (var f = new Fixture(prefix + "cd0003" + STOP, "c9")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse, 4096);
        assertTrue(preview.steps().stream().filter(s -> s.source().equals(source)).count() >= 2);
        assertEquals(List.of("0300"), call(preview.result(), source).targets());
        assertTrue(preview.result().ordinaryCallProofs().isEmpty());
      }
    }
  }

  @Test void stateLimitClearsEarlierSuccessfulTransientProofs() throws Exception {
    try (var f = new Fixture(CALL + "0000000000" + STOP, "c9")) {
      var result = f.preview(false, 5).result();
      assertEquals(AnalysisResult.Completion.STATE_LIMIT, result.completion());
      assertTrue(result.ordinaryCallProofs().isEmpty());
    }
  }

  @Test void cancelledAndChangedInputCannotPublishAuthority() throws Exception {
    for (boolean change : List.of(false, true)) try (var f = new Fixture(CALL + "cd2003" + STOP, "c9", "c9", "", GameBoyKind.GB)) {
      var monitor = new TaskMonitorAdapter(true) {
        int explorations;
        @Override public void setMessage(String message) {
          if (message.equals("Exploring bank states") && ++explorations == 3) {
            if (!change) cancel();
            else {
              int tx = f.p.startTransaction("Concurrent user annotation");
              try { f.p.getListing().setComment(ProgramMapping.staticAddress(f.p, "0300"),
                  ghidra.program.model.listing.CodeUnit.EOL_COMMENT, "Changed during preview"); }
              finally { f.p.endTransaction(tx, true); }
            }
          }
        }
      };
      var result = BankAnalysis.preview(f.p, ProgramMapping.staticAddress(f.p, "0150"), MapperState.reset(),
          AnalysisResult.Configuration.DEFAULT, monitor);
      assertEquals(change ? AnalysisResult.Completion.INPUT_CHANGED : AnalysisResult.Completion.CANCELLED, result.completion());
      assertTrue(result.ordinaryCallProofs().isEmpty());
    }
  }

  @Test void priorEngineCannotAuthorizeUnchangedProgram() throws Exception {
    for (String priorEngine : List.of("20261001-wux1p-ordinary-call-proof-1",
        "20261002-local-loop-1",
        "20261002-local-state-3", "20261002-timer-write-liveness-1", "20261002-raw-flow-view-1")) try (var f = new Fixture(CALL + STOP, "c9")) {
      var current = f.result();
      ProgramFingerprint.requireCurrent(f.p, current, TaskMonitor.DUMMY);
      var json = ProgramMapping.JSON.toJson(current).replace(AnalysisResult.ENGINE_VERSION, priorEngine);
      var prior = ProgramMapping.JSON.fromJson(json, AnalysisResult.class);
      assertEquals(current.fingerprint(), prior.fingerprint());
      assertTrue(prior.ordinaryCallProofs().isEmpty());
      assertThrows(IllegalArgumentException.class, () -> AnalysisResult.read(json));
      assertThrows(IllegalStateException.class,
          () -> ProgramFingerprint.requireCurrent(f.p, prior, TaskMonitor.DUMMY));
      assertThrows(IllegalStateException.class,
          () -> AnalysisApplication.apply(f.p, prior, TaskMonitor.DUMMY));
      assertThrows(IllegalStateException.class,
          () -> OrdinaryCallFlow.publish(f.p, prior, TaskMonitor.DUMMY));
      assertEquals(current.ordinaryCallProofs(), f.result().ordinaryCallProofs());
    }
  }

  @Test void savedOutputCannotReestablishProofAfterConsumedBytesChange() throws Exception {
    try (var f = new Fixture(CALL + STOP, "3e02c9")) {
      var prior = f.result();
      assertEquals(1, prior.ordinaryCallProofs().size());
      int tx = f.p.startTransaction("Save prior derived output");
      try { f.p.getOptions(ProgramMapping.OPTIONS).setString("analysis.latest", ProgramMapping.JSON.toJson(prior)); }
      finally { f.p.endTransaction(tx, true); }
      f.code("0300", "21fecf3600c9");
      assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(f.p, prior, TaskMonitor.DUMMY));
      var fresh = f.result();
      assertEquals(List.of("0300"), call(fresh, "0153").targets());
      assertTrue(fresh.ordinaryCallProofs().isEmpty());
      assertTrue(f.p.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", "").contains("ordinaryCallProofs"));
    }
  }

  @Test void validSoftwareSummaryNeverReceivesOrdinaryCertificate() throws Exception {
    var template = new SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x200, 3, null);
    String prefix = "3100c13e00af010000110000210000";
    int site = 0x150 + prefix.length() / 2;
    try (var f = new Fixture(prefix + "cd0002020041ea00c1c9", "", "", "", GameBoyKind.GB, 0x13)) {
      f.code("0200", template.bodyHex());
      f.code("rom2::4100", "3e5a37c9");
      int tx = f.p.startTransaction("Explicit software premise");
      try {
        f.p.getProgramContext().setValue(f.p.getRegister("F"), ProgramMapping.staticAddress(f.p, "0150"),
            ProgramMapping.staticAddress(f.p, "0150"), java.math.BigInteger.ZERO);
        f.p.getListing().clearCodeUnits(ProgramMapping.staticAddress(f.p, String.format("%04x", site + 3)),
            ProgramMapping.staticAddress(f.p, String.format("%04x", site + 5)), false);
        f.define(String.format("%04x", site + 6), 4);
      } finally { f.p.endTransaction(tx, true); }
      var config = new SoftwareCallValidation.Configuration(site, template,
          SoftwareCallModel.EntryTransfer.HARDWARE_CALL, 0xc100,
          new SoftwareCallModel.Registers(0, 0x80, 0, 0, 0), MapperState.reset());
      SoftwareCallApplication.apply(f.p, SoftwareCallApplication.preview(f.p, List.of(config), TaskMonitor.DUMMY), TaskMonitor.DUMMY);
      var result = f.result();
      assertTrue(result.complete());
      assertEquals(List.of("rom2::4100"), call(result, String.format("%04x", site)).targets());
      assertTrue(result.ordinaryCallProofs().isEmpty());
    }
  }

  @Test void productionPreviewCannotCertifyGeneratedExecutionViewSource() throws Exception {
    // The returned A=2 must flow through the canonical continuation into an actual
    // mapper store/jump. This proves composition still succeeds while withholding authority.
    for (boolean software : List.of(false, true)) try (var f = new Fixture(CALL + "ea0020c30040", "3e02c9")) {
      String name = (software ? SoftwareCallExecutionView.PREFIX : OrdinaryEntryAccess.PREFIX) + "wux1p_source";
      var segments = List.of(new SoftwareCallExecutionView.Segment(0x150, 6, "0150"));
      var reviewed = software
          ? SoftwareCallExecutionView.preview(f.p, name, segments, TaskMonitor.DUMMY)
          : SoftwareCallExecutionView.previewOrdinary(f.p, name, segments, TaskMonitor.DUMMY);
      int tx = f.p.startTransaction("Generated source view counterexample");
      try {
        if (software) SoftwareCallExecutionView.create(f.p, reviewed, TaskMonitor.DUMMY);
        else SoftwareCallExecutionView.createOrdinary(f.p, reviewed, TaskMonitor.DUMMY);
        f.define(name + "::0150", 6);
      } finally { f.p.endTransaction(tx, true); }
      var start = ProgramMapping.staticAddress(f.p, name + "::0150");
      for (boolean rename : List.of(false, true)) {
        if (rename) {
          tx = f.p.startTransaction("Rename generated block while preserving its execution space");
          try { f.p.getMemory().getBlock(start).setName("renamed_generated_source"); }
          finally { f.p.endTransaction(tx, true); }
        }
        var result = BankAnalysis.preview(f.p, start, MapperState.reset(), AnalysisResult.Configuration.DEFAULT,
            TaskMonitor.DUMMY);
        assertTrue(result.complete());
        assertEquals(List.of("0300"), call(result, name + "::0153").targets());
        assertTrue(result.findings().stream().anyMatch(x -> x.source().equals("0159")
            && x.access().equals("jump") && x.confidence() == AnalysisResult.Confidence.PROVEN
            && x.targets().equals(List.of("rom2::4000"))), "Actual returned A drives canonical continuation");
        assertTrue(result.ordinaryCallProofs().isEmpty(), "Generated execution views cannot supply source proof");
      }
    }
  }

  @Test void consumedGeneratedBlockNameGateInvalidatesPriorAliasCertificate() throws Exception {
    try (var f = new Fixture(CALL + STOP, "c9")) {
      int tx = f.p.startTransaction("Ordinary user execution alias");
      ghidra.program.model.mem.MemoryBlock alias;
      try {
        var source = ProgramMapping.staticAddress(f.p, "0150");
        alias = f.p.getMemory().createByteMappedBlock("user_alias", source, source, 6, true);
        alias.setRead(true);
        alias.setWrite(false);
        alias.setExecute(true);
        f.define("user_alias::0150", 6);
      } finally { f.p.endTransaction(tx, true); }
      var start = ProgramMapping.staticAddress(f.p, "user_alias::0150");
      var prior = BankAnalysis.preview(f.p, start, MapperState.reset(), AnalysisResult.Configuration.DEFAULT,
          TaskMonitor.DUMMY);
      assertEquals(1, prior.ordinaryCallProofs().size());
      assertEquals(List.of("user_alias::0150"), prior.starts());
      // The physical fallthrough also supplies the canonical CD site. Its SP
      // premise still originated in the explicitly selected alias root.
      assertEquals("0153", prior.ordinaryCallProofs().get(0).source());
      var sharedComponents = ProgramFingerprint.components(f.p, TaskMonitor.DUMMY);
      var fingerprint = ProgramFingerprint.capture(f.p, TaskMonitor.DUMMY);
      tx = f.p.startTransaction("Change consumed generated-storage eligibility");
      try { alias.setName(SoftwareCallExecutionView.PREFIX + "refused"); }
      finally { f.p.endTransaction(tx, true); }
      assertEquals(sharedComponents, ProgramFingerprint.components(f.p, TaskMonitor.DUMMY),
          "Certificate policy must not alter sibling dependency components");
      assertNotEquals(fingerprint, ProgramFingerprint.capture(f.p, TaskMonitor.DUMMY));
      assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(f.p, prior, TaskMonitor.DUMMY));
      var fresh = BankAnalysis.preview(f.p, start, MapperState.reset(), AnalysisResult.Configuration.DEFAULT,
          TaskMonitor.DUMMY);
      assertEquals(List.of("0300"), call(fresh, "0153").targets());
      assertTrue(fresh.ordinaryCallProofs().isEmpty());
    }
  }

  @Test void generatedStackPremiseAncestorCannotAuthorizeLaterCanonicalCall() throws Exception {
    for (boolean software : List.of(false, true)) try (var f = new Fixture(CALL + "ea0020c30040", "3e02c9")) {
      String name = (software ? SoftwareCallExecutionView.PREFIX : OrdinaryEntryAccess.PREFIX) + "wux1p_sp";
      var segments = List.of(new SoftwareCallExecutionView.Segment(0x150, 3, "0150"));
      var reviewed = software
          ? SoftwareCallExecutionView.preview(f.p, name, segments, TaskMonitor.DUMMY)
          : SoftwareCallExecutionView.previewOrdinary(f.p, name, segments, TaskMonitor.DUMMY);
      int tx = f.p.startTransaction("Generated SP premise ancestor");
      try {
        if (software) SoftwareCallExecutionView.create(f.p, reviewed, TaskMonitor.DUMMY);
        else SoftwareCallExecutionView.createOrdinary(f.p, reviewed, TaskMonitor.DUMMY);
        f.define(name + "::0150", 3);
      } finally { f.p.endTransaction(tx, true); }
      var result = BankAnalysis.preview(f.p, ProgramMapping.staticAddress(f.p, name + "::0150"),
          MapperState.reset(), AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
      assertEquals(List.of("0300"), call(result, "0153").targets());
      assertTrue(result.findings().stream().anyMatch(x -> x.source().equals("0159")
          && x.access().equals("jump") && x.confidence() == AnalysisResult.Confidence.PROVEN
          && x.targets().equals(List.of("rom2::4000"))), "Actual generated SP fact still composes");
      assertTrue(result.ordinaryCallProofs().isEmpty());
    }
  }

  @Test void generatedCalleeInteriorAndOperandBytesCannotSupplyProof() throws Exception {
    for (int split : List.of(0x301, 0x302)) try (var f = new Fixture(CALL + "ea0020c30040", "3e02c9")) {
      var prior = f.result();
      assertEquals(1, prior.ordinaryCallProofs().size());
      int tx = f.p.startTransaction("Consumed generated callee storage");
      try {
        var boundary = ProgramMapping.staticAddress(f.p, String.format("%04x", split));
        f.p.getMemory().split(f.p.getMemory().getBlock(boundary), boundary);
        f.p.getMemory().getBlock(boundary).setName(SoftwareCallExecutionView.PREFIX + "callee_interior");
      } finally { f.p.endTransaction(tx, true); }
      assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(f.p, prior, TaskMonitor.DUMMY));
      var result = BankAnalysis.preview(f.p, ProgramMapping.staticAddress(f.p, "0150"), MapperState.reset(),
          AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
      assertEquals(List.of("0300"), call(result, "0153").targets());
      assertTrue(result.findings().stream().anyMatch(x -> x.source().equals("0159")
          && x.access().equals("jump") && x.confidence() == AnalysisResult.Confidence.PROVEN
          && x.targets().equals(List.of("rom2::4000"))), "Actual callee bytes still return A=2");
      assertTrue(result.ordinaryCallProofs().isEmpty());
    }
  }
}
