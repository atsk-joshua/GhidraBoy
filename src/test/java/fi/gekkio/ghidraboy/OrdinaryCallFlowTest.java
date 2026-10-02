package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import org.junit.jupiter.api.Test;

/** Self-authored physical-bank and raw-byte oracles for WUX-1A publication. */
class OrdinaryCallFlowTest extends IntegrationTest {
  @org.junit.jupiter.api.io.TempDir java.nio.file.Path temporary;
  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("ordinary native call", getLanguage(), getLanguage().getDefaultCompilerSpec(), owner);
    final Address source;
    final Address target;
    final Instruction instruction;

    Fixture() throws Exception { this("3100d03e02ea0020cd004176", "0158"); }
    Fixture(String caller, String callSource) throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      byte[] code = HexFormat.of().parseHex(caller);
      System.arraycopy(code, 0, bytes, 0x150, code.length);
      bytes[0x4100] = (byte) 0xc9;
      bytes[0x8100] = (byte) 0xc9;
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true,
            TaskMonitor.DUMMY, new MessageLog());
      }
      edit(() -> {
        define(at("0150"), code.length);
        define(at("rom1::4100"), 1);
        define(at("rom2::4100"), 1);
      });
      source = at(callSource);
      target = at("rom2::4100");
      instruction = p.getListing().getInstructionAt(source);
    }
    Address at(String value) { return Objects.requireNonNull(ProgramMapping.staticAddress(p, value)); }
    void define(Address start, int length) throws Exception {
      Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(start,
          new AddressSet(start, start.add(length - 1)));
    }
    void edit(Checked action) throws Exception {
      int tx = p.startTransaction("ordinary call fixture");
      try { action.run(); } finally { p.endTransaction(tx, true); }
    }
    AnalysisResult preview(int limit) throws Exception {
      return BankAnalysis.previewFetch(p, at("0150"), MapperState.reset(),
          new AnalysisResult.Configuration(limit, false), TaskMonitor.DUMMY).result();
    }
    AnalysisResult proof() throws Exception {
      var result = preview(4096);
      assertTrue(result.complete());
      assertEquals(1, result.ordinaryCallProofs().size());
      assertEquals("rom2::4100", result.ordinaryCallProofs().get(0).target());
      return result;
    }
    AddressSet publish(AnalysisResult result) throws Exception {
      final AddressSet[] changed = new AddressSet[1];
      edit(() -> changed[0] = OrdinaryCallFlow.publish(p, result, TaskMonitor.DUMMY));
      return changed[0];
    }
    List<Reference> calls() {
      return Arrays.stream(instruction.getReferencesFrom()).filter(r -> r.getReferenceType().isCall()).toList();
    }
    @Override public void close() { p.release(owner); }
  }
  @FunctionalInterface private interface Checked { void run() throws Exception; }
  private static PcodeOp call(PcodeOp[] code) {
    return Arrays.stream(code).filter(op -> op.getOpcode() == PcodeOp.CALL).findFirst().orElseThrow();
  }

  @Test void exactCertificatePublishesPhysicalOperandAndStockTransportWithoutChangingRawSemantics() throws Exception {
    try (var f = new Fixture()) {
      var proof = f.proof();
      var original = f.calls().get(0);
      assertEquals(SourceType.DEFAULT, original.getSource());
      String raw = Arrays.toString(f.instruction.getPcode(false));
      assertTrue(f.publish(proof).contains(f.source));
      assertEquals(1, f.calls().size());
      var installed = f.calls().get(0);
      assertEquals(f.target, installed.getToAddress());
      assertEquals(original.getOperandIndex(), installed.getOperandIndex());
      assertEquals(0, installed.getOperandIndex());
      assertEquals(SourceType.ANALYSIS, installed.getSource());
      assertTrue(installed.isPrimary());
      assertArrayEquals(new Address[] {f.target}, f.instruction.getFlows());
      assertEquals(raw, Arrays.toString(f.instruction.getPcode(false)));
      assertEquals(f.target, call(f.instruction.getPcode(true)).getInput(0).getAddress());
      var block = new SimpleBlockModel(f.p).getCodeBlockAt(f.at("0150"), TaskMonitor.DUMMY);
      var destinations = block.getDestinations(TaskMonitor.DUMMY);
      Set<Address> targets = new HashSet<>();
      while (destinations.hasNext()) targets.add(destinations.next().getDestinationAddress());
      assertTrue(targets.contains(f.target));
      assertFalse(targets.contains(original.getToAddress()));
      ProgramFingerprint.requireCurrent(f.p, proof, TaskMonitor.DUMMY);
      assertNull(InstructionInterpretation.architecturalUnresolved(f.instruction));
    }
  }

  @Test void unchangedPublicationIsIdempotentAndCannotInvalidateItsProof() throws Exception {
    try (var f = new Fixture()) {
      var proof = f.proof();
      assertFalse(f.publish(proof).isEmpty());
      assertTrue(f.publish(proof).isEmpty());
      assertEquals(1, f.calls().size());
      ProgramFingerprint.requireCurrent(f.p, proof, TaskMonitor.DUMMY);
      var fresh = f.proof();
      assertEquals(proof.ordinaryCallProofs(), fresh.ordinaryCallProofs());
    }
  }

  @Test void removalRestoresExactDefaultTuple() throws Exception {
    try (var f = new Fixture()) {
      var original = f.calls().get(0);
      Address cpu = original.getToAddress();
      int operand = original.getOperandIndex();
      RefType type = original.getReferenceType();
      boolean primary = original.isPrimary();
      f.publish(f.proof());
      f.edit(() -> AnalysisOwnership.remove(f.p, "ordinary-call-flow", TaskMonitor.DUMMY));
      assertEquals(1, f.calls().size());
      var restored = f.calls().get(0);
      assertEquals(cpu, restored.getToAddress());
      assertEquals(operand, restored.getOperandIndex());
      assertEquals(type, restored.getReferenceType());
      assertEquals(SourceType.DEFAULT, restored.getSource());
      assertEquals(primary, restored.isPrimary());
    }
  }

  @Test void competingUserAndImportedFlowRefusePublicationWithoutDeletingEvidence() throws Exception {
    for (var origin : List.of(SourceType.USER_DEFINED, SourceType.IMPORTED)) try (var f = new Fixture()) {
      f.edit(() -> f.p.getReferenceManager().addMemoryReference(f.source, f.at("0300"), RefType.UNCONDITIONAL_CALL, origin, 0));
      var result = f.preview(4096);
      assertTrue(result.ordinaryCallProofs().isEmpty());
      assertTrue(f.publish(result).isEmpty());
      assertTrue(f.calls().stream().anyMatch(r -> r.getSource() == origin && r.getToAddress().equals(f.at("0300"))));
    }
  }

  @Test void editedPhysicalPrimacyIsPreservedAndNoLongerExemptArchitecturalEvidence() throws Exception {
    try (var f = new Fixture()) {
      var proof = f.proof();
      f.publish(proof);
      f.edit(() -> f.p.getReferenceManager().setPrimary(f.calls().get(0), false));
      assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(f.p, proof, TaskMonitor.DUMMY));
      assertNotNull(InstructionInterpretation.architecturalUnresolved(f.instruction));
      f.edit(() -> AnalysisOwnership.remove(f.p, "ordinary-call-flow", TaskMonitor.DUMMY));
      assertTrue(f.calls().stream().anyMatch(r -> r.getToAddress().equals(f.target) && !r.isPrimary()));
    }
  }

  @Test void independentFlowRemainsVisibleToCurrentness() throws Exception {
    try (var f = new Fixture()) {
      var proof = f.proof();
      f.publish(proof);
      f.edit(() -> f.p.getReferenceManager().addMemoryReference(f.source, f.at("0300"), RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 1));
      assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(f.p, proof, TaskMonitor.DUMMY));
      assertNotNull(InstructionInterpretation.architecturalUnresolved(f.instruction));
    }
  }

  @Test void consumedByteMutationRetiresBeforeIncompleteFreshAnalysis() throws Exception {
    try (var f = new Fixture()) {
      var original = f.calls().get(0).getToAddress();
      f.publish(f.proof());
      f.edit(() -> {
        f.p.getListing().clearCodeUnits(f.target, f.target, false);
        f.p.getMemory().setByte(f.target, (byte) 0x76);
        f.define(f.target, 1);
      });
      var incomplete = f.preview(1);
      assertEquals(AnalysisResult.Completion.STATE_LIMIT, incomplete.completion());
      assertTrue(incomplete.ordinaryCallProofs().isEmpty());
      assertEquals(1, f.calls().size());
      assertEquals(original, f.calls().get(0).getToAddress());
      assertEquals(SourceType.DEFAULT, f.calls().get(0).getSource());
      assertTrue(f.publish(incomplete).isEmpty());
    }
  }

  @Test void incompleteInvocationPreservesCurrentOriginalProof() throws Exception {
    try (var f = new Fixture()) {
      var original = f.proof();
      f.publish(original);
      var incomplete = f.preview(1);
      assertEquals(AnalysisResult.Completion.STATE_LIMIT, incomplete.completion());
      assertTrue(incomplete.ordinaryCallProofs().isEmpty());
      assertTrue(f.publish(incomplete).isEmpty());
      assertArrayEquals(new Address[] {f.target}, f.instruction.getFlows());
      ProgramFingerprint.requireCurrent(f.p, original, TaskMonitor.DUMMY);
    }
  }

  @Test void genericSingletonConditionalAndIncompleteResultsDoNotPublish() throws Exception {
    for (String code : List.of("3e02ea0020cd004176", "3100d03e02ea0020c4004176")) {
      try (var f = new Fixture(code, code.startsWith("31") ? "0158" : "0155")) {
        var result = f.preview(4096);
        assertTrue(result.ordinaryCallProofs().isEmpty());
        assertTrue(f.publish(result).isEmpty());
        assertTrue(f.calls().stream().allMatch(r -> r.getSource() == SourceType.DEFAULT));
      }
    }
    try (var f = new Fixture()) {
      var result = f.preview(1);
      assertTrue(f.publish(result).isEmpty());
      assertTrue(f.calls().stream().allMatch(r -> r.getSource() == SourceType.DEFAULT));
    }
  }

  @Test void generatedStackPremiseCannotAuthorizeNativePublication() throws Exception {
    try (var f = new Fixture()) {
      String name = OrdinaryEntryAccess.PREFIX + "wux1a_generated";
      var segments = List.of(new SoftwareCallExecutionView.Segment(0x150, 3, "0150"));
      var reviewed = SoftwareCallExecutionView.previewOrdinary(f.p, name, segments, TaskMonitor.DUMMY);
      f.edit(() -> {
        SoftwareCallExecutionView.createOrdinary(f.p, reviewed, TaskMonitor.DUMMY);
        f.define(f.at(name + "::0150"), 3);
      });
      var result = BankAnalysis.preview(f.p, f.at(name + "::0150"), MapperState.reset(),
          AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
      assertTrue(result.complete());
      assertTrue(result.ordinaryCallProofs().isEmpty());
      assertTrue(f.publish(result).isEmpty());
      assertTrue(f.calls().stream().allMatch(r -> r.getSource() == SourceType.DEFAULT));
    }
  }


  @Test void sharedComponentsStillRecordPhysicalFlowWhileAnalysisCaptureNormalizesOnlyOwnedFlow() throws Exception {
    try (var f = new Fixture()) {
      var proof = f.proof();
      var components = ProgramFingerprint.components(f.p, TaskMonitor.DUMMY);
      String capture = ProgramFingerprint.capture(f.p, TaskMonitor.DUMMY);
      f.publish(proof);
      assertNotEquals(components, ProgramFingerprint.components(f.p, TaskMonitor.DUMMY));
      assertEquals(capture, ProgramFingerprint.capture(f.p, TaskMonitor.DUMMY));
    }
  }

  @Test void unownedPhysicalCallCannotSupplyOrRegenerateCertificate() throws Exception {
    try (var f = new Fixture()) {
      f.edit(() -> {
        var decoded = f.calls().get(0);
        f.p.getReferenceManager().delete(decoded);
        var generated = f.p.getReferenceManager().addMemoryReference(f.source, f.target,
            RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);
        f.p.getReferenceManager().setPrimary(generated, true);
      });
      assertNotNull(InstructionInterpretation.architecturalUnresolved(f.instruction));
      var fresh = f.preview(4096);
      assertTrue(fresh.ordinaryCallProofs().isEmpty());
      assertTrue(f.publish(fresh).isEmpty());
    }
  }

  @Test void nonprimaryDecodedDefaultIsRestoredExactly() throws Exception {
    try (var f = new Fixture()) {
      f.edit(() -> f.p.getReferenceManager().setPrimary(f.calls().get(0), false));
      var decoded = f.calls().get(0).getToAddress();
      f.publish(f.proof());
      assertTrue(f.calls().get(0).isPrimary());
      f.edit(() -> AnalysisOwnership.remove(f.p, "ordinary-call-flow", TaskMonitor.DUMMY));
      assertEquals(1, f.calls().size());
      assertEquals(decoded, f.calls().get(0).getToAddress());
      assertFalse(f.calls().get(0).isPrimary());
    }
  }

  @Test void editedOwnedTargetTypeOperandAndSourceAreNotDestructivelyRemoved() throws Exception {
    for (String change : List.of("target", "type", "operand", "source")) try (var f = new Fixture()) {
      f.publish(f.proof());
      final Reference[] replacement = new Reference[1];
      f.edit(() -> {
        f.p.getReferenceManager().delete(f.calls().get(0));
        replacement[0] = f.p.getReferenceManager().addMemoryReference(f.source,
            change.equals("target") ? f.at("0300") : f.target,
            change.equals("type") ? RefType.UNCONDITIONAL_JUMP : RefType.UNCONDITIONAL_CALL,
            change.equals("source") ? SourceType.USER_DEFINED : SourceType.ANALYSIS,
            change.equals("operand") ? 1 : 0);
        f.p.getReferenceManager().setPrimary(replacement[0], true);
      });
      assertNotNull(InstructionInterpretation.architecturalUnresolved(f.instruction), change);
      f.edit(() -> AnalysisOwnership.remove(f.p, "ordinary-call-flow", TaskMonitor.DUMMY));
      assertTrue(Arrays.stream(f.instruction.getReferencesFrom()).anyMatch(r ->
          r.getToAddress().equals(replacement[0].getToAddress())
          && r.getReferenceType().equals(replacement[0].getReferenceType())
          && r.getOperandIndex() == replacement[0].getOperandIndex()
          && r.getSource() == replacement[0].getSource()), change);
      assertTrue(Arrays.stream(f.instruction.getReferencesFrom()).noneMatch(r -> r.getSource() == SourceType.DEFAULT), change);
    }
  }

  @Test void changedSourceOperandNeverRestoresOldDecodedDestination() throws Exception {
    try (var f = new Fixture()) {
      var oldCpu = f.calls().get(0).getToAddress();
      f.publish(f.proof());
      f.edit(() -> {
        f.p.getListing().clearCodeUnits(f.source, f.source.add(2), false);
        f.p.getMemory().setBytes(f.source, HexFormat.of().parseHex("cd0003"));
        f.define(f.source, 3);
      });
      f.edit(() -> AnalysisOwnership.remove(f.p, "ordinary-call-flow", TaskMonitor.DUMMY));
      var current = f.p.getListing().getInstructionAt(f.source);
      assertTrue(Arrays.stream(current.getReferencesFrom()).noneMatch(r -> r.getSource() == SourceType.DEFAULT
          && r.getToAddress().equals(oldCpu)));
      assertArrayEquals(new Address[] {f.at("0300")}, current.getDefaultFlows());
    }
  }

  @Test void actualNativeDecompilerReceivesPhysicalCallTarget() throws Exception {
    boolean nativeAvailable;
    try { nativeAvailable = ghidra.framework.Application.getOSFile("decompile").isFile(); }
    catch (Exception unavailable) { nativeAvailable = false; }
    org.junit.jupiter.api.Assumptions.assumeTrue(nativeAvailable, "Pinned distribution has no native decompiler executable");
    try (var f = new Fixture()) {
      f.publish(f.proof());
      f.edit(() -> {
        f.p.getFunctionManager().createFunction("caller", f.at("0150"),
            new AddressSet(f.at("0150"), f.at("015b")), SourceType.ANALYSIS);
        f.p.getFunctionManager().createFunction("physical_callee", f.target,
            new AddressSet(f.target), SourceType.ANALYSIS);
      });
      var nativeOwner = new ghidra.app.decompiler.DecompInterface();
      try {
        assertTrue(nativeOwner.openProgram(f.p));
        var result = nativeOwner.decompileFunction(f.p.getFunctionManager().getFunctionAt(f.at("0150")),
            60, TaskMonitor.DUMMY);
        assertTrue(result.decompileCompleted(), result.getErrorMessage());
        assertNotNull(result.getHighFunction());
        var ops = result.getHighFunction().getPcodeOps();
        Set<Address> targets = new HashSet<>();
        while (ops.hasNext()) {
          var op = ops.next();
          if (op.getOpcode() == PcodeOp.CALL) targets.add(op.getInput(0).getAddress());
        }
        assertEquals(Set.of(f.target), targets);
      } finally { nativeOwner.dispose(); }
    }
  }


  @Test void primaryUserDataOnCallOperandIsPreservedAndRefusesPublication() throws Exception {
    try (var f = new Fixture()) {
      f.edit(() -> {
        var navigation = f.p.getReferenceManager().addMemoryReference(f.source, f.at("0300"),
            RefType.DATA, SourceType.USER_DEFINED, 0);
        f.p.getReferenceManager().setPrimary(navigation, true);
      });
      var proof = f.proof();
      assertTrue(f.publish(proof).isEmpty());
      var refs = Arrays.asList(f.instruction.getReferencesFrom());
      assertTrue(refs.stream().anyMatch(r -> r.getSource() == SourceType.USER_DEFINED
          && r.getReferenceType() == RefType.DATA && r.isPrimary() && r.getOperandIndex() == 0));
      assertTrue(f.calls().stream().allMatch(r -> r.getSource() == SourceType.DEFAULT));
    }
  }


  @Test void exactReceiptPhysicalTransportAndRetirementSurvivePackedReopen() throws Exception {
    try (var f = new Fixture()) {
      var proof = f.proof();
      var original = OrdinaryCallFlow.Tuple.of(f.calls().get(0));
      String raw = Arrays.toString(f.instruction.getPcode(false));
      f.publish(proof);
      var packed = temporary.resolve("ordinary-call.gzf").toFile();
      f.p.saveToPackedFile(packed, TaskMonitor.DUMMY);
      var database = ghidra.framework.store.db.PackedDatabase.getPackedDatabase(packed, true, TaskMonitor.DUMMY);
      var consumer = new Object();
      ProgramDB reopened = null;
      try {
        reopened = new ProgramDB(database.open(TaskMonitor.DUMMY), ghidra.framework.data.OpenMode.UPDATE,
            TaskMonitor.DUMMY, consumer);
        var p = reopened;
        var source = ProgramMapping.staticAddress(p, "0158");
        var target = ProgramMapping.staticAddress(p, "rom2::4100");
        var ins = p.getListing().getInstructionAt(source);
        assertEquals(1, OrdinaryCallFlow.receipts(p).size());
        assertNotNull(OrdinaryCallFlow.exact(ins));
        ProgramFingerprint.requireCurrent(p, proof, TaskMonitor.DUMMY);
        assertArrayEquals(new Address[] {target}, ins.getFlows());
        assertEquals(raw, Arrays.toString(ins.getPcode(false)));
        assertEquals(target, call(ins.getPcode(true)).getInput(0).getAddress());
        int tx = p.startTransaction("Consume changed persisted callee");
        try {
          p.getListing().clearCodeUnits(target, target, false);
          p.getMemory().setByte(target, (byte) 0x76);
          Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(target, new AddressSet(target));
          OrdinaryCallFlow.retireStale(p, TaskMonitor.DUMMY);
        } finally { p.endTransaction(tx, true); }
        assertTrue(OrdinaryCallFlow.receipts(p).isEmpty());
        var refs = Arrays.stream(ins.getReferencesFrom()).filter(r -> r.getReferenceType().isCall()).toList();
        assertEquals(1, refs.size());
        assertEquals(original, OrdinaryCallFlow.Tuple.of(refs.get(0)));
        assertEquals(raw, Arrays.toString(ins.getPcode(false)));
      } finally {
        if (reopened != null) reopened.release(consumer);
        database.dispose();
      }
    }
  }

  @Test void obsoleteEngineKnownReceiptRetiresAfterReopenWithoutProofAuthority() throws Exception {
    for (String priorEngine : List.of("20261001-call-stack-liveness-2a-1",
        "20261001-call-stack-liveness-2c-1",
        "20261001-call-stack-liveness-2d-1",
        "20261002-memory-storage-copy-1"))
      for (String operation : List.of("retire", "remove", "edited", "future")) try (var f = new Fixture()) {
      var proof = f.proof();
      var original = OrdinaryCallFlow.Tuple.of(f.calls().get(0));
      f.publish(proof);
      f.edit(() -> {
        var group = AnalysisOwnership.group(f.p, OrdinaryCallFlow.GROUP);
        var r = group.ordinaryCalls.get(0);
        group.ordinaryCalls.set(0, new OrdinaryCallFlow.Receipt(operation.equals("future") ? 2 : 1,
            r.proof(), priorEngine, r.basis(), r.bytes(), r.installed(), r.displaced()));
        AnalysisOwnership.save(f.p, OrdinaryCallFlow.GROUP, group);
      });
      var packed = temporary.resolve("obsolete-" + priorEngine + "-" + operation + ".gzf").toFile();
      f.p.saveToPackedFile(packed, TaskMonitor.DUMMY);
      var database = ghidra.framework.store.db.PackedDatabase.getPackedDatabase(packed, true, TaskMonitor.DUMMY);
      var consumer = new Object();
      ProgramDB reopened = null;
      try {
        reopened = new ProgramDB(database.open(TaskMonitor.DUMMY), ghidra.framework.data.OpenMode.UPDATE,
            TaskMonitor.DUMMY, consumer);
        var p = reopened;
        var source = ProgramMapping.staticAddress(p, "0158");
        var target = ProgramMapping.staticAddress(p, "rom2::4100");
        var ins = p.getListing().getInstructionAt(source);
        var installed = Arrays.stream(ins.getReferencesFrom()).filter(r -> r.getReferenceType().isCall()).findFirst().orElseThrow();
        assertFalse(OrdinaryCallFlow.currentProof(OrdinaryCallFlow.receipts(p).get(0)), operation);
        assertNull(OrdinaryCallFlow.exact(ins), operation);
        assertFalse(OrdinaryCallFlow.architecturalExemption(ins, installed), operation);
        assertNotNull(InstructionInterpretation.architecturalUnresolved(ins), operation);
        assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(p, proof, TaskMonitor.DUMMY));
        int tx = p.startTransaction("Retire obsolete proof presentation");
        try {
          if (operation.equals("edited")) {
            p.getReferenceManager().delete(installed);
            var user = p.getReferenceManager().addMemoryReference(source, target,
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, installed.getOperandIndex());
            p.getReferenceManager().setPrimary(user, true);
          }
          if (operation.equals("remove")) AnalysisOwnership.remove(p, OrdinaryCallFlow.GROUP, TaskMonitor.DUMMY);
          else OrdinaryCallFlow.retireStale(p, TaskMonitor.DUMMY);
        } finally { p.endTransaction(tx, true); }
        var refs = Arrays.stream(ins.getReferencesFrom()).filter(r -> r.getReferenceType().isCall()).toList();
        assertEquals(1, refs.size(), operation);
        if (operation.equals("edited") || operation.equals("future")) {
          assertEquals(target, refs.get(0).getToAddress(), operation);
          assertEquals(operation.equals("edited") ? SourceType.USER_DEFINED : SourceType.ANALYSIS,
              refs.get(0).getSource(), operation);
        } else {
          assertTrue(OrdinaryCallFlow.receipts(p).isEmpty(), operation);
          assertEquals(original, OrdinaryCallFlow.Tuple.of(refs.get(0)), operation);
          var fresh = BankAnalysis.preview(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
              AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
          assertEquals(1, fresh.ordinaryCallProofs().size(), priorEngine);
          assertEquals(AnalysisResult.ENGINE_VERSION, fresh.engineVersion());
          ProgramFingerprint.requireCurrent(p, fresh, TaskMonitor.DUMMY);
          int publishTx = p.startTransaction("Publish recomputed current proof");
          try { assertTrue(OrdinaryCallFlow.publish(p, fresh, TaskMonitor.DUMMY).contains(source)); }
          finally { p.endTransaction(publishTx, true); }
          assertTrue(OrdinaryCallFlow.currentProof(OrdinaryCallFlow.receipts(p).get(0)));
          assertNotNull(OrdinaryCallFlow.exact(ins));
          assertArrayEquals(new Address[] {target}, ins.getFlows());
        }
      } finally {
        if (reopened != null) reopened.release(consumer);
        database.dispose();
      }
    }
  }

  @Test void historicalOwnershipEnvelopeCannotAcquireOrdinaryCallDestructiveAuthority() throws Exception {
    for (int version : List.of(1, 2, 3, 4, 5)) try (var f = new Fixture()) {
      f.publish(f.proof());
      f.edit(() -> {
        var options = f.p.getOptions(ProgramMapping.OPTIONS);
        var root = com.google.gson.JsonParser.parseString(options.getString("analysis.ownership.v1", "")).getAsJsonObject();
        root.addProperty("version", version);
        options.setString("analysis.ownership.v1", root.toString());
      });
      assertTrue(OrdinaryCallFlow.receipts(f.p).isEmpty(), "envelope " + version);
      assertNotNull(InstructionInterpretation.architecturalUnresolved(f.instruction));
      f.edit(() -> {
        AnalysisOwnership.save(f.p, "another", new AnalysisOwnership.Group());
        AnalysisOwnership.remove(f.p, "ordinary-call-flow", TaskMonitor.DUMMY);
      });
      assertEquals(1, f.calls().size());
      assertEquals(f.target, f.calls().get(0).getToAddress());
      assertEquals(SourceType.ANALYSIS, f.calls().get(0).getSource());
    }
  }


  @Test void fixedRomCallWithIdenticalDecodedAndPhysicalAddressUsesOwnedFlowAndRestoresDefault() throws Exception {
    try (var f = new Fixture("3100d0cd000376", "0153")) {
      f.edit(() -> {
        f.p.getMemory().setByte(f.at("0300"), (byte) 0xc9);
        f.define(f.at("0300"), 1);
      });
      var original = OrdinaryCallFlow.Tuple.of(f.calls().get(0));
      String raw = Arrays.toString(f.instruction.getPcode(false));
      var result = f.preview(4096);
      assertTrue(result.complete());
      assertEquals(1, result.ordinaryCallProofs().size());
      assertEquals("0300", result.ordinaryCallProofs().get(0).target());
      assertTrue(f.publish(result).contains(f.source));
      assertEquals(1, f.calls().size());
      assertEquals(SourceType.ANALYSIS, f.calls().get(0).getSource());
      assertEquals(f.at("0300"), f.calls().get(0).getToAddress());
      assertTrue(f.calls().get(0).isPrimary());
      assertArrayEquals(new Address[] {f.at("0300")}, f.instruction.getFlows());
      assertEquals(raw, Arrays.toString(f.instruction.getPcode(false)));
      ProgramFingerprint.requireCurrent(f.p, result, TaskMonitor.DUMMY);
      f.edit(() -> AnalysisOwnership.remove(f.p, "ordinary-call-flow", TaskMonitor.DUMMY));
      assertEquals(1, f.calls().size());
      assertEquals(original, OrdinaryCallFlow.Tuple.of(f.calls().get(0)));
      assertTrue(f.publish(f.preview(4096)).contains(f.source));
      f.edit(() -> {
        f.p.getListing().clearCodeUnits(f.at("0300"), f.at("0300"), false);
        f.p.getMemory().setByte(f.at("0300"), (byte) 0x76);
        f.define(f.at("0300"), 1);
      });
      var incomplete = f.preview(1);
      assertEquals(AnalysisResult.Completion.STATE_LIMIT, incomplete.completion());
      assertEquals(1, f.calls().size());
      assertEquals(original, OrdinaryCallFlow.Tuple.of(f.calls().get(0)));
      assertTrue(f.publish(incomplete).isEmpty());
    }
  }

}
