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
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import org.junit.jupiter.api.Test;

/** Disposable, self-authored stock 12.1.3 mechanism witnesses; no production lowering. */
class StockFlowMechanismTest extends IntegrationTest {
  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("stock flow witness", getLanguage(), getLanguage().getDefaultCompilerSpec(), owner);
    final Address source;
    final Address target;
    final Instruction instruction;

    Fixture(boolean call) throws Exception {
      this(call ? "3100d03e02ea0020cd0041c9" : "3e02ea0020210041e9", "0158");
    }

    Fixture(String entry, String transfer) throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19; // MBC5, independently selected physical bank 2.
      bytes[0x148] = 1;
      byte[] code = HexFormat.of().parseHex(entry);
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
      source = at(transfer);
      target = at("rom2::4100");
      instruction = p.getListing().getInstructionAt(source);
    }

    Address at(String value) { return Objects.requireNonNull(ProgramMapping.staticAddress(p, value)); }
    void define(Address start, int length) throws Exception {
      Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
          .disassemble(start, new AddressSet(start, start.add(length - 1)));
    }
    void edit(Checked action) throws Exception {
      int tx = p.startTransaction("stock mechanism experiment");
      try { action.run(); } finally { p.endTransaction(tx, true); }
    }
    AnalysisResult proof() throws Exception {
      var result = BankAnalysis.previewFetch(p, at("0150"), MapperState.reset(),
          AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY).result();
      assertTrue(result.complete());
      assertTrue(result.findings().stream().anyMatch(f -> f.source().equals(source.toString())
          && f.confidence() == AnalysisResult.Confidence.PROVEN
          && f.targets().equals(List.of(target.toString()))));
      assertEquals(List.of(new MapperState.Physical("ROM", 2, 0x100)), ProgramMapping.staticToPhysical(p, target));
      ProgramFingerprint.requireCurrent(p, result, TaskMonitor.DUMMY);
      return result;
    }
    @Override public void close() { p.release(owner); }
  }

  @FunctionalInterface private interface Checked { void run() throws Exception; }

  private static PcodeOp call(PcodeOp[] code) {
    return Arrays.stream(code).filter(op -> op.getOpcode() == PcodeOp.CALL).findFirst().orElseThrow();
  }

  private static Set<Address> destinations(Fixture f) throws Exception {
    var model = new SimpleBlockModel(f.p);
    var block = model.getCodeBlockAt(f.at("0150"), TaskMonitor.DUMMY);
    assertNotNull(block);
    var references = block.getDestinations(TaskMonitor.DUMMY);
    Set<Address> destinations = new HashSet<>();
    while (references.hasNext()) destinations.add(references.next().getDestinationAddress());
    return destinations;
  }

  @Test void dataIsNavigationOnlyForBothProvedTransfers() throws Exception {
    for (boolean isCall : List.of(true, false)) {
      try (var f = new Fixture(isCall)) {
        var result = f.proof();
        String raw = Arrays.toString(f.instruction.getPcode(false));
        String high = Arrays.toString(f.instruction.getPcode(true));
        // Reproduce the pre-WUX lowering explicitly, so this remains a mechanism control
        // when the production application's selected lowering changes.
        f.edit(() -> f.p.getReferenceManager().addMemoryReference(f.source, f.target,
            RefType.DATA, SourceType.ANALYSIS, -1));
        assertFalse(Arrays.asList(f.instruction.getFlows()).contains(f.target));
        assertFalse(destinations(f).contains(f.target));
        assertEquals(raw, Arrays.toString(f.instruction.getPcode(false)));
        assertEquals(high, Arrays.toString(f.instruction.getPcode(true)));
        assertNull(f.p.getFunctionManager().getFunctionAt(f.target));
        ProgramFingerprint.requireCurrent(f.p, result, TaskMonitor.DUMMY);
        System.out.println("WUX DATA " + (isCall ? "CALL" : "E9") + " flows="
            + Arrays.toString(f.instruction.getFlows()) + " blocks=" + destinations(f));
      }
    }
  }

  @Test void ordinaryCallReferencePrimaryStatusIsSemanticLowering() throws Exception {
    for (int operand : List.of(-1, 0)) {
      for (boolean primary : List.of(false, true)) {
        try (var f = new Fixture(true)) {
          var result = f.proof();
          String raw = Arrays.toString(f.instruction.getPcode(false));
          var rawTarget = call(f.instruction.getPcode(false)).getInput(0).getAddress();
          assertEquals(0x4100, rawTarget.getOffset());
          assertNotEquals(f.target.getAddressSpace(), rawTarget.getAddressSpace());
          var continuation = f.at("015b");
          assertEquals(continuation, f.instruction.getFallThrough());
          var originalReferences = f.instruction.getReferencesFrom();
          var originalPrimary = new HashMap<ghidra.program.model.symbol.Reference, Boolean>();
          for (var ref : originalReferences) originalPrimary.put(ref, ref.isPrimary());
          f.edit(() -> {
            // Preserve default references, but hold them nonprimary to measure the
            // chosen physical reference alone rather than whichever primary is first.
            for (var ref : f.instruction.getReferencesFrom())
              f.p.getReferenceManager().setPrimary(ref, false);
            var ref = f.p.getReferenceManager().addMemoryReference(f.source, f.target,
                RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, operand);
            System.out.println("WUX CALL operand=" + operand + " automaticPrimary=" + ref.isPrimary());
            f.p.getReferenceManager().setPrimary(ref, primary);
          });
          assertEquals(raw, Arrays.toString(f.instruction.getPcode(false)));
          assertEquals(primary ? f.target : rawTarget, call(f.instruction.getPcode(true)).getInput(0).getAddress());
          assertEquals(Arrays.stream(f.instruction.getPcode(false))
              .filter(op -> op.getOpcode() != PcodeOp.CALL).map(Object::toString).toList(),
              Arrays.stream(f.instruction.getPcode(true))
                  .filter(op -> op.getOpcode() != PcodeOp.CALL).map(Object::toString).toList(),
              "Physical call lowering must preserve SP decrement, continuation and stack writes");
          assertTrue(Arrays.asList(f.instruction.getFlows()).contains(f.target));
          assertTrue(destinations(f).contains(f.target));
          assertEquals(continuation, f.instruction.getFallThrough());
          // Demotion selects high p-code but does not retire the extra CPU-space CFG edge.
          assertTrue(Arrays.asList(f.instruction.getFlows()).contains(rawTarget));
          assertTrue(destinations(f).contains(rawTarget));
          assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(f.p, result, TaskMonitor.DUMMY));
          assertNotNull(InstructionInterpretation.architecturalUnresolved(f.instruction));
          System.out.println("WUX CALL operand=" + operand + " primary=" + primary + " highTarget="
              + call(f.instruction.getPcode(true)).getInput(0).getAddress() + " flows="
              + Arrays.toString(f.instruction.getFlows()) + " blocks=" + destinations(f));
          f.edit(() -> {
            var manager = f.p.getReferenceManager();
            manager.delete(manager.getReference(f.source, f.target, operand));
            for (var entry : originalPrimary.entrySet()) manager.setPrimary(entry.getKey(), entry.getValue());
          });
          assertEquals(rawTarget, call(f.instruction.getPcode(true)).getInput(0).getAddress());
          assertEquals(originalReferences.length, f.instruction.getReferencesFrom().length);
          for (var ref : originalReferences)
            assertEquals(originalPrimary.get(ref).booleanValue(), f.p.getReferenceManager()
                .getReference(ref.getFromAddress(), ref.getToAddress(), ref.getOperandIndex()).isPrimary());
          ProgramFingerprint.requireCurrent(f.p, result, TaskMonitor.DUMMY);
        }
      }
    }
  }

  @Test void computedJumpReferenceChangesCfgWithoutReplacingArchitecturalBranchind() throws Exception {
    for (int operand : List.of(-1, 0)) {
      for (boolean primary : List.of(false, true)) {
        try (var f = new Fixture(false)) {
          var result = f.proof();
          String raw = Arrays.toString(f.instruction.getPcode(false));
          assertEquals(1, f.instruction.getPcode(false).length);
          assertEquals(PcodeOp.BRANCHIND, f.instruction.getPcode(false)[0].getOpcode());
          assertEquals(f.p.getRegister("HL").getAddress(), f.instruction.getPcode(false)[0].getInput(0).getAddress());
          assertEquals(2, f.instruction.getPcode(false)[0].getInput(0).getSize());
          f.edit(() -> {
            var ref = f.p.getReferenceManager().addMemoryReference(f.source, f.target,
                RefType.COMPUTED_JUMP, SourceType.ANALYSIS, operand);
            System.out.println("WUX E9 operand=" + operand + " automaticPrimary=" + ref.isPrimary());
            f.p.getReferenceManager().setPrimary(ref, primary);
          });
          assertEquals(raw, Arrays.toString(f.instruction.getPcode(false)));
          assertEquals(raw, Arrays.toString(f.instruction.getPcode(true)));
          assertTrue(Arrays.asList(f.instruction.getFlows()).contains(f.target));
          assertTrue(destinations(f).contains(f.target));
          assertNull(f.instruction.getFallThrough());
          assertNull(f.p.getFunctionManager().getFunctionAt(f.target));
          assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(f.p, result, TaskMonitor.DUMMY));
          assertNotNull(InstructionInterpretation.architecturalUnresolved(f.instruction));
          System.out.println("WUX E9 operand=" + operand + " primary=" + primary + " high="
              + Arrays.toString(f.instruction.getPcode(true)) + " blocks=" + destinations(f));
        }
      }
    }
  }

  @Test void consumedMapperSelectionMutationInvalidatesPriorProof() throws Exception {
    try (var f = new Fixture(false)) {
      var result = f.proof();
      f.edit(() -> {
        f.p.getListing().clearCodeUnits(f.at("0150"), f.at("0151"), false);
        f.p.getMemory().setByte(f.at("0151"), (byte) 1);
        f.define(f.at("0150"), 2);
      });
      assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(f.p, result, TaskMonitor.DUMMY));
    }
  }

  @Test void completeResultCanContainKnownAndUnknownAlternativesAtSameE9() throws Exception {
    // One justified root establishes HL and bank 2; a second independent root at
    // the same transfer has unknown HL. Completeness does not establish agreement.
    try (var f = new Fixture(false)) {
      var result = BankAnalysis.preview(f.p, List.of(f.at("0150"), f.source),
          AnalysisResult.Configuration.DEFAULT, null, TaskMonitor.DUMMY);
      var transfers = result.findings().stream().filter(finding ->
          finding.source().equals(f.source.toString())).toList();
      System.out.println("WUX mixed same-source E9 completion=" + result.completion() + " findings=" + transfers);
      assertTrue(result.complete());
      assertTrue(transfers.stream().anyMatch(finding -> finding.confidence() == AnalysisResult.Confidence.PROVEN
          && finding.access().equals("jump")
          && finding.targets().equals(List.of(f.target.toString()))));
      assertTrue(transfers.stream().anyMatch(finding -> finding.confidence() == AnalysisResult.Confidence.UNKNOWN
          && finding.targets().isEmpty()));
    }
  }

  @Test void incompleteAnalyzerDoesNotRetireAnExistingExperimentalNativeArtifact() throws Exception {
    try (var f = new Fixture(false)) {
      f.proof();
      f.edit(() -> {
        var owned = new AnalysisOwnership.Group();
        owned.reference(f.p.getReferenceManager().addMemoryReference(f.source, f.target,
            RefType.COMPUTED_JUMP, SourceType.ANALYSIS, -1));
        AnalysisOwnership.save(f.p, "bank-analysis", owned);
      });
      var analyzer = new GhidraBoyBankAnalyzer();
      var options = f.p.getOptions("WUX experiment options");
      f.edit(() -> {
        analyzer.registerOptions(options, f.p);
        options.setInt(GhidraBoyBankAnalyzer.STATE_LIMIT, 1);
        options.setBoolean(GhidraBoyBankAnalyzer.CREATE_FUNCTIONS, false);
      });
      analyzer.optionsChanged(options, f.p);
      var log = new MessageLog();
      assertTrue(analyzer.added(f.p, new AddressSet(f.at("0150"), f.source), TaskMonitor.DUMMY, log));
      assertNotNull(f.p.getReferenceManager().getReference(f.source, f.target, -1));
      assertTrue(log.toString().contains("STATE_LIMIT"), log.toString());
      System.out.println("WUX incomplete retains experimental native artifact: " + log);
    }
  }

  @Test void distinctIncomingBanksRemainAmbiguousRatherThanSingletonNativeFlow() throws Exception {
    try (var f = new Fixture(false)) {
      f.edit(() -> {
        f.p.getMemory().setBytes(f.at("0300"), HexFormat.of().parseHex("3e01ea0020210041c35801"));
        f.define(f.at("0300"), 11);
      });
      var result = BankAnalysis.preview(f.p, List.of(f.at("0150"), f.at("0300")),
          AnalysisResult.Configuration.DEFAULT, null, TaskMonitor.DUMMY);
      assertTrue(result.complete());
      var jump = result.findings().stream().filter(finding -> finding.source().equals(f.source.toString())
          && finding.access().equals("jump")).findFirst().orElseThrow();
      assertEquals(AnalysisResult.Confidence.AMBIGUOUS, jump.confidence());
      assertEquals(List.of("rom1::4100", "rom2::4100"), jump.targets());
      BankAnalysis.apply(f.p, result, TaskMonitor.DUMMY);
      assertFalse(Arrays.stream(f.instruction.getReferencesFrom()).anyMatch(ref -> ref.getReferenceType().isFlow()));
    }
  }

  @Test void conflictingUserPrimaryRefusesOldProofWithoutReplacingUserWork() throws Exception {
    try (var f = new Fixture(true)) {
      var result = f.proof();
      var userTarget = f.at("rom1::4100");
      f.edit(() -> {
        var user = f.p.getReferenceManager().addMemoryReference(f.source, userTarget,
            RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
        f.p.getReferenceManager().setPrimary(user, true);
      });
      assertThrows(IllegalStateException.class, () -> BankAnalysis.apply(f.p, result, TaskMonitor.DUMMY));
      var user = f.p.getReferenceManager().getReference(f.source, userTarget, 0);
      assertEquals(SourceType.USER_DEFINED, user.getSource());
      assertTrue(user.isPrimary());
      assertEquals(userTarget, call(f.instruction.getPcode(true)).getInput(0).getAddress());
      assertNull(f.p.getReferenceManager().getReference(f.source, f.target, -1));
    }
  }

}
