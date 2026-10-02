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

/** Revision/currentness and bounded local performance controls. */
class OrdinaryCallBasisTest extends IntegrationTest {
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


  @Test void oneUnchangedRevisionReusesExactReceiptIndexAndNormalizedBasis() throws Exception {
    try (var f = new Fixture()) {
      var result = f.proof();
      f.publish(result);
      var basis = OrdinaryCallBasis.current(f.p, TaskMonitor.DUMMY);
      assertEquals(result.fingerprint(), basis.fingerprint());
      assertEquals(1, basis.snapshot().bySource().size());
      for (int i = 0; i < 20; i++) {
        assertTrue(OrdinaryCallFlow.architecturalExemption(f.instruction, f.calls().get(0)));
        assertSame(basis, OrdinaryCallBasis.current(f.p, TaskMonitor.DUMMY));
        assertSame(basis.snapshot(), OrdinaryCallBasis.snapshot(f.p));
      }
      // Forced cold load remains equivalent: no transient cache is proof authority.
      OrdinaryCallBasis.clear(f.p);
      var cold = OrdinaryCallBasis.current(f.p, TaskMonitor.DUMMY);
      assertNotSame(basis, cold);
      assertEquals(basis.fingerprint(), cold.fingerprint());
    }
  }

  @Test void everyProgramRevisionRebuildsBasisAndRelevantMutationsRefuseExemption() throws Exception {
    for (String mutation : List.of("flow", "bytes", "permissions", "ownership", "eligibility"))
      try (var f = new Fixture()) {
        var result = f.proof();
        f.publish(result);
        var prior = OrdinaryCallBasis.current(f.p, TaskMonitor.DUMMY);
        f.edit(() -> {
          switch (mutation) {
            case "flow" -> f.p.getReferenceManager().addMemoryReference(f.at("0150"), f.at("0300"),
                RefType.UNCONDITIONAL_JUMP, SourceType.ANALYSIS, 1);
            case "bytes" -> {
              f.p.getListing().clearCodeUnits(f.at("0150"), f.at("0152"), false);
              f.p.getMemory().setByte(f.at("0151"), (byte) 0x01);
              f.define(f.at("0150"), 3);
            }
            case "permissions" -> f.p.getMemory().getBlock(f.target).setExecute(false);
            case "ownership" -> AnalysisOwnership.save(f.p, OrdinaryCallFlow.GROUP, new AnalysisOwnership.Group());
            case "eligibility" -> f.p.getMemory().getBlock(f.target).setName(OrdinaryEntryAccess.PREFIX + "changed");
            default -> throw new AssertionError(mutation);
          }
          // Even inside an open transaction, revision changes invalidate immediately.
          assertNotEquals(prior.snapshot().revision(), f.p.getModificationNumber(), mutation);
          assertFalse(OrdinaryCallFlow.architecturalExemption(f.instruction, f.calls().get(0)), mutation);
          var current = OrdinaryCallBasis.current(f.p, TaskMonitor.DUMMY);
          assertNotSame(prior, current, mutation);
          assertNotSame(prior.snapshot(), current.snapshot(), mutation);
          assertNotEquals(prior.fingerprint(), current.fingerprint(), mutation);
        });
        assertThrows(IllegalStateException.class,
            () -> ProgramFingerprint.requireCurrent(f.p, result, TaskMonitor.DUMMY), mutation);
      }
  }

  @Test void rollbackRevisionCannotReuseAnInTransactionBasis() throws Exception {
    try (var f = new Fixture()) {
      var result = f.proof();
      f.publish(result);
      var before = OrdinaryCallBasis.current(f.p, TaskMonitor.DUMMY);
      int tx = f.p.startTransaction("Rolled back flow edit");
      OrdinaryCallBasis.Basis edited;
      try {
        f.p.getReferenceManager().addMemoryReference(f.source, f.at("0300"),
            RefType.UNCONDITIONAL_CALL, SourceType.IMPORTED, 1);
        edited = OrdinaryCallBasis.current(f.p, TaskMonitor.DUMMY);
        assertNotEquals(before.fingerprint(), edited.fingerprint());
      } finally { f.p.endTransaction(tx, false); }
      var restored = OrdinaryCallBasis.current(f.p, TaskMonitor.DUMMY);
      assertNotSame(edited, restored);
      assertEquals(before.fingerprint(), restored.fingerprint());
      assertTrue(OrdinaryCallFlow.architecturalExemption(f.p.getListing().getInstructionAt(f.source), f.calls().get(0)));
    }
  }

  @Test void boundedLargeFixtureProbe() throws Exception {
    try (var f = new Fixture()) {
      f.edit(() -> {
        byte[] code = new byte[8192];
        Arrays.fill(code, (byte) 0x04); // INC B avoids Ghidra's repeated-zero disassembly guard.
        f.p.getMemory().setBytes(f.at("1000"), code);
        var disassembler = Disassembler.getDisassembler(f.p, TaskMonitor.DUMMY, null);
        disassembler.setRepeatPatternLimit(-1);
        disassembler.disassemble(f.at("1000"), new AddressSet(f.at("1000"), f.at("1000").add(code.length - 1)));
      });
      assertTrue(f.p.getListing().getNumInstructions() >= 8192);
      var result = f.proof();
      f.publish(result);
      var ref = f.calls().get(0);
      // A bounded diagnostic only: timing never determines acceptance.
      long start = System.nanoTime();
      for (int i = 0; i < 4; i++)
        assertTrue(OrdinaryCallFlow.architecturalExemption(f.instruction, ref));
      long elapsed = System.nanoTime() - start;
      start = System.nanoTime();
      assertEquals(result.fingerprint(), ProgramFingerprint.capture(f.p, TaskMonitor.DUMMY));
      System.out.println("WUX1A_R1_PROBE instructions=" + f.p.getListing().getNumInstructions()
          + " exemption_checks=4 exemption_ns=" + elapsed
          + " capture_ns=" + (System.nanoTime() - start));
    }
  }
}
