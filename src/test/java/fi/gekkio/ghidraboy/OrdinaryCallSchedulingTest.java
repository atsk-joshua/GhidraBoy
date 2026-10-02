package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.function.FunctionAnalyzer;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** Exercises stock instruction scheduling, rather than invoking FunctionAnalyzer directly. */
class OrdinaryCallSchedulingTest extends IntegrationTest {
  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    Runnable afterCommit;
    final ProgramDB p = new ProgramDB("Ordinary CALL analyzer producer", getLanguage(), getLanguage().getDefaultCompilerSpec(), owner) {
      private int transactionDepth;

      @Override public int startTransaction(String description) {
        int id = super.startTransaction(description);
        transactionDepth++;
        return id;
      }

      @Override public boolean endTransaction(int transactionID, boolean commit) {
        boolean result = super.endTransaction(transactionID, commit);
        transactionDepth--;
        if (commit && transactionDepth == 0 && afterCommit != null) afterCommit.run();
        return result;
      }
    };
    final ghidra.program.model.address.Address root;
    final ghidra.program.model.address.Address source;
    final ghidra.program.model.address.Address target;
    final AutoAnalysisManager manager;

    Fixture() throws Exception { this(false); }

    Fixture(boolean twoCalls) throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      byte[] caller = HexFormat.of().parseHex(twoCalls ? "3100d03e02ea0020cd0040cd004076" : "3100d03e02ea0020cd004076");
      System.arraycopy(caller, 0, bytes, 0x150, caller.length);
      bytes[0x8000] = (byte) 0xc9;
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true,
            TaskMonitor.DUMMY, new MessageLog());
      }
      root = ProgramMapping.staticAddress(p, "0150");
      source = ProgramMapping.staticAddress(p, "0158");
      target = ProgramMapping.staticAddress(p, "rom2::4000");
      int tx = p.startTransaction("Define scheduling fixture");
      try {
        var disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null);
        disassembler.disassemble(root, new AddressSet(root, root.add(caller.length - 1)));
        disassembler.disassemble(target, new AddressSet(target));
      } finally { p.endTransaction(tx, true); }
      manager = AutoAnalysisManager.getAnalysisManager(p);
      var options = p.getOptions(Program.ANALYSIS_PROPERTIES);
      tx = p.startTransaction("Select affected instruction analyzers");
      try {
        for (String name : options.getOptionNames()) {
          if (manager.getAnalyzer(name) != null)
            options.setBoolean(name, name.equals("Subroutine References") || name.equals(GhidraBoyBankAnalyzer.NAME));
        }
        options.getOptions(GhidraBoyBankAnalyzer.NAME).setBoolean(GhidraBoyBankAnalyzer.CREATE_FUNCTIONS, false);
      } finally { p.endTransaction(tx, true); }
      manager.initializeOptions();
    }

    AnalysisResult proof() throws Exception {
      return BankAnalysis.previewFetch(p, root, MapperState.reset(),
          new AnalysisResult.Configuration(4096, false), TaskMonitor.DUMMY).result();
    }

    @Override public void close() { p.release(owner); }
  }

  private static final class PassMonitor extends TaskMonitorAdapter {
    int relationalPasses;

    @Override public void setMessage(String message) {
      if (message.startsWith("GhidraBoy: deriving physical entry state")) relationalPasses++;
      super.setMessage(message);
    }
  }

  @Test void cancellationDuringNotificationPreparationRollsBackWithoutFeedback() throws Exception {
    try (var f = new Fixture()) {
      var proof = f.proof();
      var decoded = OrdinaryCallFlow.Tuple.of(f.p.getListing().getInstructionAt(f.source).getReferencesFrom()[0]);
      var monitor = new TaskMonitorAdapter(true) {
        @Override public void checkCancelled() throws ghidra.util.exception.CancelledException {
          if (!OrdinaryCallFlow.receipts(f.p).isEmpty()) cancel();
          super.checkCancelled();
        }
      };
      assertThrows(ghidra.util.exception.CancelledException.class, () -> BankAnalysis.apply(f.p, proof, monitor));
      assertTrue(OrdinaryCallFlow.receipts(f.p).isEmpty());
      assertEquals(decoded, OrdinaryCallFlow.Tuple.of(f.p.getListing().getInstructionAt(f.source).getReferencesFrom()[0]));
      assertNull(f.p.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", null));
      assertFalse(OrdinaryCallFlow.consumeNotification(f.p, new AddressSet(f.source), TaskMonitor.DUMMY));
    }
  }

  @Test void cancellationAtCommitBoundaryCannotMakeSuccessfulApplyThrow() throws Exception {
    try (var f = new Fixture()) {
      var proof = f.proof();
      var monitor = new TaskMonitorAdapter(true);
      f.afterCommit = monitor::cancel;
      assertDoesNotThrow(() -> BankAnalysis.apply(f.p, proof, monitor));
      assertTrue(monitor.isCancelled(), "Cancellation must arrive immediately after the real commit");
      assertNotNull(OrdinaryCallFlow.exact(f.p.getListing().getInstructionAt(f.source)));
      assertTrue(OrdinaryCallFlow.consumeNotification(f.p, new AddressSet(f.source), TaskMonitor.DUMMY));
    }
  }

  @Test void coalescedIndependentAddressesDoNotSuppressRequiredAnalysis() throws Exception {
    try (var f = new Fixture()) {
      BankAnalysis.apply(f.p, f.proof(), TaskMonitor.DUMMY);
      var coalesced = new AddressSet(f.source);
      coalesced.add(f.root);
      assertFalse(OrdinaryCallFlow.consumeNotification(f.p, coalesced, TaskMonitor.DUMMY));
      assertFalse(OrdinaryCallFlow.consumeNotification(f.p, new AddressSet(f.source), TaskMonitor.DUMMY),
          "A rejected coalesced notification retires the token; later work runs normally");
    }
  }

  @Test void partitionedFeedbackCannotSuppressLaterIndependentWork() throws Exception {
    try (var f = new Fixture(true)) {
      var proof = f.proof();
      assertEquals(2, proof.ordinaryCallProofs().size());
      BankAnalysis.apply(f.p, proof, TaskMonitor.DUMMY);
      assertTrue(OrdinaryCallFlow.consumeNotification(f.p, new AddressSet(f.source), TaskMonitor.DUMMY));
      assertFalse(OrdinaryCallFlow.consumeNotification(f.p, new AddressSet(f.source.add(3)), TaskMonitor.DUMMY),
          "Only the first exact subset is suppressed; remaining partition conservatively reruns");
    }
  }

  @Test void ordinaryAnalyzerProducerPublishesAndStockDiscoversTargetInSameSession() throws Exception {
    try (var f = new Fixture()) {
      var monitor = new PassMonitor();
      int tx = f.p.startTransaction("Analyze caller through ordinary instruction pipeline");
      try {
        // The producer's restriction must include the actual physical callee and its RET.
        f.manager.codeDefined(new AddressSet(f.p.getMemory()));
        f.manager.startAnalysis(monitor);
      } finally { f.p.endTransaction(tx, true); }
      var result = AnalysisResult.read(f.p.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", null));
      var function = f.p.getFunctionManager().getFunctionAt(f.target);
      assertNotNull(function, "Saved producer result: " + result);
      assertEquals(SourceType.DEFAULT, function.getSymbol().getSource());
      assertFalse(GhidraBoyBankAnalyzer.roots(f.p, new AddressSet(f.p.getMemory()), TaskMonitor.DUMMY).contains(f.target),
          "A stock generated Function must not become an architectural entry premise in a broad session");
      assertArrayEquals(new Object[] {f.target}, f.p.getListing().getInstructionAt(f.source).getFlows());
      assertEquals(1, monitor.relationalPasses, "Producer should run once, and consume its own exact publication notification");
      assertTrue(result.ordinaryCallProofs().stream().anyMatch(proof -> proof.source().equals("0158")));
    }
  }

  @Test void changedDependencyFlowOrOwnershipDoesNotConsumePublicationAsUnchangedFeedback() throws Exception {
    for (int mutation = 0; mutation < 3; mutation++) try (var f = new Fixture()) {
      BankAnalysis.apply(f.p, f.proof(), TaskMonitor.DUMMY);
      int tx = f.p.startTransaction("Change state after publication notification");
      try {
        if (mutation == 2) {
          var group = AnalysisOwnership.group(f.p, OrdinaryCallFlow.GROUP);
          group.ordinaryCalls.clear();
          AnalysisOwnership.save(f.p, OrdinaryCallFlow.GROUP, group);
        } else if (mutation == 1) {
          f.p.getReferenceManager().addMemoryReference(f.source, ProgramMapping.staticAddress(f.p, "rom1::4000"),
              RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
        } else {
          f.p.getListing().clearCodeUnits(f.root.add(3), f.root.add(4), false);
          f.p.getMemory().setByte(f.root.add(4), (byte) 1);
          Disassembler.getDisassembler(f.p, TaskMonitor.DUMMY, null)
              .disassemble(f.root.add(3), new AddressSet(f.root.add(3), f.root.add(4)));
        }
      } finally { f.p.endTransaction(tx, true); }
      var monitor = new PassMonitor();
      var analyzer = (GhidraBoyBankAnalyzer) f.manager.getAnalyzer(GhidraBoyBankAnalyzer.NAME);
      assertTrue(analyzer.added(f.p, new AddressSet(f.source), monitor, new MessageLog()));
      assertEquals(1, monitor.relationalPasses, "Changed consumed semantics, independent flow or ownership must invalidate feedback suppression");
    }
  }

  @Test void publicationWakesStockFunctionDiscoveryWithoutRelationalSelfFeedback() throws Exception {
    Object owner = new Object();
    var p = new ProgramDB("Ordinary CALL stock scheduling", getLanguage(), getLanguage().getDefaultCompilerSpec(), owner);
    try {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      byte[] caller = HexFormat.of().parseHex("3100d03e02ea0020cd004076");
      System.arraycopy(caller, 0, bytes, 0x150, caller.length);
      bytes[0x8000] = (byte) 0xc9;
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true,
            TaskMonitor.DUMMY, new MessageLog());
      }
      var root = ProgramMapping.staticAddress(p, "0150");
      var source = ProgramMapping.staticAddress(p, "0158");
      var target = ProgramMapping.staticAddress(p, "rom2::4000");
      int tx = p.startTransaction("Define ordinary CALL scheduling fixture");
      try {
        var disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null);
        disassembler.disassemble(root, new AddressSet(root, root.add(caller.length - 1)));
        disassembler.disassemble(target, new AddressSet(target));
      } finally { p.endTransaction(tx, true); }
      var result = BankAnalysis.previewFetch(p, root, MapperState.reset(),
          new AnalysisResult.Configuration(4096, false), TaskMonitor.DUMMY).result();
      assertTrue(result.complete());
      assertEquals(1, result.ordinaryCallProofs().size());
      assertNull(p.getFunctionManager().getFunctionAt(target));

      var manager = AutoAnalysisManager.getAnalysisManager(p);
      assertInstanceOf(FunctionAnalyzer.class, manager.getAnalyzer("Subroutine References"));
      assertInstanceOf(GhidraBoyBankAnalyzer.class, manager.getAnalyzer(GhidraBoyBankAnalyzer.NAME));
      var options = p.getOptions(Program.ANALYSIS_PROPERTIES);
      tx = p.startTransaction("Select only affected instruction analyzers");
      try {
        for (String name : options.getOptionNames()) {
          if (manager.getAnalyzer(name) != null)
            options.setBoolean(name, name.equals("Subroutine References") || name.equals(GhidraBoyBankAnalyzer.NAME));
        }
        options.getOptions(GhidraBoyBankAnalyzer.NAME).setBoolean(GhidraBoyBankAnalyzer.CREATE_FUNCTIONS, false);
      } finally { p.endTransaction(tx, true); }
      manager.initializeOptions();

      var monitor = new PassMonitor();
      BankAnalysis.apply(p, result, monitor);
      assertArrayEquals(new Object[] {target}, p.getListing().getInstructionAt(source).getFlows());
      assertNull(p.getFunctionManager().getFunctionAt(target), "Publication must leave Function creation to stock scheduling");
      tx = p.startTransaction("Run same-session stock publication notification");
      try { manager.startAnalysis(monitor); } finally { p.endTransaction(tx, true); }
      var function = p.getFunctionManager().getFunctionAt(target);
      assertNotNull(function, "Stock Subroutine References must discover the physical target");
      assertEquals(0, monitor.relationalPasses, "An unchanged publication notification must not rerun relational analysis");
      long functionId = function.getID();

      BankAnalysis.apply(p, result, monitor);
      tx = p.startTransaction("Drain idempotent reapplication");
      try { manager.startAnalysis(monitor); } finally { p.endTransaction(tx, true); }
      assertEquals(functionId, p.getFunctionManager().getFunctionAt(target).getID());
      assertEquals(0, monitor.relationalPasses, "Idempotent publication must not feed another analysis pass");
      assertArrayEquals(new Object[] {target}, p.getListing().getInstructionAt(source).getFlows());
    } finally { p.release(owner); }
  }
}
