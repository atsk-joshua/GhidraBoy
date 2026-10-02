package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import org.junit.jupiter.api.Test;

/** Independent straight-line fixtures qualify the per-invocation analysis resource boundary. */
class BankAnalysisLocalStateBudgetTest extends IntegrationTest {
  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("Local invocation resource boundary", getLanguage(),
        getLanguage().getDefaultCompilerSpec(), owner);
    final int returnCpu;

    Fixture(int requiredLocalStates) throws Exception {
      // Each LD A,0 is one evaluation at a distinct instruction; RET consumes the final one.
      // No branch, loop, mapper write, or nested invocation contributes to this arithmetic.
      String callee = "3e00".repeat(requiredLocalStates - 1) + "c9";
      returnCpu = 0x300 + 2 * (requiredLocalStates - 1);
      var bodies = Map.of(0x150, "3100d0cd000318fe", 0x300, callee);
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      for (var entry : bodies.entrySet()) {
        byte[] code = HexFormat.of().parseHex(entry.getValue());
        System.arraycopy(code, 0, bytes, entry.getKey(), code.length);
      }
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.GB,
            true, true, TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("Define local-state fixture");
      try {
        for (var entry : bodies.entrySet()) {
          var first = ProgramMapping.staticAddress(p, String.format("%04x", entry.getKey()));
          Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first,
              new AddressSet(first, first.add(entry.getValue().length() / 2 - 1)));
        }
      } finally { p.endTransaction(tx, true); }
    }

    BankAnalysis.FetchPreview preview(boolean reverse) throws Exception {
      return BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
          new AnalysisResult.Configuration(20000, reverse), TaskMonitor.DUMMY);
    }

    @Override public void close() { p.release(owner); }
  }

  private static List<BankAnalysis.FetchStep> localSteps(BankAnalysis.FetchPreview preview) {
    return preview.steps().stream().filter(step -> step.cpu() >= 0x300 && step.cpu() < 0x500).toList();
  }

  @Test void invocationsAtAndBelow179EvaluationsCompleteTheirMatchedReturn() throws Exception {
    for (int required : List.of(1, 128, 178, 179)) {
      try (var fixture = new Fixture(required)) {
        for (boolean reverse : List.of(false, true)) {
          var preview = fixture.preview(reverse);
          assertEquals(AnalysisResult.Completion.COMPLETE, preview.result().completion());
          assertEquals(required, localSteps(preview).size());
          assertEquals(fixture.returnCpu, localSteps(preview).getLast().cpu());
          assertEquals(1, preview.result().ordinaryCallProofs().size(), preview.result().findings().toString());
          var proof = preview.result().ordinaryCallProofs().getFirst();
          assertEquals("0153", proof.source());
          assertEquals("0300", proof.target());
          assertEquals("0156", proof.continuation());
          assertTrue(preview.steps().stream().anyMatch(step -> step.cpu() == 0x156));
          assertFalse(preview.result().findings().stream().anyMatch(f -> f.reason().contains("callee state bound")));
        }
      }
    }
  }

  @Test void invocationRequiring180EvaluationsRefusesBeforeItsReturnAtTheLocalGuard() throws Exception {
    try (var fixture = new Fixture(180)) {
      for (boolean reverse : List.of(false, true)) {
        var preview = fixture.preview(reverse);
        // A local refusal does not misreport exhaustion of the separate 20,000-state session budget.
        assertEquals(AnalysisResult.Completion.COMPLETE, preview.result().completion());
        assertEquals(179, localSteps(preview).size());
        assertTrue(preview.result().exploredStates() < 20000);
        assertTrue(preview.result().ordinaryCallProofs().isEmpty());
        assertFalse(preview.steps().stream().anyMatch(step -> step.cpu() == fixture.returnCpu));
        assertTrue(preview.result().findings().stream().anyMatch(f ->
            f.source().equals(String.format("%04x", fixture.returnCpu))
                && f.reason().contains("callee state bound")), preview.result().findings().toString());
        assertFalse(preview.result().findings().stream().anyMatch(f -> f.reason().contains("widen")));
      }
    }
  }
}
