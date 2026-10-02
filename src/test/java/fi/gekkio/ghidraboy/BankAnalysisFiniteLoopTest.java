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

/** Public production paths through self-authored finite loops and refusal counterexamples. */
class BankAnalysisFiniteLoopTest extends IntegrationTest {
  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("Finite conditional loops", getLanguage(),
        getLanguage().getDefaultCompilerSpec(), owner);

    Fixture(String callee) throws Exception {
      this("3100d0cd000318fe", callee);
    }

    Fixture(String caller, String callee) throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      var bodies = Map.of(0x150, caller, 0x300, callee);
      for (var entry : bodies.entrySet()) {
        byte[] code = HexFormat.of().parseHex(entry.getValue());
        System.arraycopy(code, 0, bytes, entry.getKey(), code.length);
      }
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.GB,
            true, true, TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("Define finite-loop fixture");
      try {
        for (var entry : bodies.entrySet()) {
          var first = ProgramMapping.staticAddress(p, String.format("%04x", entry.getKey()));
          Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first,
              new AddressSet(first, first.add(entry.getValue().length() / 2 - 1)));
        }
      } finally { p.endTransaction(tx, true); }
    }

    BankAnalysis.FetchPreview preview(boolean reverse, int limit, TaskMonitor monitor) throws Exception {
      return BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
          new AnalysisResult.Configuration(limit, reverse), monitor);
    }

    BankAnalysis.FetchPreview preview(boolean reverse) throws Exception {
      return preview(reverse, 4096, TaskMonitor.DUMMY);
    }

    @Override public void close() { p.release(owner); }
  }

  private static List<BankAnalysis.WriteTransition> writes(BankAnalysis.FetchPreview preview, int destination) {
    return preview.steps().stream().flatMap(step -> step.writes().stream())
        .filter(write -> write.cpu() == destination).toList();
  }

  private static long visits(BankAnalysis.FetchPreview preview, int cpu) {
    return preview.steps().stream().filter(step -> step.cpu() == cpu).count();
  }

  private static void exactWrite(BankAnalysis.FetchPreview preview, int destination, int value) {
    assertEquals(List.of(value), writes(preview, destination).stream().map(BankAnalysis.WriteTransition::value).toList());
  }

  private static void admitted(BankAnalysis.FetchPreview preview) {
    assertEquals(AnalysisResult.Completion.COMPLETE, preview.result().completion());
    assertEquals(1, preview.result().ordinaryCallProofs().size(), preview.result().findings().toString());
    var proof = preview.result().ordinaryCallProofs().getFirst();
    assertEquals("0153", proof.source());
    assertEquals("0300", proof.target());
    assertEquals("0156", proof.continuation());
    assertFalse(preview.result().findings().stream().anyMatch(f -> f.reason().contains("widen")
        || f.reason().contains("callee state bound")), preview.result().findings().toString());
  }

  @Test void fourIncrementCompareIterationsExitExactlyAtFour() throws Exception {
    try (var fixture = new Fixture("0e000c79fe0420fa79ea00c1c9")) {
      var forward = fixture.preview(false);
      var reverse = fixture.preview(true);
      admitted(forward);
      admitted(reverse);
      assertEquals(4, visits(forward, 0x302));
      assertEquals(4, visits(forward, 0x306));
      exactWrite(forward, 0xc100, 4);
      var branches = forward.steps().stream().filter(step -> step.cpu() == 0x306).toList();
      assertEquals(List.of(List.of("0302"), List.of("0302"), List.of("0302"), List.of("0308")),
          branches.stream().map(BankAnalysis.FetchStep::successors).toList());
      assertEquals(forward.result().findings(), reverse.result().findings());
      assertEquals(forward.result().ordinaryCallProofs(), reverse.result().ordinaryCallProofs());
      exactWrite(reverse, 0xc100, 4);
    }
  }

  @Test void eightCopyDecrementIterationsPreserveUnknownCarryAndExactPointers() throws Exception {
    // Source WRAM has no written facts: eight supported unknown data bytes are copied.
    // DEC's preserved C flag remains unknown while newly computed Z controls the loop.
    try (var fixture = new Fixture("16082100c10100c22a02031520fa"
        + "7aea00c37dea01c37cea02c379ea03c378ea04c3f5c179ea05c3c9")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = fixture.preview(reverse);
        admitted(preview);
        assertEquals(8, visits(preview, 0x308));
        assertEquals(8, visits(preview, 0x30c));
        exactWrite(preview, 0xc300, 0); // D
        exactWrite(preview, 0xc301, 8); // L
        exactWrite(preview, 0xc302, 0xc1); // H
        exactWrite(preview, 0xc303, 8); // C
        exactWrite(preview, 0xc304, 0xc2); // B
        assertEquals(1, writes(preview, 0xc305).size());
        assertNull(writes(preview, 0xc305).getFirst().value()); // F is not invented as exact.
        for (int destination = 0xc200; destination < 0xc208; destination++) {
          var copied = writes(preview, destination);
          assertEquals(1, copied.size());
          assertNull(copied.getFirst().value());
        }
        var branches = preview.steps().stream().filter(step -> step.cpu() == 0x30c).toList();
        assertTrue(branches.subList(0, 7).stream().allMatch(step -> step.successors().equals(List.of("0308"))));
        assertEquals(List.of("030e"), branches.getLast().successors());
      }
    }
  }

  @Test void incrementZeroPredicateSurvivesUnknownPreservedCarry() throws Exception {
    try (var fixture = new Fixture("0efe0c20fd79ea00c1c9")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = fixture.preview(reverse);
        admitted(preview);
        assertEquals(2, visits(preview, 0x302));
        exactWrite(preview, 0xc100, 0);
        assertEquals(List.of(List.of("0302"), List.of("0305")), preview.steps().stream()
            .filter(step -> step.cpu() == 0x303).map(BankAnalysis.FetchStep::successors).toList());
      }
    }
  }

  @Test void calleeReturnsKnownZeroWithoutInventingCarryForCallerBranch() throws Exception {
    // DEC 1 establishes Z=1 but preserves incoming unknown carry. Caller JR NZ
    // must fall through after the actual CALL/RET transfer of the partial F byte.
    try (var fixture = new Fixture("3100d0cd000320093e11ea00c118fe3e22ea00c118fe", "160115c9")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = fixture.preview(reverse);
        admitted(preview);
        assertEquals(List.of("0158"), preview.steps().stream().filter(step -> step.cpu() == 0x156)
            .findFirst().orElseThrow().successors());
        exactWrite(preview, 0xc100, 0x11);
        assertEquals(0, visits(preview, 0x161));
      }
    }
  }

  @Test void compatibleReturnedFlagsMeetKeepsZeroAndLosesDisagreeingCarry() throws Exception {
    // Unknown incoming carry selects F=80 or F=90 through real PUSH/POP AF.
    // Both compatible returns agree on Z=1. The caller's NZ edge is impossible,
    // while its C predicate retains both successors after the returned-state meet.
    String caller = "3100d0cd0003201038073e11ea00c118fe3e22ea00c118fe3eeeea01c118fe";
    String callee = "3806018000c5f1c9019000c5f1c9";
    try (var fixture = new Fixture(caller, callee)) {
      var forward = fixture.preview(false);
      var reverse = fixture.preview(true);
      for (var preview : List.of(forward, reverse)) {
        admitted(preview);
        assertEquals(List.of("0158"), preview.steps().stream().filter(step -> step.cpu() == 0x156)
            .findFirst().orElseThrow().successors());
        assertEquals(Set.of("015a", "0161"), new HashSet<>(preview.steps().stream()
            .filter(step -> step.cpu() == 0x158).findFirst().orElseThrow().successors()));
        assertEquals(Set.of(0x11, 0x22), new HashSet<>(writes(preview, 0xc100).stream()
            .map(BankAnalysis.WriteTransition::value).toList()));
        assertTrue(writes(preview, 0xc101).isEmpty());
      }
      assertEquals(forward.result().findings(), reverse.result().findings());
      assertEquals(forward.result().ordinaryCallProofs(), reverse.result().ordinaryCallProofs());
    }
  }

  @Test void jrZeroAndCarryVariantsPruneOnlyKnownImpossibleEdges() throws Exception {
    for (int opcode : List.of(0x20, 0x28, 0x30, 0x38)) {
      int bit = opcode == 0x20 || opcode == 0x28 ? 0x80 : 0x10;
      for (Integer flags : Arrays.asList(null, 0, bit)) {
        String prefix = flags == null ? "" : String.format("01%02x00c5f1", flags);
        int branchCpu = 0x300 + prefix.length() / 2;
        try (var fixture = new Fixture(prefix + String.format("%02x06", opcode)
            + "3e11ea00c1c93e22ea00c1c9")) {
          for (boolean reverse : List.of(false, true)) {
            var preview = fixture.preview(reverse);
            admitted(preview);
            var branch = preview.steps().stream().filter(step -> step.cpu() == branchCpu).findFirst().orElseThrow();
            if (flags == null) {
              assertEquals(2, branch.successors().size());
              assertEquals(Set.of(0x11, 0x22), new HashSet<>(writes(preview, 0xc100).stream()
                  .map(BankAnalysis.WriteTransition::value).toList()));
            } else {
              boolean taken = (opcode & 8) == 0 ? (flags & bit) == 0 : (flags & bit) != 0;
              assertEquals(List.of(String.format("%04x", branchCpu + (taken ? 8 : 2))), branch.successors());
              exactWrite(preview, 0xc100, taken ? 0x22 : 0x11);
            }
          }
        }
      }
    }
  }

  @Test void stableLoopWithReturnArmAndUnknownCounterRemainRefused() throws Exception {
    // Unknown NZ permits both a self-loop and RET; unknown D cannot acquire a guessed count.
    for (String body : List.of("20fec9", "1520fdc9")) {
      try (var fixture = new Fixture(body)) {
        for (boolean reverse : List.of(false, true)) {
          var preview = fixture.preview(reverse);
          assertTrue(preview.result().ordinaryCallProofs().isEmpty());
          assertEquals(AnalysisResult.Completion.COMPLETE, preview.result().completion());
        }
      }
    }
  }

  @Test void wraparoundCounterCannotBecomeTerminationEvidence() throws Exception {
    try (var fixture = new Fixture("0e000c18fd")) {
      var preview = fixture.preview(false);
      assertTrue(preview.result().ordinaryCallProofs().isEmpty());
      assertEquals(0, visits(preview, 0x305));
    }
  }

  @Test void unsupportedBodyAndUnresolvedMapperCannotBeRepairedByCounterExit() throws Exception {
    // The serial read is unsupported even when the subsequent DEC terminates.
    // A supported unknown WRAM selector destroys banked-fetch identity.
    for (String body : List.of("1608f0011520fbc9", "fa00c1ea0020c30040")) {
      try (var fixture = new Fixture(body)) {
        assertTrue(fixture.preview(false).result().ordinaryCallProofs().isEmpty());
      }
    }
  }

  @Test void resourceAndCancellationGuardsStillRefuseFiniteLoops() throws Exception {
    try (var fixture = new Fixture("0e000c79fe0420fa79ea00c1c9")) {
      var limited = fixture.preview(false, 5, TaskMonitor.DUMMY);
      assertEquals(AnalysisResult.Completion.STATE_LIMIT, limited.result().completion());
      assertEquals(5, limited.result().exploredStates());
      assertTrue(limited.result().ordinaryCallProofs().isEmpty());
      var monitor = new TaskMonitorAdapter(true) {
        int invocations;
        @Override public void setMessage(String message) {
          if (message.equals("Exploring bank states") && ++invocations == 2) cancel();
        }
      };
      var cancelled = fixture.preview(false, 4096, monitor);
      assertEquals(AnalysisResult.Completion.CANCELLED, cancelled.result().completion());
      assertTrue(cancelled.result().ordinaryCallProofs().isEmpty());
    }
    try (var fixture = new Fixture("3e00".repeat(129) + "c9")) {
      var preview = fixture.preview(false);
      assertTrue(preview.result().ordinaryCallProofs().isEmpty());
      assertTrue(preview.result().findings().stream().anyMatch(f -> f.reason().contains("callee state bound")));
    }
  }
}
