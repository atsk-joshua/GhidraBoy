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

/** Independent quotient-graph decision controls plus unchanged production refusal controls. */
class LoopStateGraphDecisionTest extends IntegrationTest {
  // Memory is deliberately absent: a quotient cycle can conservatively refuse a
  // RAM-only ranking, but joining/suppressing RAM snapshots cannot hide a backedge.
  private record Key(int pc, int counter) {}
  private record Snapshot(Key key, Map<Integer, Integer> memory) {}

  private static final class DecisionGraph {
    final Map<Key, Set<Key>> edges = new HashMap<>();
    final Map<Key, Snapshot> joined = new HashMap<>();
    final ArrayDeque<Snapshot> pending = new ArrayDeque<>();

    boolean transfer(Key source, Snapshot successor) {
      edges.computeIfAbsent(source, ignored -> new HashSet<>()).add(successor.key());
      edges.computeIfAbsent(successor.key(), ignored -> new HashSet<>());
      var prior = joined.get(successor.key());
      if (prior != null) {
        var common = new HashMap<>(prior.memory());
        var incomingMemory = successor.memory();
        common.entrySet().removeIf(e -> !Objects.equals(e.getValue(), incomingMemory.get(e.getKey())));
        if (common.equals(prior.memory())) return false;
        successor = new Snapshot(successor.key(), Map.copyOf(common));
      }
      joined.put(successor.key(), successor);
      pending.addLast(successor);
      return true;
    }

    // Topological elimination is independent of production's recursive DFS.
    boolean acyclic() {
      var incoming = new HashMap<Key, Integer>();
      edges.keySet().forEach(key -> incoming.put(key, 0));
      edges.values().forEach(next -> next.forEach(key -> incoming.merge(key, 1, Integer::sum)));
      var ready = new ArrayDeque<Key>();
      incoming.forEach((key, count) -> { if (count == 0) ready.addLast(key); });
      int removed = 0;
      while (!ready.isEmpty()) {
        var key = ready.removeFirst();
        removed++;
        for (var next : edges.get(key))
          if (incoming.merge(next, -1, Integer::sum) == 0) ready.addLast(next);
      }
      return removed == incoming.size();
    }
  }

  private static Snapshot state(int pc, int counter, int ram) {
    return new Snapshot(new Key(pc, counter), Map.of(0xc100, ram));
  }

  @Test void agreeingDiamondConvergenceIsNotAStateCycle() {
    for (boolean reverse : List.of(false, true)) {
      var graph = new DecisionGraph();
      var root = new Key(0, 0);
      var left = new Key(1, 0);
      var right = new Key(2, 0);
      var end = state(3, 0, 7);
      graph.transfer(root, state(1, 0, 7));
      graph.transfer(root, state(2, 0, 7));
      assertTrue(graph.transfer(reverse ? right : left, end));
      assertFalse(graph.transfer(reverse ? left : right, end));
      assertEquals(Map.of(0xc100, 7), graph.joined.get(end.key()).memory());
      assertTrue(graph.acyclic());
    }
  }

  @Test void disagreeingDiamondWeakensMemoryWithoutCreatingACycle() {
    for (boolean reverse : List.of(false, true)) {
      var graph = new DecisionGraph();
      var root = new Key(0, 0);
      var left = new Key(1, 0);
      var right = new Key(2, 0);
      graph.transfer(root, state(1, 0, 7));
      graph.transfer(root, state(2, 0, 8));
      assertTrue(graph.transfer(reverse ? right : left, state(3, 0, reverse ? 8 : 7)));
      assertTrue(graph.transfer(reverse ? left : right, state(3, 0, reverse ? 7 : 8)));
      assertEquals(Map.of(), graph.joined.get(new Key(3, 0)).memory());
      assertTrue(graph.acyclic());
    }
  }

  @Test void suppressedMemorySnapshotStillRecordsReachableCycle() {
    var graph = new DecisionGraph();
    var first = new Key(1, 0);
    var second = new Key(2, 0);
    graph.transfer(new Key(0, 0), new Snapshot(first, Map.of()));
    graph.transfer(first, state(2, 0, 8));
    // Existing unknown RAM subsumes this exact RAM: enqueue is suppressed.
    assertFalse(graph.transfer(second, state(1, 0, 7)));
    assertTrue(graph.edges.get(second).contains(first));
    assertFalse(graph.acyclic());
  }

  @Test void changedRegisterCounterCreatesAFiniteDagDespiteAddressBackedges() {
    for (int count : List.of(4, 8)) {
      var graph = new DecisionGraph();
      var source = new Key(0, count);
      for (int remaining = count; remaining > 0; remaining--) {
        var body = state(1, remaining, remaining);
        graph.transfer(source, body);
        var next = state(0, remaining - 1, remaining - 1);
        graph.transfer(body.key(), next);
        source = next.key();
      }
      graph.transfer(source, state(2, 0, 0));
      assertTrue(graph.acyclic());
      assertEquals(count, graph.edges.keySet().stream().filter(k -> k.pc() == 1).count());
      assertEquals(Map.of(0xc100, 0), graph.joined.get(new Key(2, 0)).memory());
    }
  }

  @Test void stableLoopRefusesEvenWithReachableReturnArm() {
    var graph = new DecisionGraph();
    var loop = new Key(0, 0);
    graph.transfer(loop, state(1, 0, 0));
    graph.transfer(loop, state(0, 0, 0));
    assertFalse(graph.transfer(loop, state(0, 0, 0)));
    assertFalse(graph.acyclic());
  }

  @Test void memoryOnlyCountdownIsConservativelyRefused() {
    var graph = new DecisionGraph();
    var loop = new Key(0, 0);
    graph.transfer(new Key(2, 0), state(0, 0, 2));
    graph.transfer(loop, state(0, 0, 1));
    assertFalse(graph.transfer(loop, state(0, 0, 0)));
    graph.transfer(loop, state(1, 0, 0));
    assertFalse(graph.acyclic());
  }

  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("Loop decision refusals", getLanguage(),
        getLanguage().getDefaultCompilerSpec(), owner);

    Fixture(Map<Integer, String> bodies) throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      for (var entry : bodies.entrySet()) {
        var part = HexFormat.of().parseHex(entry.getValue());
        System.arraycopy(part, 0, bytes, entry.getKey(), part.length);
      }
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.GB,
            true, true, TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("Define decision fixture");
      try {
        for (var entry : bodies.entrySet()) {
          var first = ProgramMapping.staticAddress(p, String.format("%04x", entry.getKey()));
          Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first,
              new AddressSet(first, first.add(entry.getValue().length() / 2 - 1)));
        }
      } finally { p.endTransaction(tx, true); }
    }

    AnalysisResult preview(int limit, boolean reverse, TaskMonitor monitor) throws Exception {
      return BankAnalysis.preview(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
          new AnalysisResult.Configuration(limit, reverse), monitor);
    }

    @Override public void close() { p.release(owner); }
  }

  private static final String CALLER = "3100d0cd000318fe";

  @Test void productionRetainsFiniteAcyclicLocalBound() throws Exception {
    try (var fixture = new Fixture(Map.of(0x150, CALLER, 0x300, "3e00".repeat(129) + "c9"))) {
      for (boolean reverse : List.of(false, true)) {
        var result = fixture.preview(4096, reverse, TaskMonitor.DUMMY);
        assertEquals(AnalysisResult.Completion.COMPLETE, result.completion());
        assertTrue(result.ordinaryCallProofs().isEmpty());
        assertTrue(result.findings().stream().anyMatch(f -> f.reason().contains("callee state bound")));
      }
    }
  }

  @Test void productionRetainsGlobalBudgetAndCancellation() throws Exception {
    try (var fixture = new Fixture(Map.of(0x150, CALLER, 0x300, "3e00c9"))) {
      var limited = fixture.preview(3, false, TaskMonitor.DUMMY);
      assertEquals(AnalysisResult.Completion.STATE_LIMIT, limited.completion());
      assertEquals(3, limited.exploredStates());
      assertTrue(limited.ordinaryCallProofs().isEmpty());
      var monitor = new TaskMonitorAdapter(true) {
        int invocations;
        @Override public void setMessage(String message) {
          if (message.equals("Exploring bank states") && ++invocations == 2) cancel();
        }
      };
      var cancelled = fixture.preview(4096, false, monitor);
      assertEquals(AnalysisResult.Completion.CANCELLED, cancelled.completion());
      assertTrue(cancelled.ordinaryCallProofs().isEmpty());
    }
  }

  @Test void productionRetainsUnsupportedEffectMapperAndRecursionRefusals() throws Exception {
    // Unsupported serial-register read, supported unknown WRAM selector then banked jump, and self CALL.
    for (String body : List.of("f001c9", "fa00c1ea0020c30040", "cd0003c9")) {
      try (var fixture = new Fixture(Map.of(0x150, CALLER, 0x300, body))) {
        for (boolean reverse : List.of(false, true))
          assertTrue(fixture.preview(4096, reverse, TaskMonitor.DUMMY).ordinaryCallProofs().isEmpty());
      }
    }
  }

  @Test void productionRetainsFourthActiveCallRefusal() throws Exception {
    try (var fixture = new Fixture(Map.of(0x150, CALLER, 0x300, "cd2003c9",
        0x320, "cd4003c9", 0x340, "cd6003c9", 0x360, "c9"))) {
      var result = fixture.preview(4096, false, TaskMonitor.DUMMY);
      assertTrue(result.ordinaryCallProofs().isEmpty());
      assertTrue(result.findings().stream().anyMatch(f -> f.reason().contains("active depth 3")));
    }
  }
}
