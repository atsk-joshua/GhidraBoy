package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.address.AddressSpace;
import java.util.*;
import org.junit.jupiter.api.Test;

class OrdinaryMemoryJoinTest {
  private static final MapperState.Physical X = new MapperState.Physical("WRAM", 0, 0);
  private static final MapperState.Physical Y = new MapperState.Physical("WRAM", 0, 1);
  private static final MapperState.Physical Z = new MapperState.Physical("WRAM", 1, 0);
  private static AbstractValues.Value byteValue(int n) { return AbstractValues.constant(n, 1); }

  @Test void exactMustFactsIntersectWithoutInventingValues() {
    var left = Map.of(X, byteValue(1), Y, byteValue(2));
    assertSame(left, SymbolicMemory.State.joinOrdinary(left, left));
    assertEquals(Map.of(X, byteValue(1)), SymbolicMemory.State.joinOrdinary(left, Map.of(X, byteValue(1), Y, byteValue(3))));
    assertEquals(Map.of(X, byteValue(1)), SymbolicMemory.State.joinOrdinary(left, Map.of(X, byteValue(1), Z, byteValue(2))));
    assertEquals(Map.of(), SymbolicMemory.State.joinOrdinary(left, Map.of()));
    assertEquals(Map.of(), SymbolicMemory.State.joinOrdinary(Map.of(X, byteValue(1)), Map.of(X, byteValue(2))));
    assertEquals(Map.of(), SymbolicMemory.State.joinOrdinary(Map.of(X, byteValue(1)), Map.of(Z, byteValue(1))));
  }

  @Test void processedKeyCanWeakenAgainButCannotRecoverLostFacts() {
    var address = new GenericAddressSpace("test", 16, AddressSpace.TYPE_RAM, 0).getAddress(0x150);
    var queue = new ArrayDeque<BankAnalysis.Work>();
    var joined = new HashMap<BankAnalysis.JoinKey, BankAnalysis.Work>();
    var widened = new HashSet<ghidra.program.model.address.Address>();
    var first = new BankAnalysis.Work(address, MapperKnowledge.unknown(), Map.of(), Map.of(X, byteValue(1), Y, byteValue(2)));
    BankAnalysis.enqueue(queue, first, widened, joined);
    assertEquals(first, queue.removeFirst()); // Already processed before the second arrival.
    BankAnalysis.enqueue(queue, new BankAnalysis.Work(address, first.state(), Map.of(), Map.of(X, byteValue(1))), widened, joined);
    assertEquals(Map.of(X, byteValue(1)), queue.removeFirst().memory());
    BankAnalysis.enqueue(queue, first, widened, joined);
    assertTrue(queue.isEmpty());
    BankAnalysis.enqueue(queue, new BankAnalysis.Work(address, first.state(), Map.of(), Map.of()), widened, joined);
    assertEquals(Map.of(), queue.removeFirst().memory());
    BankAnalysis.enqueue(queue, first, widened, joined);
    assertTrue(queue.isEmpty());
  }

  @Test void exactExecutionCorrelationAndDiversityTopArePreserved() {
    var space = new GenericAddressSpace("test", 16, AddressSpace.TYPE_RAM, 0);
    var address = space.getAddress(0x150);
    var queue = new ArrayDeque<BankAnalysis.Work>();
    var joined = new HashMap<BankAnalysis.JoinKey, BankAnalysis.Work>();
    var widened = new HashSet<ghidra.program.model.address.Address>();
    var bank1 = MapperKnowledge.from(MapperState.reset());
    var bank2 = MapperKnowledge.unknown();
    var memory = Map.of(X, byteValue(2));
    for (var work : List.of(
        new BankAnalysis.Work(address, bank1, Map.of(0L, 1), memory),
        new BankAnalysis.Work(address, bank2, Map.of(0L, 1), memory),
        new BankAnalysis.Work(address, bank1, Map.of(0L, 2), memory),
        new BankAnalysis.Work(space.getAddress(0x151), bank1, Map.of(0L, 1), memory)))
      BankAnalysis.enqueue(queue, work, widened, joined);
    assertEquals(4, joined.size());
    assertEquals(4, queue.size());
    queue.clear();
    widened.add(address);
    BankAnalysis.enqueue(queue, new BankAnalysis.Work(address, bank1, Map.of(0L, 1), memory), widened, joined);
    var top = queue.removeFirst();
    assertEquals(MapperKnowledge.unknown(), top.state());
    assertTrue(top.registers().isEmpty());
    assertTrue(top.memory().isEmpty());
  }
}
