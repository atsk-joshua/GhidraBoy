package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.OpBehaviorFactory;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import org.junit.jupiter.api.Test;

/** Decision experiment only: raw p-code, domain-only byte facts, and explored-state cycles. */
class LoopDecisionPrototypeTest extends IntegrationTest {
  private static long mask(int width) { return width == 8 ? -1L : (1L << (8 * width)) - 1; }
  private static AbstractValues.PartialBits exact(long value, int width) {
    return new AbstractValues.PartialBits(mask(width), value & mask(width));
  }
  private static AbstractValues.PartialBits unknown() { return new AbstractValues.PartialBits(0, 0); }
  private static Long known(AbstractValues.PartialBits bits, int width) {
    return bits.knownMask() == mask(width) ? bits.knownValue() : null;
  }
  // Complete independent input covers are an overapproximation. No relational equality is inferred.
  private static List<Long> cover(AbstractValues.PartialBits bits, int width) {
    long missing = mask(width) & ~bits.knownMask();
    if (Long.bitCount(missing) > 8) return null;
    var values = new ArrayList<Long>();
    long part = missing;
    while (true) {
      values.add(bits.knownValue() | part);
      if (part == 0) return values;
      part = (part - 1) & missing;
    }
  }
  private static AbstractValues.PartialBits eval(PcodeOp op, List<AbstractValues.PartialBits> inputs) {
    int code = op.getOpcode(), out = op.getOutput().getSize();
    if (code != PcodeOp.COPY && !(code >= PcodeOp.INT_EQUAL && code <= PcodeOp.BOOL_OR)
        && code != PcodeOp.PIECE && code != PcodeOp.SUBPIECE) return unknown();
    var a = cover(inputs.get(0), op.getInput(0).getSize());
    var b = inputs.size() == 1 ? List.of(0L) : cover(inputs.get(1), op.getInput(1).getSize());
    if (a == null || b == null) return unknown();
    long ones = mask(out), zeros = mask(out);
    var behavior = OpBehaviorFactory.getOpBehavior(code);
    for (long x : a) for (long y : b) {
      long n;
      if (code == PcodeOp.COPY) n = x;
      else if (behavior instanceof UnaryOpBehavior unary && inputs.size() == 1)
        n = unary.evaluateUnary(out, op.getInput(0).getSize(), x);
      else if (behavior instanceof BinaryOpBehavior binary && inputs.size() == 2) {
        if (y == 0 && Set.of(PcodeOp.INT_DIV, PcodeOp.INT_SDIV, PcodeOp.INT_REM, PcodeOp.INT_SREM).contains(code)) return unknown();
        int in = code == PcodeOp.PIECE ? op.getInput(1).getSize() : op.getInput(0).getSize();
        if (code == PcodeOp.SUBPIECE && (y > in || out > in - y)) return unknown();
        n = binary.evaluateBinary(out, in, x, y);
      } else return unknown();
      ones &= n; zeros &= ~n;
    }
    return new AbstractValues.PartialBits((ones | zeros) & mask(out), ones & mask(out));
  }
  static final class Storage {
    final Map<Long, AbstractValues.PartialBits> regs = new HashMap<>(), unique = new HashMap<>();
    Storage() { regs.put(0L, new AbstractValues.PartialBits(15, 0)); }
    Storage(Map<Long, AbstractValues.PartialBits> source) { regs.putAll(source); }
    AbstractValues.PartialBits get(Varnode v) {
      if (v.isConstant()) return exact(v.getOffset(), v.getSize());
      var map = v.isRegister() ? regs : v.isUnique() ? unique : null;
      if (map == null) return unknown();
      long knownMask = 0, value = 0;
      for (int i = 0; i < v.getSize(); i++) {
        var b = map.getOrDefault(v.getOffset() + i, unknown());
        knownMask |= b.knownMask() << (8 * i); value |= b.knownValue() << (8 * i);
      }
      return new AbstractValues.PartialBits(knownMask, value);
    }
    void put(Varnode v, AbstractValues.PartialBits bits) {
      var map = v.isRegister() ? regs : v.isUnique() ? unique : null;
      if (map == null) return;
      for (int i = 0; i < v.getSize(); i++) {
        var b = new AbstractValues.PartialBits((bits.knownMask() >>> (8 * i)) & 255,
            (bits.knownValue() >>> (8 * i)) & 255);
        if (b.knownMask() == 0) map.remove(v.getOffset() + i); else map.put(v.getOffset() + i, b);
      }
    }
    Long execute(PcodeOp[] raw) {
      unique.clear(); Long condition = null;
      for (var op : raw) {
        if (op.getOpcode() == PcodeOp.CBRANCH) condition = known(get(op.getInput(1)), 1);
        else if (op.getOutput() != null)
          put(op.getOutput(), eval(op, Arrays.stream(op.getInputs()).map(this::get).toList()));
      }
      return condition;
    }
    Long register(long offset, int width) {
      long value = 0;
      for (int i = 0; i < width; i++) {
        var b = regs.getOrDefault(offset + i, unknown());
        if (b.knownMask() != 255) return null;
        value |= b.knownValue() << (8 * i);
      }
      return value;
    }
  }
  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("Loop decision raw fixture", getLanguage(), getLanguage().getDefaultCompilerSpec(), owner);
    Fixture(String hex) throws Exception {
      byte[] bytes = new byte[0x8000]; bytes[0x147] = 0;
      var code = HexFormat.of().parseHex(hex); System.arraycopy(code, 0, bytes, 0x150, code.length);
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true, TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("Self-authored loop fixture");
      try {
        var first = ProgramMapping.staticAddress(p, "0150");
        Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first, new AddressSet(first, first.add(code.length - 1)));
      } finally { p.endTransaction(tx, true); }
    }
    PcodeOp[] raw(int cpu) { return p.getListing().getInstructionAt(ProgramMapping.staticAddress(p, String.format("%04x", cpu))).getPcode(false); }
    @Override public void close() { p.release(owner); }
  }
  private record Key(int cpu, Map<Long, AbstractValues.PartialBits> regs) {}
  private record Outcome(boolean complete, List<Storage> exits, Map<Integer, Integer> counts) {}
  private Outcome explore(Fixture f, boolean reverse) {
    var queue = new ArrayDeque<Key>(); queue.add(new Key(0x150, Map.copyOf(new Storage().regs)));
    var graph = new HashMap<Key, Set<Key>>(); var exits = new ArrayList<Storage>(); var counts = new TreeMap<Integer, Integer>();
    boolean complete = true;
    while (!queue.isEmpty()) {
      var key = queue.removeFirst(); if (graph.containsKey(key)) continue;
      if (graph.size() >= 2048) { complete = false; break; }
      var ins = f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, String.format("%04x", key.cpu())));
      if (ins == null) { complete = false; break; }
      counts.merge(key.cpu(), 1, Integer::sum); graph.put(key, new HashSet<>());
      var storage = new Storage(key.regs());
      if (ins.getFlowType().isTerminal()) { exits.add(storage); continue; }
      Long condition = storage.execute(ins.getPcode(false)); var next = new ArrayList<Integer>();
      boolean conditional = Arrays.stream(ins.getPcode(false)).anyMatch(op -> op.getOpcode() == PcodeOp.CBRANCH);
      if (!conditional || condition == null || condition != 0)
        for (var target : ins.getDefaultFlows()) next.add((int) target.getOffset());
      if (ins.getFallThrough() != null && (!conditional || condition == null || condition == 0)) next.add((int) ins.getFallThrough().getOffset());
      if (next.isEmpty()) complete = false;
      if (reverse) Collections.reverse(next);
      for (int cpu : next) { var successor = new Key(cpu, Map.copyOf(storage.regs)); graph.get(key).add(successor); queue.add(successor); }
    }
    for (var key : graph.keySet()) if (cycle(key, graph, new HashSet<>(), new HashSet<>())) complete = false;
    return new Outcome(complete && !exits.isEmpty(), exits, counts);
  }
  private boolean cycle(Key key, Map<Key, Set<Key>> graph, Set<Key> active, Set<Key> done) {
    if (active.contains(key)) return true; if (!done.add(key)) return false;
    active.add(key);
    for (var next : graph.getOrDefault(key, Set.of())) if (cycle(next, graph, active, done)) return true;
    active.remove(key); return false;
  }
  @Test void rawFormsAndPartialFlagPrecision() throws Exception {
    for (String code : List.of("0cc9", "fe04c9", "15c9", "2000c9", "2800c9", "3800c9", "3000c9")) {
      try (var f = new Fixture(code)) {
        System.out.println("LOOP-RAW " + code + " " + Arrays.toString(f.raw(0x150)));
      }
    }
    try (var f = new Fixture("15c9")) {
      var state = new Storage(); state.regs.put(5L, exact(1, 1)); state.execute(f.raw(0x150));
      assertEquals(0L, state.register(5, 1));
      assertEquals(new AbstractValues.PartialBits(0xef, 0xc0), state.regs.get(0L));
      assertNull(state.register(0, 1)); // Carry remains unknown; Z/N/H and reserved nibble are exact.
      var exactState = new Storage(); exactState.regs.put(5L, exact(1, 1)); exactState.regs.put(0L, exact(0x10, 1));
      exactState.execute(f.raw(0x150)); assertEquals(0xd0L, exactState.register(0, 1));
    }
  }
  @Test void predicatesUseActualRawConditions() throws Exception {
    try (var f = new Fixture("2000c9")) {
      for (int flag : List.of(0, 0x80)) {
        var state = new Storage(); state.regs.put(0L, new AbstractValues.PartialBits(0x8f, flag));
        assertEquals(flag == 0 ? 1L : 0L, state.execute(f.raw(0x150)));
      }
      assertNull(new Storage().execute(f.raw(0x150)));
    }
  }
  @Test void finiteLoopsHaveHardwareCountsAndOrderIndependentExits() throws Exception {
    try (var f = new Fixture("0e000c79fe0420fac9")) {
      var forward = explore(f, false); var reverse = explore(f, true);
      assertTrue(forward.complete()); assertEquals(4, forward.counts().get(0x152));
      assertEquals(4L, forward.exits().getFirst().register(2, 1));
      assertEquals(forward.counts(), reverse.counts()); assertEquals(forward.exits().getFirst().regs, reverse.exits().getFirst().regs);
    }
    try (var f = new Fixture("16082100c10100c22a02031520fac9")) {
      var result = explore(f, false); assertTrue(result.complete()); assertEquals(8, result.counts().get(0x158));
      var exit = result.exits().getFirst(); assertEquals(0L, exit.register(5, 1));
      assertEquals(0xc108L, exit.register(6, 2)); assertEquals(0xc208L, exit.register(2, 2));
      assertEquals(result.counts(), explore(f, true).counts());
    }
  }
  @Test void repeatedStateControlsAreRefusedEvenWhenAnExitIsReachable() throws Exception {
    for (String hex : List.of("18fec9", "0e000c18fdc9", "1520fdc9", "20fec9")) {
      try (var f = new Fixture(hex)) { assertFalse(explore(f, false).complete(), hex); assertFalse(explore(f, true).complete(), hex); }
    }
  }
}
