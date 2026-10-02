package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import java.util.function.LongBinaryOperator;
import org.junit.jupiter.api.Test;

/** Independent complete byte covers check known-bit soundness; raw instructions check flag overlap. */
class FlagBitStateTest extends IntegrationTest {
  private final Object owner = new Object();
  private Varnode reg(ProgramDB p, String name) {
    var r = p.getRegister(name); return new Varnode(r.getAddress(), r.getMinimumByteSize());
  }
  private Varnode unique(ProgramDB p, long offset, int width) {
    return new Varnode(p.getAddressFactory().getAddressSpace("unique").getAddress(offset), width);
  }
  private Varnode constant(ProgramDB p, long value, int width) {
    return new Varnode(p.getAddressFactory().getConstantSpace().getAddress(value), width);
  }
  private PcodeOp op(ProgramDB p, int code, Varnode output, Varnode... inputs) {
    return new PcodeOp(p.getAddressFactory().getDefaultAddressSpace().getAddress(0x150), 0, code, inputs, output);
  }
  private ProgramDB program() throws Exception { return new ProgramDB("Flag bit domain", getLanguage(), getLanguage().getDefaultCompilerSpec(), owner); }
  private List<Long> cover(AbstractValues.PartialBits bits) {
    var values = new ArrayList<Long>();
    for (long v = 0; v < 256; v++) if ((v & bits.knownMask()) == bits.knownValue()) values.add(v);
    return values;
  }
  private AbstractValues.PartialBits oracle(Collection<Long> values) {
    long ones = 255, zeros = 255;
    for (long v : values) { ones &= v; zeros &= ~v; }
    return new AbstractValues.PartialBits((ones | zeros) & 255, ones & 255);
  }
  @Test void completeIndependentByteCoversCheckBitwiseTransfers() throws Exception {
    var p = program();
    try {
      var rand = new Random(0x83);
      int[] codes = {PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR, PcodeOp.BOOL_AND, PcodeOp.BOOL_OR, PcodeOp.BOOL_XOR};
      LongBinaryOperator[] operations = {(a, b) -> a & b, (a, b) -> a | b, (a, b) -> a ^ b,
          (a, b) -> a & b, (a, b) -> a | b, (a, b) -> a ^ b};
      for (int sample = 0; sample < 64; sample++) {
        int am = rand.nextInt(256), bm = rand.nextInt(256);
        var a = new AbstractValues.PartialBits(am, rand.nextInt(256) & am);
        var b = new AbstractValues.PartialBits(bm, rand.nextInt(256) & bm);
        var state = new FlagBitState(p, a, new HashMap<>(), new HashMap<>());
        var second = unique(p, 0x80, 1); state.put(second, b);
        for (int i = 0; i < codes.length; i++) {
          var results = new HashSet<Long>();
          for (long av : cover(a)) for (long bv : cover(b)) results.add(operations[i].applyAsLong(av, bv));
          assertEquals(oracle(results), state.evaluate(op(p, codes[i], unique(p, 0x100, 1), reg(p, "F"), second)));
        }
        var negatedBoolean = cover(a).stream().map(v -> v ^ 1L).toList();
        assertEquals(oracle(negatedBoolean), state.evaluate(op(p, PcodeOp.BOOL_NEGATE, unique(p, 0x100, 1), reg(p, "F"))));
        var inverted = cover(a).stream().map(v -> (~v) & 255).toList();
        assertEquals(oracle(inverted), state.evaluate(op(p, PcodeOp.INT_NEGATE, unique(p, 0x100, 1), reg(p, "F"))));
        for (int shift = 0; shift <= 9; shift++) {
          final int n = shift;
          var left = cover(a).stream().map(v -> (v << n) & 255).toList();
          var right = cover(a).stream().map(v -> v >>> n).toList();
          assertEquals(oracle(left), state.evaluate(op(p, PcodeOp.INT_LEFT, unique(p, 0x100, 1), reg(p, "F"), constant(p, shift, 4))));
          assertEquals(oracle(right), state.evaluate(op(p, PcodeOp.INT_RIGHT, unique(p, 0x100, 1), reg(p, "F"), constant(p, shift, 4))));
        }
      }
    } finally { p.release(owner); }
  }
  @Test void booleanTransfersPreserveArbitraryBitsAndComparisonsUseOnlyEvidence() throws Exception {
    var p = program();
    try {
      var state = new FlagBitState(p, FlagBitState.unknown(), new HashMap<>(), new HashMap<>());
      var out = unique(p, 0x100, 1); var f = reg(p, "F");
      assertEquals(FlagBitState.unknown(), state.evaluate(op(p, PcodeOp.BOOL_NEGATE, out, f)));
      state.put(f, new AbstractValues.PartialBits(0x80, 0x80));
      assertEquals(new AbstractValues.PartialBits(0x80, 0x80), state.evaluate(op(p, PcodeOp.BOOL_NEGATE, out, f)));
      assertEquals(FlagBitState.exact(0L, 1), state.evaluate(op(p, PcodeOp.INT_EQUAL, out, f, constant(p, 0, 1))));
      assertEquals(FlagBitState.exact(1L, 1), state.evaluate(op(p, PcodeOp.INT_LESS, out, constant(p, 127, 1), f)));
      state.put(f, FlagBitState.unknown());
      assertNull(state.value(f)); assertEquals(FlagBitState.unknown(), state.flags());
    } finally { p.release(owner); }
  }
  @Test void byteOverlapMeetAndScalarSynchronizationRetainOnlyEstablishedBits() throws Exception {
    var p = program();
    try {
      var regs = new HashMap<Long, Integer>(); var uniques = new HashMap<Long, Integer>();
      var state = new FlagBitState(p, new AbstractValues.PartialBits(0x80, 0xff), regs, uniques);
      assertEquals(new AbstractValues.PartialBits(0x80, 0x80), state.flags());
      var af = reg(p, "AF"); var f = reg(p, "F");
      state.put(af, FlagBitState.exact(0x42d0L, 2));
      assertEquals(0x42d0L, state.value(af)); assertEquals(FlagBitState.exact(0xd0L, 1), state.flags());
      state.put(f, new AbstractValues.PartialBits(0xef, 0xc0));
      assertNull(state.value(af)); assertEquals(0x42L, state.value(reg(p, "A")));
      assertFalse(regs.containsKey(f.getOffset()));
      state.put(af, FlagBitState.unknown()); assertNull(state.value(reg(p, "A"))); assertEquals(FlagBitState.unknown(), state.flags());
      assertEquals(new AbstractValues.PartialBits(0x80, 0x80), FlagBitState.meet(
          new AbstractValues.PartialBits(0xc0, 0xc0), new AbstractValues.PartialBits(0xc0, 0x80)));
      var low = unique(p, 0x80, 1); state.put(low, new AbstractValues.PartialBits(0xf0, 0xa0));
      var wide = state.evaluate(op(p, PcodeOp.INT_ZEXT, unique(p, 0x100, 2), low));
      assertEquals(new AbstractValues.PartialBits(0xfff0, 0xa0), wide);
      state.put(unique(p, 0x100, 2), wide);
      assertEquals(FlagBitState.exact(0L, 1), state.evaluate(op(p, PcodeOp.SUBPIECE, unique(p, 0x200, 1), unique(p, 0x100, 2), constant(p, 1, 4))));
      assertEquals(new AbstractValues.PartialBits(0xfff0, 0x12a0), state.evaluate(op(p, PcodeOp.PIECE, unique(p, 0x200, 2), constant(p, 0x12, 1), low)));
      assertEquals(FlagBitState.unknown(), state.evaluate(op(p, PcodeOp.LOAD, unique(p, 0x200, 1), constant(p, 1, 4), low)));
      regs.put(f.getOffset(), 0x70);
      assertEquals(FlagBitState.exact(0x70L, 1), new FlagBitState(p, FlagBitState.unknown(), regs, uniques).flags());
    } finally { p.release(owner); }
  }
  @Test void compiledIncCpDecAndJrUseRawFlagSlicesWithUnknownPreservedCarry() throws Exception {
    var p = program();
    try {
      byte[] bytes = new byte[0x8000];
      var code = HexFormat.of().parseHex("0c79fe04152000c9"); System.arraycopy(code, 0, bytes, 0x150, code.length);
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true, TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("Authored flag instructions");
      try {
        var first = ProgramMapping.staticAddress(p, "0150");
        Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first, new AddressSet(first, first.add(code.length - 1)));
      } finally { p.endTransaction(tx, true); }
      var state = new FlagBitState(p, FlagBitState.unknown(), new HashMap<>(), new HashMap<>());
      state.put(reg(p, "C"), FlagBitState.exact(3L, 1)); state.put(reg(p, "D"), FlagBitState.exact(1L, 1));
      for (int cpu : List.of(0x150, 0x151, 0x152, 0x154)) {
        var ins = p.getListing().getInstructionAt(ProgramMapping.staticAddress(p, String.format("%04x", cpu)));
        for (var raw : ins.getPcode(false)) if (raw.getOutput() != null) state.put(raw.getOutput(), state.evaluate(raw));
        if (cpu == 0x150) {
          assertEquals(new AbstractValues.PartialBits(0xe0, 0), state.flags());
          assertNull(state.value(reg(p, "F"))); assertEquals(4L, state.value(reg(p, "C")));
        }
        if (cpu == 0x152) assertEquals(new AbstractValues.PartialBits(0xf0, 0xc0), state.flags());
      }
      assertEquals(0L, state.value(reg(p, "D")));
      assertEquals(new AbstractValues.PartialBits(0xf0, 0xc0), state.flags());
      var jump = p.getListing().getInstructionAt(ProgramMapping.staticAddress(p, "0155"));
      for (var raw : jump.getPcode(false)) {
        if (raw.getOpcode() == PcodeOp.CBRANCH) assertEquals(0L, state.value(raw.getInput(1)));
        else if (raw.getOutput() != null) state.put(raw.getOutput(), state.evaluate(raw));
      }
    } finally { p.release(owner); }
  }
}
