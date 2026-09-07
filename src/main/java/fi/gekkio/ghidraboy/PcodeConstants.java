package fi.gekkio.ghidraboy;

import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.OpBehaviorFactory;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.Map;

/** Bounded little-endian p-code evaluator; unknown outputs invalidate overlapping bytes. */
final class PcodeConstants {
  private PcodeConstants() {}

  private static boolean supportedSize(int size) {
    return size > 0 && size <= Long.BYTES;
  }

  private static long truncate(long value, int size) {
    return size == Long.BYTES ? value : value & ((1L << (size * 8)) - 1);
  }

  static Long value(Varnode v, Map<Long, Integer> regs, Map<Long, Integer> unique) {
    if (!supportedSize(v.getSize())) return null;
    if (v.isConstant()) return truncate(v.getOffset(), v.getSize());
    var map = v.isRegister() ? regs : v.isUnique() ? unique : null;
    if (map == null) return null;
    long n = 0;
    for (int i = 0; i < v.getSize(); i++) {
      Integer b = map.get(v.getOffset() + i);
      if (b == null) return null;
      n |= (long) (b & 255) << (i * 8);
    }
    return n;
  }

  static void put(Varnode v, Long value, Map<Long, Integer> regs, Map<Long, Integer> unique) {
    var map = v.isRegister() ? regs : v.isUnique() ? unique : null;
    if (map == null) return;
    // A long cannot establish bytes of a wider output: invalidate the whole overlap.
    if (!supportedSize(v.getSize())) value = null;
    for (int i = 0; i < v.getSize(); i++)
      if (value == null) map.remove(v.getOffset() + i);
      else map.put(v.getOffset() + i, (int) (value >>> (i * 8)) & 255);
  }

  static Long evaluate(PcodeOp op, Map<Long, Integer> regs, Map<Long, Integer> unique) {
    if (op.getOutput() == null || !supportedSize(op.getOutput().getSize())) return null;
    int opcode = op.getOpcode();
    // Only context-free integer operations belong to this evaluator. Memory, userops,
    // floating point, phi nodes and pointer annotations remain explicitly unknown.
    if (opcode != PcodeOp.COPY
        && !(opcode >= PcodeOp.INT_EQUAL && opcode <= PcodeOp.BOOL_OR)
        && opcode != PcodeOp.PIECE
        && opcode != PcodeOp.SUBPIECE
        && opcode != PcodeOp.POPCOUNT
        && opcode != PcodeOp.LZCOUNT) return null;
    if (op.getNumInputs() == 0) return null;
    Long a = value(op.getInput(0), regs, unique);
    if (a == null) return null;
    int sizeout = op.getOutput().getSize(), sizein = op.getInput(0).getSize();
    var behavior = OpBehaviorFactory.getOpBehavior(opcode);
    try {
      if (behavior instanceof UnaryOpBehavior unary && op.getNumInputs() == 1)
        return truncate(unary.evaluateUnary(sizeout, sizein, a), sizeout);
      if (!(behavior instanceof BinaryOpBehavior binary) || op.getNumInputs() != 2) return null;
      Long b = value(op.getInput(1), regs, unique);
      if (b == null) return null;
      // The emulator behavior supplies a zero for division by zero; that fallback
      // is not a proven arithmetic value for static analysis.
      if (b == 0
          && (opcode == PcodeOp.INT_DIV
              || opcode == PcodeOp.INT_SDIV
              || opcode == PcodeOp.INT_REM
              || opcode == PcodeOp.INT_SREM)) return null;
      if (opcode == PcodeOp.PIECE) {
        // PIECE's behavior expects the low input width, unlike ordinary binary ops.
        sizein = op.getInput(1).getSize();
        if (sizeout != op.getInput(0).getSize() + sizein) return null;
      }
      if (opcode == PcodeOp.SUBPIECE) {
        // Ghidra's long behavior uses a Java shift; guard invalid extraction before
        // dispatch so a byte offset of 8 cannot silently become a shift by zero.
        if (b < 0 || b > sizein || sizeout > sizein - b) return null;
      }
      return truncate(binary.evaluateBinary(sizeout, sizein, a, b), sizeout);
    } catch (ArithmeticException e) {
      // Division by zero and other undefined arithmetic never establish a value.
      return null;
    }
  }
}
