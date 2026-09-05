package fi.gekkio.ghidraboy;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.Map;

/** Bounded p-code constant evaluator; unknown outputs invalidate their overlapping bytes. */
final class PcodeConstants {
  private PcodeConstants() {}

  static Long value(Varnode v, Map<Long, Integer> regs, Map<Long, Integer> unique) {
    if (v.isConstant()) return v.getOffset();
    var map = v.isRegister() ? regs : v.isUnique() ? unique : null;
    if (map == null || v.getSize() > 8) return null;
    long n = 0;
    for (int i = 0; i < v.getSize(); i++) {
      Integer b = map.get(v.getOffset() + i);
      if (b == null) return null;
      n |= (long) b << (i * 8);
    }
    return n;
  }

  static void put(Varnode v, Long value, Map<Long, Integer> regs, Map<Long, Integer> unique) {
    var map = v.isRegister() ? regs : v.isUnique() ? unique : null;
    if (map == null) return;
    for (int i = 0; i < v.getSize(); i++)
      if (value == null) map.remove(v.getOffset() + i);
      else map.put(v.getOffset() + i, (int) (value >>> (i * 8)) & 255);
  }

  static Long evaluate(PcodeOp op, Map<Long, Integer> regs, Map<Long, Integer> unique) {
    if (op.getNumInputs() == 0) return null;
    Long a = value(op.getInput(0), regs, unique),
        b = op.getNumInputs() > 1 ? value(op.getInput(1), regs, unique) : null;
    if (a == null) return null;
    if (op.getOpcode() == PcodeOp.COPY || op.getOpcode() == PcodeOp.INT_ZEXT) return a;
    if (b == null) return null;
    return switch (op.getOpcode()) {
      case PcodeOp.INT_ADD -> a + b;
      case PcodeOp.INT_SUB -> a - b;
      case PcodeOp.INT_AND -> a & b;
      case PcodeOp.INT_OR -> a | b;
      case PcodeOp.INT_XOR -> a ^ b;
      case PcodeOp.INT_LEFT -> a << b;
      case PcodeOp.INT_RIGHT -> a >>> b;
      case PcodeOp.SUBPIECE -> a >>> (b * 8);
      default -> null;
    };
  }
}
