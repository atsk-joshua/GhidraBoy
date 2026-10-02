package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.HashMap;
import java.util.Map;

/** Exact ordinary bytes plus bounded F/unique known bits; no expression histories or guessed flags. */
final class FlagBitState {
  private final long flagOffset;
  private final Map<Long, Integer> registers, uniques;
  private final Map<Long, AbstractValues.PartialBits> partialUniques = new HashMap<>();
  private AbstractValues.PartialBits flags;

  FlagBitState(Program p, AbstractValues.PartialBits flags,
      Map<Long, Integer> registers, Map<Long, Integer> uniques) {
    flagOffset = p.getRegister("F").getAddress().getOffset();
    this.registers = registers;
    this.uniques = uniques;
    Integer scalar = registers.get(flagOffset);
    this.flags = scalar == null ? canonical(flags, 1) : exact(scalar.longValue(), 1);
    synchronizeFlag();
  }

  static AbstractValues.PartialBits unknown() { return new AbstractValues.PartialBits(0, 0); }

  static AbstractValues.PartialBits exact(Long value, int width) {
    return value == null || width < 1 || width > 8 ? unknown()
        : new AbstractValues.PartialBits(mask(width), value & mask(width));
  }

  private static long mask(int width) { return width == 8 ? -1L : (1L << (width * 8)) - 1; }

  private static AbstractValues.PartialBits canonical(AbstractValues.PartialBits bits, int width) {
    if (bits == null || width < 1 || width > 8) return unknown();
    long known = bits.knownMask() & mask(width);
    return new AbstractValues.PartialBits(known, bits.knownValue() & known);
  }

  static AbstractValues.PartialBits meet(AbstractValues.PartialBits a, AbstractValues.PartialBits b) {
    long known = a.knownMask() & b.knownMask() & ~(a.knownValue() ^ b.knownValue());
    return new AbstractValues.PartialBits(known, a.knownValue() & known);
  }

  AbstractValues.PartialBits flags() { return flags; }

  private void synchronizeFlag() {
    if (flags.knownMask() == 255) registers.put(flagOffset, (int) flags.knownValue());
    else registers.remove(flagOffset);
  }

  AbstractValues.PartialBits bits(Varnode node) {
    int width = node.getSize();
    if (width < 1 || width > 8) return unknown();
    if (node.isConstant()) return exact(node.getOffset(), width);
    var scalar = node.isRegister() ? registers : node.isUnique() ? uniques : null;
    if (scalar == null) return unknown();
    long known = 0, value = 0;
    for (int i = 0; i < width; i++) {
      long offset = node.getOffset() + i;
      var b = node.isRegister() && offset == flagOffset ? flags
          : scalar.containsKey(offset) ? exact(scalar.get(offset).longValue(), 1)
          : node.isUnique() ? partialUniques.getOrDefault(offset, unknown()) : unknown();
      known |= b.knownMask() << (8 * i);
      value |= b.knownValue() << (8 * i);
    }
    return new AbstractValues.PartialBits(known, value);
  }

  Long value(Varnode node) {
    if (node.getSize() < 1 || node.getSize() > 8) return null;
    var bits = bits(node);
    return bits.knownMask() == mask(node.getSize()) ? bits.knownValue() : null;
  }

  void put(Varnode node, AbstractValues.PartialBits result) {
    if (node == null) return;
    var scalar = node.isRegister() ? registers : node.isUnique() ? uniques : null;
    if (scalar == null) return;
    var normalized = canonical(result, node.getSize());
    for (int i = 0; i < node.getSize(); i++) {
      long offset = node.getOffset() + i;
      var octet = i < 8 ? canonical(new AbstractValues.PartialBits(
          normalized.knownMask() >>> (8 * i), normalized.knownValue() >>> (8 * i)), 1) : unknown();
      if (octet.knownMask() == 255) scalar.put(offset, (int) octet.knownValue());
      else scalar.remove(offset);
      if (node.isRegister() && offset == flagOffset) flags = octet;
      if (node.isUnique()) {
        if (octet.knownMask() == 0 || octet.knownMask() == 255) partialUniques.remove(offset);
        else partialUniques.put(offset, octet);
      }
    }
  }

  private static AbstractValues.PartialBits booleanResult(Boolean value, int width) {
    return value == null ? new AbstractValues.PartialBits(mask(width) & ~1L, 0)
        : exact(value ? 1L : 0L, width);
  }

  AbstractValues.PartialBits evaluate(PcodeOp op) {
    if (op.getOutput() == null || op.getOutput().getSize() < 1 || op.getOutput().getSize() > 8
        || op.getNumInputs() < 1 || op.getNumInputs() > 2) return unknown();
    int out = op.getOutput().getSize(), in = op.getInput(0).getSize();
    if (in < 1 || in > 8) return unknown();
    boolean allExact = true;
    for (var input : op.getInputs()) allExact &= value(input) != null;
    if (allExact) {
      Long evaluated = PcodeConstants.evaluate(op, registers, uniques);
      if (evaluated != null) return exact(evaluated, out);
    }
    var a = bits(op.getInput(0));
    var b = op.getNumInputs() == 2 ? bits(op.getInput(1)) : unknown();
    long aMask = a.knownMask(), aValue = a.knownValue(), bMask = b.knownMask(), bValue = b.knownValue();
    AbstractValues.PartialBits result;
    switch (op.getOpcode()) {
      case PcodeOp.COPY, PcodeOp.INT_ZEXT -> {
        long highZero = mask(out) & ~mask(in);
        result = new AbstractValues.PartialBits(aMask | highZero, aValue);
      }
      case PcodeOp.INT_AND, PcodeOp.BOOL_AND -> {
        long zeros = (aMask & ~aValue) | (bMask & ~bValue), ones = aValue & bValue;
        result = new AbstractValues.PartialBits(zeros | ones, ones);
      }
      case PcodeOp.INT_OR, PcodeOp.BOOL_OR -> {
        long ones = aValue | bValue, zeros = aMask & ~aValue & bMask & ~bValue;
        result = new AbstractValues.PartialBits(ones | zeros, ones);
      }
      case PcodeOp.INT_XOR, PcodeOp.BOOL_XOR -> {
        long known = aMask & bMask;
        result = new AbstractValues.PartialBits(known, (aValue ^ bValue) & known);
      }
      case PcodeOp.INT_NEGATE -> result = new AbstractValues.PartialBits(aMask, ~aValue & aMask);
      case PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT -> {
        Long count = value(op.getInput(1));
        if (count == null) return unknown();
        if (count < 0 || count >= in * 8L) return exact(0L, out);
        int shift = count.intValue();
        if (op.getOpcode() == PcodeOp.INT_LEFT)
          result = new AbstractValues.PartialBits((aMask << shift) | ((1L << shift) - 1), aValue << shift);
        else {
          long remaining = mask(in) >>> shift;
          result = new AbstractValues.PartialBits((aMask >>> shift) | (mask(out) & ~remaining), aValue >>> shift);
        }
      }
      case PcodeOp.SUBPIECE -> {
        Long offset = value(op.getInput(1));
        if (offset == null || offset < 0 || offset > in || out > in - offset) return unknown();
        int shift = offset.intValue() * 8;
        result = new AbstractValues.PartialBits(aMask >>> shift, aValue >>> shift);
      }
      case PcodeOp.PIECE -> {
        int low = op.getInput(1).getSize();
        if (out != in + low || low < 1 || low >= 8) return unknown();
        result = new AbstractValues.PartialBits((aMask << (low * 8)) | bMask, (aValue << (low * 8)) | bValue);
      }
      case PcodeOp.BOOL_NEGATE ->
          result = new AbstractValues.PartialBits(aMask, (aValue ^ 1L) & aMask);
      case PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL -> {
        Boolean equal = ((aValue ^ bValue) & aMask & bMask) != 0 ? false : null;
        return booleanResult(equal == null ? null : op.getOpcode() == PcodeOp.INT_EQUAL ? equal : !equal, out);
      }
      case PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL -> {
        long aMax = aValue | (mask(in) & ~aMask), bMax = bValue | (mask(in) & ~bMask);
        boolean inclusive = op.getOpcode() == PcodeOp.INT_LESSEQUAL;
        int allTrue = Long.compareUnsigned(aMax, bValue), allFalse = Long.compareUnsigned(aValue, bMax);
        Boolean predicate = null;
        if (inclusive ? allTrue <= 0 : allTrue < 0) predicate = true;
        else if (inclusive ? allFalse > 0 : allFalse >= 0) predicate = false;
        return booleanResult(predicate, out);
      }
      case PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL, PcodeOp.INT_CARRY,
          PcodeOp.INT_SCARRY, PcodeOp.INT_SBORROW -> { return booleanResult(null, out); }
      default -> { return unknown(); }
    }
    return canonical(result, out);
  }
}
