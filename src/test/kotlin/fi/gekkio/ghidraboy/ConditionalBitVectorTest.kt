package fi.gekkio.ghidraboy

import ghidra.program.model.pcode.PcodeOp
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test

/** Width-specific unsigned bit-vector specification, independent of AbstractValues evaluation. */
class ConditionalBitVectorTest {
    private fun operation(
        code: Int,
        width: Int,
        vararg inputs: AbstractValues.Value,
    ) = AbstractValues.evaluate(code, width, inputs.toList(), "independent vector")

    private fun reference(
        origin: AbstractValues.Origin,
        assignments: Map<String, Long>,
    ): Long {
        val mask = (1L shl (origin.width() * 8)) - 1
        if (origin.kind() == AbstractValues.OriginKind.INPUT) return assignments.getValue(origin.input()) and mask
        if (origin.kind() == AbstractValues.OriginKind.CONSTANT) return origin.constant() and mask
        val values = origin.inputs().map { reference(it, assignments) }
        val a = values[0]
        val b = values.getOrElse(1) { 0 }
        val value =
            when (origin.opcode()) {
                PcodeOp.COPY, PcodeOp.INT_ZEXT -> a
                PcodeOp.PIECE -> a * (1L shl (8 * origin.inputs()[1].width())) + b
                PcodeOp.SUBPIECE -> a / (1L shl (8 * b.toInt()))
                PcodeOp.INT_LEFT -> if (b >= origin.width() * 8) 0 else a * (1L shl b.toInt())
                PcodeOp.INT_RIGHT -> if (b >= origin.inputs()[0].width() * 8) 0 else a / (1L shl b.toInt())
                PcodeOp.INT_AND -> a and b
                PcodeOp.INT_OR -> a or b
                PcodeOp.INT_XOR -> a xor b
                PcodeOp.INT_ADD -> a + b
                PcodeOp.INT_SUB -> a - b
                else -> error("Unspecified reference opcode ${origin.opcode()}")
            }
        return value and mask
    }

    @Test
    fun exhaustiveBytePairsPreservePieceShiftMaskAndCorrelation() {
        val hi = AbstractValues.input("vector", "byte", 0, 1)
        val lo = AbstractValues.input("vector", "byte", 1, 1)
        val pair = operation(PcodeOp.PIECE, 2, hi, lo)
        val zero = AbstractValues.constant(0, 1)
        val one = AbstractValues.constant(1, 1)
        val expressions =
            listOf(
                operation(PcodeOp.SUBPIECE, 1, pair, zero),
                operation(PcodeOp.SUBPIECE, 1, pair, one),
                operation(PcodeOp.SUBPIECE, 1, operation(PcodeOp.INT_LEFT, 2, pair, AbstractValues.constant(8, 1)), one),
                operation(PcodeOp.SUBPIECE, 1, operation(PcodeOp.INT_RIGHT, 2, pair, AbstractValues.constant(8, 1)), zero),
                operation(PcodeOp.INT_AND, 2, pair, AbstractValues.constant(0xff00, 2)),
                operation(
                    PcodeOp.INT_OR,
                    2,
                    operation(PcodeOp.INT_AND, 2, pair, AbstractValues.constant(0xff, 2)),
                    AbstractValues.constant(0xff00, 2),
                ),
                operation(PcodeOp.INT_XOR, 1, hi, lo),
                operation(PcodeOp.INT_XOR, 1, hi, hi),
                operation(PcodeOp.SUBPIECE, 1, operation(PcodeOp.INT_ZEXT, 2, hi), one),
            )
        val normalized = expressions.map { AbstractValues.canonical(it).origin() }
        assertEquals(lo.origin(), normalized[0])
        assertEquals(hi.origin(), normalized[1])
        assertNotEquals(hi.origin(), lo.origin())
        for (a in 0L..255L) {
            for (b in 0L..255L) {
                val assignment = mapOf(hi.origin().input() to a, lo.origin().input() to b)
                for ((index, expression) in expressions.withIndex()) {
                    val expected = reference(expression.origin(), assignment)
                    assertEquals(expected, reference(normalized[index], assignment), "canonical $index / $a / $b")
                    assertEquals(
                        expected,
                        AbstractValues.concrete(normalized[index], mapOf(hi.origin() to a, lo.origin() to b), HashMap(), longArrayOf(0)),
                    )
                }
            }
        }
    }

    @Test
    fun deterministicWordEdgesAndTruncationUseIndependentArithmetic() {
        val word = AbstractValues.input("vector", "pair", 0, 2)
        val values =
            listOf(0L, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xfffe, 0xffff) +
                List(1024) { ((it.toLong() * 40503 + 97) and 65535) }
        for (mask in listOf(0L, 1, 0xff, 0xff00, 0xffff)) {
            val original =
                operation(
                    PcodeOp.SUBPIECE,
                    1,
                    operation(PcodeOp.INT_AND, 2, word, AbstractValues.constant(mask, 2)),
                    AbstractValues.constant(1, 1),
                )
            val normalized = AbstractValues.canonical(original)
            for (value in values) {
                val expected = ((value and mask) / 256) and 255
                assertEquals(expected, reference(original.origin(), mapOf(word.origin().input() to value)))
                assertEquals(expected, reference(normalized.origin(), mapOf(word.origin().input() to value)))
            }
        }
    }
}
