package fi.gekkio.ghidraboy

import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/** General operation-contract cases; these do not claim SM83 instruction reachability. */
class PcodeConstantsTest : IntegrationTest() {
    private val regs = mutableMapOf<Long, Int>()
    private val unique = mutableMapOf<Long, Int>()

    private fun constant(
        value: Long,
        size: Int,
    ) = Varnode(language.addressFactory.constantSpace.getAddress(value), size)

    private fun reg(
        offset: Long,
        size: Int,
    ) = Varnode(
        language
            .getRegister("HL")
            .address.addressSpace
            .getAddress(offset),
        size,
    )

    private fun evaluate(
        opcode: Int,
        size: Int,
        vararg inputs: Varnode,
    ): Long? = PcodeConstants.evaluate(PcodeOp(address(0), 0, opcode, inputs, reg(0x80, size)), regs, unique)

    @Test
    fun `shifts respect operand width and unsigned counts without host modulo`() {
        for (width in (1..8)) {
            val bits = width * 8
            val high = 1L shl (bits - 1)
            val mask = if (width == 8) -1L else (1L shl bits) - 1
            for (count in listOf(0L, 1L, bits.toLong() - 1, bits.toLong(), 64L, 65L, 256L, Long.MIN_VALUE, -1L)) {
                val a = constant(high, width)
                val b = constant(count, 8)
                val outside = count < 0 || count >= bits
                assertEquals(if (outside) 0L else high ushr count.toInt(), evaluate(PcodeOp.INT_RIGHT, width, a, b), "$width >> $count")
                assertEquals(if (outside) 0L else (1L shl count.toInt()) and mask, evaluate(PcodeOp.INT_LEFT, width, constant(1, width), b))
                val signedExpected = if (outside) mask else ((high shl (64 - bits)) shr (64 - bits) shr count.toInt()) and mask
                assertEquals(signedExpected, evaluate(PcodeOp.INT_SRIGHT, width, a, b), "$width s>> $count")
                assertEquals(0L, evaluate(PcodeOp.INT_SRIGHT, width, constant(0, width), b))
            }
        }
    }

    @Test
    fun `extension truncation concatenation and wrap have explicit widths`() {
        assertEquals(0x80L, evaluate(PcodeOp.INT_ZEXT, 2, constant(0x80, 1)))
        assertEquals(0xff80L, evaluate(PcodeOp.INT_SEXT, 2, constant(0x80, 1)))
        assertEquals(-128L, evaluate(PcodeOp.INT_SEXT, 8, constant(0x80, 1)))
        assertEquals(0x7fL, evaluate(PcodeOp.INT_SEXT, 8, constant(0x7f, 1)))
        assertEquals(0x12L, evaluate(PcodeOp.SUBPIECE, 1, constant(0x1234, 2), constant(1, 4)))
        assertNull(evaluate(PcodeOp.SUBPIECE, 1, constant(-1, 8), constant(8, 4)))
        assertEquals(0x123456L, evaluate(PcodeOp.PIECE, 3, constant(0x12, 1), constant(0x3456, 2)))
        assertEquals(0L, evaluate(PcodeOp.INT_ADD, 1, constant(255, 1), constant(1, 1)))
        assertEquals(255L, evaluate(PcodeOp.INT_SUB, 1, constant(0, 1), constant(1, 1)))
        assertEquals(0L, evaluate(PcodeOp.INT_ADD, 8, constant(-1, 8), constant(1, 8)))
        assertEquals(0xfeL, evaluate(PcodeOp.INT_MULT, 1, constant(255, 1), constant(2, 1)))
        assertEquals(1L, evaluate(PcodeOp.INT_SLESS, 1, constant(255, 1), constant(1, 1)))
        assertEquals(0L, evaluate(PcodeOp.INT_LESS, 1, constant(255, 1), constant(1, 1)))
        assertEquals(0xfeL, evaluate(PcodeOp.INT_SDIV, 1, constant(0xf9, 1), constant(3, 1)))
        assertEquals(0xffL, evaluate(PcodeOp.INT_SREM, 1, constant(0xf9, 1), constant(3, 1)))
        assertEquals(0x80L, evaluate(PcodeOp.INT_SDIV, 1, constant(0x80, 1), constant(0xff, 1)))
        assertNull(evaluate(PcodeOp.INT_DIV, 1, constant(7, 1), constant(0, 1)))
        assertEquals(0xffL, PcodeConstants.value(constant(0x1ff, 1), regs, unique))
    }

    @Test
    fun `integer flags logic and unsigned arithmetic follow pcode contract`() {
        val binaryCases =
            listOf(
                listOf(PcodeOp.INT_EQUAL, 7, 7, 1),
                listOf(PcodeOp.INT_NOTEQUAL, 7, 8, 1),
                listOf(PcodeOp.INT_SLESSEQUAL, 128, 127, 1),
                listOf(PcodeOp.INT_LESSEQUAL, 128, 127, 0),
                listOf(PcodeOp.INT_CARRY, 255, 1, 1),
                listOf(PcodeOp.INT_SCARRY, 127, 1, 1),
                listOf(PcodeOp.INT_SCARRY, 255, 1, 0),
                listOf(PcodeOp.INT_SBORROW, 128, 1, 1),
                listOf(PcodeOp.INT_XOR, 0x55, 0x0f, 0x5a),
                listOf(PcodeOp.INT_AND, 0x55, 0x0f, 0x05),
                listOf(PcodeOp.INT_OR, 0x55, 0x0f, 0x5f),
                listOf(PcodeOp.INT_DIV, 255, 2, 127),
                listOf(PcodeOp.INT_REM, 255, 2, 1),
                listOf(PcodeOp.BOOL_XOR, 1, 1, 0),
                listOf(PcodeOp.BOOL_AND, 1, 0, 0),
                listOf(PcodeOp.BOOL_OR, 1, 0, 1),
            )
        for ((opcode, a, b, expected) in binaryCases) {
            assertEquals(
                expected.toLong(),
                evaluate(opcode, 1, constant(a.toLong(), 1), constant(b.toLong(), 1)),
                PcodeOp.getMnemonic(opcode),
            )
        }
        for ((opcode, input, expected) in listOf(
            listOf(PcodeOp.COPY, 0x80, 0x80),
            listOf(PcodeOp.INT_2COMP, 1, 255),
            listOf(PcodeOp.INT_NEGATE, 0x55, 0xaa),
            listOf(PcodeOp.BOOL_NEGATE, 0, 1),
            listOf(PcodeOp.POPCOUNT, 0x81, 2),
            listOf(PcodeOp.LZCOUNT, 1, 7),
        )) {
            assertEquals(expected.toLong(), evaluate(opcode, 1, constant(input.toLong(), 1)), PcodeOp.getMnemonic(opcode))
        }
        assertEquals(1L, evaluate(PcodeOp.INT_LESS, 1, constant(Long.MAX_VALUE, 8), constant(Long.MIN_VALUE, 8)))
        assertEquals(Long.MAX_VALUE, evaluate(PcodeOp.INT_DIV, 8, constant(-1, 8), constant(2, 8)))
    }

    @Test
    fun `overlapping writes preserve independent bytes and unknowns kill dependencies`() {
        regs.clear()
        val pair = reg(0, 2)
        val low = reg(0, 1)
        val high = reg(1, 1)
        PcodeConstants.put(pair, 0x1234, regs, unique)
        PcodeConstants.put(low, 0xab, regs, unique)
        assertEquals(0x12abL, PcodeConstants.value(pair, regs, unique))
        val unsupported = evaluate(PcodeOp.LOAD, 1, constant(0, 4), constant(0, 2))
        assertNull(unsupported)
        PcodeConstants.put(high, unsupported, regs, unique)
        assertNull(PcodeConstants.value(pair, regs, unique))
        assertEquals(0xabL, PcodeConstants.value(low, regs, unique))
        assertNull(evaluate(PcodeOp.INT_ADD, 2, pair, constant(1, 2)))
        PcodeConstants.put(reg(0, 9), -1, regs, unique)
        assertNull(PcodeConstants.value(low, regs, unique))
        assertNull(PcodeConstants.value(reg(0, 9), regs, unique))
        assertNull(evaluate(PcodeOp.COPY, 9, constant(1, 8)))
        val temporary = Varnode(language.addressFactory.uniqueSpace.getAddress(0), 2)
        val temporaryHigh = Varnode(language.addressFactory.uniqueSpace.getAddress(1), 1)
        PcodeConstants.put(temporary, 0x1234, regs, unique)
        PcodeConstants.put(temporaryHigh, null, regs, unique)
        assertNull(PcodeConstants.value(temporary, regs, unique))
        assertEquals(0x34, unique[0L])
    }
}
