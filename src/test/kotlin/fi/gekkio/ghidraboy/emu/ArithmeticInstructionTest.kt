package fi.gekkio.ghidraboy.emu

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/** Executes compiled SLEIGH in one initialized emulator per test, not a Java model. */
class ArithmeticInstructionTest : EmuTest() {
    @Test
    fun `ADC exhaustive inputs and carry`() = arithmetic(0x88, false)

    @Test
    fun `SBC exhaustive inputs and carry`() = arithmetic(0x98, true)

    private fun arithmetic(
        opcode: Int,
        subtract: Boolean,
    ) {
        emulator.write(0u, opcode.toUByte())
        for (a in 0..255) {
            for (b in 0..255) {
                for (c in 0..1) {
                    emulator.writePC(0u)
                    emulator.writeA(a.toUByte())
                    emulator.writeB(b.toUByte())
                    emulator.writeF((c * 16).toUByte())
                    emulator.step()
                    val full = if (subtract) a - b - c else a + b + c
                    val half = if (subtract) (a % 16) - (b % 16) - c < 0 else (a % 16) + (b % 16) + c >= 16
                    val flags =
                        (if ((full and 255) == 0) 128 else 0) +
                            (if (subtract) 64 else 0) + (if (half) 32 else 0) +
                            (if (full < 0 || full > 255) 16 else 0)
                    assertEquals(((full and 255) shl 8) or flags, emulator.readAF().toInt(), "a=$a b=$b c=$c")
                }
            }
        }
    }

    @Test
    fun `DAA exhaustive including non BCD inputs`() {
        emulator.write(0u, 0x27u)
        for (a in 0..255) {
            for (n in 0..1) {
                for (h in 0..1) {
                    for (c in 0..1) {
                        emulator.writePC(0u)
                        emulator.writeA(a.toUByte())
                        emulator.writeF((n * 64 + h * 32 + c * 16 + 128).toUByte())
                        emulator.step()
                        // Independent sequential correction in a wider accumulator (SameBoy v1.0.3).
                        var result = a
                        if (n != 0) {
                            if (h != 0) result = (result - 6) and 255
                            if (c != 0) result -= 96
                        } else {
                            if (h != 0 || result % 16 > 9) result += 6
                            if (c != 0 || result > 159) result += 96
                        }
                        val flags =
                            n * 64 + (if ((result and 255) == 0) 128 else 0) +
                                (if (c != 0 || (result and 256) != 0) 16 else 0)
                        assertEquals(((result and 255) shl 8) or flags, emulator.readAF().toInt(), "a=$a n=$n h=$h c=$c")
                    }
                }
            }
        }
    }

    @Test
    fun `POP AF normalizes flags`() {
        emulator.write(0u, 0xf1u)
        emulator.writeSP(0xc000u)
        emulator.write(0xc000u, 0x3fu, 0x12u)
        emulator.step()
        emulator.assertAF(0x1230u)
        emulator.assertSP(0xc002u)
    }

    @Test
    fun `overlapping arithmetic operands`() {
        for (opcode in listOf(0x8f, 0x9f)) {
            emulator.write(opcode.toUShort(), opcode.toUByte())
            for (a in 0..255) {
                for (c in 0..1) {
                    emulator.writePC(opcode.toUShort())
                    emulator.writeA(a.toUByte())
                    emulator.writeF((c * 16).toUByte())
                    emulator.step()
                    val full = if (opcode == 0x8f) a * 2 + c else -c
                    val half = if (opcode == 0x8f) (a % 16) * 2 + c >= 16 else c != 0
                    val f =
                        (if ((full and 255) == 0) 128 else 0) + (if (opcode == 0x9f) 64 else 0) +
                            (if (half) 32 else 0) + (if (full < 0 || full > 255) 16 else 0)
                    assertEquals(((full and 255) shl 8) or f, emulator.readAF().toInt())
                }
            }
        }
    }
}
