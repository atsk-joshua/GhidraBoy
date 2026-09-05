package fi.gekkio.ghidraboy.emu

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class AluInstructionTest : EmuTest() {
    @Test
    fun `eight bit arithmetic and logic execute all input pairs`() {
        for (opcode in listOf(0x80, 0x90, 0xa0, 0xa8, 0xb0, 0xb8)) {
            emulator.write(opcode.toUShort(), opcode.toUByte())
            for (a in 0..255) {
                for (b in 0..255) {
                    emulator.writePC(opcode.toUShort())
                    emulator.writeA(a.toUByte())
                    emulator.writeB(b.toUByte())
                    emulator.writeF(0xf0u)
                    emulator.step()
                    val full =
                        when (opcode) {
                            0x80 -> a + b
                            0x90, 0xb8 -> a - b
                            0xa0 -> a and b
                            0xa8 -> a xor b
                            else -> a or b
                        }
                    val subtract = opcode == 0x90 || opcode == 0xb8
                    val arithmetic = opcode == 0x80 || subtract
                    val half = if (subtract) a % 16 < b % 16 else a % 16 + b % 16 > 15
                    val flags =
                        (if ((full and 255) == 0) 128 else 0) + (if (subtract) 64 else 0) +
                            (if ((arithmetic && half) || opcode == 0xa0) 32 else 0) +
                            (if (arithmetic && (full < 0 || full > 255)) 16 else 0)
                    assertEquals(if (opcode == 0xb8) a else full and 255, emulator.readA().toInt(), "opcode=$opcode a=$a b=$b")
                    assertEquals(flags, emulator.readF().toInt(), "flags opcode=$opcode a=$a b=$b")
                }
            }
        }
    }

    @Test
    fun `ADD HL HL executes all inputs with preserved zero flag`() {
        emulator.write(0u, 0x29u)
        for (hl in 0..65535) {
            emulator.writePC(0u)
            emulator.writeHL(hl.toUShort())
            emulator.writeF(0xf0u)
            emulator.step()
            val flags = 128 + (if ((hl % 4096) * 2 > 4095) 32 else 0) + (if (hl * 2 > 65535) 16 else 0)
            assertEquals((hl * 2) and 65535, emulator.readHL().toInt())
            assertEquals(flags, emulator.readF().toInt(), "HL=$hl")
        }
    }

    @Test
    fun `increment decrement preserve carry and compute other flags`() {
        for (opcode in listOf(4, 5)) {
            emulator.write(opcode.toUShort(), opcode.toUByte())
            for (b in 0..255) {
                for (carry in 0..1) {
                    emulator.writePC(opcode.toUShort())
                    emulator.writeB(b.toUByte())
                    emulator.writeF((0xe0 + carry * 16).toUByte())
                    emulator.step()
                    val result = (b + if (opcode == 4) 1 else -1) and 255
                    val half = if (opcode == 4) b % 16 == 15 else b % 16 == 0
                    val flags = (if (result == 0) 128 else 0) + (if (opcode == 5) 64 else 0) + (if (half) 32 else 0) + carry * 16
                    assertEquals(result, emulator.readB().toInt())
                    assertEquals(flags, emulator.readF().toInt())
                }
            }
        }
    }
}
