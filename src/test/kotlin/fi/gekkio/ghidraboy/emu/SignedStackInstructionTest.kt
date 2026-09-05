package fi.gekkio.ghidraboy.emu

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SignedStackInstructionTest : EmuTest() {
    @Test
    fun `signed SP additions preserve correct low byte flags and wrap`() {
        for ((index, opcode) in listOf(0xe8, 0xf8).withIndex()) {
            for (imm in 0..255) {
                val pc = index * 0x200 + imm * 2
                emulator.write(pc.toUShort(), opcode.toUByte(), imm.toUByte())
                for (low in 0..255) {
                    val sp = 0xff00 + low
                    emulator.writePC(pc.toUShort())
                    emulator.writeSP(sp.toUShort())
                    emulator.writeF(0xf0u)
                    emulator.step()
                    val expected = (sp + imm.toByte().toInt()) and 0xffff
                    val actual = if (opcode == 0xe8) emulator.readSP().toInt() else emulator.readHL().toInt()
                    assertEquals(expected, actual, "opcode=$opcode sp=$sp imm=$imm")
                    val flags = (if (low + imm > 255) 16 else 0) + (if (low % 16 + imm % 16 > 15) 32 else 0)
                    assertEquals(flags, emulator.readF().toInt())
                }
            }
        }
    }

    @Test
    fun `HL auto increment and decrement wrap at sixteen bits`() {
        emulator.write(0x100u, 0x2au, 0x3au)
        emulator.write(0xffffu, 0x42u)
        emulator.writePC(0x100u)
        emulator.writeHL(0xffffu)
        emulator.writeF(0xb0u)
        emulator.step()
        emulator.assertA(0x42u)
        emulator.assertHL(0u)
        emulator.write(0u, 0x51u)
        emulator.step()
        emulator.assertA(0x51u)
        emulator.assertHL(0xffffu)
        emulator.assertF(0xb0u)
    }

    @Test
    fun `stack word accesses wrap the flat sixteen bit address space`() {
        emulator.write(0x100u, 0xc5u, 0xd1u)
        emulator.writePC(0x100u)
        emulator.writeSP(1u)
        emulator.writeBC(0x1234u)
        emulator.step()
        emulator.assertSP(0xffffu)
        assertEquals(0x34, emulator.read(0xffffu).toInt())
        assertEquals(0x12, emulator.read(0u).toInt())
        emulator.step()
        emulator.assertDE(0x1234u)
        emulator.assertSP(1u)
    }
}
