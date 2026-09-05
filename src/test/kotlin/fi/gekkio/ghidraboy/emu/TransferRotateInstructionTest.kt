package fi.gekkio.ghidraboy.emu

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class TransferRotateInstructionTest : EmuTest() {
    @Test
    fun `accumulator rotates clear zero and preserve unrelated registers`() {
        for (opcode in listOf(0x07, 0x0f, 0x17, 0x1f)) {
            emulator.write(opcode.toUShort(), opcode.toUByte())
            for (value in 0..255) {
                for (carry in 0..1) {
                    emulator.writePC(opcode.toUShort())
                    emulator.writeA(value.toUByte())
                    emulator.writeF((0xe0 + carry * 16).toUByte())
                    emulator.writeBC(0x1234u)
                    emulator.writeDE(0x5678u)
                    emulator.writeHL(0x9abcu)
                    emulator.writeSP(0xdff0u)
                    val left = opcode == 0x07 || opcode == 0x17
                    val outgoing = if (left) value shr 7 else value and 1
                    val incoming = if (opcode < 0x10) outgoing else carry
                    val result = if (left) ((value shl 1) or incoming) and 255 else (value shr 1) or (incoming shl 7)
                    emulator.step()
                    emulator.assertA(result.toUByte())
                    emulator.assertF((outgoing * 16).toUByte())
                    emulator.assertBC(0x1234u)
                    emulator.assertDE(0x5678u)
                    emulator.assertHL(0x9abcu)
                    emulator.assertSP(0xdff0u)
                    emulator.assertPC((opcode + 1).toUShort())
                }
            }
        }
    }

    @Test
    fun `LD register matrix uses old HL for aliased memory and preserves unaffected state`() {
        val registers = listOf("B", "C", "D", "E", "H", "L", "memory", "A")
        val initial = listOf(0x13, 0x27, 0x39, 0x51, 0xc0, 0xff, 0x99, 0x85)
        for (opcode in 0x40..0x7f) {
            if (opcode == 0x76) continue
            val pc = 0x400 + opcode * 2
            emulator.write(pc.toUShort(), opcode.toUByte())
            for (flags in listOf(0, 0xf0)) {
                for (i in registers.indices) {
                    if (i != 6) emulator.writeRegister(registers[i], initial[i].toLong())
                }
                emulator.write(0xc0ffu, initial[6].toUByte())
                emulator.writeF(flags.toUByte())
                emulator.writeSP(0xdff0u)
                emulator.writePC(pc.toUShort())
                val source = opcode and 7
                val destination = (opcode shr 3) and 7
                emulator.step()
                for (i in registers.indices) {
                    val expected = if (i == destination) initial[source] else initial[i]
                    val actual = if (i == 6) emulator.read(0xc0ffu).toInt() else emulator.readRegister(registers[i]).toInt()
                    assertEquals(expected, actual, "opcode=$opcode register=${registers[i]}")
                }
                emulator.assertF(flags.toUByte())
                emulator.assertSP(0xdff0u)
                emulator.assertPC((pc + 1).toUShort())
            }
        }
    }
}
