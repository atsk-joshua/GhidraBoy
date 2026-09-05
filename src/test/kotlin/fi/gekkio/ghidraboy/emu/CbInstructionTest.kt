package fi.gekkio.ghidraboy.emu

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class CbInstructionTest : EmuTest() {
    @Test
    fun `all CB encodings execute register and memory semantics`() {
        val regs = listOf("B", "C", "D", "E", "H", "L", "memory", "A")
        for (opcode in 0..255) {
            val pc = opcode * 2
            emulator.write(pc.toUShort(), 0xcbu, opcode.toUByte())
            for (value in 0..255) {
                for (carry in 0..1) {
                    emulator.writePC(pc.toUShort())
                    emulator.writeHL(0xc000u)
                    emulator.writeF((0xe0 + carry * 16).toUByte())
                    val r = regs[opcode and 7]
                    if (r == "memory") emulator.write(0xc000u, value.toUByte()) else emulator.writeRegister(r, value.toLong())
                    emulator.step()
                    val group = opcode shr 6
                    val bit = (opcode shr 3) and 7
                    var result = value
                    var flags = 0xe0 + carry * 16
                    if (group == 0) {
                        var co = 0
                        when (bit) {
                            0 -> {
                                co = value shr 7
                                result = (value shl 1) or co
                            }
                            1 -> {
                                co = value and 1
                                result = (value shr 1) or (co shl 7)
                            }
                            2 -> {
                                co = value shr 7
                                result = (value shl 1) or carry
                            }
                            3 -> {
                                co = value and 1
                                result = (value shr 1) or (carry shl 7)
                            }
                            4 -> {
                                co = value shr 7
                                result = value shl 1
                            }
                            5 -> {
                                co = value and 1
                                result = (value shr 1) or (value and 128)
                            }
                            6 -> result = (value shl 4) or (value shr 4)
                            7 -> {
                                co = value and 1
                                result = value shr 1
                            }
                        }
                        result = result and 255
                        flags = (if (result == 0) 128 else 0) + co * 16
                    } else if (group == 1) {
                        flags = (if (value and (1 shl bit) == 0) 128 else 0) + 32 + carry * 16
                    } else if (group == 2) {
                        result = value and (1 shl bit).inv()
                    } else {
                        result = value or (1 shl bit)
                    }
                    val actual = if (r == "memory") emulator.read(0xc000u).toInt() else emulator.readRegister(r).toInt()
                    assertEquals(result, actual, "opcode=$opcode input=$value carry=$carry")
                    assertEquals(flags, emulator.readF().toInt(), "flags opcode=$opcode input=$value")
                    emulator.assertPC((pc + 2).toUShort())
                }
            }
        }
    }
}
