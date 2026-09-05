package fi.gekkio.ghidraboy

import ghidra.program.database.ProgramDB
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.data.DWordDataType
import ghidra.program.model.data.WordDataType
import ghidra.program.model.lang.CompilerSpecID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CompilerSpecTest : IntegrationTest() {
    @Test
    fun `compiler generated ordinary scalar storage matches explicit variants`() {
        val byte = ByteDataType.dataType
        val word = WordDataType.dataType
        val dword = DWordDataType.dataType
        val cases =
            listOf(
                Triple("call0", arrayOf(byte, byte, byte, byte), listOf("E", "Stack[0x2]", "Stack[0x3]", "Stack[0x4]")),
                Triple("call1-first8", arrayOf(byte, byte, byte, byte), listOf("A", "A", "E", "Stack[0x2]")),
                Triple("call1-first16", arrayOf(word, word, word, byte), listOf("BC", "DE", "BC", "Stack[0x2]")),
                Triple("call1-first16", arrayOf(word, word, byte, word), listOf("BC", "DE", "A", "Stack[0x2]")),
                Triple("call1-first8", arrayOf(word, byte, word, byte), listOf("BC", "A", "DE", "Stack[0x2]")),
            )
        for ((variant, types, expected) in cases) {
            val spec = language.getCompilerSpecByID(CompilerSpecID("sdcc451-$variant"))
            val consumer = Any()
            val p = ProgramDB("abi", language, spec, consumer)
            try {
                val storage = spec.defaultCallingConvention.getStorageLocations(p, types, false)
                assertEquals(expected.size, storage.size)
                for (i in storage.indices) {
                    assertTrue(
                        storage[i].toString().startsWith(expected[i]),
                        "$variant arg$i ${storage[i]} != ${expected[i]}",
                    )
                }
            } finally {
                p.release(consumer)
            }
        }
        for (variant in listOf("call0", "call1-first32")) {
            val spec = language.getCompilerSpecByID(CompilerSpecID("sdcc451-$variant"))
            val consumer = Any()
            val p = ProgramDB("abi32", language, spec, consumer)
            try {
                val storage = spec.defaultCallingConvention.getStorageLocations(p, arrayOf(dword, dword), false)
                assertEquals(4, storage[0].size())
                assertEquals(4, storage[1].size())
                assertEquals(if (variant == "call0") "HL" else "DE", storage[0].registers[0].name)
            } finally {
                p.release(consumer)
            }
        }
    }
}
