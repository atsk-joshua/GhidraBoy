package fi.gekkio.ghidraboy

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.nio.charset.CharacterCodingException

class SymbolTest {
    @Test
    fun `UTF8 comments duplicates BOOT any bank wide bank and local attachment`() {
        val text =
            """
            123:4567 Parent.local @private ordinary
            123:4001 Parent
            123:4567 Parent.local
            124:4567 Parent.local
            boot:0010 Start
            4001 AnyBank
            ffffffff:ffff Maximum
            0:0100 Unicode\u00e9
            """.trimIndent().replace("\n", "\r\n")
        val result = SymbolFile.parse(text.toByteArray())
        assertEquals(7, result.symbols().size)
        assertEquals(1, result.diagnostics().size)
        assertEquals("Parent", SymbolFile.parent(result.symbols()[0], result.symbols()).get().name())
        assertEquals("BOOT", result.symbols()[3].location().form())
        assertEquals("ANY", result.symbols()[4].location().form())
        assertEquals(0xffffffffL, result.symbols()[5].location().bank())
        val again = SymbolFile.parse(SymbolFile.format(result.symbols()).toByteArray())
        assertEquals(result.symbols().map { it.location() to it.name() }, again.symbols().map { it.location() to it.name() })
    }

    @Test
    fun `invalid names encoding and ranges are diagnosed`() {
        val text = "0:10000 Bad\n100000000:0000 Bad\n0:100 \\u0000Bad\n0:100 Bad\\ud800\n0:100 .Local\n0:100 Good @ok weird;comment\n"
        val parsed = SymbolFile.parse(text.toByteArray())
        assertEquals(1, parsed.symbols().size)
        assertEquals(6, parsed.diagnostics().size)
        assertThrows(CharacterCodingException::class.java) { SymbolFile.parse(byteArrayOf(0xc0.toByte(), 0xaf.toByte())) }
    }

    @Test
    fun `Unicode escapes identify the same character and all private metadata is ignored`() {
        val input = "0:1234 Caf\\u00e9 @anything @ignore @tool=value\n0:1234 Caf\\u00E9\n"
        val result = SymbolFile.parse(input.toByteArray())
        assertEquals(1, result.symbols().size)
        assertEquals("Café", result.symbols()[0].name())
        assertEquals(0, result.diagnostics().size)
        assertEquals("0:1234 Caf\\u00e9\n", SymbolFile.format(result.symbols()))
    }
}
