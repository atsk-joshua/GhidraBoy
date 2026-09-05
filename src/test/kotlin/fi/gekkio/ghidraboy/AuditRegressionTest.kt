package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Independent audit cases reproduced against a9e1ca7 before production changes. */
class AuditRegressionTest : IntegrationTest() {
    private fun loaded(banks: Int = 4, type: Int = 0x19, boot: Boolean = false, prepare: (ByteArray) -> Unit = {}, test: (ProgramDB) -> Unit) {
        val bytes = ByteArray(if (boot) 0x900 else banks * 0x4000)
        if (!boot) {
            bytes[0x143] = 0x80.toByte()
            bytes[0x147] = type.toByte()
            bytes[0x148] = Integer.numberOfTrailingZeros(banks / 2).toByte()
        }
        prepare(bytes)
        val consumer = Any()
        val p = ProgramDB("audit", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use { CartridgeLayout.load(p, it, if (boot) "CGB_BOOT" else "CARTRIDGE", "AUTO", GameBoyKind.CGB, true, true, TaskMonitor.DUMMY, MessageLog()) }
            test(p)
        } finally { p.release(consumer) }
    }

    private fun define(p: ProgramDB, start: Address, end: Address) = p.withTransaction {
        val range = AddressSet(start, end)
        val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
        disassembler.setRepeatPatternLimitIgnored(range)
        disassembler.disassemble(start, range)
    }

    @Test
    fun `R1 incomplete exploration cannot apply a singleton`() = loaded(prepare = { b ->
        byteArrayOf(0xca.toByte(), 0, 0x30).copyInto(b, 0x150)
        byteArrayOf(0x3e, 2, 0xc3.toByte(), 0x10, 0x30).copyInto(b, 0x2153)
        byteArrayOf(0x3e, 1, 0xc3.toByte(), 0x10, 0x30).copyInto(b, 0x3000)
        byteArrayOf(0xea.toByte(), 0, 0x20, 0xc3.toByte(), 0, 0x40).copyInto(b, 0x3010)
    }) { p ->
        define(p, address(0x150), address(0x3015))
        assertTrue(p.listing.getInstructionAt(address(0x2153)) != null, "Authored long path must be defined")
        val findings = BankAnalysis.analyze(p, address(0x150), MapperState.reset(), TaskMonitor.DUMMY, true)
        assertTrue(findings.any { it.access() == "limit" })
        assertTrue(findings.any { it.source() == "3013" && it.targets().isNotEmpty() }, "Retain useful candidates")
        assertFalse(p.referenceManager.getReferencesFrom(address(0x3013)).any { it.operandIndex == -1 }, findings.toString())
    }

    @Test
    fun `R2 word store writes both mapper registers`() = loaded(prepare = { b ->
        byteArrayOf(0x31, 0x0a, 2, 8, 0xff.toByte(), 0x1f, 0xc3.toByte(), 0, 0x40).copyInto(b, 0x150)
    }) { p ->
        define(p, address(0x150), address(0x158))
        val findings = BankAnalysis.analyze(p, address(0x150), MapperState.reset(), TaskMonitor.DUMMY, false)
        assertEquals(listOf("rom2::4000"), findings.single { it.source() == "0156" && it.access() == "jump" }.targets())
    }

    @Test
    fun `R3 masked MBC1 bank zero has an upper window view`() = loaded(16, 3) { p ->
        val c = ProgramMapping.cartridge(p)
        val state = MapperState.reset().write(c, 0x2000, 0x10)
        assertEquals(0, MapperState.translate(c, state, 0x4000, false).physical().bank())
        assertTrue(ProgramMapping.cpuToStatic(p, state, 0x4000, false).addresses().isNotEmpty())
    }

    @Test
    fun `R4 fixed to switchable window fallthrough resolves the new view`() = loaded(prepare = { b ->
        byteArrayOf(0xc3.toByte(), 0x10, 0x40).copyInto(b, 0x4000)
    }) { p ->
        define(p, address(0x3fff), address(0x3fff))
        val upper = ProgramMapping.fileToStatic(p, 0x4000).single()
        define(p, upper, upper.add(2))
        val findings = BankAnalysis.analyze(p, address(0x3fff), MapperState.reset(), TaskMonitor.DUMMY, false)
        assertTrue(findings.any { it.source() == "rom1::4000" && it.targets() == listOf("rom1::4010") }, findings.toString())
    }

    @Test
    fun `R5 shared symbol remains until the last source is removed`() = loaded { p ->
        val parsed = SymbolFile.parse("2:4010 Shared\n".toByteArray())
        SymbolService.importSymbols(p, parsed, "first.sym", TaskMonitor.DUMMY)
        SymbolService.importSymbols(p, parsed, "second.sym", TaskMonitor.DUMMY)
        SymbolService.removeOwned(p, "first.sym", TaskMonitor.DUMMY)
        assertTrue(p.symbolTable.getSymbols("Shared").hasNext())
        SymbolService.removeOwned(p, "second.sym", TaskMonitor.DUMMY)
        assertFalse(p.symbolTable.getSymbols("Shared").hasNext())
    }

    @Test
    fun `R6 BOOT symbols never leak into echo RAM`() = loaded(boot = true) { p ->
        val parsed = SymbolFile.parse("BOOT:e010 BootOnly\n".toByteArray())
        val preview = SymbolService.preview(p, parsed).single()
        assertTrue(preview.addresses().isEmpty(), preview.toString())
        assertTrue(preview.diagnostic().isNotEmpty())
        p.withTransaction {
            p.memory.createByteMappedBlock("nested echo", address(0x5000), address(0xe000), 0x100, true)
            p.memory.createByteMappedBlock("boot alias", address(0x6000), address(0), 0x100, true)
        }
        fun locations(text: String) = SymbolService.preview(p, SymbolFile.parse((text + "\n").toByteArray())).single().addresses()
        assertTrue(locations("BOOT:5010 Wrong").isEmpty())
        assertTrue(locations("BOOT:0010 Valid").isNotEmpty())
        assertTrue(locations("BOOT:6010 Alias").isNotEmpty())
        assertTrue(locations("6010 Any").isEmpty())
        assertTrue(locations("0:6010 Bank").isEmpty())
        assertTrue(locations("e010 Any").isNotEmpty())
    }
}
