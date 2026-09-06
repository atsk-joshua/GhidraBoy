package fi.gekkio.ghidraboy

import ghidra.app.plugin.core.disassembler.EntryPointAnalyzer
import ghidra.app.util.PseudoDisassembler
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.listing.CodeUnit
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.IOException

class CartridgeEntryTest : IntegrationTest() {
    private fun cartridge(): ByteArray =
        ByteArray(0x10000) { 0xd3.toByte() }.also {
            it[0x147] = 0x19
            it[0x148] = 1
            it[0x149] = 0
            byteArrayOf(0, 0xc3.toByte(), 0x50, 1).copyInto(it, 0x100)
            // Startup is valid code but cannot be certified as a normal subroutine:
            // its destination is a CPU window with no statically selected bank.
            byteArrayOf(0xf3.toByte(), 0x31, 0, 0xd0.toByte(), 0xc3.toByte(), 0, 0x40).copyInto(it, 0x150)
            it[0x200] = 0xc9.toByte()
        }

    private fun loaded(
        mode: String = "CARTRIDGE",
        mapper: String = "AUTO",
        bytes: ByteArray = cartridge(),
        action: (ProgramDB) -> Unit,
    ) {
        val consumer = Any()
        val p = ProgramDB("entry-seed", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, mode, mapper, GameBoyKind.GB, false, true, TaskMonitor.DUMMY, MessageLog())
            }
            action(p)
        } finally {
            p.release(consumer)
        }
    }

    private fun analyzeEntries(p: ProgramDB) {
        p.withTransaction {
            EntryPointAnalyzer().added(p, p.memory, TaskMonitor.DUMMY, MessageLog())
        }
    }

    @Test
    fun `cartridge startup gets code despite ordinary subroutine rejection`() {
        loaded { p ->
            assertFalse(PseudoDisassembler(p).isValidSubroutine(address(0x100)))
            val seed = p.getAddressSetPropertyMap("CodeMap")
            assertNotNull(seed)
            val seeds =
                seed.addresses
                    .iterator()
                    .asSequence()
                    .toList()
            assertEquals(listOf(address(0x100)), seeds)
            // Reproduce the old loader behavior on the same legal fixture.
            p.withTransaction { p.deleteAddressSetPropertyMap("CodeMap") }
            analyzeEntries(p)
            assertNull(p.listing.getInstructionAt(address(0x100)))
            p.withTransaction { p.createAddressSetPropertyMap("CodeMap").add(address(0x100), address(0x100)) }
            analyzeEntries(p)
            assertEquals("NOP", p.listing.getInstructionAt(address(0x100)).mnemonicString)
            assertEquals("JP", p.listing.getInstructionAt(address(0x101)).mnemonicString)
            assertEquals("DI", p.listing.getInstructionAt(address(0x150)).mnemonicString)
            assertNotNull(p.listing.getDefinedDataAt(address(0x104)))
            assertNull(p.listing.getInstructionAt(address(0)))
            assertNull(p.listing.getInstructionAt(ProgramMapping.fileToStatic(p, 0x4000).single()))
            assertNull(p.memory.getBlock(address(0x4000)))
        }
    }

    @Test
    fun `entry seed respects later marked data and existing user instructions`() {
        loaded { p ->
            p.withTransaction {
                p.listing.createData(address(0x100), ByteDataType.dataType)
                p.listing.setComment(address(0x100), CodeUnit.EOL_COMMENT, "reviewed entry byte")
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(address(0x200), AddressSet(address(0x200)))
                p.symbolTable.createLabel(address(0x200), "student_code", SourceType.USER_DEFINED)
                p.listing.getInstructionAt(address(0x200)).setFallThrough(address(0x201))
            }
            analyzeEntries(p)
            assertNotNull(p.listing.getDefinedDataAt(address(0x100)))
            assertNull(p.listing.getInstructionAt(address(0x100)))
            assertEquals("reviewed entry byte", p.listing.getComment(CodeUnit.EOL_COMMENT, address(0x100)))
            assertEquals("RET", p.listing.getInstructionAt(address(0x200)).mnemonicString)
            assertTrue(p.listing.getInstructionAt(address(0x200)).isFallThroughOverridden)
            assertEquals("student_code", p.symbolTable.getPrimarySymbol(address(0x200)).name)
            assertThrows(IOException::class.java) {
                ByteArrayProvider(cartridge()).use {
                    CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, true, TaskMonitor.DUMMY, MessageLog())
                }
            }
            assertNotNull(p.listing.getDefinedDataAt(address(0x100)))
            assertEquals("student_code", p.symbolTable.getPrimarySymbol(address(0x200)).name)
        }
    }

    @Test
    fun `salvage raw and boot inputs do not claim cartridge startup`() {
        loaded(mode = "SALVAGE") { assertNull(it.getAddressSetPropertyMap("CodeMap")) }
        loaded(mode = "SALVAGE", mapper = "RAW") { assertNull(it.getAddressSetPropertyMap("CodeMap")) }
        loaded(mode = "DMG_BOOT", bytes = ByteArray(0x100)) {
            assertNull(it.getAddressSetPropertyMap("CodeMap"))
            assertTrue(it.symbolTable.isExternalEntryPoint(address(0)))
            assertFalse(it.symbolTable.isExternalEntryPoint(address(0x100)))
        }
    }
}
