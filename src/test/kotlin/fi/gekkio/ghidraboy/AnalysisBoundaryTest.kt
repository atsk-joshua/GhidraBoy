package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AnalysisBoundaryTest : IntegrationTest() {
    private fun program(test: (ProgramDB) -> Unit) {
        val bytes = ByteArray(0x10000).also { it[0x147] = 0x19; it[0x148] = 1; it[0x143] = 0x80.toByte() }
        val consumer = Any(); val p = ProgramDB("boundaries", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use { CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.CGB, true, true, TaskMonitor.DUMMY, MessageLog()) }
            test(p)
        } finally { p.release(consumer) }
    }
    @Test
    fun `relative cross-window instruction fetch requires the correct physical bytes`() {
        for (valid in listOf(false, true)) program { p ->
            val start = ProgramMapping.fileToStatic(p, 0x7fff).single()
            val vram = p.memory.getBlock("vram0")
            p.withTransaction {
                p.memory.convertToInitialized(vram, 0)
                p.memory.setByte(vram.start.add(1), 0xc9.toByte())
                p.memory.setByte(start, 0x18)
                val source = if (valid) vram.start else ProgramMapping.fileToStatic(p, 0x8000).single()
                p.memory.createByteMappedBlock("fetch suffix", start.addressSpace.getAddressInThisSpaceOnly(0x8000), source, 2, false).isExecute = true
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                d.disassemble(start, AddressSet(start, start.add(1)))
                d.disassemble(vram.start.add(1), AddressSet(vram.start.add(1)))
            }
            assertTrue(p.listing.getInstructionAt(start) != null, "valid=$valid data=${p.listing.getCodeUnitAt(start)} bytes=${p.memory.getByte(start)},${p.memory.getByte(start.add(1))}")
            val result = BankAnalysis.preview(p, start, MapperState.reset(), AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY)
            if (valid) assertTrue(result.findings().any { it.access() == "jump" && "vram0::8001" in it.targets() }, result.toString())
            else assertTrue(result.findings().any { it.reason().contains("Instruction fetch") }, result.toString())
        }
    }
    @Test
    fun `PC wrap follows the established low ROM window`() = program { p ->
        p.withTransaction {
            p.memory.convertToInitialized(p.memory.getBlock("ie"), 0)
            p.listing.clearCodeUnits(address(0xffff), address(0xffff), false)
            p.memory.setByte(address(0), 0xc9.toByte())
            val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
            d.disassemble(address(0xffff), AddressSet(address(0xffff)))
            d.disassemble(address(0), AddressSet(address(0)))
        }
        val result = BankAnalysis.preview(p, address(0xffff), MapperState.reset(), AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY)
        assertTrue(result.exploredStates() >= 2, result.toString())
        assertFalse(result.findings().any { it.reason().contains("No defined instruction") }, result.toString())
    }
}
