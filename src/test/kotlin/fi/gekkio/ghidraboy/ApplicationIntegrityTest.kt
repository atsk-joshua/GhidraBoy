package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class ApplicationIntegrityTest : IntegrationTest() {
    private fun program(test: (ProgramDB) -> Unit) {
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        bytes[0x149] = 3
        bytes[0x150] = 0xc9.toByte()
        val consumer = Any()
        val p = ProgramDB("application-integrity", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.CGB, true, true, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(address(0x150), AddressSet(address(0x150)))
            }
            test(p)
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `late cancellation rolls back saved result and final discovery ownership`() =
        program { p ->
            val result =
                BankAnalysis.preview(
                    p,
                    address(0x150),
                    MapperState.reset(),
                    AnalysisResult.Configuration.DEFAULT,
                    TaskMonitor.DUMMY,
                )
            val options = p.getOptions(ProgramMapping.OPTIONS)
            val cancelApply =
                object : TaskMonitorAdapter() {
                    override fun checkCancelled() {
                        if (options.getString("analysis.latest", null) != null) throw CancelledException()
                    }
                }
            assertThrows(CancelledException::class.java) { BankAnalysis.apply(p, result, cancelApply) }
            assertNull(options.getString("analysis.latest", null))
            val cancelDiscovery =
                object : TaskMonitorAdapter() {
                    override fun checkCancelled() {
                        if (p.functionManager.getFunctionAt(address(0x150)) != null) throw CancelledException()
                    }
                }
            assertThrows(CancelledException::class.java) {
                FunctionDiscovery.discover(p, listOf(address(0x150)), result, cancelDiscovery)
            }
            assertNull(p.functionManager.getFunctionAt(address(0x150)))
        }

    @Test
    fun `old supplemental reference receipt cannot authorize deleting user primary edit`() =
        program { p ->
            val legacy = """[{"from":"0150","to":"0200","type":"DATA"}]"""
            val options = p.getOptions(ProgramMapping.OPTIONS)
            p.withTransaction {
                val reference = p.referenceManager.addMemoryReference(address(0x150), address(0x200), RefType.DATA, SourceType.ANALYSIS, -1)
                p.referenceManager.setPrimary(reference, !reference.isPrimary)
                options.setString("analysis.ownedReferences", legacy)
            }
            val result =
                BankAnalysis.preview(
                    p,
                    address(0x150),
                    MapperState.reset(),
                    AnalysisResult.Configuration.DEFAULT,
                    TaskMonitor.DUMMY,
                )
            BankAnalysis.apply(p, result, TaskMonitor.DUMMY)
            assertNotNull(p.referenceManager.getReference(address(0x150), address(0x200), -1))
            assertEquals(legacy, options.getString("analysis.ownedReferences", null))
        }
}
