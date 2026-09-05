package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AnalysisHardeningTest : IntegrationTest() {
    private fun program(
        banks: Int = 4,
        prepare: (ByteArray) -> Unit,
        test: (ProgramDB) -> Unit,
    ) {
        val bytes = ByteArray(banks * 0x4000)
        bytes[0x143] = 0x80.toByte()
        bytes[0x147] = 0x1b
        bytes[0x148] = Integer.numberOfTrailingZeros(banks / 2).toByte()
        bytes[0x149] =
            3
        prepare(bytes)
        val consumer = Any()
        val p = ProgramDB("analysis hardening", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.CGB, true, true, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                val range = AddressSet(address(0x150), address(0x3fff))
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                d.setRepeatPatternLimitIgnored(range)
                d.disassemble(address(0x150), range)
            }
            test(p)
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `both branch orders preserve candidates without proof on worklist exhaustion`() {
        for (reverse in listOf(false, true)) {
            program(prepare = { b ->
                byteArrayOf(0xca.toByte(), 0, 0x30).copyInto(b, 0x150)
                byteArrayOf(0x3e, 2, 0xc3.toByte(), 0x10, 0x30).copyInto(b, 0x2153)
                byteArrayOf(0x3e, 1, 0xc3.toByte(), 0x10, 0x30).copyInto(b, 0x3000)
                byteArrayOf(0xea.toByte(), 0, 0x20, 0xcd.toByte(), 0, 0x40, 0xc9.toByte()).copyInto(b, 0x3010)
            }) { p ->
                val r =
                    BankAnalysis.preview(
                        p,
                        address(0x150),
                        MapperState.reset(),
                        AnalysisResult.Configuration(4096, reverse),
                        TaskMonitor.DUMMY,
                    )
                assertEquals(AnalysisResult.Completion.STATE_LIMIT, r.completion())
                assertEquals(4096, r.exploredStates())
                assertTrue(r.pendingStates() > 0)
                assertTrue(r.findings().any { it.targets().isNotEmpty() })
                assertFalse(r.findings().any { it.confidence() == AnalysisResult.Confidence.PROVEN })
                BankAnalysis.apply(p, r, TaskMonitor.DUMMY)
                assertFalse(p.referenceManager.getReferencesFrom(address(0x3013)).any { it.operandIndex == -1 })
                val before = p.functionManager.functionCount
                FunctionDiscovery.discover(p, listOf(address(0x150)), r, TaskMonitor.DUMMY)
                assertEquals(before, p.functionManager.functionCount)
            }
        }
    }

    @Test
    fun `loop duplicate states do not consume the exploration budget`() =
        program(prepare = { b ->
            byteArrayOf(0, 0xc3.toByte(), 0x50, 1).copyInto(b, 0x150)
        }) { p ->
            val r = BankAnalysis.preview(p, address(0x150), MapperState.reset(), AnalysisResult.Configuration(2, false), TaskMonitor.DUMMY)
            assertEquals(AnalysisResult.Completion.COMPLETE, r.completion())
            assertEquals(2, r.exploredStates())
        }

    @Test
    fun `cancelled preview and patched results cannot mutate the program`() =
        program(prepare = { b ->
            byteArrayOf(0, 0, 0, 0xc3.toByte(), 0, 0x40).copyInto(b, 0x150)
        }) { p ->
            val monitor =
                object : TaskMonitorAdapter(true) {
                    var exploring = false
                    var checks = 0

                    override fun setMessage(message: String?) {
                        if (message == "Exploring bank states") exploring = true
                    }

                    override fun checkCancelled() {
                        if (exploring && ++checks == 3) throw CancelledException()
                    }
                }
            val cancelled = BankAnalysis.preview(p, address(0x150), MapperState.reset(), AnalysisResult.Configuration.DEFAULT, monitor)
            assertEquals(AnalysisResult.Completion.CANCELLED, cancelled.completion())
            assertThrows(CancelledException::class.java) { BankAnalysis.apply(p, cancelled, TaskMonitor.DUMMY) }
            val r = BankAnalysis.preview(p, address(0x150), MapperState.reset(), AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY)
            p.withTransaction {
                p.listing.clearCodeUnits(address(0x151), address(0x151), false)
                p.memory.setByte(address(0x151), 0x3f)
            }
            assertThrows(IllegalStateException::class.java) { BankAnalysis.apply(p, r, TaskMonitor.DUMMY) }
            assertThrows(IllegalStateException::class.java) { FunctionDiscovery.discover(p, listOf(), r, TaskMonitor.DUMMY) }
        }

    @Test
    fun `wide writes across mapper hardware and address boundaries affect every byte`() {
        data class Case(
            val banks: Int,
            val where: Int,
            val word: Int,
            val target: Int,
            val expected: String,
        )
        for (case in listOf(
            Case(4, 0x1fff, 0x020a, 0x4000, "rom2::4000"),
            Case(512, 0x2fff, 0x0100, 0x4000, "rom256::4000"),
            Case(4, 0xff4e, 0x0100, 0x8034, "vram1::8034"),
            Case(4, 0xff6f, 0x0300, 0xd034, "wram3::d034"),
            Case(4, 0xffff, 0x0a00, 0xa010, "a010"),
        )) {
            program(case.banks, prepare = { b ->
                byteArrayOf(
                    0x31,
                    case.word.toByte(),
                    (case.word shr 8).toByte(),
                    8,
                    case.where.toByte(),
                    (case.where shr 8).toByte(),
                    0xfa.toByte(),
                    case.target.toByte(),
                    (case.target shr 8).toByte(),
                    0xc9.toByte(),
                ).copyInto(b, 0x150)
            }) { p ->
                val r =
                    BankAnalysis.preview(
                        p,
                        address(0x150),
                        MapperState.reset(),
                        AnalysisResult.Configuration.DEFAULT,
                        TaskMonitor.DUMMY,
                    )
                assertTrue(
                    r.findings().any { it.source() == "0156" && it.access() == "read" && case.expected in it.targets() },
                    "$case: $r",
                )
            }
        }
    }

    @Test
    fun `stack stores affect mapper registers in architectural byte order`() =
        program(prepare = { b ->
            byteArrayOf(1, 0x0a, 2, 0x31, 1, 0x20, 0xc5.toByte(), 0xc3.toByte(), 0, 0x40).copyInto(b, 0x150)
        }) { p ->
            val stores =
                p.listing
                    .getInstructionAt(address(0x156))
                    .pcode
                    .filter { it.opcode == ghidra.program.model.pcode.PcodeOp.STORE }
            assertEquals(2, stores.size)
            assertTrue(stores.all { it.getInput(2).size == 1 })
            val r = BankAnalysis.preview(p, address(0x150), MapperState.reset(), AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY)
            assertTrue(r.findings().any { it.access() == "jump" && it.targets() == listOf("rom2::4000") }, r.toString())
        }
}
