package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BankAnalysisFetchTest : IntegrationTest() {
    @Test
    fun `production fetch follows mapper write with symmetric continuations and unknown entry state`() {
        withFixture(2) { p ->
            val preview = previewFromDriver(p)
            val steps = preview.steps()
            assertEquals(
                listOf("rom1::4000", "rom1::4002", "rom2::4005", "rom2::4007", "rom2::4008", "rom2::400b"),
                steps.map { it.source() },
            )
            assertEquals(1, steps.first().incoming().low())
            assertNull(steps.first().incoming().high())
            assertNull(steps.first().incoming().enabled())
            val mapper = steps[1].writes().single()
            assertTrue(mapper.mapperControl())
            assertEquals(0x2000, mapper.cpu())
            assertEquals(2, mapper.value())
            assertEquals(1, mapper.before().low())
            assertNull(mapper.before().enabled())
            assertEquals(2, mapper.after().low())
            assertNull(mapper.after().high())
            assertNull(mapper.after().enabled())
            assertEquals(listOf("rom2::4005"), steps[1].successors())
            val postWrite = steps.drop(2).flatMap { it.bytes() }
            assertEquals((5..11).toList(), postWrite.map { it.physical().offset() })
            assertTrue(postWrite.all { it.physical().bank() == 2 })
            assertEquals(listOf(6, 0xa7, 0x78, 0xea, 0x10, 0xc0, 0xc9), postWrite.map { it.value() })
            val effect = steps[4].writes().single()
            assertEquals(0xc010, effect.cpu())
            assertEquals(0xa7, effect.value())
            assertFalse(effect.mapperControl())
            assertTrue(preview.frontier().any { it.contains("rom2::400b") && it.contains("Unknown load address") })
            assertTrue(preview.result().complete())
            assertEquals(0, preview.result().pendingStates())
            val ordinary = BankAnalysis.preview(p, entry(p), null, AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY)
            assertEquals(ordinary, preview.result())
        }
    }

    @Test
    fun `same selector retains bank one through the identical production path`() {
        withFixture(1) { p ->
            val steps = previewFromDriver(p).steps()
            assertEquals(listOf("rom1::4005"), steps[1].successors())
            assertTrue(steps.flatMap { it.bytes() }.all { it.physical().bank() == 1 })
            assertEquals(0xd1, steps[2].bytes()[1].value())
            assertEquals(0xd1, steps[3].writes().single().value())
        }
    }

    @Test
    fun `unknown selector stops before either available continuation`() {
        withFixture(2, unknownSelector = true) { p ->
            val result = BankAnalysis.previewFetch(p, entry(p).add(2), null, AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY)
            assertEquals(listOf("rom1::4002"), result.steps().map { it.source() })
            assertTrue(
                result
                    .steps()
                    .single()
                    .successors()
                    .isEmpty(),
            )
            assertNull(
                result
                    .steps()
                    .single()
                    .writes()
                    .single()
                    .value(),
            )
            assertTrue(result.frontier().any { it.contains("Fallthrough execution view unresolved") })
        }
    }

    @Test
    fun `derived execution aliases cannot supply production fetch evidence`() {
        withFixture(2, derivedView = true) { p ->
            val preview = previewFromDriver(p)
            assertEquals(6, preview.steps().size)
            assertTrue(preview.steps().none { it.source().contains("gb_ordinary_") })
            assertEquals(listOf("rom2::4005"), preview.steps()[1].successors())
            val alias = p.addressFactory.getAddress("gb_ordinary_diagnostic::4005")
            val foreign = BankAnalysis.previewFetch(p, alias, null, AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY)
            assertTrue(foreign.steps().isEmpty())
            assertTrue(foreign.frontier().any { it.contains("unestablished physical execution view") })
        }
    }

    private fun entry(p: ProgramDB) = ProgramMapping.fileToStatic(p, 0x4000).single()

    private fun previewFromDriver(p: ProgramDB): BankAnalysis.FetchPreview {
        val driver = BankAnalysis.previewFetch(p, address(0x180), null, AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY).result()
        val call = driver.findings().single { it.source() == "018d" && it.access() == "call" }
        assertEquals(AnalysisResult.Confidence.PROVEN, call.confidence())
        assertEquals(listOf("rom1::4000"), call.targets())
        val invocation = ProgramMapping.staticAddress(p, call.targets().single())
        assertEquals(entry(p), invocation)
        return BankAnalysis.previewFetch(p, invocation, null, AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY)
    }

    private fun withFixture(
        selector: Int,
        unknownSelector: Boolean = false,
        derivedView: Boolean = false,
        block: (ProgramDB) -> Unit,
    ) {
        val data = ByteArray(0x10000)
        data[0x147] = 0x19
        data[0x148] = 1
        byteArrayOf(
            0xf3.toByte(),
            0x31,
            0xfe.toByte(),
            0xcf.toByte(),
            0xaf.toByte(),
            0xea.toByte(),
            0,
            0x30,
            0x3e,
            1,
            0xea.toByte(),
            0,
            0x20,
            0xcd.toByte(),
            0,
            0x40,
            0xc9.toByte(),
        ).copyInto(data, 0x180)
        byteArrayOf(0x3e, selector.toByte(), 0xea.toByte(), 0, 0x20).copyInto(data, 0x4000)
        byteArrayOf(0x3e, 0xd1.toByte(), 0xea.toByte(), 0x10, 0xc0.toByte(), 0xc9.toByte()).copyInto(data, 0x4005)
        byteArrayOf(6, 0xa7.toByte(), 0x78, 0xea.toByte(), 0x10, 0xc0.toByte(), 0xc9.toByte()).copyInto(data, 0x8005)
        val owner = Any()
        val p = ProgramDB("banked-fetch", language, language.defaultCompilerSpec, owner)
        try {
            ByteArrayProvider(data).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                disassembler.disassemble(address(0x180), AddressSet(address(0x180), address(0x190)))
                val bankOne = entry(p)
                disassembler.disassemble(bankOne, AddressSet(bankOne, bankOne.add(11)))
                val bankTwo = ProgramMapping.fileToStatic(p, 0x8005).single()
                disassembler.disassemble(bankTwo, AddressSet(bankTwo, bankTwo.add(6)))
                if (derivedView) {
                    val alias = p.memory.createByteMappedBlock("gb_ordinary_diagnostic", address(0x4005), bankTwo, 7, true)
                    alias.isRead = true
                    alias.isWrite = false
                    alias.isExecute = true
                    Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(alias.start, AddressSet(alias.start, alias.end))
                    assertTrue(p.listing.getInstructionAt(alias.start) != null)
                }
            }
            assertTrue(p.listing.getInstructionAt(entry(p).add(5)) != null)
            assertTrue(p.listing.getInstructionAt(p.addressFactory.getAddress("rom2::4005")) != null)
            if (unknownSelector) assertNull(p.programContext.getRegisterValue(p.getRegister("A"), entry(p).add(2)))
            val before = ProgramFingerprint.capture(p, TaskMonitor.DUMMY)
            block(p)
            assertEquals(before, ProgramFingerprint.capture(p, TaskMonitor.DUMMY))
        } finally {
            p.release(owner)
        }
    }
}
