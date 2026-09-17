package fi.gekkio.ghidraboy

import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.Analyzer
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.framework.plugintool.Plugin
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.util.classfinder.ClassSearcher
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class GhidraBoyAnalyzerIntegrationTest : IntegrationTest() {
    @Test
    fun `ClassSearcher discovers analyzer with stock lifecycle and options`() {
        val analyzers = ClassSearcher.getInstances(Analyzer::class.java)
        val analyzer = analyzers.single { it.javaClass == GhidraBoyBankAnalyzer::class.java }
        assertEquals(GhidraBoyBankAnalyzer.NAME, analyzer.name)
        assertEquals(AnalysisPriority.LOW_PRIORITY.priority(), analyzer.priority.priority())
        assertTrue(analyzer.supportsOneTimeAnalysis())
        assertTrue(
            ClassSearcher
                .getClasses(Plugin::class.java)
                .any { it == GhidraBoyProgramPlugin::class.java },
        )
        val (sm83, sm83Consumer) = program("sm83", language)
        try {
            assertTrue(analyzer.canAnalyze(sm83))
        } finally {
            sm83.release(sm83Consumer)
        }

        val otherLanguage =
            SleighLanguageProvider
                .getSleighLanguageProvider()
                .languageDescriptions
                .first { it.languageID.toString() != "SM83:LE:16:default" }
                .let { SleighLanguageProvider.getSleighLanguageProvider().getLanguage(it.languageID) }
        val (other, otherConsumer) = program("other", otherLanguage)
        try {
            assertFalse(analyzer.canAnalyze(other))
        } finally {
            other.release(otherConsumer)
        }

        fixture(2).useProgram { p, start ->
            val options = p.getOptions("GhidraBoy analyzer test")
            analyzer.registerOptions(options, p)
            assertTrue(options.contains(GhidraBoyBankAnalyzer.STATE_LIMIT))
            assertEquals(GhidraBoyBankAnalyzer.DEFAULT_STATE_LIMIT, options.getInt(GhidraBoyBankAnalyzer.STATE_LIMIT, 0))
            assertTrue(options.contains(GhidraBoyBankAnalyzer.CREATE_FUNCTIONS))
            p.withTransaction { options.setBoolean(GhidraBoyBankAnalyzer.CREATE_FUNCTIONS, false) }
            analyzer.optionsChanged(options, p)

            val log = MessageLog()
            assertTrue(analyzer.added(p, AddressSet(start, start.add(2)), TaskMonitor.DUMMY, log))
            assertEquals("", log.toString())
            val saved = AnalysisResult.read(p.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", null))
            assertEquals(listOf(start.toString()), saved.starts())
            assertEquals(
                2,
                saved
                    .entryPremises()
                    .single()
                    .knowledge()
                    .low(),
            )
            assertNull(
                saved
                    .entryPremises()
                    .single()
                    .knowledge()
                    .enabled(),
            )
            assertNull(
                saved
                    .entryPremises()
                    .single()
                    .knowledge()
                    .ram(),
            )
            assertNull(
                saved
                    .entryPremises()
                    .single()
                    .knowledge()
                    .vbk(),
            )
            assertNull(
                saved
                    .entryPremises()
                    .single()
                    .knowledge()
                    .svbk(),
            )
        }
    }

    @Test
    fun `physical MBC5 entry derives only selector bits and rejects alleged conflicts`() {
        fixture(12).useProgram { p, start ->
            val result =
                BankAnalysis.preview(
                    p,
                    start,
                    null,
                    AnalysisResult.Configuration.DEFAULT,
                    TaskMonitor.DUMMY,
                )
            val premise = result.entryPremises().single()
            assertEquals(12, premise.physical().bank())
            assertEquals(12, premise.knowledge().low())
            assertNull(premise.knowledge().high())
            assertNull(premise.knowledge().enabled())
            assertNull(premise.knowledge().ram())
            assertNull(premise.knowledge().vbk())
            assertNull(premise.knowledge().svbk())
            assertTrue(result.findings().any { it.access() == "jump" && it.targets() == listOf("rom12::4010") })

            assertThrows(IllegalArgumentException::class.java) {
                BankAnalysis.preview(
                    p,
                    start,
                    MapperState.reset(),
                    AnalysisResult.Configuration.DEFAULT,
                    TaskMonitor.DUMMY,
                )
            }
        }
    }

    @Test
    fun `function discovery consumes proved session roots without circular reseeding`() {
        fixture(3).useProgram { program, start ->
            val analyzer = GhidraBoyBankAnalyzer()
            val requested = AddressSet(start, start.add(2))
            assertTrue(analyzer.added(program, requested, TaskMonitor.DUMMY, MessageLog()))
            assertNotNull(program.functionManager.getFunctionAt(start))
            assertTrue(AnalysisOwnership.functionOwned(program, start))
            assertTrue(GhidraBoyBankAnalyzer.roots(program, requested, TaskMonitor.DUMMY).isEmpty())
        }
    }

    @Test
    fun `changing exact loop states widen to explicit unknown and converge`() {
        val data = ByteArray(0x10000)
        data[0x147] = 0x19
        data[0x148] = 1
        byteArrayOf(0x3e, 0, 0x3c, 0x18, 0xfd.toByte()).copyInto(data, 0x4000)
        val (program, consumer) = program("widening", language)
        try {
            ByteArrayProvider(data).use {
                CartridgeLayout.load(
                    program,
                    it,
                    "CARTRIDGE",
                    "AUTO",
                    GameBoyKind.GB,
                    true,
                    true,
                    TaskMonitor.DUMMY,
                    MessageLog(),
                )
            }
            val start = ProgramMapping.fileToStatic(program, 0x4000).single()
            program.withTransaction {
                Disassembler
                    .getDisassembler(program, TaskMonitor.DUMMY, null)
                    .disassemble(start, AddressSet(start, start.add(4)))
            }
            val result =
                BankAnalysis.preview(
                    program,
                    start,
                    null,
                    AnalysisResult.Configuration(1000, false),
                    TaskMonitor.DUMMY,
                )
            assertTrue(result.complete())
            assertTrue(result.exploredStates() < 1000)
            assertTrue(result.findings().any { it.reason().contains("State diversity widened to unknown") })
        } finally {
            program.release(consumer)
        }
    }

    @Test
    fun `broad auto-analysis session unions later scheduler batches while one-shot stays local`() {
        fixture(2).useProgram { program, first ->
            val second = ProgramMapping.fileToStatic(program, 3L * 0x4000).single()
            program.withTransaction {
                Disassembler
                    .getDisassembler(program, TaskMonitor.DUMMY, null)
                    .disassemble(second, AddressSet(second, second))
            }
            val analyzer = GhidraBoyBankAnalyzer()
            val options = program.getOptions("GhidraBoy session test")
            analyzer.registerOptions(options, program)
            program.withTransaction { options.setBoolean(GhidraBoyBankAnalyzer.CREATE_FUNCTIONS, false) }
            analyzer.optionsChanged(options, program)

            val broad = AddressSet()
            program.memory.blocks.forEach { broad.add(it.start, it.end) }
            assertTrue(broad.numAddresses > 0x10000)
            assertTrue(analyzer.added(program, broad, TaskMonitor.DUMMY, MessageLog()))
            assertTrue(analyzer.added(program, AddressSet(second, second), TaskMonitor.DUMMY, MessageLog()))
            val accumulated =
                AnalysisResult.read(program.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", null))
            assertTrue(accumulated.starts().contains(first.toString()))
            assertTrue(accumulated.starts().contains(second.toString()))

            analyzer.analysisEnded(program)
            assertTrue(analyzer.added(program, AddressSet(second, second), TaskMonitor.DUMMY, MessageLog()))
            val local = AnalysisResult.read(program.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", null))
            assertEquals(listOf(second.toString()), local.starts())
        }
    }

    @Test
    fun `unprepared SM83 Program reports prerequisite without InvocationTargetException`() {
        val (program, consumer) = program("legacy", language)
        try {
            val analyzer = GhidraBoyBankAnalyzer()
            val log = MessageLog()
            assertTrue(analyzer.added(program, AddressSet(), TaskMonitor.DUMMY, log))
            assertTrue(log.toString().contains("legacy preparation is required"))
            assertFalse(log.toString().contains("InvocationTargetException"))
        } finally {
            program.release(consumer)
        }
    }

    private fun fixture(bank: Int): Fixture {
        val banks = 16
        val data = ByteArray(banks * 0x4000)
        data[0x147] = 0x19
        data[0x148] = 3
        byteArrayOf(0xc3.toByte(), 0x10, 0x40).copyInto(data, bank * 0x4000)
        val (program, consumer) = program("analyzer", language)
        ByteArrayProvider(data).use {
            CartridgeLayout.load(
                program,
                it,
                "CARTRIDGE",
                "AUTO",
                GameBoyKind.GB,
                true,
                true,
                TaskMonitor.DUMMY,
                MessageLog(),
            )
        }
        val start = ProgramMapping.fileToStatic(program, bank * 0x4000L).single()
        program.withTransaction {
            Disassembler
                .getDisassembler(program, TaskMonitor.DUMMY, null)
                .disassemble(start, AddressSet(start, start.add(2)))
        }
        assertNotNull(program.listing.getInstructionAt(start))
        return Fixture(program, consumer, start)
    }

    private fun program(
        name: String,
        selectedLanguage: ghidra.program.model.lang.Language,
    ): Pair<ProgramDB, Any> {
        val consumer = Any()
        return ProgramDB(name, selectedLanguage, selectedLanguage.defaultCompilerSpec, consumer) to consumer
    }

    private class Fixture(
        private val program: ProgramDB,
        private val consumer: Any,
        private val start: ghidra.program.model.address.Address,
    ) {
        fun <T> useProgram(block: (ProgramDB, ghidra.program.model.address.Address) -> T): T =
            try {
                block(program, start)
            } finally {
                program.release(consumer)
            }
    }
}
