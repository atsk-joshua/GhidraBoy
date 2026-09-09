package fi.gekkio.ghidraboy

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary
import ghidra.pcode.exec.BytesPcodeArithmetic
import ghidra.pcode.exec.BytesPcodeExecutorState
import ghidra.pcode.exec.PcodeExecutor
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason
import ghidra.pcode.exec.PcodeProgram
import ghidra.pcode.exec.PcodeStateCallbacks
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.util.HexFormat

/** EX-02-03: genuinely missing entry knowledge, with independent successful ordinary controls. */
class OrdinaryUnknownAccessTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY
    private val unknownSelector = "ea00202100607eea20c0c9"
    private val unknownPointer = "3e02ea00207eea21c0c9"
    private val knownSelectorControl = "3e02ea00202100607eea20c0c9"
    private val knownPointerControl = "3e02ea00202100607eea21c0c9"

    private fun fixture(
        code: String,
        control: String = knownSelectorControl,
        action: (ProgramDB, Function, Function) -> Unit,
    ) {
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x19
        bytes[0x148] = 1
        bytes[0x2000] = 0x6e
        bytes[0x6000] = 0x31
        bytes[0xa000] = 0xa7.toByte()
        bytes[0xe000] = 0xd3.toByte()
        val kernels = listOf(0x150L to code, 0x250L to control)
        for ((entry, hex) in kernels) HexFormat.of().parseHex(hex).copyInto(bytes, entry.toInt())
        val owner = Any()
        val p = ProgramDB("ordinary-unknown-access", language, language.defaultCompilerSpec, owner)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog())
            }
            p.withTransaction {
                for ((entry, hex) in kernels) {
                    val start = address(entry)
                    val body = AddressSet(start, start.add(hex.length / 2L - 1))
                    Disassembler.getDisassembler(p, monitor, null).disassemble(start, body)
                    p.functionManager.createFunction("kernel_${entry.toString(16)}", start, body, SourceType.USER_DEFINED)
                }
            }
            action(p, p.functionManager.getFunctionAt(address(0x150)), p.functionManager.getFunctionAt(address(0x250)))
        } finally {
            p.release(owner)
        }
    }

    private fun analyze(
        p: ProgramDB,
        f: Function,
    ) = BankAnalysis.preview(p, f.entryPoint, null, AnalysisResult.Configuration.DEFAULT, monitor)

    private fun fetch(
        p: ProgramDB,
        f: Function,
    ) = BankAnalysis.previewFetch(p, f.entryPoint, null, AnalysisResult.Configuration.DEFAULT, monitor)

    private fun entryUnknown(
        p: ProgramDB,
        f: Function,
    ) {
        assertEquals("absent", SoftwareCallRegistry.configurationIdentity(p))
        for (name in listOf("A", "F", "BC", "DE", "HL", "SP")) {
            assertNull(p.programContext.getValue(p.getRegister(name), f.entryPoint, false), name)
        }
    }

    private fun refuseWithoutMutation(
        p: ProgramDB,
        f: Function,
        guard: String = "Missing exact immutable read proof",
    ) {
        val revision = p.modificationNumber
        val fingerprint = ProgramFingerprint.capture(p, monitor)
        val blocks = p.memory.blocks.map { it.start.toString() to it.size }
        val body = AddressSet(f.body)
        val functions = p.functionManager.functionCount
        val options = p.optionsNames.toSet()
        val failure = assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.preview(p, f, monitor) }
        assertTrue(failure.message.orEmpty().startsWith(guard), failure.message)
        assertEquals(revision, p.modificationNumber)
        assertEquals(fingerprint, ProgramFingerprint.capture(p, monitor))
        assertEquals(blocks, p.memory.blocks.map { it.start.toString() to it.size })
        assertEquals(body, f.body)
        assertEquals(functions, p.functionManager.functionCount)
        assertEquals(options, p.optionsNames.toSet())
        assertFalse(OrdinaryEntryAccess.registered(p, f.entryPoint))
        assertFalse(p.memory.blocks.any { it.name.startsWith(OrdinaryEntryAccess.PREFIX) })
    }

    private fun unresolvedRead(
        result: AnalysisResult,
        cpu: Long,
        reason: String,
    ): BankAnalysis.Finding {
        assertTrue(result.complete())
        assertEquals(0, result.pendingStates())
        val read = result.findings().single { it.source() == address(cpu).toString() && it.access() == "read" }
        assertEquals(AnalysisResult.Confidence.UNKNOWN, read.confidence())
        assertEquals(emptyList<String>(), read.targets(), "No physical singleton or candidate may be fabricated")
        assertEquals(reason, read.reason())
        return read
    }

    private fun bankTwoDisplay(p: ProgramDB) {
        val source = ProgramMapping.fileToStatic(p, 0xa000).single()
        val name = "gb_call_view_display_bank2"
        val preview =
            SoftwareCallExecutionView.preview(
                p,
                name,
                listOf(SoftwareCallExecutionView.Segment(0x6000, 1, source.toString())),
                monitor,
            )
        p.withTransaction {
            val created = SoftwareCallExecutionView.create(p, preview, monitor)
            // The visible data alias is a display selection, not an executable source premise.
            p.memory.getBlock(created.body().minAddress).isExecute = false
        }
        val displayed = p.addressFactory.getAddressSpace(name).getAddress(0x6000)
        assertEquals(MapperState.Physical("ROM", 2, 0x2000), ProgramMapping.staticToPhysical(p, displayed).single())
        assertEquals(0xa7, p.memory.getByte(displayed).toInt() and 255)
        assertEquals("absent", SoftwareCallRegistry.configurationIdentity(p))
    }

    @Test
    fun `genuinely unknown selector remains unknown and emits no physical target`() =
        fixture(unknownSelector) { p, f, _ ->
            entryUnknown(p, f)
            assertEquals(
                "ld",
                p.listing
                    .getInstructionAt(f.entryPoint)
                    .mnemonicString
                    .lowercase(),
            )
            val diagnostic = fetch(p, f)
            val write =
                diagnostic
                    .steps()
                    .first()
                    .writes()
                    .single()
            assertEquals(0x2000, write.cpu())
            assertTrue(write.mapperControl())
            assertNull(write.value())
            assertEquals(MapperKnowledge.unknown(), write.before())
            assertEquals(MapperKnowledge.unknown(), write.after())
            val resolution = write.after().translate(ProgramMapping.cartridge(p), 0x6000, false)
            assertNull(resolution.physical(), "The internal representative bank is not a mapper fact")
            assertEquals("unknown", resolution.status())
            assertEquals("Required mapper register is unknown", resolution.reason())
            val read = unresolvedRead(analyze(p, f), 0x156, "unknown: Required mapper register is unknown")
            assertEquals(read, unresolvedRead(diagnostic.result(), 0x156, read.reason()))
            assertTrue(diagnostic.frontier().contains("0156 read: ${read.reason()}"))
            refuseWithoutMutation(p, f)
        }

    @Test
    fun `bank two display cannot supply missing selector or previous invocation proof`() =
        fixture(unknownSelector) { p, f, control ->
            val before = analyze(p, f).findings()
            bankTwoDisplay(p)
            entryUnknown(p, f)
            val known = OrdinaryEntryAccess.preview(p, control, monitor)
            assertEquals(
                0xa7,
                known
                    .replacements()
                    .single()
                    .value()
                    .toInt(),
            )
            assertEquals(before, analyze(p, f).findings())
            unresolvedRead(fetch(p, f).result(), 0x156, "unknown: Required mapper register is unknown")
            refuseWithoutMutation(p, f)
        }

    @Test
    fun `known bank with genuinely unknown HL stops at pointer boundary`() =
        fixture(unknownPointer, knownPointerControl) { p, f, _ ->
            entryUnknown(p, f)
            val diagnostic = fetch(p, f)
            val write =
                diagnostic
                    .steps()
                    .single { it.cpu() == 0x152 }
                    .writes()
                    .single()
            assertEquals(2, write.value())
            assertNull(write.before().low())
            assertEquals(2, write.after().low())
            assertEquals(
                MapperState.Physical("ROM", 2, 0x2000),
                write.after().translate(ProgramMapping.cartridge(p), 0x6000, false).physical(),
            )
            val read = unresolvedRead(analyze(p, f), 0x155, "Unknown load address")
            assertEquals(read, unresolvedRead(diagnostic.result(), 0x155, "Unknown load address"))
            assertTrue(diagnostic.frontier().contains("0155 read: Unknown load address"))
            refuseWithoutMutation(p, f)
            bankTwoDisplay(p)
            entryUnknown(p, f)
            unresolvedRead(analyze(p, f), 0x155, "Unknown load address")
            refuseWithoutMutation(p, f)
        }

    /** Executes provider output only; it contains no fixture-specific physical-value substitutions. */
    class WriteBus(
        private val p: ProgramDB,
        private val state: BytesPcodeExecutorState,
        private val arithmetic: BytesPcodeArithmetic,
    ) : AnnotatedPcodeUseropLibrary<ByteArray>() {
        val writes = mutableListOf<Pair<Long, Long>>()

        @PcodeUserop
        fun gb_direct_write8(
            cpu: Long,
            value: Long,
        ) {
            writes.add(cpu to value)
            if (cpu >= 0xc000) {
                state.setVar(p.addressFactory.defaultAddressSpace.getAddress(cpu), 1, true, arithmetic.fromConst(value, 1))
            }
        }
    }

    private fun verifyControl(
        p: ProgramDB,
        f: Function,
        destination: Long,
    ) {
        entryUnknown(p, f)
        val proof = OrdinaryEntryAccess.preview(p, f, monitor)
        val replacement = proof.replacements().single()
        assertEquals(0xa7, replacement.value().toInt())
        assertEquals(MapperState.Physical("ROM", 2, 0x2000), replacement.sources().single().physical())
        val alias = OrdinaryEntryAccess.install(p, proof, monitor)
        val emitted = OrdinaryEntryAccess.emit(p, alias, 0x200000, monitor)
        val arithmetic = BytesPcodeArithmetic.forLanguage(language)
        val state = BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE)
        // These are concrete execution witnesses supplied after proof creation, never analysis premises.
        state.setVar(p.getRegister("SP"), arithmetic.fromConst(0xcffc, 2))
        state.setVar(address(0xcffc), 1, true, arithmetic.fromConst(0x90, 1))
        state.setVar(address(0xcffd), 1, true, arithmetic.fromConst(1, 1))
        val executor = PcodeExecutor(language as SleighLanguage, arithmetic, state, Reason.EXECUTE_READ)
        val source = PcodeProgram.fromInstruction(p.listing.getInstructionAt(f.entryPoint), false)
        val bus = WriteBus(p, state, arithmetic)
        executor.execute(PcodeProgram(source, emitted.toList()), bus)
        assertEquals(listOf(0x2000L to 2L, destination to 0xa7L), bus.writes)
        assertEquals(0xa7, state.getVar(address(destination), 1, true, Reason.INSPECT).single().toInt() and 255)
    }

    @Test
    fun `known selector and known pointer controls use production proof and emit A7`() {
        fixture(knownSelectorControl) { p, f, _ -> verifyControl(p, f, 0xc020) }
        fixture(knownPointerControl, knownPointerControl) { p, f, _ ->
            bankTwoDisplay(p)
            verifyControl(p, f, 0xc021)
        }
    }

    @Test
    fun `stale ProgramContext HL cannot fill a genuine unknown pointer`() =
        fixture(unknownPointer, knownPointerControl) { p, f, _ ->
            entryUnknown(p, f)
            p.withTransaction {
                p.programContext.setValue(p.getRegister("HL"), f.entryPoint, f.body.maxAddress, BigInteger.valueOf(0x6000))
            }
            assertEquals(BigInteger.valueOf(0x6000), p.programContext.getValue(p.getRegister("HL"), f.entryPoint, false))
            unresolvedRead(analyze(p, f), 0x155, "Unknown load address")
            refuseWithoutMutation(p, f, "Canonical entry register context must remain unknown: HL")
        }

    @Test
    fun `known control cannot be relabelled as either unknown function`() {
        for (code in listOf(unknownSelector, unknownPointer)) {
            fixture(code) { p, f, control ->
                val proof = OrdinaryEntryAccess.preview(p, control, monitor)
                val record = ProgramMapping.JSON.toJsonTree(proof).asJsonObject
                record.addProperty("entry", f.entryPoint.toString())
                record.addProperty("end", f.body.maxAddress.toString())
                val relabelled = ProgramMapping.JSON.fromJson(record, OrdinaryEntryAccess.Proof::class.java)
                val revision = p.modificationNumber
                val failure =
                    assertThrows(IllegalArgumentException::class.java) {
                        OrdinaryEntryAccess.install(p, relabelled, monitor)
                    }
                assertTrue(failure.message.orEmpty().startsWith("Missing exact immutable read proof"), failure.message)
                assertEquals(revision, p.modificationNumber)
                refuseWithoutMutation(p, f)
            }
        }
    }

    @Test
    fun `proof cannot cross Program ownership or survive changed dependencies`() =
        fixture(unknownSelector) { first, _, control ->
            val proof = OrdinaryEntryAccess.preview(first, control, monitor)
            fixture(unknownSelector) { second, unknown, _ ->
                val revision = second.modificationNumber
                val failure =
                    assertThrows(IllegalArgumentException::class.java) {
                        OrdinaryEntryAccess.install(second, proof, monitor)
                    }
                assertEquals("Stale or foreign ordinary-entry proof", failure.message)
                assertEquals(revision, second.modificationNumber)
                refuseWithoutMutation(second, unknown)
            }
            first.withTransaction { first.memory.setByte(address(0x300), 0x42) }
            val revision = first.modificationNumber
            val failure =
                assertThrows(IllegalArgumentException::class.java) {
                    OrdinaryEntryAccess.install(first, proof, monitor)
                }
            assertEquals("Stale or foreign ordinary-entry proof", failure.message)
            assertEquals(revision, first.modificationNumber)
            assertFalse(first.memory.blocks.any { it.name.startsWith(OrdinaryEntryAccess.PREFIX) })
        }
}
