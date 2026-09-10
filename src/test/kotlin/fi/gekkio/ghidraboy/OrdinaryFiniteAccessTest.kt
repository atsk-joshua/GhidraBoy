package fi.gekkio.ghidraboy

import com.google.gson.JsonParser
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
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Function
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.util.HexFormat

/** EX-02-04: supplied immutable fixtures and independent raw/emitted execution of one static payload. */
class OrdinaryFiniteAccessTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY
    private val hashes =
        mapOf(
            "F12" to "6af7ff922913418033058056b9475099e56ca564d23e9434ed8fcde797c983c5",
            "F12_KNOWN1" to "b3ec4e693f6eabd2ec8caac22336caf496ee5cb8d9dd676af08a61c53c10d47b",
            "F12_SAME" to "b4cde46efae2ded6e1afa6394d9f24e9fd25414a6b95bc1973a28c4282837565",
            "F12_INDEPENDENT" to "b39f4ecf72fa9bcb19749b8db682cf1434d6ea6394a940e6e6f6b0c36d23125b",
            "F12_D4" to "e29b08db7e3a6ed8c9ea8df228887d5de6006e28710f9e72e30ee135d35e53a5",
            "F12_WIDE" to "44b7a11c813075fe32ba757e5dceac9e738396b69e5056c008ce027b6db6b306",
            "F12_UNUSED" to "9c2589c5a93bf3c234325a0e8419029a41379cb648b6e0d6dd0842686682eb46",
            "U_SEL" to "3c9caa92af32bfb1e10471b48781d48368ac260b043d97e03e37f726d36d6ce8",
            "U_PAIR" to "e144152a55822f77a4c136f5b18165a3442926177ec2ea5d7438526b381ebb00",
        )

    private fun fixture(
        name: String = "F12",
        action: (ProgramDB, Function) -> Unit,
    ) {
        val bytes =
            requireNotNull(javaClass.getResourceAsStream("/ordinary/$name.gb")) { "Missing ordinary fixture: $name.gb" }
                .use { it.readBytes() }
        assertEquals(hashes.getValue(name), HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)))
        val size = bytes.drop(0x150).indexOf(0xc9.toByte()) + 1
        require(size in 1..64)
        val owner = Any()
        val p = ProgramDB("finite-$name", language, language.defaultCompilerSpec, owner)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog())
            }
            p.withTransaction {
                val body = AddressSet(address(0x150), address(0x150 + size.toLong() - 1))
                Disassembler.getDisassembler(p, monitor, null).disassemble(address(0x150), body)
                p.functionManager.createFunction("finite_kernel", address(0x150), body, SourceType.USER_DEFINED)
            }
            action(p, p.functionManager.getFunctionAt(address(0x150)))
        } finally {
            p.release(owner)
        }
    }

    /** Independent four-bank specimen bus. It never reads finite proof facts or calls their transfer functions. */
    class SpecimenBus(
        private val p: ProgramDB,
        private val state: BytesPcodeExecutorState,
        private val arithmetic: BytesPcodeArithmetic,
        private val markers: List<Int>,
    ) : AnnotatedPcodeUseropLibrary<ByteArray>() {
        val writes = mutableListOf<Pair<Long, Long>>()

        @PcodeUserop
        fun gb_direct_write8(
            cpu: Long,
            value: Long,
        ) {
            writes.add(cpu to value)
            val space = p.addressFactory.defaultAddressSpace
            if (cpu == 0x2000L) {
                // Independent fixture geometry: selector wraps over the four supplied physical banks.
                state.setVar(space.getAddress(0x6000), 1, true, arithmetic.fromConst(markers[(value and 3).toInt()].toLong(), 1))
            } else {
                require(cpu in 0xc030L..0xc032L)
                state.setVar(space.getAddress(cpu), 1, true, arithmetic.fromConst(value, 1))
            }
        }
    }

    private data class Execution(
        val outputs: List<Int>,
        val writes: List<Pair<Long, Long>>,
        val registers: Map<String, Int>,
    )

    private inner class Runner(
        private val p: ProgramDB,
        f: Function,
        emitted: Array<PcodeOp>,
    ) {
        private val arithmetic = BytesPcodeArithmetic.forLanguage(language)
        private val raw = p.listing.getInstructions(f.body, true).map { PcodeProgram.fromInstruction(it, false) }
        private val lowered = PcodeProgram(raw.first(), emitted.toList())
        private val markers =
            (0..3).map { bank ->
                ProgramMapping
                    .fileToStatic(p, bank * 0x4000L + 0x2000)
                    .map { p.memory.getByte(it).toInt() and 255 }
                    .distinct()
                    .single()
            }

        fun execute(
            b: Int,
            d: Int,
            injected: Boolean,
            stack: Int = 0xcffc,
        ): Execution {
            val state = BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE)
            val initial =
                mapOf(
                    "A" to 0x95,
                    "F" to 0xf0,
                    "BC" to ((b shl 8) or 0x53),
                    "DE" to ((d shl 8) or 0xa6),
                    "HL" to 0xbeef,
                    "SP" to stack,
                    "PC" to 0x150,
                )
            for ((name, value) in initial) {
                val register = language.getRegister(name)
                state.setVar(register, arithmetic.fromConst(value, register.minimumByteSize))
            }
            state.setVar(address(0x2000), 1, true, arithmetic.fromConst(markers[0].toLong(), 1))
            state.setVar(address(stack.toLong()), 1, true, arithmetic.fromConst(0x90, 1))
            state.setVar(address(stack + 1L), 1, true, arithmetic.fromConst(1, 1))
            val bus = SpecimenBus(p, state, arithmetic, markers)
            val executor = PcodeExecutor(language as SleighLanguage, arithmetic, state, Reason.EXECUTE_READ)
            if (injected) executor.execute(lowered, bus) else raw.forEach { executor.execute(it, bus) }

            fun value(bytes: ByteArray): Int = bytes.foldIndexed(0) { i, n, byte -> n or ((byte.toInt() and 255) shl (8 * i)) }

            return Execution(
                (0xc030L..0xc032L).map { value(state.getVar(address(it), 1, true, Reason.INSPECT)) },
                bus.writes.toList(),
                (initial.keys + listOf("AF", "B", "C", "D", "E", "H", "L")).associateWith {
                    value(state.getVar(language.getRegister(it), Reason.INSPECT))
                },
            )
        }
    }

    private fun emit(
        p: ProgramDB,
        alias: Address,
    ) = OrdinaryEntryAccess.emit(p, alias, 0x200000, monitor)

    private fun assertWitness(
        runner: Runner,
        b: Int,
        d: Int,
        firstSelector: Int = (b and 1) + 1,
        secondSelector: Int = 2,
        markers: List<Int> = listOf(0x6e, 0x31, 0xa7, 0xd3),
        stack: Int = 0xcffc,
    ): List<Int> {
        val original = runner.execute(b, d, false, stack)
        val lowered = runner.execute(b, d, true, stack)
        val expected = listOf(markers[firstSelector and 3], markers[secondSelector and 3], 0x6e)
        assertEquals(expected, original.outputs, "raw B=$b D=$d")
        assertEquals(original, lowered, "emitted parity B=$b D=$d")
        assertEquals(
            listOf(
                0x2000L to firstSelector.toLong(),
                0xc030L to expected[0].toLong(),
                0x2000L to secondSelector.toLong(),
                0xc031L to expected[1].toLong(),
                0xc032L to 0x6eL,
            ),
            lowered.writes,
        )
        assertEquals(0x190, lowered.registers["PC"])
        assertEquals(stack + 2, lowered.registers["SP"])
        assertEquals(0, lowered.registers["F"])
        assertEquals((b shl 8) or 0x53, lowered.registers["BC"])
        assertEquals((d shl 8) or 0xa6, lowered.registers["DE"])
        assertEquals(0x6000, lowered.registers["HL"])
        assertEquals(0x6e00, lowered.registers["AF"])
        return lowered.outputs
    }

    @Test
    fun `one code-derived F12 payload covers every unknown B and preserves effects`() =
        fixture { p, f ->
            for (name in listOf("A", "F", "BC", "DE", "HL", "SP")) {
                assertNull(p.programContext.getValue(p.getRegister(name), f.entryPoint, false))
            }
            val revision = p.modificationNumber
            val proof = OrdinaryEntryAccess.preview(p, f, monitor)
            assertEquals(revision, p.modificationNumber)
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            val ops = emit(p, alias)
            assertEquals(2, ops.count { it.opcode == PcodeOp.LOAD }, "Only symbolic return-frame loads remain")
            assertEquals(1, ops.count { it.opcode == PcodeOp.RETURN })
            assertTrue(ops.none { it.opcode == PcodeOp.MULTIEQUAL })
            val fixedRevision = p.modificationNumber
            val runner = Runner(p, f, ops)
            val outputs = (0..255).map { assertWitness(runner, it, 0xa3) }.groupingBy { it }.eachCount()
            assertEquals(mapOf(listOf(0x31, 0xa7, 0x6e) to 128, listOf(0xa7, 0xa7, 0x6e) to 128), outputs)
            assertWitness(runner, 0, 0, stack = 0xc000)
            assertWitness(runner, 255, 255, stack = 0xcffd)
            assertEquals(fixedRevision, p.modificationNumber, "No per-input Program or proof specialization")
        }

    @Test
    fun `known mask and same-input selectors preserve their exact correlation`() {
        for (name in listOf("F12_KNOWN1", "F12_SAME", "F12_D4", "F12_UNUSED")) {
            fixture(name) { p, f ->
                val alias = OrdinaryEntryAccess.install(p, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
                val runner = Runner(p, f, emit(p, alias))
                for (b in 0..255) {
                    val first = if (name == "F12_KNOWN1") 1 else (b and 1) + 1
                    val second = if (name == "F12_SAME") first else 2
                    val bankTwo = if (name == "F12_D4") 0xd4 else 0xa7
                    assertWitness(runner, b, 255 - b, first, second, listOf(0x6e, 0x31, bankTwo, 0xd3))
                }
            }
        }
    }

    @Test
    fun `independent inputs retain all four pairs for 65536 witnesses on one payload`() =
        fixture("F12_INDEPENDENT") { p, f ->
            val alias = OrdinaryEntryAccess.install(p, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
            val runner = Runner(p, f, emit(p, alias))
            val revision = p.modificationNumber
            val counts = mutableMapOf<List<Int>, Int>()
            for (b in 0..255) {
                for (d in 0..255) {
                    val output = assertWitness(runner, b, d, secondSelector = (d and 1) + 1)
                    counts[output] = counts.getOrDefault(output, 0) + 1
                }
            }
            assertEquals(
                mapOf(
                    listOf(0x31, 0x31, 0x6e) to 16384,
                    listOf(0x31, 0xa7, 0x6e) to 16384,
                    listOf(0xa7, 0x31, 0x6e) to 16384,
                    listOf(0xa7, 0xa7, 0x6e) to 16384,
                ),
                counts,
            )
            assertEquals(revision, p.modificationNumber)
        }

    @Test
    fun `live consumed and unused bytes invalidate old registration before valid refresh`() {
        for ((offset, value) in listOf(0xa000L to 0xd4, 0xa001L to 0x5a)) {
            fixture { p, f ->
                val oldProof = OrdinaryEntryAccess.preview(p, f, monitor)
                val alias = OrdinaryEntryAccess.install(p, oldProof, monitor)
                emit(p, alias)
                p.withTransaction { p.memory.setByte(ProgramMapping.fileToStatic(p, offset).single(), value.toByte()) }
                assertThrows(IllegalArgumentException::class.java) { emit(p, alias) }
                assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.refresh(p, alias, oldProof, monitor) }
                OrdinaryEntryAccess.refresh(p, alias, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
                val runner = Runner(p, f, emit(p, alias))
                val bankTwo = if (offset == 0xa000L) 0xd4 else 0xa7
                for (b in 0..255) assertWitness(runner, b, 0, markers = listOf(0x6e, 0x31, bankTwo, 0xd3))
            }
        }
    }

    @Test
    fun `live wider producer rejects old proof and freshly derives supported F12_WIDE domain`() =
        fixture { p, f ->
            val oldProof = OrdinaryEntryAccess.preview(p, f, monitor)
            val alias = OrdinaryEntryAccess.install(p, oldProof, monitor)
            p.withTransaction {
                p.listing.clearCodeUnits(address(0x151), address(0x152), false)
                p.listing.clearCodeUnits(alias.add(1), alias.add(2), false)
                p.memory.setByte(address(0x152), 3)
                Disassembler.getDisassembler(p, monitor, null).disassemble(address(0x151), f.body)
            }
            assertThrows(IllegalArgumentException::class.java) { emit(p, alias) }
            assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.refresh(p, alias, oldProof, monitor) }
            val refreshed = OrdinaryEntryAccess.preview(p, f, monitor)
            val read = requireNotNull(refreshed.finite()).reads().first()
            assertEquals(listOf(1L, 2L, 3L, 4L), read.choice().values())
            // F12_WIDE retains four physical banks: raw selector 4 wraps to bank 0.
            val selectorSources = mapOf(1L to (1 to 0x31), 2L to (2 to 0xa7), 3L to (3 to 0xd3), 4L to (0 to 0x6e))
            assertEquals(selectorSources.keys.toList(), read.alternatives().map { it.key() })
            for (alternative in read.alternatives()) {
                val (bank, value) = selectorSources.getValue(alternative.key())
                val source = alternative.sources().single()
                assertEquals(MapperState.Physical("ROM", bank, 0x2000), source.physical())
                assertEquals(0, source.byteIndex())
                assertEquals(value, source.value())
                assertEquals(value.toLong(), alternative.value())
            }
            OrdinaryEntryAccess.refresh(p, alias, refreshed, monitor)
            val runner = Runner(p, f, emit(p, alias))
            val counts = mutableMapOf<Pair<Int, Int>, Int>()
            for (b in 0..255) {
                val selector = (b and 3) + 1
                val output = assertWitness(runner, b, 0, firstSelector = selector)
                val pair = selector to output.first()
                counts[pair] = counts.getOrDefault(pair, 0) + 1
            }
            assertEquals(mapOf((1 to 0x31) to 64, (2 to 0xa7) to 64, (3 to 0xd3) to 64, (4 to 0x6e) to 64), counts)
        }

    @Test
    fun `finite proof rejects foreign ownership relabelled instructions and same-view substitution`() =
        fixture { p, f ->
            val proof = OrdinaryEntryAccess.preview(p, f, monitor)
            fixture { other, _ ->
                assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.install(other, proof, monitor) }
            }
            val relabelled = ProgramMapping.JSON.toJsonTree(proof).asJsonObject
            relabelled.addProperty("entry", "0151")
            assertThrows(IllegalArgumentException::class.java) {
                OrdinaryEntryAccess.install(p, ProgramMapping.JSON.fromJson(relabelled, OrdinaryEntryAccess.Proof::class.java), monitor)
            }
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            val options = p.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS)
            val original = options.getString(alias.toString(), "")
            val tampered = JsonParser.parseString(original).asJsonObject
            tampered.addProperty("alias", f.entryPoint.toString())
            p.withTransaction { options.setString(alias.toString(), tampered.toString()) }
            assertThrows(IllegalArgumentException::class.java) { emit(p, alias) }
            p.withTransaction { options.setString(alias.toString(), original) }
            assertWitness(Runner(p, f, emit(p, alias)), 1, 0)
            for (field in listOf("alternative-value", "selector-values", "selector-expression", "old-version")) {
                val changed = JsonParser.parseString(original).asJsonObject
                val serializedProof = changed.getAsJsonObject("proof")
                val finite = serializedProof.getAsJsonObject("finite")
                when (field) {
                    "alternative-value" ->
                        finite
                            .getAsJsonArray("reads")[0]
                            .asJsonObject
                            .getAsJsonArray("alternatives")[0]
                            .asJsonObject
                            .addProperty("value", 0x99)
                    "selector-values" ->
                        finite
                            .getAsJsonArray("choices")[0]
                            .asJsonObject
                            .add("values", ProgramMapping.JSON.toJsonTree(listOf(1)))
                    "selector-expression" ->
                        finite
                            .getAsJsonArray("choices")[0]
                            .asJsonObject
                            .addProperty("expression", "unproved entry-bank constant")
                    "old-version" -> changed.addProperty("version", "ordinary-entry-access-experiment-2")
                }
                p.withTransaction { options.setString(alias.toString(), changed.toString()) }
                assertThrows(IllegalArgumentException::class.java, { emit(p, alias) }, field)
                p.withTransaction { options.setString(alias.toString(), original) }
                assertWitness(Runner(p, f, emit(p, alias)), 0, 0)
                assertWitness(Runner(p, f, emit(p, alias)), 1, 0)
            }
        }

    @Test
    fun `original unrestricted selector specimens remain explicit open capability refusals`() {
        for (name in listOf("U_SEL", "U_PAIR")) {
            fixture(name) { p, f ->
                val revision = p.modificationNumber
                val failure = assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.preview(p, f, monitor) }
                assertFalse(failure.message.isNullOrBlank())
                assertEquals(revision, p.modificationNumber)
                assertFalse(OrdinaryEntryAccess.registered(p, f.entryPoint))
            }
        }
    }
}
