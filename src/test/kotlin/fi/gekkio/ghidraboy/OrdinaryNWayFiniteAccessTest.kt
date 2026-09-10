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
import ghidra.program.model.pcode.Varnode
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

/** W2e: an eight-physical-bank specimen and independently executed complete selector relation. */
class OrdinaryNWayFiniteAccessTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY
    private val markers = listOf(0, 0x31, 0xa7, 0xd3, 0x5c, 0, 0, 0)
    private val code = HexFormat.of().parseHex("78e6033cea31c0ea00202100607eea30c0c9")

    private fun fixture(
        instructions: ByteArray = code,
        action: (ProgramDB, Function) -> Unit,
    ) {
        val bytes = requireNotNull(javaClass.getResourceAsStream("/ordinary/F1234.gb")).use { it.readBytes() }
        assertEquals(
            "047326108b357c6216e408258e56433ba8a5a18bc20fb046437dc72bada4d40b",
            HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)),
        )
        assertEquals(8 * 0x4000, bytes.size)
        instructions.copyInto(bytes, 0x150)
        val owner = Any()
        val p = ProgramDB("finite-F1234", language, language.defaultCompilerSpec, owner)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog())
            }
            p.withTransaction {
                val body = AddressSet(address(0x150), address(0x150 + instructions.size.toLong() - 1))
                Disassembler.getDisassembler(p, monitor, null).disassemble(address(0x150), body)
                p.functionManager.createFunction("four_way_kernel", address(0x150), body, SourceType.USER_DEFINED)
            }
            action(p, p.functionManager.getFunctionAt(address(0x150)))
        } finally {
            p.release(owner)
        }
    }

    /** Fixture-only eight-bank bus, independent of MapperKnowledge, proof facts, and lowering. */
    class SpecimenBus(
        private val p: ProgramDB,
        private val state: BytesPcodeExecutorState,
        private val arithmetic: BytesPcodeArithmetic,
        private val physicalMarkers: List<Int>,
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
                state.setVar(space.getAddress(0x6000), 1, true, arithmetic.fromConst(physicalMarkers[(value and 7).toInt()].toLong(), 1))
            } else {
                require(cpu in 0xc030L..0xc031L)
                state.setVar(space.getAddress(cpu), 1, true, arithmetic.fromConst(value, 1))
            }
        }
    }

    private data class Execution(
        val selector: Int,
        val output: Int,
        val writes: List<Pair<Long, Long>>,
        val registers: Map<String, Int>,
    )

    private inner class Runner(
        private val p: ProgramDB,
        f: Function,
        emitted: Array<PcodeOp>,
        private val physicalMarkers: List<Int> = markers,
    ) {
        private val arithmetic = BytesPcodeArithmetic.forLanguage(language)
        private val raw = p.listing.getInstructions(f.body, true).map { PcodeProgram.fromInstruction(it, false) }
        private val lowered = PcodeProgram(raw.first(), emitted.toList())

        fun execute(
            b: Int,
            injected: Boolean,
        ): Execution {
            val state = BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE)
            val initial =
                mapOf(
                    "A" to 0x95,
                    "F" to 0xf0,
                    "BC" to ((b shl 8) or 0x53),
                    "DE" to 0x12a6,
                    "HL" to 0xbeef,
                    "SP" to 0xcffc,
                    "PC" to 0x150,
                )
            for ((name, value) in initial) {
                val register = language.getRegister(name)
                state.setVar(register, arithmetic.fromConst(value, register.minimumByteSize))
            }
            state.setVar(address(0x6000), 1, true, arithmetic.fromConst(0xee, 1))
            state.setVar(address(0xcffc), 1, true, arithmetic.fromConst(0x90, 1))
            state.setVar(address(0xcffd), 1, true, arithmetic.fromConst(1, 1))
            val bus = SpecimenBus(p, state, arithmetic, physicalMarkers)
            val executor = PcodeExecutor(language as SleighLanguage, arithmetic, state, Reason.EXECUTE_READ)
            if (injected) executor.execute(lowered, bus) else raw.forEach { executor.execute(it, bus) }

            fun value(bytes: ByteArray): Int = bytes.foldIndexed(0) { i, n, byte -> n or ((byte.toInt() and 255) shl (8 * i)) }

            return Execution(
                value(state.getVar(address(0xc031), 1, true, Reason.INSPECT)),
                value(state.getVar(address(0xc030), 1, true, Reason.INSPECT)),
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

    private fun relation(
        runner: Runner,
        expectedMarkers: List<Int> = markers,
    ): Map<Pair<Int, Int>, Int> {
        val counts = mutableMapOf<Pair<Int, Int>, Int>()
        for (b in 0..255) {
            val selector = (b and 3) + 1
            val expected = expectedMarkers[selector]
            val raw = runner.execute(b, false)
            val lowered = runner.execute(b, true)
            assertEquals(selector, raw.selector, "raw selector B=$b")
            assertEquals(expected, raw.output, "raw physical byte B=$b")
            assertEquals(raw, lowered, "all registers and ordered effects B=$b")
            assertEquals(listOf(0xc031L to selector.toLong(), 0x2000L to selector.toLong(), 0xc030L to expected.toLong()), lowered.writes)
            assertEquals(0x190, lowered.registers["PC"])
            assertEquals(0xcffe, lowered.registers["SP"])
            assertEquals(0, lowered.registers["F"])
            assertEquals((b shl 8) or 0x53, lowered.registers["BC"])
            assertEquals(0x12a6, lowered.registers["DE"])
            assertEquals(0x6000, lowered.registers["HL"])
            val pair = lowered.selector to lowered.output
            counts[pair] = counts.getOrDefault(pair, 0) + 1
        }
        assertRelation(counts, expectedMarkers)
        return counts
    }

    private fun assertRelation(
        actual: Map<Pair<Int, Int>, Int>,
        expectedMarkers: List<Int> = markers,
    ) = assertEquals((1..4).associate { (it to expectedMarkers[it]) to 64 }, actual)

    private fun assertSources(proof: OrdinaryEntryAccess.Proof) {
        val finite = requireNotNull(proof.finite())
        assertEquals(listOf(1L, 2L, 3L, 4L), finite.choices().single().values())
        val read = finite.reads().single()
        assertEquals(listOf(1L, 2L, 3L, 4L), read.alternatives().map { it.key() })
        for (alternative in read.alternatives()) {
            assertEquals(MapperState.Physical("ROM", alternative.key().toInt(), 0x2000), alternative.sources().single().physical())
            assertEquals(0, alternative.sources().single().byteIndex())
        }
    }

    @Test
    fun `one four-way payload covers every B with exact physical correlation and ordered effects`() =
        fixture { p, f ->
            for (name in listOf("A", "F", "BC", "DE", "HL", "SP")) {
                assertNull(p.programContext.getValue(p.getRegister(name), f.entryPoint, false))
            }
            val proof = OrdinaryEntryAccess.preview(p, f, monitor)
            assertSources(proof)
            assertEquals(
                listOf(0x31L, 0xa7L, 0xd3L, 0x5cL),
                proof
                    .finite()
                    .reads()
                    .single()
                    .alternatives()
                    .map { it.value() },
            )
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            val ops = emit(p, alias)
            assertEquals(2, ops.count { it.opcode == PcodeOp.LOAD }, "Only symbolic return-frame loads remain")
            val rawEqualities =
                p.listing.getInstructions(f.body, true).sumOf { instruction ->
                    instruction.getPcode(false).count {
                        it.opcode ==
                            PcodeOp.INT_EQUAL
                    }
                }
            assertEquals(
                rawEqualities + 3,
                ops.count { it.opcode == PcodeOp.INT_EQUAL },
                "One added equality for each non-default alternative",
            )
            val revision = p.modificationNumber
            relation(Runner(p, f, ops))
            assertEquals(revision, p.modificationNumber, "All 256 inputs share one unchanged Program and registration")
        }

    @Test
    fun `one consumed alternative stales then refresh changes only its rooted relation`() {
        for ((offset, changed) in listOf(0xe000L to true, 0xe001L to false)) {
            fixture { p, f ->
                val old = OrdinaryEntryAccess.preview(p, f, monitor)
                val alias = OrdinaryEntryAccess.install(p, old, monitor)
                relation(Runner(p, f, emit(p, alias)))
                p.withTransaction { p.memory.setByte(ProgramMapping.fileToStatic(p, offset).single(), 0xe4.toByte()) }
                assertThrows(IllegalArgumentException::class.java) { emit(p, alias) }
                assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.refresh(p, alias, old, monitor) }
                val refreshed = OrdinaryEntryAccess.preview(p, f, monitor)
                assertSources(refreshed)
                val expected = if (changed) markers.toMutableList().apply { this[3] = 0xe4 } else markers
                assertEquals(
                    (1..4).map { expected[it].toLong() },
                    refreshed
                        .finite()
                        .reads()
                        .single()
                        .alternatives()
                        .map { it.value() },
                )
                OrdinaryEntryAccess.refresh(p, alias, refreshed, monitor)
                relation(Runner(p, f, emit(p, alias), expected), expected)
            }
        }
    }

    @Test
    fun `unproduced missing conflicting swapped or truncated proof alternatives are refused`() =
        fixture { p, f ->
            val proof = OrdinaryEntryAccess.preview(p, f, monitor)
            fixture { other, _ ->
                assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.install(other, proof, monitor) }
            }
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            val options = p.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS)
            val original = options.getString(alias.toString(), "")
            for (kind in listOf("missing", "conflicting-duplicate", "swapped", "unproduced", "truncated")) {
                val registration = JsonParser.parseString(original).asJsonObject
                val finite = registration.getAsJsonObject("proof").getAsJsonObject("finite")
                val read = finite.getAsJsonArray("reads")[0].asJsonObject
                val alternatives = read.getAsJsonArray("alternatives")
                when (kind) {
                    "missing" -> alternatives.remove(2)
                    "conflicting-duplicate" -> alternatives[2].asJsonObject.addProperty("key", 2)
                    "swapped" -> {
                        alternatives[1].asJsonObject.addProperty("key", 3)
                        alternatives[2].asJsonObject.addProperty("key", 2)
                    }
                    "unproduced" -> {
                        val invented = alternatives[3].deepCopy().asJsonObject
                        invented.addProperty("key", 5)
                        alternatives.add(invented)
                        finite
                            .getAsJsonArray("choices")[0]
                            .asJsonObject
                            .getAsJsonArray("values")
                            .add(5)
                    }
                    "truncated" -> {
                        alternatives.remove(3)
                        alternatives.remove(2)
                        finite.getAsJsonArray("choices")[0].asJsonObject.add("values", ProgramMapping.JSON.toJsonTree(listOf(1, 2)))
                    }
                }
                p.withTransaction { options.setString(alias.toString(), registration.toString()) }
                assertThrows(IllegalArgumentException::class.java, { emit(p, alias) }, kind)
                p.withTransaction { options.setString(alias.toString(), original) }
            }
            relation(Runner(p, f, emit(p, alias)))
        }

    @Test
    fun `independent checker rejects constant Cartesian missing and reordered mapper effects`() =
        fixture { p, f ->
            val alias = OrdinaryEntryAccess.install(p, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
            val ops = emit(p, alias)
            val constant =
                ops
                    .map {
                        if (it.opcode == PcodeOp.INT_EQUAL && it.getInput(0).isUnique && it.getInput(1).isConstant &&
                            it.getInput(1).offset in 2L..4L
                        ) {
                            PcodeOp(
                                alias,
                                it.seqnum.time,
                                PcodeOp.COPY,
                                arrayOf(Varnode(p.addressFactory.constantSpace.getAddress(0), 1)),
                                it.output,
                            )
                        } else {
                            it
                        }
                    }.toTypedArray()
            assertThrows(AssertionError::class.java) { relation(Runner(p, f, constant)) }
            val mapper = ops.single { CartridgeBus.isDirectWrite(language, it) && it.getInput(1).offset == 0x2000L }
            val deleted = ops.filter { it !== mapper }.toTypedArray()
            assertThrows(AssertionError::class.java) { relation(Runner(p, f, deleted)) }
            val moved = deleted.toMutableList().apply { add(lastIndex, mapper) }.toTypedArray()
            assertThrows(AssertionError::class.java) { relation(Runner(p, f, moved)) }
            val legal = (1..4).associate { (it to markers[it]) to 64 }
            assertThrows(AssertionError::class.java) { assertRelation(legal.filterKeys { it.first != 3 }) }
            val cartesian = (1..4).flatMap { selector -> (1..4).map { bank -> (selector to markers[bank]) to 16 } }.toMap()
            assertThrows(AssertionError::class.java) { assertRelation(cartesian) }
            val swapped =
                (1..4).associate {
                    (
                        it to
                            markers[
                                if (it == 2) {
                                    3
                                } else if (it == 3) {
                                    2
                                } else {
                                    it
                                },
                            ]
                    ) to 64
                }
            assertThrows(AssertionError::class.java) { assertRelation(swapped) }
        }

    @Test
    fun `display selection cannot specialize the four-way incoming domain`() =
        fixture { p, f ->
            val source = ProgramMapping.fileToStatic(p, 0xa000).single()
            val display =
                SoftwareCallExecutionView.preview(
                    p,
                    "gb_call_view_display_bank2",
                    listOf(SoftwareCallExecutionView.Segment(0x6000, 1, source.toString())),
                    monitor,
                )
            p.withTransaction {
                val view = SoftwareCallExecutionView.create(p, display, monitor)
                p.memory.getBlock(view.body().minAddress).isExecute = false
            }
            val proof = OrdinaryEntryAccess.preview(p, f, monitor)
            assertSources(proof)
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            relation(Runner(p, f, emit(p, alias)))
        }

    @Test
    fun `resource budget admits 128 alternatives then refuses excess work without partial payload`() {
        // Ten reads cost 1 snapshot + 10 * 127 * 3 = 3811 added operations.
        // Eleven cost 4192, exceeding the documented 4096 finite-lowering allowance.
        val prefix = HexFormat.of().parseHex("78e67f3cea0020210060")
        for (reads in listOf(10, 11)) {
            fixture(prefix + ByteArray(reads) { 0x7e } + byteArrayOf(0xc9.toByte())) { p, f ->
                val revision = p.modificationNumber
                if (reads == 10) {
                    val proof = OrdinaryEntryAccess.preview(p, f, monitor)
                    assertEquals(
                        (1L..128L).toList(),
                        proof
                            .finite()
                            .choices()
                            .single()
                            .values(),
                    )
                    assertEquals(10, proof.finite().reads().size)
                    assertTrue(proof.finite().reads().all { it.alternatives().size == 128 })
                    val alias = OrdinaryEntryAccess.install(p, proof, monitor)
                    val rawEqualities =
                        p.listing.getInstructions(f.body, true).sumOf { instruction ->
                            instruction.getPcode(false).count {
                                it.opcode ==
                                    PcodeOp.INT_EQUAL
                            }
                        }
                    assertEquals(rawEqualities + 1270, emit(p, alias).count { it.opcode == PcodeOp.INT_EQUAL })
                } else {
                    val failure = assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.preview(p, f, monitor) }
                    assertTrue(failure.message.orEmpty().contains("finite lowering operation budget", ignoreCase = true), failure.message)
                    assertTrue(failure.message.orEmpty().contains("4192"), failure.message)
                    assertEquals(revision, p.modificationNumber)
                    assertFalse(OrdinaryEntryAccess.registered(p, f.entryPoint))
                    assertFalse(p.memory.blocks.any { it.name.startsWith(OrdinaryEntryAccess.PREFIX) })
                }
            }
        }
    }
}
