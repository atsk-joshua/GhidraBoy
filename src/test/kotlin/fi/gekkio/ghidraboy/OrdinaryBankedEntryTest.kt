package fi.gekkio.ghidraboy

import com.google.gson.JsonObject
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
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

/** Original C physical bytes, independently selected fetches and controlled architectural execution. */
class OrdinaryBankedEntryTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY
    private val invocation = OrdinaryEntryAccess.Invocation("0180", "018d")

    private fun canonical(
        p: ProgramDB,
        bank: Int,
        cpu: Int,
    ): Address = p.addressFactory.getAddress("rom$bank::${cpu.toString(16).padStart(4, '0')}")

    private fun fixture(
        selector: Int = 2,
        action: (ProgramDB, Function) -> Unit,
    ) {
        val data = ByteArray(0x10000)
        data[0x147] = 0x19
        data[0x148] = 1
        HexFormat.of().parseHex("f331fecfafea00303e01ea0020cd0040c9").copyInto(data, 0x180)
        HexFormat.of().parseHex("3e02ea00203ed1ea10c0c9").copyInto(data, 0x4000)
        data[0x4001] = selector.toByte()
        HexFormat.of().parseHex("06a778ea10c0c9").copyInto(data, 0x8005)
        val owner = Any()
        val p = ProgramDB("ordinary-banked-entry", language, language.defaultCompilerSpec, owner)
        try {
            ByteArrayProvider(data).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true, monitor, MessageLog())
            }
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, monitor, null)
                disassembler.disassemble(address(0x180), AddressSet(address(0x180), address(0x190)))
                val entry = canonical(p, 1, 0x4000)
                val body = AddressSet(entry, entry.add(10))
                disassembler.disassemble(entry, body)
                val continuation = canonical(p, 2, 0x4005)
                disassembler.disassemble(continuation, AddressSet(continuation, continuation.add(6)))
                p.functionManager.createFunction("ordinary_banked_kernel", entry, body, SourceType.USER_DEFINED)
            }
            assertTrue(p.listing.getInstructionAt(canonical(p, 1, 0x4005)) != null)
            assertTrue(p.listing.getInstructionAt(canonical(p, 2, 0x4005)) != null)
            action(p, p.functionManager.getFunctionAt(canonical(p, 1, 0x4000)))
        } finally {
            p.release(owner)
        }
    }

    /** The concrete oracle is the four-bank fixture bus, with no analysis/proof input. */
    class FixtureBus(
        private val program: ProgramDB,
        private val state: BytesPcodeExecutorState,
        private val arithmetic: BytesPcodeArithmetic,
    ) : AnnotatedPcodeUseropLibrary<ByteArray>() {
        var selectedBank = 1
            private set
        val writes = mutableListOf<Pair<Long, Long>>()

        @PcodeUserop
        fun gb_direct_write8(
            cpu: Long,
            value: Long,
        ) {
            writes.add(cpu to value)
            if (cpu == 0x2000L) {
                selectedBank = (value and 3).toInt()
            } else {
                require(cpu == 0xc010L)
                state.setVar(program.addressFactory.defaultAddressSpace.getAddress(cpu), 1, true, arithmetic.fromConst(value, 1))
            }
        }
    }

    private data class Fetch(
        val cpu: Int,
        val file: Int,
        val octet: Int,
    )

    private data class Execution(
        val observable: Int,
        val pc: Int,
        val sp: Int,
        val writes: List<Pair<Long, Long>>,
        val fetched: List<Fetch>,
    )

    private fun execute(
        p: ProgramDB,
        injected: Array<PcodeOp>? = null,
    ): Execution {
        val arithmetic = BytesPcodeArithmetic.forLanguage(language)
        val state = BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE)
        val executor = PcodeExecutor(language as SleighLanguage, arithmetic, state, Reason.EXECUTE_READ)
        // One controlled driver member only; these are never passed to static preview or install.
        for ((name, value) in mapOf(
            "A" to 1,
            "F" to 0x80,
            "BC" to 0x1234,
            "DE" to 0x5678,
            "HL" to 0x4321,
            "SP" to 0xcffc,
            "PC" to 0x4000,
        )) {
            val register = language.getRegister(name)
            state.setVar(register, arithmetic.fromConst(value, register.minimumByteSize))
        }
        state.setVar(address(0xcffc), 1, true, arithmetic.fromConst(0x90, 1))
        state.setVar(address(0xcffd), 1, true, arithmetic.fromConst(1, 1))
        val bus = FixtureBus(p, state, arithmetic)
        val fetched = mutableListOf<Fetch>()
        if (injected != null) {
            val source = PcodeProgram.fromInstruction(p.listing.getInstructionAt(canonical(p, 1, 0x4000)), false)
            executor.execute(PcodeProgram(source, injected.toList()), bus)
        } else {
            var cpu = 0x4000
            var returned = false
            repeat(16) {
                if (!returned) {
                    // The executed mapper userop controls each next fetch; the proof is not consulted.
                    val bank = bus.selectedBank
                    val instruction = p.listing.getInstructionAt(canonical(p, bank, cpu))
                    assertTrue(instruction != null, "Missing physical instruction bank$bank:$cpu")
                    instruction.bytes.forEachIndexed { index, value ->
                        fetched.add(Fetch(cpu + index, bank * 0x4000 + cpu - 0x4000 + index, value.toInt() and 255))
                    }
                    executor.execute(PcodeProgram.fromInstruction(instruction, false), bus)
                    returned = instruction.bytes
                        .singleOrNull()
                        ?.toInt()
                        ?.and(255) == 0xc9
                    cpu = (cpu + instruction.length) and 65535
                }
            }
            assertTrue(returned, "Controlled architectural execution did not reach RET")
        }

        fun value(bytes: ByteArray): Int =
            bytes.foldIndexed(0) { index, result, byte -> result or ((byte.toInt() and 255) shl (8 * index)) }

        return Execution(
            value(state.getVar(address(0xc010), 1, true, Reason.INSPECT)),
            value(state.getVar(language.getRegister("PC"), Reason.INSPECT)),
            value(state.getVar(language.getRegister("SP"), Reason.INSPECT)),
            bus.writes.toList(),
            fetched,
        )
    }

    private fun preview(
        p: ProgramDB,
        f: Function,
    ): OrdinaryEntryAccess.Proof = OrdinaryEntryAccess.preview(p, f, invocation, monitor)

    private fun emitted(
        p: ProgramDB,
        alias: Address,
    ): Array<PcodeOp> = OrdinaryEntryAccess.emit(p, alias, 0x200000, monitor)

    private fun assertExecution(
        p: ProgramDB,
        alias: Address,
        expected: Int,
        expectedBank: Int,
    ) {
        val raw = execute(p)
        val lowered = execute(p, emitted(p, alias))
        assertEquals(expected, raw.observable)
        assertEquivalent(raw, lowered)
        assertEquals(0x190, lowered.pc)
        assertEquals(0xcffe, lowered.sp)
        assertEquals(expectedBank * 0x4000 + 5, raw.fetched.first { it.cpu == 0x4005 }.file)
        assertTrue(raw.fetched.filter { it.cpu >= 0x4005 }.all { it.file / 0x4000 == expectedBank })
        assertEquals(listOf(0x2000L to expectedBank.toLong(), 0xc010L to expected.toLong()), lowered.writes)
    }

    private fun assertEquivalent(
        raw: Execution,
        lowered: Execution,
    ) {
        assertEquals(raw.observable, lowered.observable)
        assertEquals(raw.pc, lowered.pc)
        assertEquals(raw.sp, lowered.sp)
        assertEquals(raw.writes, lowered.writes)
    }

    @Test
    fun `architectural checker rejects deleted or late actual mapper userop despite final A7`() =
        fixture { p, f ->
            val alias = OrdinaryEntryAccess.install(p, preview(p, f), monitor)
            val correct = emitted(p, alias).toList()
            val mapper = correct.single { it.opcode == PcodeOp.CALLOTHER && it.getInput(1).offset == 0x2000L }
            val deleted = correct.filter { it !== mapper }
            val moved = deleted.toMutableList()
            val dataWrite = moved.indexOfFirst { it.opcode == PcodeOp.CALLOTHER && it.getInput(1).offset == 0xc010L }
            assertTrue(dataWrite >= 0)
            moved.add(dataWrite + 1, mapper)
            val raw = execute(p)
            for (tampered in listOf(deleted, moved)) {
                val result = execute(p, tampered.toTypedArray())
                assertEquals(0xa7, result.observable, "Correct final data alone must not satisfy the checker")
                assertThrows(AssertionError::class.java) { assertEquivalent(raw, result) }
            }
        }

    @Test
    fun `production fetch installs two exact shared read-only ranges and preserves canonical sources`() =
        fixture { p, f ->
            val before = canonicalSnapshot(p, f)
            val revision = p.modificationNumber
            val proof = preview(p, f)
            assertEquals(revision, p.modificationNumber)
            assertEquals(invocation, proof.invocation())
            assertEquals(listOf(0x4000, 0x4005), proof.segments().map { it.cpu() })
            assertEquals(listOf(5, 7), proof.segments().map { it.length() })
            assertEquals(listOf("rom1::4000", "rom2::4005"), proof.segments().map { it.source() })
            assertEquals(MapperKnowledge.unknown(), proof.fetchSteps().first().incoming())
            assertEquals(listOf("rom2::4005"), proof.fetchSteps()[1].successors())
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            assertTrue(OrdinaryEntryAccess.registered(p, alias))
            assertFalse(OrdinaryEntryAccess.registered(p, f.entryPoint))
            for (step in proof.fetchSteps()) {
                for (byte in step.bytes()) {
                    val mapped = ProgramMapping.staticAddress(p, byte.source())
                    assertEquals(listOf(byte.physical()), ProgramMapping.staticToPhysical(p, mapped))
                    assertEquals(byte.value(), p.memory.getByte(mapped).toInt() and 255)
                    val block = p.memory.getBlock(mapped)
                    assertFalse(block.isWrite)
                    assertTrue(block.isRead)
                    assertTrue(ProgramMapping.staticToPhysical(p, mapped).isNotEmpty())
                }
            }
            assertEquals(before, canonicalSnapshot(p, f))
            assertEquals(listOf(6, 0xa7), proof.fetchSteps()[2].bytes().map { it.value() })
            assertEquals(listOf(5, 6), proof.fetchSteps()[2].bytes().map { it.physical().offset() })
            assertTrue(proof.fetchSteps()[2].bytes().all { it.physical().bank() == 2 })
            assertExecution(p, alias, 0xa7, 2)
        }

    @Test
    fun `same selector uses original bank-one instructions and actual shorter return boundary`() =
        fixture(selector = 1) { p, f ->
            val proof = preview(p, f)
            assertEquals(listOf("rom1::4000"), proof.segments().map { it.source() })
            assertEquals(listOf(11), proof.segments().map { it.length() })
            assertEquals("rom1::400a", proof.fetchSteps().last().source())
            assertEquals(listOf(0x3e, 0xd1), proof.fetchSteps()[2].bytes().map { it.value() })
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            assertExecution(p, alias, 0xd1, 1)
        }

    private fun canonicalSnapshot(
        p: ProgramDB,
        f: Function,
    ): List<String> =
        listOf(f.name, f.entryPoint.toString(), f.body.toString()) +
            listOf(1, 2).flatMap { bank ->
                val start = canonical(p, bank, 0x4000)
                val bytes = ByteArray(12).also { p.memory.getBytes(start, it) }
                listOf(HexFormat.of().formatHex(bytes)) +
                    p.listing
                        .getInstructions(AddressSet(start, start.add(11)), true)
                        .iterator()
                        .asSequence()
                        .map { instruction -> instruction.address.toString() + instruction.getPcode(false).toList().toString() }
                        .toList()
            }

    private fun mutateAndDecode(
        p: ProgramDB,
        bank: Int,
        value: Int,
    ) {
        val target = canonical(p, bank, 0x4006)
        val affected =
            ProgramMapping
                .fileToStatic(p, bank * 0x4000L + 6)
                .mapNotNull { p.listing.getInstructionContaining(it) }
                .map { it.address to it.maxAddress }
                .distinct()
        p.withTransaction {
            // Ghidra requires all decoded shared aliases cleared before a physical byte write.
            for ((start, end) in affected) {
                p.listing.clearCodeUnits(start, end, false)
            }
            p.memory.setByte(target, value.toByte())
            for ((start, end) in affected) {
                Disassembler.getDisassembler(p, monitor, null).disassemble(start, AddressSet(start, end))
                assertTrue(p.listing.getInstructionAt(start) != null)
            }
        }
    }

    @Test
    fun `consumed B2 mutation rejects stale same-owner proof then refreshes physical bank-two operand`() =
        fixture { p, f ->
            val proof = preview(p, f)
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            assertExecution(p, alias, 0xa7, 2)
            mutateAndDecode(p, 2, 0xb2)
            assertThrows(IllegalArgumentException::class.java) { emitted(p, alias) }
            assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.install(p, proof, monitor) }
            val refreshed = preview(p, f)
            assertEquals("rom2::4005", refreshed.fetchSteps()[2].source())
            assertEquals(listOf(6, 0xb2), refreshed.fetchSteps()[2].bytes().map { it.value() })
            OrdinaryEntryAccess.refresh(p, alias, refreshed, monitor)
            assertExecution(p, alias, 0xb2, 2)
        }

    @Test
    fun `unreachable D5 mutation leaves consumed provenance and A7 unchanged after refresh`() =
        fixture { p, f ->
            val alias = OrdinaryEntryAccess.install(p, preview(p, f), monitor)
            mutateAndDecode(p, 1, 0xd5)
            val refreshed = preview(p, f)
            assertTrue(
                refreshed
                    .fetchSteps()
                    .drop(2)
                    .flatMap { it.bytes() }
                    .all { it.physical().bank() == 2 },
            )
            assertEquals(listOf(6, 0xa7), refreshed.fetchSteps()[2].bytes().map { it.value() })
            OrdinaryEntryAccess.refresh(p, alias, refreshed, monitor)
            assertExecution(p, alias, 0xa7, 2)
        }

    @Test
    fun `banked display address without a proved physical invocation is refused`() =
        fixture { p, f ->
            val revision = p.modificationNumber
            assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.preview(p, f, monitor) }
            assertThrows(IllegalArgumentException::class.java) {
                OrdinaryEntryAccess.preview(p, f, OrdinaryEntryAccess.Invocation("rom1::4000", "rom1::4000"), monitor)
            }
            assertEquals(revision, p.modificationNumber)
        }

    @Test
    fun `same specimen in a foreign Program cannot reuse physical proof ownership`() =
        fixture { first, firstFunction ->
            val proof = preview(first, firstFunction)
            fixture { second, secondFunction ->
                val before = canonicalSnapshot(second, secondFunction)
                val revision = second.modificationNumber
                assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.install(second, proof, monitor) }
                assertEquals(revision, second.modificationNumber)
                assertEquals(before, canonicalSnapshot(second, secondFunction))
            }
        }

    @Test
    fun `serialized correct A7 cannot certify wrong fetch source or absent production evidence`() =
        fixture { p, f ->
            val alias = OrdinaryEntryAccess.install(p, preview(p, f), monitor)
            val mutations: List<(JsonObject) -> Unit> =
                listOf(
                    { proof ->
                        proof
                            .getAsJsonArray(
                                "fetchSteps",
                            )[2]
                            .asJsonObject
                            .getAsJsonArray("bytes")[0]
                            .asJsonObject
                            .getAsJsonObject("physical")
                            .addProperty("bank", 1)
                    },
                    { proof ->
                        proof
                            .getAsJsonArray(
                                "fetchSteps",
                            )[2]
                            .asJsonObject
                            .getAsJsonArray("bytes")[1]
                            .asJsonObject
                            .addProperty("value", 0xd1)
                    },
                    { proof -> proof.getAsJsonArray("segments")[1].asJsonObject.addProperty("source", "rom1::4005") },
                    { proof -> proof.getAsJsonArray("instructions").remove(1) },
                    { proof ->
                        val steps = proof.getAsJsonArray("fetchSteps")
                        val write = steps[1].asJsonObject.getAsJsonArray("writes").remove(0)
                        steps[2].asJsonObject.getAsJsonArray("writes").add(write)
                    },
                    { proof -> proof.add("fetchSteps", ProgramMapping.JSON.toJsonTree(emptyList<Any>())) },
                    { proof -> proof.remove("invocationAnalysis") },
                    { proof -> proof.remove("invocation") },
                )
            for (mutate in mutations) {
                rejectRegistrationMutation(p, alias, mutate)
            }
            assertExecution(p, alias, 0xa7, 2)
        }

    private fun rejectRegistrationMutation(
        p: ProgramDB,
        alias: Address,
        mutate: (JsonObject) -> Unit,
    ) {
        val options = p.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS)
        val original = options.getString(alias.toString(), "")
        val changed = JsonParser.parseString(original).asJsonObject
        mutate(changed.getAsJsonObject("proof"))
        p.withTransaction { options.setString(alias.toString(), changed.toString()) }
        assertThrows(IllegalArgumentException::class.java) { emitted(p, alias) }
        p.withTransaction { options.setString(alias.toString(), original) }
    }
}
