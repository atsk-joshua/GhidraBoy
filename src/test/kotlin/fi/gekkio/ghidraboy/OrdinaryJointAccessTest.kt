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
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.util.HexFormat

/** W2f: independently execute actual code-derived ROM addresses and downstream mapper effects. */
class OrdinaryJointAccessTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY
    private val code = hex("78e6013cea50c0ea00207ae6016f26607eea51c0c9")

    private fun hex(value: String) = HexFormat.of().parseHex(value)

    private fun fixture(
        instructions: ByteArray = code,
        prepare: (ByteArray) -> Unit = {},
        action: (ProgramDB, Function, ByteArray) -> Unit,
    ) {
        val bytes = requireNotNull(javaClass.getResourceAsStream("/ordinary/JOINT_INDEPENDENT.gb")).use { it.readBytes() }
        assertEquals(
            "abb27a904946c7c1684948bf37f45de710e982faa7c6c5ade8e546316045e5b8",
            HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)),
        )
        assertEquals(8 * 0x4000, bytes.size)
        bytes.fill(0, 0x150, 0x150 + maxOf(code.size, instructions.size))
        instructions.copyInto(bytes, 0x150)
        prepare(bytes)
        val owner = Any()
        val p = ProgramDB("rom-index", language, language.defaultCompilerSpec, owner)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog())
            }
            p.withTransaction {
                val body = AddressSet(address(0x150), address(0x150 + instructions.size.toLong() - 1))
                Disassembler.getDisassembler(p, monitor, null).disassemble(address(0x150), body)
                p.functionManager.createFunction("rom_index_kernel", address(0x150), body, SourceType.USER_DEFINED)
            }
            action(p, p.functionManager.getFunctionAt(address(0x150)), bytes)
        } finally {
            p.release(owner)
        }
    }

    /** Concrete eight-bank fixture bus; no provider mapper, proof alternatives, or emitted constants. */
    class SpecimenBus(
        private val p: ProgramDB,
        private val state: BytesPcodeExecutorState,
        private val arithmetic: BytesPcodeArithmetic,
        private val rom: ByteArray,
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
                val bank = (value and 7).toInt()
                state.setVar(space.getAddress(0x4000), 0x4000, true, rom.copyOfRange(bank * 0x4000, (bank + 1) * 0x4000))
            } else {
                require(cpu in 0xc050L..0xc051L)
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
        private val rom: ByteArray,
    ) {
        private val arithmetic = BytesPcodeArithmetic.forLanguage(language)
        private val raw = p.listing.getInstructions(f.body, true).map { PcodeProgram.fromInstruction(it, false) }
        private val lowered = PcodeProgram(raw.first(), emitted.toList())

        fun execute(
            b: Int,
            d: Int,
            injected: Boolean,
        ): Execution {
            val state = BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE)
            val initial =
                mapOf(
                    "A" to 0x95,
                    "F" to 0xf0,
                    "BC" to ((b shl 8) or 0x53),
                    "DE" to ((d shl 8) or 0xa6),
                    "HL" to 0xbeef,
                    "SP" to 0xcffc,
                    "PC" to 0x150,
                )
            for ((name, value) in initial) {
                val register = language.getRegister(name)
                state.setVar(register, arithmetic.fromConst(value, register.minimumByteSize))
            }
            state.setVar(address(0), 0x4000, true, rom.copyOfRange(0, 0x4000))
            state.setVar(address(0xcffc), 2, true, byteArrayOf(0x90.toByte(), 1))
            val bus = SpecimenBus(p, state, arithmetic, rom)
            val executor = PcodeExecutor(language as SleighLanguage, arithmetic, state, Reason.EXECUTE_READ)
            if (injected) executor.execute(lowered, bus) else raw.forEach { executor.execute(it, bus) }

            fun value(bytes: ByteArray): Int = bytes.foldIndexed(0) { i, n, byte -> n or ((byte.toInt() and 255) shl (8 * i)) }

            return Execution(
                value(state.getVar(address(0xc050), 1, true, Reason.INSPECT)),
                value(state.getVar(address(0xc051), 1, true, Reason.INSPECT)),
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

    private val sameCode = hex("78e6013cea50c0ea002078e6016f26607eea51c0c9")

    private fun joint(proof: OrdinaryEntryAccess.Proof) =
        requireNotNull(
            proof
                .finite()
                .reads()
                .single()
                .joint(),
        )

    private fun checkRelation(
        runner: Runner,
        same: Boolean = false,
        offDiagonal: Int = 0x5d,
    ) {
        for (b in 0..255) {
            for (d in listOf(0, 1, 128, 255)) {
                val selector = (b and 1) + 1
                val bit = (if (same) b else d) and 1
                val expected = if (selector == 1) (if (bit == 0) 0x31 else offDiagonal) else (if (bit == 0) 0xc6 else 0xa7)
                val raw = runner.execute(b, d, false)
                val emitted = runner.execute(b, d, true)
                assertEquals(raw, emitted, "raw/emitted registers/effects B=$b D=$d")
                assertEquals(selector, emitted.selector)
                assertEquals(expected, emitted.output)
                assertEquals(
                    listOf(0xc050L to selector.toLong(), 0x2000L to selector.toLong(), 0xc051L to expected.toLong()),
                    emitted.writes,
                )
                assertEquals(0x190, emitted.registers["PC"])
                assertEquals(0xcffe, emitted.registers["SP"])
            }
        }
    }

    @Test
    fun `independent and same-input origins produce four and two guarded physical pairs`() {
        for (same in listOf(false, true)) {
            fixture(if (same) sameCode else code) { p, f, rom ->
                val proof = OrdinaryEntryAccess.preview(p, f, monitor)
                val relation = joint(proof)
                assertTrue(relation.complete())
                assertEquals(4, relation.candidateCover().size)
                val expected =
                    if (same) {
                        listOf(1L to 0x6000L, 2L to 0x6001L)
                    } else {
                        listOf(
                            1L to 0x6000L,
                            1L to 0x6001L,
                            2L to 0x6000L,
                            2L to 0x6001L,
                        )
                    }
                assertEquals(expected, relation.reachable().map { it.endpoint().selector() to it.endpoint().pointer() })
                for (guard in relation.reachable()) {
                    val endpoint = guard.endpoint()
                    assertEquals(
                        MapperState.Physical("ROM", endpoint.selector().toInt(), (endpoint.pointer() - 0x4000).toInt()),
                        endpoint.sources().single().physical(),
                    )
                    assertEquals(2, guard.condition().terms().size)
                }
                for (name in listOf("BC", "DE")) assertNull(p.programContext.getValue(p.getRegister(name), f.entryPoint, false))
                val alias = OrdinaryEntryAccess.install(p, proof, monitor)
                checkRelation(Runner(p, f, emit(p, alias), rom), same)
            }
        }
    }

    @Test
    fun `copied register shares definition while actual LOAD output overlap preserves snapshot`() {
        fixture(byteArrayOf(0x50) + code) { p, f, _ ->
            assertEquals(2, joint(OrdinaryEntryAccess.preview(p, f, monitor)).reachable().size)
        }
        fixture(hex("78e6013cea50c0ea00207ae6016f2660667cea51c0c9")) { p, f, rom ->
            val alias = OrdinaryEntryAccess.install(p, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
            checkRelation(Runner(p, f, emit(p, alias), rom))
        }
    }

    @Test
    fun `storage copies preserve roots and overwrites replace only actual slices`() {
        val storage = AbstractValues.Storage("scoped-program-entry")
        val b = Varnode(language.getRegister("B").address, 1)
        val d = Varnode(language.getRegister("D").address, 1)
        val bc = Varnode(language.getRegister("BC").address, 2)
        val first = storage.get(b)
        storage.put(d, first)
        assertEquals(first.origin(), storage.get(d).origin())
        storage.put(b, AbstractValues.constant(0x12, 1))
        assertNotEquals(first.origin(), storage.get(b).origin())
        assertEquals(first.origin(), storage.get(d).origin())
        storage.put(bc, AbstractValues.constant(0x1234, 2))
        assertEquals(setOf(0x12L), storage.get(b).values())
        storage.put(b, AbstractValues.constant(0xff, 1))
        assertEquals(setOf(0xff34L), storage.get(bc).values())
    }

    @Test
    fun `equal byte endpoints retain distinct conditions and alias provenance`() {
        fixture(prepare = {
            it[0x6001] = 0x31
            it[0xa000] = 0x31
            it[0xa001] = 0x31
        }) { p, f, _ ->
            val relation = joint(OrdinaryEntryAccess.preview(p, f, monitor))
            assertEquals(4, relation.reachable().size)
            assertEquals(
                4,
                relation
                    .reachable()
                    .map { it.condition() }
                    .distinct()
                    .size,
            )
            assertEquals(
                4,
                relation
                    .reachable()
                    .map { it.endpoint().sources() }
                    .distinct()
                    .size,
            )
        }
        // Selectors1/9 share the same physical bank in the eight-bank fixture.
        fixture(hex("78e6083cea50c0ea00207ae6016f26607eea51c0c9")) { p, f, _ ->
            val relation = joint(OrdinaryEntryAccess.preview(p, f, monitor))
            assertEquals(4, relation.reachable().size)
            assertEquals(
                2,
                relation
                    .reachable()
                    .map { it.endpoint().sources() }
                    .distinct()
                    .size,
            )
        }
    }

    @Test
    fun `consumed off-diagonal mutation stales both proofs but only independent values change`() {
        for (same in listOf(false, true)) {
            fixture(if (same) sameCode else code) { p, f, rom ->
                val old = OrdinaryEntryAccess.preview(p, f, monitor)
                val alias = OrdinaryEntryAccess.install(p, old, monitor)
                p.withTransaction { p.memory.setByte(p.addressFactory.getAddress("rom1::6001"), 0x6e) }
                rom[0x6001] = 0x6e
                assertThrows(IllegalArgumentException::class.java) { emit(p, alias) }
                assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.refresh(p, alias, old, monitor) }
                val fresh = OrdinaryEntryAccess.preview(p, f, monitor)
                assertFalse(old.dependencies() == fresh.dependencies())
                if (same) assertEquals(joint(old).reachable(), joint(fresh).reachable())
                OrdinaryEntryAccess.refresh(p, alias, fresh, monitor)
                checkRelation(Runner(p, f, emit(p, alias), rom), same, 0x6e)
            }
        }
    }

    @Test
    fun `actual input-definition mutation requires new joint guard coverage`() =
        fixture { p, f, rom ->
            val old = OrdinaryEntryAccess.preview(p, f, monitor)
            val alias = OrdinaryEntryAccess.install(p, old, monitor)
            p.withTransaction {
                val at = address(0x15a)
                p.listing.clearCodeUnits(alias.add(10), alias.add(10), false)
                p.listing.clearCodeUnits(at, at, false)
                p.memory.setByte(at, 0x78)
                Disassembler.getDisassembler(p, monitor, null).disassemble(at, AddressSet(at, at))
            }
            rom[0x15a] = 0x78
            assertThrows(IllegalArgumentException::class.java) { emit(p, alias) }
            val fresh = OrdinaryEntryAccess.preview(p, f, monitor)
            assertEquals(2, joint(fresh).reachable().size)
            OrdinaryEntryAccess.refresh(p, alias, fresh, monitor)
            checkRelation(Runner(p, f, emit(p, alias), rom), true)
        }

    @Test
    fun `missing swapped forged joint guards and foreign proof cannot authorize fallback`() =
        fixture { p, f, _ ->
            val proof = OrdinaryEntryAccess.preview(p, f, monitor)
            fixture {
                other,
                _,
                _,
                ->
                assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.install(other, proof, monitor) }
            }
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            val options = p.getOptions(OrdinaryEntryAccess.OPTIONS)
            val original = options.getString(alias.toString(), "")
            for (kind in listOf("missing", "swapped", "guard", "coverage")) {
                val record = JsonParser.parseString(original).asJsonObject
                val relation =
                    record
                        .getAsJsonObject(
                            "proof",
                        ).getAsJsonObject("finite")
                        .getAsJsonArray("reads")[0]
                        .asJsonObject
                        .getAsJsonObject("joint")
                val rows = relation.getAsJsonArray("reachable")
                when (kind) {
                    "missing" -> rows.remove(0)
                    "swapped" -> rows[0].asJsonObject.getAsJsonObject("endpoint").addProperty("pointer", 0x6001)
                    "guard" ->
                        rows[0]
                            .asJsonObject
                            .getAsJsonObject("condition")
                            .getAsJsonArray("terms")[0]
                            .asJsonObject
                            .addProperty("value", 9)
                    "coverage" -> relation.addProperty("complete", false)
                }
                p.withTransaction { options.setString(alias.toString(), record.toString()) }
                assertThrows(IllegalArgumentException::class.java, { emit(p, alias) }, kind)
                p.withTransaction { options.setString(alias.toString(), original) }
            }
        }

    @Test
    fun `candidate construction and unknown guard growth refuse before registration`() {
        fixture(hex("78e67f3cea50c0ea00207ae67f6f26607eea51c0c9")) { p, f, _ ->
            val error = assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.preview(p, f, monitor) }
            assertTrue(error.message.orEmpty().contains("candidate budget"), error.message)
            assertFalse(p.memory.blocks.any { it.name.startsWith(OrdinaryEntryAccess.PREFIX) })
        }
    }

    @Test
    fun `v4 record is rejected without changing stored authority`() =
        fixture(hex("3e02ea002078e6016f26607eea51c0c9")) { p, f, _ ->
            val alias = OrdinaryEntryAccess.install(p, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
            val options = p.getOptions(OrdinaryEntryAccess.OPTIONS)
            val record = JsonParser.parseString(options.getString(alias.toString(), "")).asJsonObject
            record.addProperty("version", "ordinary-entry-access-experiment-4-rom-index")
            val oldProof = record.getAsJsonObject("proof")
            oldProof.addProperty("version", "ordinary-entry-access-experiment-4-rom-index")
            val finite = oldProof.getAsJsonObject("finite")
            finite.addProperty("version", "finite-entry-producer-w2f-rom-index-2")
            for (choice in finite.getAsJsonArray("choices")) choice.asJsonObject.remove("origin")
            for (read in finite.getAsJsonArray("reads")) read.asJsonObject.getAsJsonObject("choice")?.remove("origin")
            p.withTransaction { options.setString(alias.toString(), record.toString()) }
            val revision = p.modificationNumber
            val error = assertThrows(IllegalArgumentException::class.java) { emit(p, alias) }
            assertTrue(error.message.orEmpty().contains("Unsupported ordinary registration version"))
            assertEquals(revision, p.modificationNumber)
            assertEquals(record.toString(), options.getString(alias.toString(), ""))
        }
}
