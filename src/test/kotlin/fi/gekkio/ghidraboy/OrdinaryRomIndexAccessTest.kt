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

/** W2f: independently execute actual code-derived ROM addresses and downstream mapper effects. */
class OrdinaryRomIndexAccessTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY
    private val code = hex("3e02ea002078e6036f26607eea40c0ea00202100617eea41c0c9")
    private val suffix = "7eea40c0ea00202100617eea41c0c9"
    private val table = listOf(1, 3, 2, 4)
    private val markers = listOf(0, 0x31, 0xa7, 0xd3, 0x5c, 0, 0, 0)

    private fun hex(value: String) = HexFormat.of().parseHex(value)

    private fun fixture(
        instructions: ByteArray = code,
        prepare: (ByteArray) -> Unit = {},
        action: (ProgramDB, Function, ByteArray) -> Unit,
    ) {
        val bytes = requireNotNull(javaClass.getResourceAsStream("/ordinary/ROM_INDEX.gb")).use { it.readBytes() }
        assertEquals(
            "dc0b697ff7727df3391be878c8deb02dd3700e6620abeef7efcc3d28c597290c",
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
                require(cpu in 0xc040L..0xc041L)
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
            state.setVar(address(0), 0x4000, true, rom.copyOfRange(0, 0x4000))
            state.setVar(address(0xcffc), 2, true, byteArrayOf(0x90.toByte(), 1))
            val bus = SpecimenBus(p, state, arithmetic, rom)
            val executor = PcodeExecutor(language as SleighLanguage, arithmetic, state, Reason.EXECUTE_READ)
            if (injected) executor.execute(lowered, bus) else raw.forEach { executor.execute(it, bus) }

            fun value(bytes: ByteArray): Int = bytes.foldIndexed(0) { i, n, byte -> n or ((byte.toInt() and 255) shl (8 * i)) }

            return Execution(
                value(state.getVar(address(0xc040), 1, true, Reason.INSPECT)),
                value(state.getVar(address(0xc041), 1, true, Reason.INSPECT)),
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
        selectors: List<Int> = table,
        initialBank: Int = 2,
        index: (Int) -> Int = { it and 3 },
    ) {
        for (b in 0..255) {
            val selector = selectors[index(b)]
            val expected = markers[selector and 7]
            val raw = runner.execute(b, false)
            val lowered = runner.execute(b, true)
            assertEquals(selector, raw.selector, "raw table byte B=$b")
            assertEquals(expected, raw.output, "raw selected physical byte B=$b")
            assertEquals(raw, lowered, "all registers and ordered effects B=$b")
            assertEquals(
                listOf(
                    0x2000L to initialBank.toLong(),
                    0xc040L to selector.toLong(),
                    0x2000L to selector.toLong(),
                    0xc041L to expected.toLong(),
                ),
                lowered.writes,
                "real bus write ordering B=$b",
            )
            assertEquals(0x190, lowered.registers["PC"])
            assertEquals(0xcffe, lowered.registers["SP"])
            assertEquals((b shl 8) or 0x53, lowered.registers["BC"])
            assertEquals(0x12a6, lowered.registers["DE"])
            assertEquals(0x6100, lowered.registers["HL"])
        }
    }

    private fun assertPointerSources(
        proof: OrdinaryEntryAccess.Proof,
        pointers: List<Long>,
        physical: List<MapperState.Physical>,
        values: List<Int>,
    ) {
        val read = proof.finite().reads().first { it.choice()?.kind() == FiniteEntryProducer.Kind.CPU_POINTER }
        val choice = read.choice()
        assertEquals(pointers, choice.values())
        assertEquals(2, choice.width())
        assertNull(choice.mapperCpu())
        assertEquals(1, choice.input())
        assertEquals(pointers, read.alternatives().map { it.key() })
        assertEquals(physical, read.alternatives().map { it.sources().single().physical() })
        assertEquals(values.map { it.toLong() }, read.alternatives().map { it.value() })
        assertEquals(values, read.alternatives().map { it.sources().single().value() })
        assertTrue(read.alternatives().all { it.sources().single().byteIndex() == 0 })
    }

    @Test
    fun `unknown B derives finite ROM pointer table value and downstream bank for every input`() =
        fixture { p, f, rom ->
            for (name in listOf("A", "F", "BC", "DE", "HL", "SP")) {
                assertNull(p.programContext.getValue(p.getRegister(name), f.entryPoint, false))
            }
            val proof = OrdinaryEntryAccess.preview(p, f, monitor)
            assertPointerSources(proof, (0x6000L..0x6003L).toList(), (0..3).map { MapperState.Physical("ROM", 2, 0x2000 + it) }, table)
            val downstream = proof.finite().reads().last()
            assertEquals(FiniteEntryProducer.Kind.MAPPER_SELECTOR, downstream.choice().kind())
            assertEquals(listOf(1L, 2L, 3L, 4L), downstream.alternatives().map { it.key() })
            assertEquals(
                (1..4).map { MapperState.Physical("ROM", it, 0x2100) },
                downstream.alternatives().map { it.sources().single().physical() },
            )
            assertEquals((1..4).map { markers[it].toLong() }, downstream.alternatives().map { it.value() })
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            val ops = emit(p, alias)
            assertEquals(2, ops.count { it.opcode == PcodeOp.LOAD }, "Only real return-frame LOADs remain")
            val revision = p.modificationNumber
            relation(Runner(p, f, ops, rom))
            assertEquals(revision, p.modificationNumber, "All 256 inputs use one unchanged Program and registration")
        }

    @Test
    fun `finite pointers across ROM windows retain each physical identity`() =
        fixture(hex("3e02ea002078e601c63f672eff$suffix"), {
            it[0x3fff] = 1
            it[0x80ff] = 3
        }) { p, f, rom ->
            val proof = OrdinaryEntryAccess.preview(p, f, monitor)
            assertPointerSources(
                proof,
                listOf(0x3fffL, 0x40ffL),
                listOf(MapperState.Physical("ROM", 0, 0x3fff), MapperState.Physical("ROM", 2, 0xff)),
                listOf(1, 3),
            )
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            relation(Runner(p, f, emit(p, alias), rom), listOf(1, 3), index = { it and 1 })
        }

    @Test
    fun `equal bytes preserve four pointer alternatives and downstream relationship`() =
        fixture(prepare = { it[0xa002] = 1 }) { p, f, rom ->
            val proof = OrdinaryEntryAccess.preview(p, f, monitor)
            val repeated = listOf(1, 3, 1, 4)
            assertPointerSources(proof, (0x6000L..0x6003L).toList(), (0..3).map { MapperState.Physical("ROM", 2, 0x2000 + it) }, repeated)
            assertEquals(
                listOf(1L, 3L, 4L),
                proof
                    .finite()
                    .reads()
                    .last()
                    .choice()
                    .values(),
            )
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            relation(Runner(p, f, emit(p, alias), rom), repeated)
        }

    @Test
    fun `physical aliases preserve distinct CPU pointer guards`() =
        fixture(hex("3e00ea002078e640672eff$suffix"), { it[0xff] = 3 }) { p, f, rom ->
            val proof = OrdinaryEntryAccess.preview(p, f, monitor)
            assertPointerSources(proof, listOf(0xffL, 0x40ffL), List(2) { MapperState.Physical("ROM", 0, 0xff) }, listOf(3, 3))
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            relation(Runner(p, f, emit(p, alias), rom), listOf(3, 3), initialBank = 0, index = { (it and 0x40) ushr 6 })
        }

    @Test
    fun `actual 16-bit pointer wrap and overlapping L write retain CPU addresses`() =
        fixture(hex("3e02ea002021ffff2378e6036f$suffix"), { table.forEachIndexed { i, v -> it[i] = v.toByte() } }) { p, f, rom ->
            val proof = OrdinaryEntryAccess.preview(p, f, monitor)
            assertPointerSources(proof, (0L..3L).toList(), (0..3).map { MapperState.Physical("ROM", 0, it) }, table)
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            relation(Runner(p, f, emit(p, alias), rom))
        }

    @Test
    fun `consumed table mutation rejects stale proof and refresh changes rooted input relationship`() =
        fixture { p, f, rom ->
            val old = OrdinaryEntryAccess.preview(p, f, monitor)
            val alias = OrdinaryEntryAccess.install(p, old, monitor)
            p.withTransaction { p.memory.setByte(ProgramMapping.fileToStatic(p, 0xa001).single(), 4) }
            rom[0xa001] = 4
            assertThrows(IllegalArgumentException::class.java) { emit(p, alias) }
            assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.refresh(p, alias, old, monitor) }
            val fresh = OrdinaryEntryAccess.preview(p, f, monitor)
            assertFalse(old.dependencies() == fresh.dependencies())
            val changed = listOf(1, 4, 2, 4)
            assertPointerSources(fresh, (0x6000L..0x6003L).toList(), (0..3).map { MapperState.Physical("ROM", 2, 0x2000 + it) }, changed)
            OrdinaryEntryAccess.refresh(p, alias, fresh, monitor)
            relation(Runner(p, f, emit(p, alias), rom), changed)
        }

    @Test
    fun `actual pointer producer widening rejects stale proof then derives all eight addresses`() =
        fixture(prepare = { listOf(4, 2, 3, 1).forEachIndexed { i, v -> it[0xa004 + i] = v.toByte() } }) { p, f, rom ->
            val old = OrdinaryEntryAccess.preview(p, f, monitor)
            val alias = OrdinaryEntryAccess.install(p, old, monitor)
            p.withTransaction {
                val at = address(0x156)
                p.listing.clearCodeUnits(at, at.add(1), false)
                p.listing.clearCodeUnits(alias.add(6), alias.add(7), false)
                p.memory.setByte(at.add(1), 7)
                Disassembler.getDisassembler(p, monitor, null).disassemble(at, AddressSet(at, at.add(1)))
            }
            rom[0x157] = 7
            assertThrows(IllegalArgumentException::class.java) { emit(p, alias) }
            assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.refresh(p, alias, old, monitor) }
            val fresh = OrdinaryEntryAccess.preview(p, f, monitor)
            val values = table + listOf(4, 2, 3, 1)
            assertPointerSources(fresh, (0x6000L..0x6007L).toList(), (0..7).map { MapperState.Physical("ROM", 2, 0x2000 + it) }, values)
            OrdinaryEntryAccess.refresh(p, alias, fresh, monitor)
            relation(Runner(p, f, emit(p, alias), rom), values, index = { it and 7 })
        }

    @Test
    fun `omitted forged swapped truncated and foreign pointer proofs are rejected`() =
        fixture { p, f, rom ->
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
            for (kind in listOf("missing", "forged", "swapped", "truncated", "lost-source")) {
                val registration = JsonParser.parseString(original).asJsonObject
                val read =
                    registration
                        .getAsJsonObject("proof")
                        .getAsJsonObject("finite")
                        .getAsJsonArray("reads")[0]
                        .asJsonObject
                val alternatives = read.getAsJsonArray("alternatives")
                when (kind) {
                    "missing" -> alternatives.remove(1)
                    "forged" -> alternatives[0].asJsonObject.addProperty("key", 0x6004)
                    "swapped" -> {
                        alternatives[0].asJsonObject.addProperty("key", 0x6001)
                        alternatives[1].asJsonObject.addProperty("key", 0x6000)
                    }
                    "truncated" -> {
                        alternatives.remove(3)
                        read.getAsJsonObject("choice").getAsJsonArray("values").remove(3)
                    }
                    "lost-source" -> alternatives[0].asJsonObject.getAsJsonArray("sources").remove(0)
                }
                p.withTransaction { options.setString(alias.toString(), registration.toString()) }
                assertThrows(IllegalArgumentException::class.java, { emit(p, alias) }, kind)
                p.withTransaction { options.setString(alias.toString(), original) }
            }
            relation(Runner(p, f, emit(p, alias), rom))
        }

    @Test
    fun `unsupported non-ROM mixed mapper pointer and full-byte domains refuse without payload`() {
        val cases =
            listOf(
                "non-ROM" to "3e02ea002078e601c67f672eff$suffix",
                "unknown-pointer" to "3e02ea0020$suffix",
                "full-byte-pointer" to "3e02ea0020786f2660$suffix",
            )
        for ((name, instructions) in cases) {
            fixture(hex(instructions)) { p, f, _ ->
                val before = p.modificationNumber
                assertThrows(IllegalArgumentException::class.java, { OrdinaryEntryAccess.preview(p, f, monitor) }, name)
                assertEquals(before, p.modificationNumber)
                assertFalse(OrdinaryEntryAccess.registered(p, f.entryPoint))
                assertFalse(p.memory.blocks.any { it.name.startsWith(OrdinaryEntryAccess.PREFIX) })
            }
        }
    }

    @Test
    fun `pointer expansion checks complete work budget before registration`() {
        for (reads in listOf(10, 11)) {
            val prefix = hex("3e02ea002078e67f6f2660")
            fixture(prefix + ByteArray(reads) { 0x7e } + byteArrayOf(0xc9.toByte())) { p, f, _ ->
                if (reads == 10) {
                    val proof = OrdinaryEntryAccess.preview(p, f, monitor)
                    assertEquals(reads, proof.finite().reads().size)
                    assertTrue(proof.finite().reads().all { it.alternatives().size == 128 })
                    OrdinaryEntryAccess.install(p, proof, monitor)
                } else {
                    val before = p.modificationNumber
                    val failure = assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.preview(p, f, monitor) }
                    assertTrue(failure.message.orEmpty().contains("finite lowering operation budget"), failure.message)
                    assertEquals(before, p.modificationNumber)
                    assertFalse(OrdinaryEntryAccess.registered(p, f.entryPoint))
                }
            }
        }
    }

    @Test
    fun `old experimental record is rejected without deleting persisted user data`() =
        fixture(hex("78e6033cea00202100617ec9")) { p, f, _ ->
            // This mapper-only entry is in the old v3 domain. Recreate its actual old field
            // layout rather than relabeling a new pointer proof that v3 could never derive.
            val alias = OrdinaryEntryAccess.install(p, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
            val options = p.getOptions(OrdinaryEntryAccess.OPTIONS)
            val original = options.getString(alias.toString(), "")
            val old = JsonParser.parseString(original).asJsonObject
            old.addProperty("version", "ordinary-entry-access-experiment-3-finite")
            old.getAsJsonObject("proof").addProperty("version", "ordinary-entry-access-experiment-3-finite")
            val finite = old.getAsJsonObject("proof").getAsJsonObject("finite")
            finite.addProperty("version", "finite-entry-producer-ex0204-1")
            val selectors = finite.remove("choices").asJsonArray
            for (element in selectors) {
                val selector = element.asJsonObject
                assertEquals("MAPPER_SELECTOR", selector.remove("kind").asString)
                selector.add("cpu", selector.remove("mapperCpu"))
            }
            finite.add("selectors", selectors)
            for (element in finite.getAsJsonArray("reads")) {
                val read = element.asJsonObject
                val selector = read.remove("choice").asJsonObject
                assertEquals("MAPPER_SELECTOR", selector.remove("kind").asString)
                selector.add("cpu", selector.remove("mapperCpu"))
                read.add("selector", selector)
                for (alternative in read.getAsJsonArray("alternatives")) {
                    alternative.asJsonObject.add("selector", alternative.asJsonObject.remove("key"))
                }
            }
            p.withTransaction { options.setString(alias.toString(), old.toString()) }
            val revision = p.modificationNumber
            val failure = assertThrows(IllegalArgumentException::class.java) { emit(p, alias) }
            assertEquals("Unsupported ordinary registration version; record retained without migration", failure.message)
            assertEquals(revision, p.modificationNumber)
            assertEquals(old.toString(), options.getString(alias.toString(), ""))
            assertTrue(p.memory.contains(alias))
            p.withTransaction { options.setString(alias.toString(), original) }
            assertTrue(emit(p, alias).isNotEmpty())
        }

    @Test
    fun `independent checker rejects wrong pointer guards and lost mapper dependency`() =
        fixture { p, f, rom ->
            val alias = OrdinaryEntryAccess.install(p, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
            val ops = emit(p, alias)
            val wrongPointer =
                ops
                    .map {
                        if (it.opcode == PcodeOp.INT_EQUAL && it.getInput(1).isConstant && it.getInput(1).offset in 0x6000L..0x6003L) {
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
            assertThrows(AssertionError::class.java) { relation(Runner(p, f, wrongPointer, rom)) }
            val mapper = ops.last { CartridgeBus.isDirectWrite(language, it) && it.getInput(1).offset == 0x2000L }
            assertThrows(AssertionError::class.java) { relation(Runner(p, f, ops.filter { it !== mapper }.toTypedArray(), rom)) }
        }
}
