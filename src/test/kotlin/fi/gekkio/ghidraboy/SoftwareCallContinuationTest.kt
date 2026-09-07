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
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

class SoftwareCallContinuationTest : IntegrationTest() {
    class ContinuationBus(
        private val program: ProgramDB,
        private val state: BytesPcodeExecutorState,
        private val arithmetic: BytesPcodeArithmetic,
    ) : AnnotatedPcodeUseropLibrary<ByteArray>() {
        val writes = mutableListOf<Pair<Long, Long>>()

        @PcodeUserop
        fun gb_direct_write8(
            cpu: Long,
            value: Long,
        ) {
            if (cpu < 0x8000) {
                writes.add(cpu to value)
            } else {
                state.setVar(program.addressFactory.defaultAddressSpace.getAddress(cpu), 1, true, arithmetic.fromConst(value, 1))
            }
        }

        @PcodeUserop
        fun gb_cartridge_write8(
            cpu: Long,
            value: Long,
        ) {
            writes.add(cpu to value)
        }
    }

    private fun fixture(
        continuation: String,
        caller: Int = 0x150,
        extra: Map<Int, String> = emptyMap(),
        action: (ProgramDB, SoftwareCallModel.Frame, SoftwareCallEffects.Path) -> Unit,
    ) {
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x200, 0, null)
        val regions = linkedMapOf(0x200 to template.bodyHex(), 0x8000 to "c9")
        val continuationOffset = if (caller < 0x4000) caller + 3 else 0x8000 + caller + 3 - 0x4000
        regions[continuationOffset] = continuation
        regions.putAll(extra)
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                for ((offset, hex) in regions) HexFormat.of().parseHex(hex).copyInto(this, offset)
            }
        val consumer = Any()
        val p = ProgramDB("continuation-effects", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                for ((offset, hex) in regions) {
                    val bank = offset / 0x4000
                    val cpu = if (bank == 0) offset else 0x4000 + offset % 0x4000
                    val mapper = MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, bank)
                    val at = SoftwareCallValidation.executionAddress(p, mapper, cpu)
                    disassembler.disassemble(at, AddressSet(at, at.add(hex.length.toLong() / 2 - 1)))
                }
            }
            val entry =
                SoftwareCallModel.Entry(
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    caller + 3,
                    SoftwareCallModel.Registers(2, 0, 2, 0x1234, 0x4000),
                    MapperState.reset(),
                    byteArrayOf(),
                )
            val frame = SoftwareCallModel.enter(ProgramMapping.cartridge(p), template, HexFormat.of().parseHex(template.bodyHex()), entry)
            val effects = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertTrue(effects.complete(), effects.unresolved().toString())
            action(p, frame, effects.paths().single())
        } finally {
            p.release(consumer)
        }
    }

    private fun trace(
        p: ProgramDB,
        frame: SoftwareCallModel.Frame,
        path: SoftwareCallEffects.Path,
        candidates: List<SoftwareCallValidation.Configuration> = emptyList(),
    ): SoftwareCallEffects.ContinuationSummary = SoftwareCallEffects.deriveContinuation(p, frame, path, candidates, TaskMonitor.DUMMY)

    @Test
    fun `later ordinary call supplies real return frame registers flags and memory`() =
        fixture("cd40023cea00c2c9", extra = mapOf(0x240 to "3e5a37c9")) { p, frame, path ->
            val result = trace(p, frame, path)
            assertTrue(result.complete(), result.unresolved().toString())
            assertTrue(result.nativeCompatible(), result.nativeIncompatibilities().toString())
            val call = result.steps().first()
            assertEquals("CALL", call.transfer())
            assertEquals(0xc0fe, call.after().sp())
            assertEquals(0xc100, call.afterCall().sp())
            assertEquals(0x156, call.afterCall().cpu())
            assertEquals(0x5a, call.afterCall().registers().a())
            assertEquals(0x10, call.afterCall().registers().f())
            assertEquals(listOf(1, 0x56), call.accesses().filter { it.write() }.map { it.value() })
            val write = result.steps().flatMap { it.accesses() }.single { it.write() && it.cpu() == 0xc200 }
            assertEquals(0x5b, write.value())
            assertEquals("RETURN", result.exit())
            val terminal = result.steps().last()
            assertEquals("EXTERNAL_RETURN", terminal.transfer())
            assertEquals(listOf(0xc100, 0xc101), terminal.accesses().map { it.cpu() })
            assertTrue(terminal.accesses().all { it.value() == null })
            assertEquals(0xc102, terminal.after().sp())
        }

    @Test
    fun `same CPU PC is revisited in distinct physical banks without merging states`() =
        fixture(
            "3e03ea0020c30041",
            extra = mapOf(0xc100 to "3e02c34002", 0x240 to "ea0020c30041", 0x8100 to "3e5bea00c2c9"),
        ) { p, frame, path ->
            val result = trace(p, frame, path)
            assertTrue(result.complete(), result.unresolved().toString())
            val repeated = result.steps().filter { it.before().cpu() == 0x4100 }
            assertEquals(listOf(3, 2), repeated.map { it.before().physical().bank() })
            assertNotEquals(repeated[0].address(), repeated[1].address())
            assertEquals(
                0x5b,
                result
                    .steps()
                    .last()
                    .before()
                    .registers()
                    .a(),
            )
            assertFalse(result.nativeCompatible())
            assertTrue(result.nativeIncompatibilities().any { it.contains("native entry space") })
        }

    @Test
    fun `indirect mapper write propagates physical fetch while retaining native bus veto`() =
        fixture("2100203603c30041", extra = mapOf(0xc100 to "c9")) { p, frame, path ->
            val result = trace(p, frame, path)
            assertTrue(result.complete(), result.unresolved().toString())
            val write = result.steps().flatMap { it.accesses() }.single { it.mapperControl() }
            assertEquals(0x2000, write.cpu())
            assertEquals(3, write.value())
            assertEquals(
                3,
                result
                    .steps()
                    .last()
                    .before()
                    .physical()
                    .bank(),
            )
            assertTrue(result.nativeIncompatibilities().any { it.contains("native bus lowering") })
        }

    @Test
    fun `banked data reads retain physical identities independent of code location`() =
        fixture(
            "3e03ea00202100427eea00c23e02ea00207eea01c2c9",
            extra = mapOf(0xc200 to "a7", 0x8200 to "5c"),
        ) { p, frame, path ->
            val result = trace(p, frame, path)
            assertTrue(result.complete(), result.unresolved().toString())
            val reads = result.steps().flatMap { it.accesses() }.filter { !it.write() && it.cpu() == 0x4200 }
            assertEquals(listOf(3, 2), reads.map { it.physical().bank() })
            assertEquals(listOf(0xa7, 0x5c), reads.map { it.value() })
            assertTrue(
                result.steps().filter { it.accesses().any { access -> access.cpu() == 0x4200 } }.all {
                    it.before().physical().bank() ==
                        0
                },
            )
        }

    @Test
    fun `nested later calls restore selected bank before returning to banked continuation`() =
        fixture(
            "cd4002ea00c2c9",
            caller = 0x4100,
            extra = mapOf(0x240 to "3e03ea0020cd60023e02ea0020c9", 0x260 to "3e7737c9"),
        ) { p, frame, path ->
            val result = trace(p, frame, path)
            assertTrue(result.complete(), result.unresolved().toString())
            val call = result.steps().first()
            assertEquals(2, call.afterCall().mapper().romLow())
            assertEquals(0x4106, call.afterCall().cpu())
            assertEquals(0xc100, call.afterCall().sp())
            assertEquals(0x10, call.afterCall().registers().f())
            assertEquals(
                2,
                result
                    .steps()
                    .last()
                    .before()
                    .physical()
                    .bank(),
            )
            assertEquals(2, result.steps().maxOf { it.callDepth() })
        }

    @Test
    fun `configured later restoring call preserves wrapper clobbers and verifies premises`() {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.RESTORING_REGISTER_JP, 0x230, 0, null)
        fixture("3e02010300210041cd3002ea00c2c9", extra = mapOf(0x230 to helper.bodyHex(), 0xc100 to "3e7737c9")) { p, frame, path ->
            p.withTransaction {
                val at = address(helper.epilogueCpu().toLong())
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(
                    at,
                    AddressSet(
                        at,
                        address(0x230 + helper.bodyHex().length.toLong() / 2 - 1),
                    ),
                )
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x15b,
                    helper,
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 3, 0x1234, 0x4100),
                    frame.targetMapper(),
                )
            val result = trace(p, frame, path, listOf(config))
            assertTrue(result.complete(), result.unresolved().toString())
            val call = result.steps().single { it.softwareCall() != null }
            assertEquals(3, call.softwareCall().target().bank())
            assertEquals(2, call.afterCall().registers().a())
            assertEquals(0x200, call.afterCall().registers().bc())
            assertEquals(0x10, call.afterCall().registers().f())
            assertEquals(2, call.afterCall().mapper().romLow())
            val contradicted =
                SoftwareCallValidation.Configuration(
                    config.callCpu(),
                    helper,
                    config.transfer(),
                    0xc102,
                    config.registers(),
                    config.mapper(),
                )
            assertFalse(trace(p, frame, path, listOf(contradicted)).complete())
        }
    }

    @Test
    fun `conditional return uses proved flags and exact loops retain a back edge`() {
        fixture("37d8c9") { p, frame, path ->
            val result = trace(p, frame, path)
            assertTrue(result.complete(), result.unresolved().toString())
            assertEquals(listOf(0x153, 0x154), result.steps().map { it.before().cpu() })
            assertEquals("RETURN", result.exit())
        }
        fixture("3e0318fe") { p, frame, path ->
            val result = trace(p, frame, path)
            assertTrue(result.complete(), result.unresolved().toString())
            assertEquals("LOOP", result.exit())
            assertEquals(1, result.steps().last().successor())
        }
    }

    @Test
    fun `unknown initial RAM and partially changed live return word remain unresolved`() {
        for (body in listOf("fa00c2c9", "3e12ea00c1c9")) {
            fixture(body) { p, frame, path ->
                val result = trace(p, frame, path)
                assertFalse(result.complete())
                assertTrue(
                    result.unresolved().single().contains(
                        if (body.startsWith("fa")) "Unknown initial RAM" else "Partially known external return",
                    ),
                )
            }
        }
    }

    @Test
    fun `later consumed byte mutation changes dependencies and effect state`() =
        fixture("cd4002c9", extra = mapOf(0x240 to "3e5ac9")) { p, frame, path ->
            val first = trace(p, frame, path)
            p.withTransaction {
                p.listing.clearCodeUnits(address(0x240), address(0x241), false)
                p.memory.setByte(address(0x241), 0x6b)
                Disassembler
                    .getDisassembler(
                        p,
                        TaskMonitor.DUMMY,
                        null,
                    ).disassemble(address(0x240), AddressSet(address(0x240), address(0x242)))
            }
            val second = trace(p, frame, path)
            assertTrue(second.complete(), second.unresolved().toString())
            assertNotEquals(first.dependencies(), second.dependencies())
            assertEquals(
                0x6b,
                second
                    .steps()
                    .first()
                    .afterCall()
                    .registers()
                    .a(),
            )
        }

    @Test
    fun `known later nonlocal return preserves actual destination and popped stack`() =
        fixture("3e80ea00c13e01ea01c1c9", extra = mapOf(0x180 to "c9")) { p, frame, path ->
            val result = trace(p, frame, path)
            assertTrue(result.complete(), result.unresolved().toString())
            assertEquals("NONLOCAL", result.exit())
            assertEquals(
                0x180,
                result
                    .steps()
                    .last()
                    .after()
                    .cpu(),
            )
            assertEquals(
                0xc102,
                result
                    .steps()
                    .last()
                    .after()
                    .sp(),
            )
            assertEquals(
                MapperState.Physical("ROM", 0, 0x180),
                result
                    .steps()
                    .last()
                    .after()
                    .physical(),
            )
        }

    @Test
    fun `later false noReturn remains a veto until matched return repair is reviewed`() =
        fixture("cd4002c9", extra = mapOf(0x240 to "c9")) { p, frame, path ->
            p.withTransaction {
                p.functionManager
                    .createFunction(
                        "later_returning_target",
                        address(0x240),
                        AddressSet(address(0x240)),
                        ghidra.program.model.symbol.SourceType.USER_DEFINED,
                    ).setNoReturn(true)
            }
            val strict = trace(p, frame, path)
            assertTrue(strict.complete(), strict.unresolved().toString())
            assertFalse(strict.nativeCompatible())
            assertTrue(strict.nativeIncompatibilities().any { it.contains("noReturn") })
            val reviewed = SoftwareCallEffects.deriveContinuationForReview(p, frame, path, emptyList(), TaskMonitor.DUMMY)
            assertTrue(reviewed.nativeCompatible(), reviewed.nativeIncompatibilities().toString())
            assertTrue(reviewed.returningCalls().any { it.site() == address(0x153).toString() && it.target() == address(0x240).toString() })
            assertTrue(p.functionManager.getFunctionAt(address(0x240)).hasNoReturn())
        }

    @Test
    fun `later manual software transfer consumes its actual pushed continuation`() {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x230, 0, null)
        fixture(
            "3e03210041015f01c5c33002ea00c2c9",
            extra = mapOf(0x230 to helper.bodyHex(), 0xc100 to "3e6637c9", 0x15f to "ea00c2c9"),
        ) { p, frame, path ->
            val config =
                SoftwareCallValidation.Configuration(
                    0x158,
                    helper,
                    SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION,
                    0xc100,
                    SoftwareCallModel.Registers(3, 0, 0x15f, 0x1234, 0x4100),
                    frame.targetMapper(),
                )
            val result = trace(p, frame, path, listOf(config))
            assertTrue(result.complete(), result.unresolved().toString())
            val call = result.steps().single { it.softwareCall() != null }
            assertEquals("BRANCH", call.transfer())
            assertEquals(0x15f, call.afterCall().cpu())
            assertEquals(0xc100, call.afterCall().sp())
            assertEquals(0x66, call.afterCall().registers().a())
            assertEquals(0x10, call.afterCall().registers().f())
            assertEquals(3, call.afterCall().mapper().romLow())
            val push = result.steps().single { it.before().cpu() == 0x15b }
            assertEquals(listOf(1, 0x5f), push.accesses().filter { it.write() }.map { it.value() })
        }
    }

    @Test
    fun `callee graph preserves competing banks and raw root return before caller continuation`() =
        fixture(
            "c9",
            extra =
                mapOf(
                    0x8000 to "c30003",
                    0x300 to "3e03ea0020c30041",
                    0xc100 to "3e02c34002",
                    0x240 to "ea0020c30041",
                    0x8100 to "3e5bea00c2c9",
                ),
        ) { p, frame, _ ->
            val graph = SoftwareCallEffects.deriveCalleeGraph(p, frame, emptyList(), TaskMonitor.DUMMY)
            assertTrue(graph.complete(), graph.unresolved().toString())
            assertEquals("CALLEE", graph.kind())
            assertEquals(listOf(3, 2), graph.steps().filter { it.before().cpu() == 0x4100 }.map { it.before().physical().bank() })
            assertEquals("RETURN", graph.exit())
            val terminal = graph.steps().last()
            assertEquals("RETURN", terminal.transfer())
            assertEquals(listOf(0x53, 1), terminal.accesses().filter { !it.write() }.map { it.value() })
            assertEquals(0x153, terminal.after().cpu())
            assertEquals(0xc100, terminal.after().sp())
            assertEquals(0x5b, terminal.after().registers().a())
            assertFalse(graph.nativeCompatible())
            assertTrue(graph.transportVetoes().all { it.callDepth() == 0 })
        }

    @Test
    fun `callee graph stops at live restoring epilogue frame without applying wrapper clobbers`() {
        val wrapper = SoftwareCallModel.Template(SoftwareCallModel.Family.RESTORING_REGISTER_JP, 0x230, 0, null)
        fixture("c9", extra = mapOf(0x230 to wrapper.bodyHex(), 0x8000 to "3e7737c9")) { p, _, _ ->
            val entry =
                SoftwareCallModel.Entry(
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    0x153,
                    SoftwareCallModel.Registers(1, 0, 2, 0x1234, 0x4000),
                    MapperState.reset(),
                    byteArrayOf(),
                )
            val frame = SoftwareCallModel.enter(ProgramMapping.cartridge(p), wrapper, HexFormat.of().parseHex(wrapper.bodyHex()), entry)
            val graph = SoftwareCallEffects.deriveCalleeGraph(p, frame, emptyList(), TaskMonitor.DUMMY)
            assertTrue(graph.complete(), graph.unresolved().toString())
            val last = graph.steps().last().after()
            assertEquals(wrapper.epilogueCpu(), last.cpu())
            assertEquals(frame.targetSp() + 2, last.sp())
            assertEquals(0x77, last.registers().a())
            assertEquals(0x10, last.registers().f())
            assertEquals(0x23a, last.registers().bc()) // The helper loads BC with its live epilogue word before JP HL.
            assertEquals(2, last.mapper().romLow())
            val returned =
                SoftwareCallEffects
                    .derive(p, frame, TaskMonitor.DUMMY)
                    .paths()
                    .single()
                    .returned()
            assertEquals(1, returned.registers().a())
            assertEquals(0x100, returned.registers().bc())
            assertEquals(0xc100, returned.sp())
        }
    }

    @Test
    fun `state lowering matches raw architectural operations with two distinct live external return words`() =
        fixture(
            "3e03ea0020c30041",
            extra = mapOf(0xc100 to "3e02c34002", 0x240 to "ea0020c30041", 0x8100 to "3e5bea00c2c9"),
        ) { p, frame, path ->
            val graph = trace(p, frame, path)
            val lowered = SoftwareCallContinuationView.emit(p, address(0x153), graph, emptyList(), 0x70000000L)
            val source = PcodeProgram.fromInstruction(p.listing.getInstructionAt(address(0x153)), false)

            fun execute(
                useLowering: Boolean,
                word: Int,
            ): Pair<Map<String, Int>, List<Pair<Long, Long>>> {
                val arithmetic = BytesPcodeArithmetic.forLanguage(language)
                val state = BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE)
                val executor = PcodeExecutor(language as SleighLanguage, arithmetic, state, Reason.EXECUTE_READ)
                val bus = ContinuationBus(p, state, arithmetic)
                for ((name, value) in mapOf("A" to 2, "F" to 0, "BC" to 2, "DE" to 0x1234, "HL" to 0x4000, "SP" to 0xc100, "PC" to 0x153)) {
                    val register = language.getRegister(name)
                    state.setVar(register, arithmetic.fromConst(value, register.minimumByteSize))
                }
                state.setVar(address(0xc100), 2, true, arithmetic.fromConst(word, 2))
                if (useLowering) {
                    executor.execute(PcodeProgram(source, lowered.toList()), bus)
                } else {
                    // Independent hand-checked path: mapper writes occur in fixed code before each banked fetch.
                    val bank3 = MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, 3)
                    val bank2 = MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, 2)
                    val addresses =
                        listOf(
                            address(0x153),
                            address(0x155),
                            address(0x158),
                            SoftwareCallValidation.executionAddress(p, bank3, 0x4100),
                            SoftwareCallValidation.executionAddress(p, bank3, 0x4102),
                            address(0x240),
                            address(0x243),
                            SoftwareCallValidation.executionAddress(p, bank2, 0x4100),
                            SoftwareCallValidation.executionAddress(p, bank2, 0x4102),
                            SoftwareCallValidation.executionAddress(p, bank2, 0x4105),
                        )
                    for (at in addresses) executor.execute(PcodeProgram.fromInstruction(p.listing.getInstructionAt(at), false), bus)
                }

                fun value(name: String): Int =
                    state.getVar(language.getRegister(name), Reason.INSPECT).foldIndexed(0) { index, total, byte ->
                        total or
                            ((byte.toInt() and 255) shl (index * 8))
                    }
                val values =
                    listOf("A", "F", "BC", "DE", "HL", "SP", "PC").associateWith { value(it) } +
                        ("c200" to (state.getVar(address(0xc200), 1, true, Reason.INSPECT)[0].toInt() and 255))
                assertEquals(word, values["PC"])
                assertEquals(0xc102, values["SP"])
                assertEquals(0x5b, values["A"])
                assertEquals(0x5b, values["c200"])
                assertEquals(listOf(0x2000L to 3L, 0x2000L to 2L), bus.writes)
                return values to bus.writes
            }
            for (word in listOf(0x3456, 0x6789)) assertEquals(execute(false, word), execute(true, word))
        }

    @Test
    fun `nested invocation slices retain live frames and normalize only native graph depth`() =
        fixture(
            "c9",
            extra =
                mapOf(
                    0x8000 to "cd004247c9",
                    0x8200 to "3e03ea0020",
                    0xc205 to "cd00433e02ea0020",
                    0xc300 to "0cc9",
                    0x820d to "c9",
                ),
        ) { p, frame, _ ->
            val source = SoftwareCallEffects.deriveCalleeGraph(p, frame, emptyList(), TaskMonitor.DUMMY)
            assertTrue(source.complete(), source.unresolved().toString())
            val invocations = SoftwareCallEffects.calleeInvocations(source)
            assertEquals(2, invocations.size)
            val outer = invocations[0].graph()
            val inner = invocations[1].graph()
            assertEquals(
                0x4200,
                outer
                    .steps()
                    .first()
                    .before()
                    .cpu(),
            )
            assertEquals(
                0xc0fc,
                outer
                    .steps()
                    .first()
                    .before()
                    .sp(),
            )
            assertEquals(
                0x4003,
                outer
                    .steps()
                    .last()
                    .after()
                    .cpu(),
            )
            assertEquals(
                0xc0fe,
                outer
                    .steps()
                    .last()
                    .after()
                    .sp(),
            )
            assertEquals(0, outer.steps().first().callDepth())
            assertEquals(1, outer.steps().maxOf { it.callDepth() })
            assertTrue(outer.transportVetoes().any { it.callDepth() == 0 && it.kind() == "FETCH_SPACE" })
            assertEquals(
                0x4300,
                inner
                    .steps()
                    .first()
                    .before()
                    .cpu(),
            )
            assertEquals(
                0xc0fa,
                inner
                    .steps()
                    .first()
                    .before()
                    .sp(),
            )
            assertEquals(
                0x4208,
                inner
                    .steps()
                    .last()
                    .after()
                    .cpu(),
            )
            assertEquals(
                0xc0fc,
                inner
                    .steps()
                    .last()
                    .after()
                    .sp(),
            )
            assertTrue(inner.steps().all { it.callDepth() == 0 })
            assertNull(inner.steps().last().successor())
            assertNotEquals(source.dependencies(), outer.dependencies())
            assertNotEquals(outer.dependencies(), inner.dependencies())
        }

    @Test
    fun `later nonreturning call retains live hardware frame and terminal callee loop`() =
        fixture("cd4002c9", extra = mapOf(0x240 to "18fe")) { p, frame, path ->
            val graph = trace(p, frame, path)
            assertTrue(graph.complete(), graph.unresolved().toString())
            assertEquals("LOOP", graph.exit())
            val call = graph.steps().first()
            assertNull(call.afterCall())
            assertEquals("NONRETURNING", call.callOutcome().exit())
            assertEquals(0xc0fe, call.callOutcome().state().sp())
            assertEquals(0x240, call.callOutcome().state().cpu())
            val live = call.callOutcome().liveFrames().single()
            assertEquals(0x156, live.returnCpu())
            assertEquals(0xc0fe, live.returnWordCpu())
            assertEquals(0x156, live.liveReturnWord())
            val callee = SoftwareCallEffects.calleeInvocations(graph).single().graph()
            assertEquals("LOOP", callee.exit())
            assertEquals(callee.steps().first().index(), callee.steps().last().successor())
        }

    @Test
    fun `later nonlocal call records changed live return word without a balanced afterCall`() =
        fixture("cd4002c9", extra = mapOf(0x240 to "f8003680233601c9", 0x180 to "c9")) { p, frame, path ->
            val graph = trace(p, frame, path)
            assertTrue(graph.complete(), graph.unresolved().toString())
            assertEquals("RETURN", graph.exit())
            val call = graph.steps().first()
            assertNull(call.afterCall())
            assertEquals(
                0x180,
                graph
                    .steps()
                    .single { it.index() == call.callOutcome().resumeStep() }
                    .before()
                    .cpu(),
            )
            assertEquals("NONLOCAL", call.callOutcome().exit())
            assertEquals(0xc100, call.callOutcome().state().sp())
            assertEquals(0x180, call.callOutcome().state().cpu())
            val live = call.callOutcome().liveFrames().single()
            assertEquals(0x156, live.returnCpu())
            assertEquals(0x180, live.liveReturnWord())
            assertTrue(graph.nativeIncompatibilities().any { it.contains("bypasses an active native call frame") })
            val callee = SoftwareCallEffects.calleeInvocations(graph).single().graph()
            assertEquals("NONLOCAL", callee.exit())
            assertEquals(
                0x180,
                callee
                    .steps()
                    .last()
                    .after()
                    .cpu(),
            )
            assertTrue(callee.transportVetoes().any { it.kind() == "NONLOCAL_CALL" && it.callDepth() == 0 })
        }

    @Test
    fun `later configured nonreturn skips wrapper epilogue while unknown callee never gains outcome`() {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.RESTORING_REGISTER_JP, 0x230, 0, null)
        fixture("3e02010300210041cd3002c9", extra = mapOf(0x230 to helper.bodyHex(), 0xc100 to "18fe")) { p, frame, path ->
            p.withTransaction {
                val at = address(helper.epilogueCpu().toLong())
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(
                    at,
                    AddressSet(
                        at,
                        address(0x230 + helper.bodyHex().length.toLong() / 2 - 1),
                    ),
                )
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x15b,
                    helper,
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 3, 0x1234, 0x4100),
                    frame.targetMapper(),
                )
            val graph = trace(p, frame, path, listOf(config))
            assertTrue(graph.complete(), graph.unresolved().toString())
            val call = graph.steps().single { it.softwareCall() != null }
            assertNull(call.afterCall())
            assertEquals("NONRETURNING", call.callOutcome().exit())
            assertEquals(
                3,
                call
                    .callOutcome()
                    .state()
                    .mapper()
                    .romLow(),
            )
            assertEquals(
                helper.epilogueCpu(),
                call
                    .callOutcome()
                    .state()
                    .registers()
                    .bc(),
            )
            assertEquals(
                1,
                call
                    .callOutcome()
                    .liveFrames()
                    .single()
                    .phase(),
            )
            assertFalse(graph.steps().any { it.before().cpu() == helper.epilogueCpu() })
            assertEquals(
                0x4100,
                SoftwareCallEffects
                    .calleeInvocations(graph)
                    .single()
                    .graph()
                    .steps()
                    .first()
                    .before()
                    .cpu(),
            )
        }
        fixture("cd4002c9", extra = mapOf(0x240 to "fa00c2c9")) { p, frame, path ->
            val graph = trace(p, frame, path)
            assertFalse(graph.complete())
            assertNull(graph.steps().first().callOutcome())
        }
    }

    @Test
    fun `stateful continuation binds exact callee prerequisite while retaining original vetoes`() =
        fixture(
            "cd6002c9",
            extra =
                mapOf(
                    0x8000 to "c30003",
                    0x300 to "3e03ea0020c30041",
                    0xc100 to "3e02c34002",
                    0x240 to "ea0020c30041",
                    0x8100 to "3e5bea00c2c9",
                    0x260 to "3e07c9",
                ),
        ) { p, frame, path ->
            val graph = trace(p, frame, path)
            assertTrue(graph.complete(), graph.unresolved().toString())
            val prerequisite = graph.prerequisiteCallee()
            assertEquals("CALLEE", prerequisite.kind())
            assertEquals(
                0x5b,
                prerequisite
                    .steps()
                    .last()
                    .after()
                    .registers()
                    .a(),
            )
            assertEquals(
                0x5b,
                graph
                    .steps()
                    .first()
                    .before()
                    .registers()
                    .a(),
            )
            assertEquals(
                7,
                graph
                    .steps()
                    .first()
                    .afterCall()
                    .registers()
                    .a(),
            )
            assertTrue(graph.transportVetoes().any { it.step() < 0 })
            assertFalse(graph.nativeCompatible())
            assertNotEquals(prerequisite.dependencies(), graph.dependencies())
        }

    @Test
    fun `nonlocal software target resumes real cleanup code with saved wrapper words intact`() {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.RESTORING_REGISTER_JP, 0x230, 0, null)
        fixture(
            "3e02010300210041cd3002c9",
            extra =
                mapOf(
                    0x230 to helper.bodyHex(),
                    0xc100 to "f8003680233601c9",
                    0x180 to "c1d13e07ea30c2c9",
                ),
        ) { p, frame, path ->
            p.withTransaction {
                val at = address(helper.epilogueCpu().toLong())
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(
                    at,
                    AddressSet(
                        at,
                        address(0x230 + helper.bodyHex().length.toLong() / 2 - 1),
                    ),
                )
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x15b,
                    helper,
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 3, 0x1234, 0x4100),
                    frame.targetMapper(),
                )
            val graph = trace(p, frame, path, listOf(config))
            assertTrue(graph.complete(), graph.unresolved().toString())
            assertEquals("RETURN", graph.exit())
            val call = graph.steps().single { it.softwareCall() != null }
            assertNull(call.afterCall())
            assertEquals("NONLOCAL", call.callOutcome().exit())
            assertEquals(0xc0fc, call.callOutcome().state().sp())
            assertEquals(
                3,
                call
                    .callOutcome()
                    .state()
                    .mapper()
                    .romLow(),
            )
            assertEquals(
                0x180,
                graph
                    .steps()
                    .single { it.index() == call.callOutcome().resumeStep() }
                    .before()
                    .cpu(),
            )
            assertFalse(graph.steps().any { it.before().cpu() == helper.epilogueCpu() })
            val terminal = graph.steps().last().before()
            assertEquals(0x200, terminal.registers().bc())
            assertEquals(0x15e, terminal.registers().de())
            assertEquals(7, terminal.registers().a())
            assertEquals(3, terminal.mapper().romLow())
            assertEquals(0xc100, terminal.sp())
            assertEquals(
                "NONLOCAL",
                SoftwareCallEffects
                    .calleeInvocations(graph)
                    .single()
                    .graph()
                    .exit(),
            )
        }
    }

    @Test
    fun `unmatched nonlocal stack boundary remains unresolved with no invented departed frame`() =
        fixture("cd4002c9", extra = mapOf(0x240 to "3e00ea00c133c9")) { p, frame, path ->
            val graph = trace(p, frame, path)
            assertFalse(graph.complete())
            assertTrue(graph.unresolved().single().contains("exactly departed native frame boundaries"))
            assertNull(graph.steps().first().callOutcome())
        }

    @Test
    fun `initial software nonlocal preserves actual SP while locating the original live external frame`() {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.RESTORING_REGISTER_JP, 0x230, 0, null)
        fixture("c9", extra = mapOf(0x230 to helper.bodyHex(), 0x8000 to "f8003680233601c9", 0x180 to "c1d13e07ea30c2c9")) { p, _, _ ->
            val entry =
                SoftwareCallModel.Entry(
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    0x153,
                    SoftwareCallModel.Registers(1, 0, 2, 0x1234, 0x4000),
                    MapperState.reset(),
                    byteArrayOf(),
                )
            val frame = SoftwareCallModel.enter(ProgramMapping.cartridge(p), helper, HexFormat.of().parseHex(helper.bodyHex()), entry)
            val summary = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertTrue(summary.complete(), summary.unresolved().toString())
            val path = summary.paths().single()
            assertEquals(SoftwareCallModel.Exit.NONLOCAL, path.returned().exit())
            assertEquals(0xc0fc, path.returned().sp())
            val graph = trace(p, frame, path)
            assertTrue(graph.complete(), graph.unresolved().toString())
            assertEquals(
                0xc0fc,
                graph
                    .steps()
                    .first()
                    .before()
                    .sp(),
            )
            assertEquals(
                0xc100,
                graph
                    .steps()
                    .last()
                    .before()
                    .sp(),
            )
            assertEquals(
                0x100,
                graph
                    .steps()
                    .last()
                    .before()
                    .registers()
                    .bc(),
            )
            assertEquals(
                0x153,
                graph
                    .steps()
                    .last()
                    .before()
                    .registers()
                    .de(),
            )
            assertEquals(
                2,
                graph
                    .steps()
                    .last()
                    .before()
                    .mapper()
                    .romLow(),
            )
            assertEquals("RETURN", graph.exit())
        }
    }

    @Test
    fun `initial nested nonlocal frame retires by exact SP and outer continuation still executes`() =
        fixture("3cea31c2c9", extra = mapOf(0x8000 to "cd4002c9", 0x240 to "f8003680233601c9", 0x180 to "3e07ea30c2c9")) { p, frame, path ->
            assertEquals(SoftwareCallModel.Exit.MAY_RETURN, path.returned().exit())
            assertEquals(7, path.returned().registers().a())
            assertEquals(0xc100, path.returned().sp())
            val graph = trace(p, frame, path)
            assertTrue(graph.complete(), graph.unresolved().toString())
            assertEquals(
                "NONLOCAL",
                graph
                    .prerequisiteCallee()
                    .steps()
                    .first()
                    .callOutcome()
                    .exit(),
            )
            assertEquals(
                0xc0fe,
                graph
                    .prerequisiteCallee()
                    .steps()
                    .first()
                    .callOutcome()
                    .state()
                    .sp(),
            )
            assertEquals(
                8,
                graph
                    .steps()
                    .last()
                    .before()
                    .registers()
                    .a(),
            )
            assertTrue(graph.steps().flatMap { it.accesses() }.any { it.write() && it.cpu() == 0xc231 && it.value() == 8 })
            assertEquals("RETURN", graph.exit())
        }
}
