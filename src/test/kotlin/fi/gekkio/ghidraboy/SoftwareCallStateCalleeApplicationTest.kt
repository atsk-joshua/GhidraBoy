package fi.gekkio.ghidraboy

import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
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
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayload
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

/** Native/public counterparts of the unchanged physical instruction fixtures in SoftwareCallStatePathsTest. */
class SoftwareCallStateCalleeApplicationTest : IntegrationTest() {
    private data class Code(
        val bank: Int,
        val cpu: Int,
        val hex: String,
    )

    private fun fixture(
        code: List<Code>,
        expectedBC: Int,
        flags: Int = 0,
        data: Map<Int, Int> = emptyMap(),
        fresh: Boolean = false,
        expectedA: Int? = null,
    ) {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val observer = "efea02c278ea00c279ea01c2c9"
        val image = ByteArray(0x10000)
        image[0x147] = 0x13
        image[0x148] = 1
        HexFormat.of().parseHex(helper.bodyHex()).copyInto(image, 0x28)
        HexFormat.of().parseHex(observer).copyInto(image, 0x200)
        for (chunk in code) HexFormat.of().parseHex(chunk.hex).copyInto(image, chunk.bank * 0x4000 + chunk.cpu - 0x4000)
        for ((offset, value) in data) image[offset] = value.toByte()
        val consumer = Any()
        val p = ProgramDB("public state-sensitive callee", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(image).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, TaskMonitor.DUMMY, MessageLog())
            }

            fun physical(
                bank: Int,
                cpu: Int,
            ): Address =
                SoftwareCallValidation.executionAddress(p, MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, bank), cpu)
            val target = physical(2, 0x4100)
            p.withTransaction {
                if (!fresh) {
                    val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                    disassembler.disassemble(address(0x28), AddressSet(address(0x28), address(0x28 + helper.bodyHex().length / 2L - 1)))
                    disassembler.disassemble(address(0x200), AddressSet(address(0x200), address(0x200 + observer.length / 2L - 1)))
                    for (chunk in code) {
                        val at = physical(chunk.bank, chunk.cpu)
                        disassembler.disassemble(at, AddressSet(at, at.add(chunk.hex.length / 2L - 1)))
                    }
                }
                p.functionManager.createFunction(
                    "state_caller",
                    address(0x200),
                    AddressSet(
                        address(0x200),
                        address(0x200 + observer.length / 2L - 1),
                    ),
                    SourceType.USER_DEFINED,
                )
                p.symbolTable.createLabel(target, "state_callee", SourceType.USER_DEFINED)
                p.symbolTable.createLabel(address(0x350), "preserved_unrelated_symbol", SourceType.USER_DEFINED)
            }
            if (fresh) {
                assertNull(p.listing.getInstructionAt(address(0x28)))
                assertNull(p.listing.getInstructionAt(target))
                assertNull(p.listing.getInstructionAt(address(0x201)))
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x200,
                    helper,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(2, flags, 0, 0, 0x4100),
                    MapperState.reset(),
                )
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            val graph = review.stateCallees().getValue(address(0x200).toString())
            assertEquals("CALLEE", graph.kind())
            assertEquals(
                expectedBC,
                graph
                    .steps()
                    .last()
                    .after()
                    .registers()
                    .bc(),
            )
            if (expectedA != null) {
                assertEquals(
                    expectedA,
                    graph
                        .steps()
                        .last()
                        .after()
                        .registers()
                        .a(),
                )
            }
            assertEquals(
                0xc0fe,
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
                    .after()
                    .sp(),
            )
            if (fresh) {
                assertTrue(review.instructionDiscovery().candidates().isNotEmpty())
                assertNull(p.listing.getInstructionAt(target))
            }
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val aliases = mutableListOf<Address>()
            val functions = p.functionManager.getFunctions(true)
            while (functions.hasNext()) {
                val entry = functions.next().entryPoint
                if (entry != target && entry.addressSpace.name.startsWith(SoftwareCallExecutionView.PREFIX) &&
                    ProgramMapping.staticToPhysical(p, entry) == ProgramMapping.staticToPhysical(p, target)
                ) {
                    aliases.add(entry)
                }
            }
            assertEquals(1, aliases.size)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                for (entry in listOf(target) + aliases + address(0x200)) {
                    val result = decompiler.decompileFunction(p.functionManager.getFunctionAt(entry), 30, TaskMonitor.DUMMY)
                    assertTrue(result.decompileCompleted(), "$entry: ${result.errorMessage}")
                    val c = result.decompiledFunction.c
                    assertFalse(c.contains("bad instruction", ignoreCase = true), c)
                    assertFalse(c.contains("truncating control flow", ignoreCase = true), c)
                    assertFalse(c.contains("halt_baddata"), c)
                    val ops =
                        result.highFunction.pcodeOps
                            .asSequence()
                            .toList()
                    assertTrue(ops.any { it.opcode == PcodeOp.RETURN }, c)
                    if (entry == address(0x200)) {
                        assertTrue(
                            ops.any {
                                it.opcode == PcodeOp.CALL &&
                                    ProgramMapping.staticToPhysical(p, it.getInput(0).address) == ProgramMapping.staticToPhysical(p, target)
                            },
                            c,
                        )
                        val expectedWrites =
                            mapOf(0xc200 to (expectedBC ushr 8), 0xc201 to (expectedBC and 255)) +
                                if (expectedA == null) emptyMap() else mapOf(0xc202 to expectedA)
                        for ((cpu, value) in expectedWrites) {
                            assertTrue(
                                ops.any { op ->
                                    (
                                        op.opcode == PcodeOp.COPY && op.output?.address == address(cpu.toLong()) &&
                                            op.getInput(0).isConstant &&
                                            op.getInput(0).offset == value.toLong()
                                    ) ||
                                        (
                                            op.opcode == PcodeOp.STORE &&
                                                op
                                                    .getInput(
                                                        1,
                                                    ).isConstant && op.getInput(1).offset == cpu.toLong() &&
                                                op.getInput(2).isConstant &&
                                                op.getInput(2).offset == value.toLong()
                                        )
                                },
                                c,
                            )
                        }
                    }
                }
            } finally {
                decompiler.dispose()
            }
            for (chunk in code) assertNotNull(p.listing.getInstructionAt(physical(chunk.bank, chunk.cpu)))
            assertTrue(p.symbolTable.getSymbols("preserved_unrelated_symbol").hasNext())
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `native public callee revisits one CPU PC in two physical banks`() =
        fixture(
            listOf(Code(2, 0x4100, "043e03ea0020"), Code(3, 0x4106, "c30041"), Code(3, 0x4100, "0cc30042"), Code(3, 0x4200, "c9")),
            0x0101,
        )

    @Test
    fun `fresh missing callee helper and continuation instructions become reviewed native state entries`() =
        fixture(
            listOf(Code(2, 0x4100, "043e03ea0020"), Code(3, 0x4106, "c30041"), Code(3, 0x4100, "0cc30042"), Code(3, 0x4200, "c9")),
            0x0101,
            fresh = true,
        )

    @Test
    fun `native callee banked data identities remain distinct at identical CPU address`() =
        fixture(
            listOf(Code(2, 0x4100, "fa0050473e03ea0020"), Code(3, 0x4109, "fa00504fc9")),
            0x2233,
            data = mapOf(0x9000 to 0x22, 0xd000 to 0x33),
        )

    @Test
    fun `native nested ordinary calls restore prior bank before consuming live frames`() =
        fixture(
            listOf(
                Code(2, 0x4100, "cd004247c9"),
                Code(2, 0x4200, "3e03ea0020"),
                Code(3, 0x4205, "cd00433e02ea0020"),
                Code(3, 0x4300, "0cc9"),
                Code(2, 0x420d, "c9"),
            ),
            0x0201,
        )

    @Test
    fun `conditional selector premises reach same CPU PC in different banks through normal native entries`() {
        val code =
            listOf(
                Code(2, 0x4100, "ca20413e03ea0020"),
                Code(3, 0x4108, "c30042"),
                Code(2, 0x4120, "3e02ea0020c30042"),
                Code(2, 0x4200, "3e22c9"),
                Code(3, 0x4200, "3e33c9"),
            )
        fixture(code, 0, flags = 0, expectedA = 0x33)
        fixture(code, 0, flags = 0x80, expectedA = 0x22)
    }

    @Test
    fun `same Program retains both flag contexts and public canonical selection changes native physical path`() {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val chunks =
            listOf(
                Code(2, 0x4100, "ca20413e03ea0020"),
                Code(3, 0x4108, "c30042"),
                Code(2, 0x4120, "3e02ea0020c30042"),
                Code(2, 0x4200, "3e22ea10c2c9"),
                Code(3, 0x4200, "3e33ea10c2c9"),
            )
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                HexFormat.of().parseHex(helper.bodyHex()).copyInto(this, 0x28)
                HexFormat.of().parseHex("efc9").copyInto(this, 0x200)
                HexFormat.of().parseHex("efc9").copyInto(this, 0x300)
                for (chunk in chunks) HexFormat.of().parseHex(chunk.hex).copyInto(this, chunk.bank * 0x4000 + chunk.cpu - 0x4000)
            }
        val consumer = Any()
        val p = ProgramDB("two public callee contexts", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, TaskMonitor.DUMMY, MessageLog())
            }

            fun at(
                bank: Int,
                cpu: Int,
            ): Address =
                SoftwareCallValidation.executionAddress(p, MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, bank), cpu)
            val target = at(2, 0x4100)
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                disassembler.disassemble(address(0x28), AddressSet(address(0x28), address(0x28 + helper.bodyHex().length / 2L - 1)))
                for (caller in listOf(0x200, 0x300)) {
                    disassembler.disassemble(address(caller.toLong()), AddressSet(address(caller.toLong()), address(caller + 1L)))
                    p.functionManager.createFunction(
                        "caller_${caller.toString(16)}",
                        address(caller.toLong()),
                        AddressSet(
                            address(caller.toLong()),
                            address(caller + 1L),
                        ),
                        SourceType.USER_DEFINED,
                    )
                }
                for (chunk in chunks) {
                    disassembler.disassemble(
                        at(chunk.bank, chunk.cpu),
                        AddressSet(
                            at(chunk.bank, chunk.cpu),
                            at(chunk.bank, chunk.cpu).add(chunk.hex.length / 2L - 1),
                        ),
                    )
                }
                p.functionManager
                    .createFunction(
                        "shared_state_callee",
                        target,
                        AddressSet(target, target.add(7)),
                        SourceType.USER_DEFINED,
                    ).comment =
                    "Original callee note"
            }
            val configs =
                listOf(0x200 to 0, 0x300 to 0x80).map { (caller, flags) ->
                    SoftwareCallValidation.Configuration(
                        caller,
                        helper,
                        SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                        0xc100,
                        SoftwareCallModel.Registers(2, flags, 0, 0, 0x4100),
                        MapperState.reset(),
                    )
                }
            val review = SoftwareCallApplication.preview(p, configs, TaskMonitor.DUMMY)
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val contexts = SoftwareCallRegistry.stateContexts(p, target, TaskMonitor.DUMMY)
            assertEquals(2, contexts.size)
            val byCaller = contexts.associateBy { it.site() }
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))

                fun verify(
                    entry: Address,
                    value: Int,
                ) {
                    val result = decompiler.decompileFunction(p.functionManager.getFunctionAt(entry), 30, TaskMonitor.DUMMY)
                    assertTrue(result.decompileCompleted(), result.errorMessage)
                    val c = result.decompiledFunction.c
                    assertFalse(c.contains("bad instruction", ignoreCase = true), c)
                    assertFalse(c.contains("truncating control flow", ignoreCase = true), c)
                    assertTrue(
                        result.highFunction.pcodeOps.asSequence().any { op ->
                            (
                                op.opcode == PcodeOp.COPY && op.output?.address == address(0xc210) && op.getInput(0).isConstant &&
                                    op.getInput(0).offset == value.toLong()
                            ) ||
                                (
                                    op.opcode == PcodeOp.STORE && op.getInput(1).isConstant && op.getInput(1).offset == 0xc210L &&
                                        op.getInput(2).isConstant &&
                                        op.getInput(2).offset == value.toLong()
                                )
                        },
                        c,
                    )
                }
                for ((caller, expected) in listOf(0x200 to 0x33, 0x300 to 0x22)) {
                    val context = byCaller.getValue(address(caller.toLong()).toString())
                    val entry = ProgramMapping.staticAddress(p, context.entry())
                    val payload =
                        p.compilerSpec.pcodeInjectLibrary.getPayload(
                            InjectPayload.CALLMECHANISM_TYPE,
                            SoftwareCallStateEntryInjection.NAME,
                        )
                    val injectionContext = InjectContext()
                    injectionContext.baseAddr = entry
                    injectionContext.nextAddr = entry
                    val injected = payload.getPcode(p, injectionContext)
                    val rawProgram = PcodeProgram.fromInstruction(p.listing.getInstructionAt(target), false)

                    fun execute(
                        lowered: Boolean,
                        externalWord: Int,
                    ): Pair<Map<String, Int>, List<Pair<Long, Long>>> {
                        val arithmetic = BytesPcodeArithmetic.forLanguage(language)
                        val state = BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE)
                        val executor = PcodeExecutor(language as SleighLanguage, arithmetic, state, Reason.EXECUTE_READ)
                        val bus = SoftwareCallContinuationTest.ContinuationBus(p, state, arithmetic)
                        for ((name, value) in mapOf(
                            "A" to 2,
                            "F" to
                                if (caller ==
                                    0x200
                                ) {
                                    0
                                } else {
                                    0x80
                                },
                            "BC" to 0,
                            "DE" to 0,
                            "HL" to 0x4100,
                            "SP" to 0xc0fe,
                            "PC" to 0x4100,
                        )) {
                            val register = language.getRegister(name)
                            state.setVar(register, arithmetic.fromConst(value, register.minimumByteSize))
                        }
                        state.setVar(address(0xc0fe), 2, true, arithmetic.fromConst(caller + 1, 2))
                        state.setVar(address(0xc100), 2, true, arithmetic.fromConst(externalWord, 2))
                        if (lowered) {
                            executor.execute(PcodeProgram(rawProgram, injected.toList()), bus)
                        } else {
                            val physicalPath =
                                if (caller ==
                                    0x200
                                ) {
                                    listOf(
                                        at(2, 0x4100),
                                        at(2, 0x4103),
                                        at(2, 0x4105),
                                        at(3, 0x4108),
                                        at(3, 0x4200),
                                        at(3, 0x4202),
                                        at(3, 0x4205),
                                    )
                                } else {
                                    listOf(
                                        at(2, 0x4100),
                                        at(2, 0x4120),
                                        at(2, 0x4122),
                                        at(2, 0x4125),
                                        at(2, 0x4200),
                                        at(2, 0x4202),
                                        at(2, 0x4205),
                                    )
                                }
                            for (physicalEntry in physicalPath) {
                                executor.execute(
                                    PcodeProgram.fromInstruction(p.listing.getInstructionAt(physicalEntry), false),
                                    bus,
                                )
                            }
                        }

                        fun register(name: String): Int =
                            state.getVar(language.getRegister(name), Reason.INSPECT).foldIndexed(0) { index, value, byte ->
                                value or
                                    ((byte.toInt() and 255) shl (index * 8))
                            }
                        val result =
                            listOf("A", "F", "BC", "DE", "HL", "SP", "PC").associateWith { register(it) } +
                                ("c210" to (state.getVar(address(0xc210), 1, true, Reason.INSPECT)[0].toInt() and 255))
                        assertEquals(caller + 1, result["PC"])
                        assertEquals(0xc100, result["SP"])
                        assertEquals(expected, result["c210"])
                        assertEquals(
                            listOf(externalWord and 255, externalWord ushr 8),
                            state.getVar(address(0xc100), 2, true, Reason.INSPECT).map {
                                it.toInt() and
                                    255
                            },
                        )
                        return result to bus.writes
                    }
                    for (externalWord in listOf(0x3456, 0x6789)) assertEquals(execute(false, externalWord), execute(true, externalWord))
                    verify(entry, expected)
                    val result =
                        decompiler.decompileFunction(
                            p.functionManager.getFunctionAt(address(caller.toLong())),
                            30,
                            TaskMonitor.DUMMY,
                        )
                    assertTrue(result.decompileCompleted(), result.errorMessage)
                    assertTrue(
                        result.highFunction.pcodeOps.asSequence().any {
                            it.opcode == PcodeOp.CALL && it.getInput(0).address == entry
                        },
                        result.decompiledFunction.c,
                    )
                    assertEquals(ProgramMapping.staticToPhysical(p, target), ProgramMapping.staticToPhysical(p, entry))
                    SoftwareCallRegistry.selectStateContext(p, target, entry, TaskMonitor.DUMMY)
                    verify(target, expected)
                    assertTrue(
                        SoftwareCallRegistry
                            .stateContexts(
                                p,
                                target,
                                TaskMonitor.DUMMY,
                            ).single { it.selected() }
                            .entry() == context.entry(),
                    )
                    assertTrue(
                        p.functionManager
                            .getFunctionAt(target)
                            .comment
                            .contains("Original callee note"),
                    )
                }
            } finally {
                decompiler.dispose()
            }
        } finally {
            p.release(consumer)
        }
    }
}
