package fi.gekkio.ghidraboy

import ghidra.app.decompiler.DecompInterface
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
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
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

class SoftwareCallStateContinuationApplicationTest : IntegrationTest() {
    private fun physical(
        p: ProgramDB,
        offset: Int,
    ): Address {
        val cpu = if (offset < 0x4000) offset else 0x4000 + offset % 0x4000
        return ProgramMapping.fileToStatic(p, offset.toLong()).single {
            it.offset == cpu.toLong() &&
                SoftwareCallExecutionView.canonical(p, it)
        }
    }

    private fun fixture(
        continuation: String,
        code: Map<Int, String> = emptyMap(),
        data: Map<Int, String> = emptyMap(),
        functions: Map<Int, String> = emptyMap(),
        action: (ProgramDB, SoftwareCallValidation.Configuration, Address) -> Unit,
    ) {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val regions = linkedMapOf(0x28 to helper.bodyHex(), 0x4500 to "ef", 0x8000 to "c9", 0x8501 to continuation)
        regions.putAll(code)
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                for ((at, hex) in regions + data) HexFormat.of().parseHex(hex).copyInto(this, at)
            }
        val consumer = Any()
        val p = ProgramDB("state-qualified public continuation", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, TaskMonitor.DUMMY, MessageLog())
            }
            val root = physical(p, 0x4500)
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                for ((offset, hex) in regions) {
                    val at = physical(p, offset)
                    disassembler.disassemble(at, AddressSet(at, at.add(hex.length.toLong() / 2 - 1)))
                }
                for ((offset, name) in mapOf(0x4500 to "state_source", 0x8000 to "initial_target") + functions) {
                    val at = physical(p, offset)
                    p.functionManager.createFunction(
                        name,
                        at,
                        AddressSet(at, at.add(regions.getValue(offset).length.toLong() / 2 - 1)),
                        SourceType.USER_DEFINED,
                    )
                }
                p.symbolTable.createLabel(address(0x350), "preserved_user_knowledge", SourceType.USER_DEFINED)
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x4500,
                    helper,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 0, 0, 0x4000),
                    MapperState.reset(),
                )
            action(p, config, root)
        } finally {
            p.release(consumer)
        }
    }

    private fun alias(
        p: ProgramDB,
        review: SoftwareCallApplication.Review,
        root: Address,
    ): Address = p.addressFactory.getAddressSpace(review.executionViews().getValue(root.toString()).name()).getAddress(root.offset)

    private fun verifyNative(
        p: ProgramDB,
        decompiler: DecompInterface,
        entries: List<Address>,
        writes: Map<Int, Int>,
        calls: List<Address>,
    ) {
        for (entry in entries) {
            val result = decompiler.decompileFunction(p.functionManager.getFunctionAt(entry), 30, TaskMonitor.DUMMY)
            assertTrue(result.decompileCompleted(), "$entry: ${result.errorMessage}")
            val c = result.decompiledFunction.c
            assertFalse(c.contains("bad instruction", ignoreCase = true), c)
            assertFalse(c.contains("truncating control flow", ignoreCase = true), c)
            assertFalse(c.contains("halt_baddata"), c)
            val operations =
                result.highFunction.pcodeOps
                    .asSequence()
                    .toList()
            for (target in calls) {
                assertTrue(
                    operations.any {
                        it.opcode == PcodeOp.CALL &&
                            ProgramMapping.staticToPhysical(
                                p,
                                if (StockEntryInjection.owned(
                                        p,
                                        it.getInput(0).address,
                                    )
                                ) {
                                    StockEntries.source(p, it.getInput(0).address)
                                } else {
                                    it.getInput(0).address
                                },
                            ) ==
                            ProgramMapping.staticToPhysical(p, target)
                    },
                    "$entry missing $target\n$c",
                )
            }
            for ((cpu, value) in writes) {
                assertTrue(
                    operations.any { op ->
                        (
                            op.opcode == PcodeOp.COPY && op.output?.address == address(cpu.toLong()) && op.getInput(0).isConstant &&
                                op.getInput(0).offset == value.toLong()
                        ) ||
                            (
                                op.opcode == PcodeOp.STORE && op.getInput(1).isConstant && op.getInput(1).offset == cpu.toLong() &&
                                    op.getInput(2).isConstant &&
                                    op.getInput(2).offset == value.toLong()
                            )
                    },
                    "$entry missing write ${cpu.toString(16)}=${value.toString(16)}\n$c",
                )
            }
            assertTrue(operations.any { it.opcode == PcodeOp.RETURN }, c)
        }
    }

    @Test
    fun `public canonical and derived roots retain repeated CPU fetches from competing banks`() =
        fixture(
            "c30003",
            code = mapOf(0x300 to "3e03ea0020c30041", 0xc100 to "3e02c34002", 0x240 to "ea0020c30041", 0x8100 to "3e5bea00c2c9"),
        ) { p, config, root ->
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            val graph = review.stateContinuations().getValue(root.toString())
            assertEquals(listOf(3, 2), graph.steps().filter { it.before().cpu() == 0x4100 }.map { it.before().physical().bank() })
            assertTrue(review.executionViews().size >= 3)
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val derived = alias(p, review, root)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                verifyNative(p, decompiler, listOf(root, derived), mapOf(0xc200 to 0x5b), listOf(physical(p, 0x8000)))
            } finally {
                decompiler.dispose()
            }
            assertNotNull(p.listing.getInstructionAt(physical(p, 0xc100)))
            assertNotNull(p.listing.getInstructionAt(physical(p, 0x8100)))
            assertTrue(p.symbolTable.getSymbols("preserved_user_knowledge").hasNext())
        }

    @Test
    fun `banked data mutation invalidates paired roots and same interface sees reviewed new values`() =
        fixture(
            "c30003",
            code = mapOf(0x300 to "3e03ea00202100427eea00c23e02ea00207eea01c2c9"),
            data = mapOf(0xc200 to "a7", 0x8200 to "5c"),
        ) { p, config, root ->
            val first = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            SoftwareCallApplication.apply(p, first, TaskMonitor.DUMMY)
            val oldAlias = alias(p, first, root)
            val initialTarget = physical(p, 0x8000)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                verifyNative(p, decompiler, listOf(root, oldAlias), mapOf(0xc200 to 0xa7, 0xc201 to 0x5c), listOf(initialTarget))
                p.withTransaction { p.memory.setByte(physical(p, 0xc200), 0x6b) }
                for (entry in listOf(
                    root,
                    oldAlias,
                )) {
                    assertThrows(IllegalArgumentException::class.java) { SoftwareCallRegistry.resolve(p, entry) }
                }
                AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
                val updated = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
                SoftwareCallApplication.apply(p, updated, TaskMonitor.DUMMY)
                verifyNative(
                    p,
                    decompiler,
                    listOf(root, alias(p, updated, root)),
                    mapOf(0xc200 to 0x6b, 0xc201 to 0x5c),
                    listOf(initialTarget),
                )
                assertFalse(p.memory.getBlock(oldAlias).isExecute)
                assertTrue(p.symbolTable.getSymbols("preserved_user_knowledge").hasNext())
            } finally {
                decompiler.dispose()
            }
        }

    @Test
    fun `later ordinary call retains physical native target register flag and memory results`() =
        fixture(
            "cd40023c38023e00ea00c2c9",
            code = mapOf(0x240 to "3e5a37c9"),
            functions = mapOf(0x240 to "later_target"),
        ) { p, config, root ->
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            val graph = review.stateContinuations().getValue(root.toString())
            val call = graph.steps().first()
            assertEquals(0xc100, call.afterCall().sp())
            assertEquals(0x10, call.afterCall().registers().f())
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                verifyNative(
                    p,
                    decompiler,
                    listOf(root, alias(p, review, root)),
                    mapOf(0xc200 to 0x5b),
                    listOf(physical(p, 0x8000), address(0x240)),
                )
            } finally {
                decompiler.dispose()
            }
        }

    @Test
    fun `later configured restoring call keeps physical target wrapper effects and canonical navigation`() {
        val nested = SoftwareCallModel.Template(SoftwareCallModel.Family.RESTORING_REGISTER_JP, 0x230, 0, null)
        fixture(
            "3e02010300210041cd3002ea00c2c9",
            code = mapOf(0x230 to nested.bodyHex(), 0xc100 to "3e7737c9"),
            functions =
                mapOf(0xc100 to "nested_target"),
        ) { p, config, root ->
            p.withTransaction {
                val at = address(nested.epilogueCpu().toLong())
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(
                    at,
                    AddressSet(
                        at,
                        address(0x230 + nested.bodyHex().length.toLong() / 2 - 1),
                    ),
                )
            }
            val inner =
                SoftwareCallValidation.Configuration(
                    0x4509,
                    nested,
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 3, 0, 0x4100),
                    config.mapper().write(ProgramMapping.cartridge(p), 0x2000, 2),
                )
            val review = SoftwareCallApplication.preview(p, listOf(config, inner), TaskMonitor.DUMMY)
            val call =
                review
                    .stateContinuations()
                    .getValue(root.toString())
                    .steps()
                    .single { it.softwareCall() != null }
            assertEquals(2, call.afterCall().registers().a())
            assertEquals(0x200, call.afterCall().registers().bc())
            assertEquals(0x10, call.afterCall().registers().f())
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                verifyNative(
                    p,
                    decompiler,
                    listOf(root, alias(p, review, root)),
                    mapOf(0xc200 to 2),
                    listOf(physical(p, 0x8000), physical(p, 0xc100)),
                )
            } finally {
                decompiler.dispose()
            }
        }
    }

    @Test
    fun `later manual software transfer preserves physical call and selected return bank`() {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x230, 0, null)
        fixture(
            "3e03210041010d45c5c33002",
            code = mapOf(0x230 to helper.bodyHex(), 0xc100 to "3e6637c9", 0xc50d to "ea00c2c9"),
            functions =
                mapOf(0xc100 to "manual_target"),
        ) { p, config, root ->
            val inner =
                SoftwareCallValidation.Configuration(
                    0x4506,
                    helper,
                    SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION,
                    0xc100,
                    SoftwareCallModel.Registers(3, 0, 0x450d, 0, 0x4100),
                    config.mapper().write(ProgramMapping.cartridge(p), 0x2000, 2),
                )
            val review = SoftwareCallApplication.preview(p, listOf(config, inner), TaskMonitor.DUMMY)
            val call =
                review
                    .stateContinuations()
                    .getValue(root.toString())
                    .steps()
                    .single { it.softwareCall() != null }
            assertEquals("BRANCH", call.transfer())
            assertEquals(0x450d, call.afterCall().cpu())
            assertEquals(3, call.afterCall().physical().bank())
            assertEquals(0xc100, call.afterCall().sp())
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                verifyNative(
                    p,
                    decompiler,
                    listOf(root, alias(p, review, root)),
                    mapOf(0xc200 to 0x66),
                    listOf(physical(p, 0x8000), physical(p, 0xc100)),
                )
            } finally {
                decompiler.dispose()
            }
        }
    }

    @Test
    fun `later ordinary callee revisits CPU under another bank and preserves internal memory effect`() =
        fixture(
            "cd0042ea00c2c9",
            code = mapOf(0x8200 to "3e03ea0020", 0xc205 to "c30042", 0xc200 to "3e66c38002", 0x280 to "ea10c23e02ea0020c9"),
            functions = mapOf(0x8200 to "later_state_target"),
        ) { p, config, root ->
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            val call =
                review
                    .stateContinuations()
                    .getValue(root.toString())
                    .steps()
                    .first()
            assertEquals(2, call.afterCall().mapper().romLow())
            assertEquals(0xc100, call.afterCall().sp())
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val target = physical(p, 0x8200)
            val contexts = SoftwareCallRegistry.stateContexts(p, target, TaskMonitor.DUMMY)
            val context = contexts.single { it.site() == root.toString() }
            val calleeEntry = ProgramMapping.staticAddress(p, context.entry())
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                verifyNative(p, decompiler, listOf(root, alias(p, review, root)), mapOf(0xc200 to 2), listOf(physical(p, 0x8000), target))
                verifyNative(p, decompiler, listOf(calleeEntry), mapOf(0xc210 to 0x66), emptyList())
                assertEquals(
                    ProgramMapping.staticToPhysical(p, target),
                    ProgramMapping.staticToPhysical(p, StockEntries.source(p, calleeEntry)),
                )
            } finally {
                decompiler.dispose()
            }
        }

    @Test
    fun `later configured constant-bank return preserves flags and actual wrapper bank`() {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.CONSTANT_REGISTER_JP, 0x230, 0, 1)
        fixture(
            "c30003",
            code = mapOf(0x300 to "3e03210041cd3002ea00c2c9", 0x230 to helper.bodyHex(), 0xc100 to "3e7737c9"),
            functions =
                mapOf(0xc100 to "constant_policy_target"),
        ) { p, config, root ->
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
            val inner =
                SoftwareCallValidation.Configuration(
                    0x305,
                    helper,
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    SoftwareCallModel.Registers(3, 0, 0, 0, 0x4100),
                    config.mapper().write(ProgramMapping.cartridge(p), 0x2000, 2),
                )
            val review = SoftwareCallApplication.preview(p, listOf(config, inner), TaskMonitor.DUMMY)
            val call =
                review
                    .stateContinuations()
                    .getValue(root.toString())
                    .steps()
                    .single { it.softwareCall() != null }
            assertEquals(1, call.afterCall().registers().a())
            assertEquals(0x238, call.afterCall().registers().bc())
            assertEquals(0x10, call.afterCall().registers().f())
            assertEquals(1, call.afterCall().mapper().romLow())
            assertEquals(0xc100, call.afterCall().sp())
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                verifyNative(
                    p,
                    decompiler,
                    listOf(root, alias(p, review, root)),
                    mapOf(0xc200 to 1),
                    listOf(physical(p, 0x8000), physical(p, 0xc100)),
                )
            } finally {
                decompiler.dispose()
            }
        }
    }

    @Test
    fun `later ordinary nonlocal return executes its actual destination instead of encoded continuation`() =
        fixture(
            "cd4002ea00c2c9",
            code = mapOf(0x240 to "f8003680233603c9", 0x380 to "3e07ea30c2c9"),
            functions =
                mapOf(0x240 to "later_nonlocal_target"),
        ) { p, config, root ->
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            val graph = review.stateContinuations().getValue(root.toString())
            val outcome = graph.steps().first().callOutcome()
            assertEquals("NONLOCAL", outcome.exit())
            assertEquals(0x380, outcome.state().cpu())
            assertEquals(0xc100, outcome.state().sp())
            assertEquals(
                0x380,
                graph
                    .steps()
                    .single { it.index() == outcome.resumeStep() }
                    .before()
                    .cpu(),
            )
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                verifyNative(
                    p,
                    decompiler,
                    listOf(root, alias(p, review, root)),
                    mapOf(0xc230 to 7),
                    listOf(physical(p, 0x8000), address(0x240)),
                )
            } finally {
                decompiler.dispose()
            }
            assertNotNull(p.listing.getInstructionAt(physical(p, 0x8504)))
        }

    @Test
    fun `later software nonlocal return preserves saved wrapper words for actual cleanup instructions`() {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.RESTORING_REGISTER_JP, 0x230, 0, null)
        fixture(
            "3e02010300210041cd3002ea00c2c9",
            code =
                mapOf(
                    0x230 to helper.bodyHex(),
                    0xc100 to "f8003680233603c9",
                    0x380 to "c1d13e07ea30c2c9",
                ),
            functions = mapOf(0xc100 to "software_nonlocal_target"),
        ) { p, config, root ->
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
            val inner =
                SoftwareCallValidation.Configuration(
                    0x4509,
                    helper,
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 3, 0, 0x4100),
                    config.mapper().write(ProgramMapping.cartridge(p), 0x2000, 2),
                )
            val review = SoftwareCallApplication.preview(p, listOf(config, inner), TaskMonitor.DUMMY)
            val graph = review.stateContinuations().getValue(root.toString())
            val call = graph.steps().single { it.softwareCall() != null }
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
                0x200,
                graph
                    .steps()
                    .last()
                    .before()
                    .registers()
                    .bc(),
            )
            assertEquals(
                0x450c,
                graph
                    .steps()
                    .last()
                    .before()
                    .registers()
                    .de(),
            )
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                verifyNative(
                    p,
                    decompiler,
                    listOf(root, alias(p, review, root)),
                    mapOf(0xc230 to 7),
                    listOf(physical(p, 0x8000), physical(p, 0xc100)),
                )
            } finally {
                decompiler.dispose()
            }
        }
    }

    @Test
    fun `later nonreturning native call terminates only its proved contextual alias`() =
        fixture("cd4002c9", code = mapOf(0x240 to "18fe"), functions = mapOf(0x240 to "later_loop_target")) { p, config, root ->
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            assertEquals(
                "NONRETURNING",
                review
                    .stateContinuations()
                    .getValue(root.toString())
                    .steps()
                    .first()
                    .callOutcome()
                    .exit(),
            )
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val context = SoftwareCallRegistry.stateContexts(p, address(0x240), TaskMonitor.DUMMY).single { it.site() == root.toString() }
            val loopEntry = ProgramMapping.staticAddress(p, context.entry())
            assertTrue(p.functionManager.getFunctionAt(loopEntry).hasNoReturn())
            assertFalse(p.functionManager.getFunctionAt(address(0x240)).hasNoReturn())
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                for (entry in listOf(root, alias(p, review, root))) {
                    val result = decompiler.decompileFunction(p.functionManager.getFunctionAt(entry), 30, TaskMonitor.DUMMY)
                    assertTrue(result.decompileCompleted(), result.errorMessage)
                    val c = result.decompiledFunction.c
                    assertFalse(c.contains("bad instruction", ignoreCase = true), c)
                    assertFalse(c.contains("truncating control flow", ignoreCase = true), c)
                    val ops =
                        result.highFunction.pcodeOps
                            .asSequence()
                            .toList()
                    assertTrue(ops.any { it.opcode == PcodeOp.CALL && it.getInput(0).address == loopEntry }, c)
                    // Pinned FlowInfo::artificialHalt encodes a noreturn call with RETURN const:4(1).
                    // This native halt has no architectural PC load or stack pop.
                    val halt = ops.single { it.opcode == PcodeOp.RETURN }
                    assertEquals(1, halt.numInputs, c)
                    assertTrue(halt.getInput(0).isConstant, c)
                    assertEquals(4, halt.getInput(0).size, c)
                    assertEquals(1L, halt.getInput(0).offset, c)
                    assertTrue(c.contains("Subroutine does not return"), c)
                    val context = InjectContext()
                    context.baseAddr = entry
                    context.nextAddr = entry
                    context.callAddr = address(0x28)
                    val payload = p.compilerSpec.pcodeInjectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, SoftwareCallInjection.NAME)
                    val rawInjected = payload.getPcode(p, context)
                    assertEquals(PcodeOp.CALL, rawInjected.last().opcode)
                    assertEquals(loopEntry, rawInjected.last().getInput(0).address)
                }
            } finally {
                decompiler.dispose()
            }
        }

    @Test
    fun `later call register results justify indirect mapper write and subsequent physical fetch`() =
        fixture(
            "c30003",
            code = mapOf(0x300 to "cd400277c30041", 0x240 to "2100203e03c9", 0xc100 to "3e5bea00c2c9"),
            functions =
                mapOf(0x240 to "mapper_setup"),
        ) { p, config, root ->
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            val graph = review.stateContinuations().getValue(root.toString())
            val indirect = graph.steps().single { it.before().cpu() == 0x303 }
            assertEquals(0x2000, indirect.before().registers().hl())
            assertEquals(3, indirect.before().registers().a())
            assertTrue(indirect.accesses().single().mapperControl())
            assertTrue(graph.transportVetoes().any { it.kind() == "MAPPER_WRITE" && it.step() == indirect.index() })
            assertEquals(
                3,
                graph
                    .steps()
                    .last()
                    .before()
                    .physical()
                    .bank(),
            )
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                verifyNative(
                    p,
                    decompiler,
                    listOf(root, alias(p, review, root)),
                    mapOf(0xc200 to 0x5b),
                    listOf(physical(p, 0x8000), address(0x240)),
                )
            } finally {
                decompiler.dispose()
            }
        }
}
