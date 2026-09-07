package fi.gekkio.ghidraboy

import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Function
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.util.UndefinedFunction
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

/** A supplementary listing can reach the normal decompiler through an UndefinedFunction. */
class SoftwareCallDerivedFlowIntegrityTest : IntegrationTest() {
    private fun fixture(action: (ProgramDB, Address, Address, Address) -> Unit) {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                for ((offset, hex) in
                    mapOf(
                        0x28 to helper.bodyHex(),
                        0x240 to "3e5a37c9",
                        0x4500 to "ef",
                        0x8000 to "c9",
                        0x8501 to "cd40023c38023e00ea00c2c9",
                    )
                ) {
                    HexFormat.of().parseHex(hex).copyInto(this, offset)
                }
            }
        val consumer = Any()
        val p = ProgramDB("supplementary continuation analysis", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, TaskMonitor.DUMMY, MessageLog())
            }
            val root = SoftwareCallValidation.executionAddress(p, MapperState.reset(), 0x4500)
            val config =
                SoftwareCallValidation.Configuration(
                    0x4500,
                    helper,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 0, 0, 0x4000),
                    MapperState.reset(),
                )
            p.withTransaction { p.symbolTable.createLabel(root, "fragment_source", SourceType.USER_DEFINED) }
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            val graph = review.stateContinuations().getValue(root.toString())
            val branch = graph.steps().single { it.before().cpu() == 0x4505 }
            assertEquals(0x4509, branch.after().cpu(), "SCF and INC A preserve the taken carry branch")
            assertFalse(graph.steps().any { it.before().cpu() == 0x4507 }, "The untaken physical bytes are not proof steps")
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val fragment =
                review.executionViews().entries.single {
                    it.key.startsWith("$root#state") && it.value.segments().any { segment -> segment.cpu() == 0x4501 }
                }.value
            val continuation = p.addressFactory.getAddressSpace(fragment.name()).getAddress(0x4501)
            val canonical = ProgramMapping.staticAddress(p, graph.steps().first().address())
            action(p, root, continuation, canonical)
        } finally {
            p.release(consumer)
        }
    }

    private fun functionForAnalysis(
        p: ProgramDB,
        entry: Address,
    ): Function =
        p.functionManager.getFunctionContaining(entry)
            ?: requireNotNull(UndefinedFunction.findFunctionUsingSimpleBlockModel(p, entry, TaskMonitor.DUMMY))

    private fun verifyContinuation(
        p: ProgramDB,
        entry: Address,
    ) {
        val decompiler = DecompInterface()
        try {
            assertTrue(decompiler.openProgram(p))
            val function = functionForAnalysis(p, entry)
            val result = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY)
            assertTrue(result.decompileCompleted(), "$entry: ${result.errorMessage}")
            val c = result.decompiledFunction.c
            for (diagnostic in listOf("bad instruction", "truncating control flow", "halt_baddata", "non-existing memory")) {
                assertFalse(c.contains(diagnostic, ignoreCase = true), "$entry: $c")
                assertFalse(result.errorMessage.orEmpty().contains(diagnostic, ignoreCase = true), "$entry: ${result.errorMessage}")
            }
            val ops = result.highFunction.pcodeOps.asSequence().toList()
            assertTrue(ops.any { it.opcode == PcodeOp.CALL && it.getInput(0).address == address(0x240) }, c)
            assertTrue(ops.any { it.opcode == PcodeOp.RETURN }, c)
            assertTrue(
                ops.any {
                    it.opcode == PcodeOp.COPY && it.output?.address == address(0xc200) &&
                        it.getInput(0).isConstant && it.getInput(0).offset == 0x5bL ||
                        it.opcode == PcodeOp.STORE && it.getInput(1).isConstant && it.getInput(1).offset == 0xc200L &&
                        it.getInput(2).isConstant && it.getInput(2).offset == 0x5bL
                },
                "The separately opened continuation must preserve the callee carry and write 5b: $c",
            )
        } finally {
            decompiler.dispose()
        }
    }

    @Test
    fun `supplementary continuation can be independently decompiled without following its untaken unmapped edge`() =
        fixture { p, _, continuation, canonical ->
            assertNotNull(p.listing.getInstructionAt(continuation))
            assertEquals(listOf(0x38.toByte(), 0x02.toByte()), p.listing.getInstructionAt(canonical.add(4)).bytes.toList())
            assertNotNull(p.memory.getBlock(continuation.add(8)), "The proved branch destination fragment must remain present")
            verifyContinuation(p, continuation)
        }

    @Test
    fun `repeated ordinary analysis preserves all supplementary fragments and their independently opened continuation`() =
        fixture { p, root, continuation, _ ->
            val originalBlocks =
                p.memory.blocks
                    .filter { it.name.startsWith(SoftwareCallExecutionView.PREFIX) }
                    .associate { it.name to Triple(it.start, it.size, it.sourceInfos.map { info -> info.toString() }) }
            val manager = AutoAnalysisManager.getAnalysisManager(p)
            repeat(2) {
                p.withTransaction {
                    manager.reAnalyzeAll(AddressSet(p.memory))
                    manager.startAnalysis(TaskMonitor.DUMMY)
                }
                assertNotNull(SoftwareCallRegistry.resolve(p, root))
                verifyContinuation(p, continuation)
                val currentBlocks =
                    p.memory.blocks
                        .filter { it.name.startsWith(SoftwareCallExecutionView.PREFIX) }
                        .associate { it.name to Triple(it.start, it.size, it.sourceInfos.map { info -> info.toString() }) }
                assertEquals(originalBlocks, currentBlocks, "Analysis must retain every derived fragment and its exact shared mapping")
                val decompiler = DecompInterface()
                try {
                    assertTrue(decompiler.openProgram(p))
                    for (function in p.functionManager.getFunctions(true)) {
                        if (p.memory.getBlock(function.entryPoint)?.name?.startsWith(SoftwareCallExecutionView.PREFIX) != true) continue
                        val result = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY)
                        assertTrue(result.decompileCompleted(), "${function.entryPoint}: ${result.errorMessage}")
                        assertFalse(result.decompiledFunction.c.contains("halt_baddata"), result.decompiledFunction.c)
                        assertFalse(result.decompiledFunction.c.contains("truncating control flow", ignoreCase = true), result.decompiledFunction.c)
                    }
                } finally {
                    decompiler.dispose()
                }
            }
        }

    @Test
    fun `later bank projection retains its own repeated invocation context`() {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                for ((offset, hex) in
                    mapOf(
                        0x28 to helper.bodyHex(),
                        0x200 to "efc9",
                        0x8100 to "afcd0042f601cd0042c9",
                        0x8200 to "3e03ea0020",
                        0xc205 to "28043e3318023e22ea10c23e02ea0020",
                        0x8215 to "c9",
                    )
                ) {
                    HexFormat.of().parseHex(hex).copyInto(this, offset)
                }
            }
        val consumer = Any()
        val p = ProgramDB("repeated invocation projection provenance", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction { p.symbolTable.createLabel(address(0x200), "repeated_projection_source", SourceType.USER_DEFINED) }
            val config =
                SoftwareCallValidation.Configuration(
                    0x200,
                    helper,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 0, 0, 0x4100),
                    MapperState.reset(),
                )
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            val source = review.stateCallees().getValue(address(0x200).toString())
            val invocations = SoftwareCallEffects.calleeInvocations(source).filter { it.graph().steps().first().before().cpu() == 0x4200 }
            assertEquals(2, invocations.size)
            assertEquals(listOf(0x80, 0), invocations.map { it.graph().steps().first().before().registers().f() })
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                for ((invocation, expected) in invocations.zip(listOf(0x22L, 0x33L))) {
                    val index = invocation.graph().steps().first().index()
                    val view =
                        review.executionViews().entries.single {
                            it.key.startsWith("${address(0x200)}#native_CALLEE_${index}_") &&
                                it.value.segments().any { segment -> segment.cpu() == 0x4205 }
                        }.value
                    val entry = p.addressFactory.getAddressSpace(view.name()).getAddress(0x4205)
                    val input = SoftwareCallRegistry.resolveStateEntry(p, entry)
                    val graph = SoftwareCallRegistry.entryGraph(p, entry, input)
                    assertEquals(index, graph.steps().first().index(), "The fragment must retain the invocation which planned it")
                    val result = decompiler.decompileFunction(functionForAnalysis(p, entry), 30, TaskMonitor.DUMMY)
                    assertTrue(result.decompileCompleted(), "$entry: ${result.errorMessage}")
                    val c = result.decompiledFunction.c
                    assertFalse(c.contains("halt_baddata"), c)
                    assertFalse(c.contains("truncating control flow", ignoreCase = true), c)
                    assertTrue(
                        result.highFunction.pcodeOps.asSequence().any {
                            it.opcode == PcodeOp.COPY && it.output?.address == address(0xc210) &&
                                it.getInput(0).isConstant && it.getInput(0).offset == expected ||
                                it.opcode == PcodeOp.STORE && it.getInput(1).isConstant && it.getInput(1).offset == 0xc210L &&
                                it.getInput(2).isConstant && it.getInput(2).offset == expected
                        },
                        "The selected invocation must write ${expected.toString(16)} to c210: $c",
                    )
                }
            } finally {
                decompiler.dispose()
            }
        } finally {
            p.release(consumer)
        }
    }


    @Test
    fun `later bank projection preserves a loop backedge before its selected entry`() {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                for ((offset, hex) in
                    mapOf(
                        0x28 to helper.bodyHex(),
                        0x200 to "efc9",
                        0x8100 to "3e03ea0020",
                        0xc105 to "3e02ea0020",
                        0x810a to "c30041",
                    )
                ) {
                    HexFormat.of().parseHex(hex).copyInto(this, offset)
                }
            }
        val consumer = Any()
        val p = ProgramDB("later projection with earlier backedge", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction { p.symbolTable.createLabel(address(0x200), "loop_projection_source", SourceType.USER_DEFINED) }
            val config =
                SoftwareCallValidation.Configuration(
                    0x200,
                    helper,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 0, 0, 0x4100),
                    MapperState.reset(),
                )
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            val source = review.stateCallees().getValue(address(0x200).toString())
            assertEquals("LOOP", source.exit())
            val view =
                review.executionViews().entries.single {
                    it.key.startsWith("${address(0x200)}#native_CALLEE_0_") &&
                        it.value.segments().any { segment -> segment.cpu() == 0x4105 }
                }.value
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val entry = p.addressFactory.getAddressSpace(view.name()).getAddress(0x4105)
            val input = SoftwareCallRegistry.resolveStateEntry(p, entry)
            val graph = SoftwareCallRegistry.entryGraph(p, entry, input)
            val selected = SoftwareCallRegistry.entryStep(p, entry)
            assertTrue(selected > graph.steps().first().index())
            assertTrue(graph.steps().any { it.successor() != null && it.successor() < selected })
            val ops = SoftwareCallContinuationView.emit(p, entry, graph, listOf(config), 0x20000000L, selected)
            assertTrue(ops.any { it.opcode == PcodeOp.BRANCH && it.getInput(0).isConstant && it.getInput(0).offset > 0x7fffffffL })
            assertFalse(ops.any { it.opcode == PcodeOp.RETURN }, "The physical loop cannot acquire a synthetic return")
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                val result = decompiler.decompileFunction(functionForAnalysis(p, entry), 30, TaskMonitor.DUMMY)
                assertTrue(result.decompileCompleted(), "$entry: ${result.errorMessage}")
                val c = result.decompiledFunction.c
                assertFalse(c.contains("halt_baddata"), c)
                assertFalse(c.contains("truncating control flow", ignoreCase = true), c)
                assertFalse(result.highFunction.pcodeOps.asSequence().any { it.opcode == PcodeOp.RETURN }, c)
            } finally {
                decompiler.dispose()
            }
        } finally {
            p.release(consumer)
        }
    }

}
