package fi.gekkio.ghidraboy

import ghidra.app.decompiler.DecompInterface
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayload
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

/** Independent review regressions for contextual native-entry ownership and public selection. */
class SoftwareCallStateEntryIntegrityTest : IntegrationTest() {
    private data class Chunk(
        val bank: Int,
        val cpu: Int,
        val hex: String,
    )

    private fun fixture(
        nested: Boolean = false,
        action: (ProgramDB, List<SoftwareCallValidation.Configuration>, Address, Address?) -> Unit,
    ) {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val chunks =
            if (nested) {
                listOf(
                    Chunk(2, 0x4100, "cd0042c9"),
                    Chunk(2, 0x4200, "3e03ea0020"),
                    Chunk(3, 0x4205, "3e02ea0020"),
                    Chunk(2, 0x420a, "c9"),
                )
            } else {
                listOf(
                    Chunk(2, 0x4100, "ca20413e03ea0020"),
                    Chunk(3, 0x4108, "c30042"),
                    Chunk(2, 0x4120, "3e02ea0020c30042"),
                    Chunk(2, 0x4200, "3e22ea10c2c9"),
                    Chunk(3, 0x4200, "3e33ea10c2c9"),
                )
            }
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                HexFormat.of().parseHex(helper.bodyHex()).copyInto(this, 0x28)
                for (caller in listOf(0x200, 0x300)) HexFormat.of().parseHex("efc9").copyInto(this, caller)
                for (chunk in chunks) HexFormat.of().parseHex(chunk.hex).copyInto(this, chunk.bank * 0x4000 + chunk.cpu - 0x4000)
            }
        val consumer = Any()
        val p = ProgramDB("independent state-entry integrity", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, TaskMonitor.DUMMY, MessageLog())
            }

            fun physical(
                bank: Int,
                cpu: Int,
            ): Address =
                SoftwareCallValidation.executionAddress(p, MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, bank), cpu)
            val target = physical(2, 0x4100)
            val nestedTarget = if (nested) physical(2, 0x4200) else null
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                disassembler.disassemble(address(0x28), AddressSet(address(0x28), address(0x28 + helper.bodyHex().length / 2L - 1)))
                for (caller in listOf(0x200, 0x300)) {
                    val root = address(caller.toLong())
                    disassembler.disassemble(root, AddressSet(root, root.add(1)))
                    p.functionManager.createFunction(
                        "source_${caller.toString(16)}",
                        root,
                        AddressSet(root, root.add(1)),
                        SourceType.USER_DEFINED,
                    )
                }
                for (chunk in chunks) {
                    val root = physical(chunk.bank, chunk.cpu)
                    disassembler.disassemble(root, AddressSet(root, root.add(chunk.hex.length / 2L - 1)))
                }
                p.functionManager
                    .createFunction(
                        "original_state_target",
                        target,
                        AddressSet(target, target.add(if (nested) 3 else 7)),
                        SourceType.USER_DEFINED,
                    ).comment =
                    "Original target note"
                if (nestedTarget != null) {
                    p.functionManager
                        .createFunction(
                            "nested_user_target",
                            nestedTarget,
                            AddressSet(nestedTarget, nestedTarget.add(4)),
                            SourceType.USER_DEFINED,
                        ).comment =
                        "Original nested note"
                }
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
            action(p, configs, target, nestedTarget)
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `renaming and commenting canonical entry does not strand owned protocol after removal`() =
        fixture { p, configs, target, _ ->
            val function = p.functionManager.getFunctionAt(target)
            val originalConvention = function.callingConventionName
            val originalBytes = ByteArray(8).also { p.memory.getBytes(target, it) }
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, configs, TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            val aliases =
                SoftwareCallRegistry
                    .stateContexts(
                        p,
                        target,
                        TaskMonitor.DUMMY,
                    ).map { ProgramMapping.staticAddress(p, it.entry()) }
            p.withTransaction {
                function.setName("user_renamed_target", SourceType.USER_DEFINED)
                function.comment = "User replacement note after application"
            }
            for (entry in listOf(target) + aliases) {
                assertThrows(IllegalArgumentException::class.java) { SoftwareCallRegistry.resolveStateEntry(p, entry) }
            }
            AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            val preserved = p.functionManager.getFunctionAt(target)
            assertNotNull(preserved)
            assertEquals("user_renamed_target", preserved.name)
            assertEquals("User replacement note after application", preserved.comment)
            assertEquals(originalConvention, preserved.callingConventionName)
            assertFalse(p.getOptions(ProgramMapping.OPTIONS).contains(SoftwareCallRegistry.KEY))
            assertEquals(originalBytes.toList(), ByteArray(8).also { p.memory.getBytes(target, it) }.toList())
            for (entry in aliases) {
                assertFalse(p.memory.getBlock(entry).isExecute)
                assertTrue(p.functionManager.getFunctionAt(entry) == null)
            }
        }

    @Test
    fun `selection restores original comment and convention after clean removal`() =
        fixture { p, configs, target, _ ->
            val original = p.functionManager.getFunctionAt(target)
            val convention = original.callingConventionName
            val comment = original.comment
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, configs, TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            val contexts = SoftwareCallRegistry.stateContexts(p, target, TaskMonitor.DUMMY)
            val other = contexts.single { !it.selected() }
            SoftwareCallRegistry.selectStateContext(p, target, ProgramMapping.staticAddress(p, other.entry()), TaskMonitor.DUMMY)
            AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            assertEquals(comment, p.functionManager.getFunctionAt(target).comment)
            assertEquals(convention, p.functionManager.getFunctionAt(target).callingConventionName)
        }

    @Test
    fun `nested explicit return contract is rejected before any reviewed mutation`() =
        fixture(nested = true) { p, configs, _, nestedTarget ->
            val nested = p.functionManager.getFunctionAt(nestedTarget)
            p.withTransaction { nested.setReturnType(ByteDataType.dataType, SourceType.USER_DEFINED) }
            val originalType = nested.returnType
            val originalStorage = nested.getReturn().variableStorage.serializationString
            val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            val failure =
                assertThrows(
                    IllegalArgumentException::class.java,
                ) { SoftwareCallApplication.preview(p, configs.take(1), TaskMonitor.DUMMY) }
            assertTrue(failure.message.orEmpty().contains("contract"), failure.message)
            assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
            assertEquals(SourceType.USER_DEFINED, nested.signatureSource)
            assertTrue(originalType.isEquivalent(nested.returnType))
            assertEquals(originalType.pathName, nested.returnType.pathName)
            assertEquals(originalStorage, nested.getReturn().variableStorage.serializationString)
            assertEquals("Original nested note", nested.comment)
        }

    @Test
    fun `nested custom storage is rejected before any reviewed mutation`() =
        fixture(nested = true) { p, configs, _, nestedTarget ->
            val nested = p.functionManager.getFunctionAt(nestedTarget)
            p.withTransaction { nested.setCustomVariableStorage(true) }
            val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            val failure =
                assertThrows(
                    IllegalArgumentException::class.java,
                ) { SoftwareCallApplication.preview(p, configs.take(1), TaskMonitor.DUMMY) }
            assertTrue(failure.message.orEmpty().contains("contract"), failure.message)
            assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
            assertTrue(nested.hasCustomVariableStorage())
        }

    @Test
    fun `cancelled selection after comment mutation rolls back registry ownership and visible context`() =
        fixture { p, configs, target, _ ->
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, configs, TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            val contexts = SoftwareCallRegistry.stateContexts(p, target, TaskMonitor.DUMMY)
            val alternate = ProgramMapping.staticAddress(p, contexts.single { !it.selected() }.entry())
            val comment = p.functionManager.getFunctionAt(target).comment
            val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            var sawMutation = false
            val monitor =
                object : TaskMonitorAdapter(true) {
                    override fun checkCancelled() {
                        if (p.functionManager.getFunctionAt(target).comment != comment) {
                            sawMutation = true
                            throw CancelledException()
                        }
                        super.checkCancelled()
                    }
                }
            assertThrows(CancelledException::class.java) { SoftwareCallRegistry.selectStateContext(p, target, alternate, monitor) }
            assertTrue(sawMutation, "Cancellation must exercise rollback after a real context write")
            assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
            assertEquals(contexts, SoftwareCallRegistry.stateContexts(p, target, TaskMonitor.DUMMY))
        }

    @Test
    fun `consumed byte drift rejects cached context selection without rebaselining dependencies`() =
        fixture { p, configs, target, _ ->
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, configs, TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            val contexts = SoftwareCallRegistry.stateContexts(p, target, TaskMonitor.DUMMY)
            val alternate = ProgramMapping.staticAddress(p, contexts.single { !it.selected() }.entry())
            p.withTransaction {
                // Revise the exact helper instruction; its mapped state views contain callee
                // bytes, so this does not write through an already-decoded alias instruction.
                p.listing.clearCodeUnits(address(0x28), address(0x2a), false)
                p.memory.setByte(address(0x29), 0x01)
                Disassembler
                    .getDisassembler(
                        p,
                        TaskMonitor.DUMMY,
                        null,
                    ).disassemble(address(0x28), AddressSet(address(0x28), address(0x2a)))
            }
            val changed = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            assertThrows(
                IllegalArgumentException::class.java,
            ) { SoftwareCallRegistry.selectStateContext(p, target, alternate, TaskMonitor.DUMMY) }
            assertEquals(changed, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
        }

    @Test
    fun `later nonlocal exit across two native frames preserves actual destination and adds no second pop`() {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val regions =
            mapOf(
                0x28 to helper.bodyHex(),
                0x240 to "cd6002c9",
                0x260 to "c1f8003680233603c9",
                0x380 to "3e07ea30c2c9",
                0x4500 to "ef",
                0x8000 to "c9",
                // Encoded continuation writes 09. The nonlocal destination must instead write07.
                0x8501 to "cd40023e09ea30c2c9",
            )
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                for ((offset, hex) in regions) HexFormat.of().parseHex(hex).copyInto(this, offset)
            }
        val consumer = Any()
        val p = ProgramDB("two departed native continuation frames", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, TaskMonitor.DUMMY, MessageLog())
            }

            fun physical(offset: Int): Address {
                val cpu = if (offset < 0x4000) offset.toLong() else 0x4000L + offset % 0x4000
                return ProgramMapping.fileToStatic(p, offset.toLong()).single {
                    SoftwareCallExecutionView.canonical(p, it) &&
                        it.offset == cpu
                }
            }
            val root = physical(0x4500)
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                for ((offset, hex) in regions) {
                    val entry = physical(offset)
                    disassembler.disassemble(entry, AddressSet(entry, entry.add(hex.length / 2L - 1)))
                }
                for ((offset, name) in mapOf(
                    0x4500 to "nonlocal_outer_source",
                    0x8000 to "initial_returning_target",
                    0x240 to "departed_intermediate",
                    0x260 to "nonlocal_leaf",
                )) {
                    val entry = physical(offset)
                    p.functionManager.createFunction(
                        name,
                        entry,
                        AddressSet(entry, entry.add(regions.getValue(offset).length / 2L - 1)),
                        SourceType.USER_DEFINED,
                    )
                }
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
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            val graph = review.stateContinuations().getValue(root.toString())
            val departed = graph.steps().filter { it.callOutcome() != null }
            assertEquals(2, departed.size)
            assertTrue(departed.all { it.callOutcome().exit() == "NONLOCAL" && it.callOutcome().state().sp() == 0xc100 })
            assertEquals(
                listOf(0xc0fe, 0xc100),
                departed
                    .first()
                    .callOutcome()
                    .liveFrames()
                    .map { it.returnSp() },
            )
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val intermediate = address(0x240)
            val context = SoftwareCallRegistry.stateContexts(p, intermediate, TaskMonitor.DUMMY).single()
            val alias = ProgramMapping.staticAddress(p, context.entry())
            val payload =
                p.compilerSpec.pcodeInjectLibrary.getPayload(
                    InjectPayload.CALLMECHANISM_TYPE,
                    SoftwareCallStateEntryInjection.NAME,
                )
            val request = InjectContext()
            request.baseAddr = alias
            request.nextAddr = alias
            val emitted = payload.getPcode(p, request)
            // The leaf's real RET consumed the departed hardware words. The intermediate
            // propagation RETURN cannot read/pop a third word or add an extra stack write.
            assertEquals(0, emitted.count { it.opcode == PcodeOp.LOAD })
            assertEquals(
                p.listing
                    .getInstructionAt(intermediate)
                    .getPcode(false)
                    .count { it.opcode == PcodeOp.STORE },
                emitted.count {
                    it.opcode ==
                        PcodeOp.STORE
                },
            )
            assertEquals(PcodeOp.RETURN, emitted.last().opcode)
            assertEquals(2, emitted.last().getInput(0).size)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                val sourceAlias =
                    p.addressFactory
                        .getAddressSpace(
                            review.executionViews().getValue(root.toString()).name(),
                        ).getAddress(root.offset)
                for (entry in listOf(root, sourceAlias, intermediate, alias)) {
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
                    if (entry == root || entry == sourceAlias) {
                        assertTrue(
                            ops.any { op ->
                                (
                                    op.opcode == PcodeOp.COPY && op.output?.address == address(0xc230) && op.getInput(0).isConstant &&
                                        op.getInput(0).offset == 7L
                                ) ||
                                    (
                                        op.opcode == PcodeOp.STORE && op.getInput(1).isConstant && op.getInput(1).offset == 0xc230L &&
                                            op.getInput(2).isConstant &&
                                            op.getInput(2).offset == 7L
                                    )
                            },
                            c,
                        )
                    }
                }
            } finally {
                decompiler.dispose()
            }
        } finally {
            p.release(consumer)
        }
    }
}
