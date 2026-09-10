package fi.gekkio.ghidraboy

import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.CommentType
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

/** Fresh discovery must survive the standard analyzers which recognize ordinary thunks. */
class SoftwareCallAutomaticAnalysisTest : IntegrationTest() {
    private fun fixture(action: (ProgramDB, SoftwareCallValidation.Configuration, Address, Address) -> Unit) {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val regions =
            mapOf(
                0x28 to helper.bodyHex(),
                0x240 to "3e5a37c9",
                0x4500 to "ef",
                0x8000 to "c9",
                0x8501 to "cd40023c38023e00ea00c2c9",
            )
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                for ((offset, hex) in regions) HexFormat.of().parseHex(hex).copyInto(this, offset)
            }
        val consumer = Any()
        val p = ProgramDB("fresh label-only state continuation with automatic analysis", language, language.defaultCompilerSpec, consumer)
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
            val target = physical(0x8000)
            p.withTransaction {
                p.symbolTable.createLabel(root, "fresh_named_source", SourceType.USER_DEFINED)
                p.symbolTable.createLabel(address(0x350), "unrelated_user_label", SourceType.USER_DEFINED)
                p.listing.setComment(root, CommentType.EOL, "Original source instruction note")
            }
            assertFalse(p.listing.getInstructions(true).hasNext(), "Fixture must supply no Instruction boundaries")
            assertFalse(p.functionManager.getFunctions(true).hasNext(), "Fixture must supply no Function boundaries")
            val config =
                SoftwareCallValidation.Configuration(
                    0x4500,
                    helper,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 0, 0, 0x4000),
                    MapperState.reset(),
                )
            action(p, config, root, target)
        } finally {
            p.release(consumer)
        }
    }

    private fun applyFresh(
        p: ProgramDB,
        config: SoftwareCallValidation.Configuration,
        root: Address,
    ): Address {
        val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
        val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
        assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
        assertTrue(review.instructionDiscovery().candidates().isNotEmpty())
        assertTrue(review.stateContinuations().containsKey(root.toString()))
        SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
        val alias = p.addressFactory.getAddressSpace(review.executionViews().getValue(root.toString()).name()).getAddress(root.offset)
        assertRedirect(p, root, alias)
        return alias
    }

    private fun assertRedirect(
        p: ProgramDB,
        root: Address,
        alias: Address,
    ) {
        val canonical = p.functionManager.getFunctionAt(root)
        val derived = p.functionManager.getFunctionAt(alias)
        assertNotNull(canonical)
        assertNotNull(derived)
        assertTrue(canonical.isThunk, "Fresh canonical source needs its owned execution redirect")
        assertEquals(alias, canonical.getThunkedFunction(false).entryPoint)
        assertTrue(AnalysisOwnership.sourceRedirectCurrent(p, canonical))
        assertFalse(derived.isThunk, "Derived source must not become a thunk to the raw RST helper")
        assertEquals("fresh_named_source_software_call", derived.name)
        assertNull(derived.callFixup, "Derived source must not inherit the helper's software-call fixup")
        assertNull(canonical.callFixup, "Canonical redirect must resolve to the caller contract")
        assertEquals(SoftwareCallInjection.NAME, p.functionManager.getFunctionAt(address(0x28)).callFixup)
        assertNotNull(SoftwareCallRegistry.resolve(p, root))
        assertNotNull(SoftwareCallRegistry.resolve(p, alias))
    }

    private fun verifyNative(
        p: ProgramDB,
        decompiler: DecompInterface,
        entries: List<Address>,
        target: Address,
        expected: Long = 0x5bL,
    ) {
        for (entry in entries) {
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
            assertTrue(
                ops.any {
                    it.opcode == PcodeOp.CALL &&
                        ProgramMapping.staticToPhysical(p, it.getInput(0).address) == ProgramMapping.staticToPhysical(p, target)
                },
                c,
            )
            assertTrue(ops.any { it.opcode == PcodeOp.CALL && it.getInput(0).address == address(0x240) }, c)
            assertTrue(ops.any { it.opcode == PcodeOp.RETURN }, c)
            assertTrue(
                ops.any { op ->
                    (
                        op.opcode == PcodeOp.COPY && op.output?.address == address(0xc200) && op.getInput(0).isConstant &&
                            op.getInput(0).offset == expected
                    ) ||
                        (
                            op.opcode == PcodeOp.STORE && op.getInput(1).isConstant && op.getInput(1).offset == 0xc200L &&
                                op.getInput(2).isConstant &&
                                op.getInput(2).offset == expected
                        )
                },
                c,
            )
        }
    }

    @Test
    fun `fresh label-only caller remains paired and natively valid after full ordinary automatic analysis`() =
        fixture { p, config, root, target ->
            val alias = applyFresh(p, config, root)
            val canonicalId = p.functionManager.getFunctionAt(root).id
            val aliasId = p.functionManager.getFunctionAt(alias).id
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                verifyNative(p, decompiler, listOf(root, alias), target)
                val manager = AutoAnalysisManager.getAnalysisManager(p)
                repeat(2) {
                    p.withTransaction {
                        manager.reAnalyzeAll(AddressSet(p.memory))
                        manager.startAnalysis(TaskMonitor.DUMMY)
                    }
                    assertRedirect(p, root, alias)
                    verifyNative(p, decompiler, listOf(root, alias), target)
                }
                assertEquals(canonicalId, p.functionManager.getFunctionAt(root).id)
                assertEquals(aliasId, p.functionManager.getFunctionAt(alias).id)
                assertRedirect(p, root, alias)
                verifyNative(p, decompiler, listOf(root, alias), target)
                assertEquals("Original source instruction note", p.listing.getComment(CommentType.EOL, root))
                assertTrue(p.symbolTable.getSymbols("unrelated_user_label").hasNext())
                // Mutate a consumed helper operand while retaining this same native interface.
                // The helper has no projected aliases in this fixture, so this changes only
                // its actual canonical bytes and exact decoded instruction boundary.
                p.withTransaction {
                    val helper = address(0x28)
                    p.listing.clearCodeUnits(helper, helper.add(2), false)
                    p.memory.setByte(helper.add(1), 1)
                    ghidra.program.disassemble.Disassembler
                        .getDisassembler(p, TaskMonitor.DUMMY, null)
                        .disassemble(helper, AddressSet(helper, helper.add(2)))
                }
                assertThrows(IllegalArgumentException::class.java) { SoftwareCallRegistry.resolve(p, root) }
                assertThrows(IllegalArgumentException::class.java) { SoftwareCallRegistry.resolve(p, alias) }
                AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
                p.withTransaction {
                    val helper = address(0x28)
                    p.listing.clearCodeUnits(helper, helper.add(2), false)
                    p.memory.setByte(helper.add(1), 0)
                    ghidra.program.disassemble.Disassembler
                        .getDisassembler(p, TaskMonitor.DUMMY, null)
                        .disassemble(helper, AddressSet(helper, helper.add(2)))
                    p.listing.clearCodeUnits(address(0x240), address(0x241), false)
                    p.memory.setByte(address(0x241), 0x6a)
                    ghidra.program.disassemble.Disassembler
                        .getDisassembler(p, TaskMonitor.DUMMY, null)
                        .disassemble(address(0x240), AddressSet(address(0x240), address(0x241)))
                }
                val reapplied = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
                SoftwareCallApplication.apply(p, reapplied, TaskMonitor.DUMMY)
                val nextAlias =
                    p.addressFactory
                        .getAddressSpace(
                            reapplied.executionViews().getValue(root.toString()).name(),
                        ).getAddress(root.offset)
                p.withTransaction {
                    manager.reAnalyzeAll(AddressSet(p.memory))
                    manager.startAnalysis(TaskMonitor.DUMMY)
                }
                assertRedirect(p, root, nextAlias)
                verifyNative(p, decompiler, listOf(root, nextAlias), target, 0x6bL)
                AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
                assertNull(p.functionManager.getFunctionAt(nextAlias))
                assertFalse(p.memory.getBlock(nextAlias).isExecute)
                assertFalse(p.getOptions(ProgramMapping.OPTIONS).contains(SoftwareCallRegistry.STOCK_KEY))
                assertEquals("Original source instruction note", p.listing.getComment(CommentType.EOL, root))
            } finally {
                decompiler.dispose()
            }
        }

    @Test
    fun `edited fresh canonical source survives removal while owned redirect clears and alias retires`() =
        fixture { p, config, root, _ ->
            val alias = applyFresh(p, config, root)
            val canonical = p.functionManager.getFunctionAt(root)
            val originalBytes =
                p.listing
                    .getInstructionAt(root)
                    .bytes
                    .toList()
            p.withTransaction {
                canonical.setName("user_renamed_source", SourceType.USER_DEFINED)
                canonical.comment = "User source comment after application"
            }
            assertFalse(
                AnalysisOwnership.sourceRedirectCurrent(p, canonical),
                "Edited metadata must differ from the original whole-function receipt",
            )
            assertEquals(alias, canonical.getThunkedFunction(false).entryPoint)
            AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            val preserved = p.functionManager.getFunctionAt(root)
            assertNotNull(preserved)
            assertEquals("user_renamed_source", preserved.name)
            assertEquals("User source comment after application", preserved.comment)
            assertEquals(SourceType.USER_DEFINED, preserved.symbol.source)
            assertFalse(preserved.isThunk, "Unchanged owned redirect must clear despite unrelated user edits")
            assertNull(preserved.callFixup)
            assertFalse(p.getOptions(ProgramMapping.OPTIONS).contains(SoftwareCallRegistry.STOCK_KEY))
            assertNotNull(p.memory.getBlock(alias))
            assertFalse(p.memory.getBlock(alias).isExecute)
            assertNull(p.listing.getInstructionAt(alias))
            assertNull(p.functionManager.getFunctionAt(alias))
            assertEquals(
                originalBytes,
                p.listing
                    .getInstructionAt(root)
                    .bytes
                    .toList(),
            )
            assertEquals("Original source instruction note", p.listing.getComment(CommentType.EOL, root))
            assertTrue(p.symbolTable.getSymbols("unrelated_user_label").hasNext())
        }
}
