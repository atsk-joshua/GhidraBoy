package fi.gekkio.ghidraboy

import ghidra.app.decompiler.DecompInterface
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.listing.CommentType
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

class SoftwareCallInstructionDiscoveryTest : IntegrationTest() {
    @Test
    fun `public review discovers absent helper callee and continuation and native canonical call`() {
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x28, 3, null)
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        HexFormat.of().parseHex(template.bodyHex()).copyInto(bytes, 0x28)
        HexFormat.of().parseHex("ef020040ea00c2c9").copyInto(bytes, 0x200)
        HexFormat.of().parseHex("3e5b37c9").copyInto(bytes, 0x8000)
        val consumer = Any()
        val p = ProgramDB("fresh public software call", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            val target = ProgramMapping.fileToStatic(p, 0x8000).single()
            // Named caller and callee roots are user annotations; no Function or Instruction
            // boundaries have been supplied. Configuration and physical flow justify discovery.
            p.withTransaction {
                p.symbolTable.createLabel(address(0x200), "fresh_caller", SourceType.USER_DEFINED)
                p.symbolTable.createLabel(target, "named_fresh_target", SourceType.USER_DEFINED)
                p.listing.setComment(address(0x204), CommentType.EOL, "preserve continuation comment")
            }
            assertNull(p.functionManager.getFunctionAt(address(0x200)))
            assertNull(p.functionManager.getFunctionAt(target))
            assertNull(p.listing.getInstructionAt(address(0x28)))
            assertNull(p.listing.getInstructionAt(address(0x200)))
            assertNull(p.listing.getInstructionAt(address(0x204)))
            assertNull(p.listing.getInstructionAt(target))
            val config =
                SoftwareCallValidation.Configuration(
                    0x200,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(0, 0, 0, 0, 0),
                    MapperState.reset(),
                )
            val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
            val discovered = review.instructionDiscovery().candidates().map { it.address() }
            assertTrue(
                discovered.containsAll(
                    listOf(address(0x28).toString(), address(0x200).toString(), address(0x204).toString(), target.toString()),
                ),
            )
            assertFalse(discovered.any { it in (0x201L..0x203L).map { offset -> address(offset).toString() } })
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            assertNotNull(p.listing.getInstructionAt(address(0x28)))
            assertNotNull(p.listing.getInstructionAt(target))
            assertNotNull(p.listing.getInstructionAt(address(0x204)))
            assertNotNull(p.listing.getDefinedDataAt(address(0x201)))
            assertNull(p.listing.getInstructionAt(address(0x201)))
            assertEquals("preserve continuation comment", p.listing.getComment(CommentType.EOL, address(0x204)))
            assertNotNull(p.functionManager.getFunctionAt(target))
            assertEquals("named_fresh_target", p.functionManager.getFunctionAt(target).name)
            assertEquals(
                SourceType.USER_DEFINED,
                p.functionManager
                    .getFunctionAt(target)
                    .symbol.source,
            )
            assertEquals("fresh_caller", p.functionManager.getFunctionAt(address(0x200)).name)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                val result = decompiler.decompileFunction(p.functionManager.getFunctionAt(address(0x200)), 30, TaskMonitor.DUMMY)
                assertTrue(result.decompileCompleted(), result.errorMessage)
                assertTrue(
                    result.highFunction.pcodeOps.asSequence().any {
                        it.opcode == PcodeOp.CALL && it.getInput(0).address == target
                    },
                    result.decompiledFunction.c,
                )
                assertTrue(result.decompiledFunction.c.contains("c200"), result.decompiledFunction.c)
            } finally {
                decompiler.dispose()
            }
            val reapplied = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            assertTrue(reapplied.instructionDiscovery().candidates().isEmpty())
            SoftwareCallApplication.apply(p, reapplied, TaskMonitor.DUMMY)
            AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            assertNotNull(p.listing.getInstructionAt(target))
            assertTrue(p.symbolTable.getSymbols("fresh_caller").hasNext())
            assertTrue(p.symbolTable.getSymbols("named_fresh_target").hasNext())
            assertEquals("preserve continuation comment", p.listing.getComment(CommentType.EOL, address(0x204)))
        } finally {
            p.release(consumer)
        }
    }

    private fun fixture(action: (ProgramDB) -> Unit) {
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        HexFormat.of().parseHex("3e42c90000").copyInto(bytes, 0x200)
        HexFormat.of().parseHex("ea00c2c9").copyInto(bytes, 0x8000)
        val consumer = Any()
        val p = ProgramDB("fresh rooted discovery", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            action(p)
        } finally {
            p.release(consumer)
        }
    }

    private fun discover(p: ProgramDB): SoftwareCallInstructionDiscovery.Plan =
        SoftwareCallInstructionDiscovery.begin(p, TaskMonitor.DUMMY).use { session ->
            val instruction = SoftwareCallInstructionDiscovery.instructionAt(p, address(0x200), "JUSTIFIED_CALLEE_FETCH", TaskMonitor.DUMMY)
            assertEquals(2, instruction.length)
            assertEquals("ld", instruction.mnemonicString.lowercase())
            session.plan(TaskMonitor.DUMMY)
        }

    @Test
    fun `fresh speculative decode changes no listing and commits only requested rooted extent`() =
        fixture { p ->
            val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            assertNull(p.listing.getInstructionAt(address(0x200)))
            val plan = discover(p)
            assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
            assertNull(p.listing.getInstructionAt(address(0x200)))
            assertEquals(listOf("0200"), plan.candidates().map { it.address() })
            assertEquals("3e42", plan.candidates().single().bytes())
            assertEquals(
                listOf(0, 0),
                plan
                    .candidates()
                    .single()
                    .physicalBytes()
                    .map { it.bank() },
            )
            SoftwareCallInstructionDiscovery.apply(p, plan, TaskMonitor.DUMMY)
            assertEquals(2, p.listing.getInstructionAt(address(0x200)).length)
            assertNull(p.listing.getInstructionAt(address(0x202)))
            assertNull(p.listing.getInstructionAt(address(0x203)))
            assertNull(p.functionManager.getFunctionAt(address(0x200)))
        }

    @Test
    fun `data payload and conflicting instruction boundaries remain intact`() =
        fixture { p ->
            p.withTransaction { p.listing.createData(address(0x201), ByteDataType.dataType) }
            assertThrows(IllegalArgumentException::class.java) { discover(p) }
            assertNotNull(p.listing.getDefinedDataAt(address(0x201)))
            p.withTransaction {
                p.listing.clearCodeUnits(address(0x201), address(0x201), false)
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(address(0x201), AddressSet(address(0x201)), false)
            }
            assertThrows(IllegalArgumentException::class.java) { discover(p) }
            assertNotNull(p.listing.getInstructionAt(address(0x201)))
        }

    @Test
    fun `inline reservations prevent even plausible opcode roots and operands`() =
        fixture { p ->
            SoftwareCallInstructionDiscovery.begin(p, TaskMonitor.DUMMY).use { session ->
                session.reserve(address(0x201), 1, "INLINE_PAYLOAD")
                assertThrows(IllegalArgumentException::class.java) {
                    SoftwareCallInstructionDiscovery.instructionAt(p, address(0x200), "CALLEE_FETCH", TaskMonitor.DUMMY)
                }
                assertThrows(IllegalArgumentException::class.java) {
                    SoftwareCallInstructionDiscovery.instructionAt(p, address(0x201), "CONTINUATION", TaskMonitor.DUMMY)
                }
                assertTrue(session.plan(TaskMonitor.DUMMY).candidates().isEmpty())
            }
            assertNull(p.listing.getInstructionAt(address(0x200)))
        }

    @Test
    fun `named root comments function and incoming reference are preserved`() =
        fixture { p ->
            p.withTransaction {
                p.symbolTable.createLabel(address(0x200), "named_root", SourceType.USER_DEFINED)
                p.listing.setComment(address(0x200), CommentType.EOL, "reviewed root")
                p.functionManager.createFunction(
                    "root_function",
                    address(0x200),
                    AddressSet(address(0x200), address(0x202)),
                    SourceType.USER_DEFINED,
                )
                p.referenceManager.addMemoryReference(
                    address(0x350),
                    address(0x200),
                    RefType.UNCONDITIONAL_CALL,
                    SourceType.USER_DEFINED,
                    0,
                )
            }
            val function = p.functionManager.getFunctionAt(address(0x200))
            val body = AddressSet(function.body)
            SoftwareCallInstructionDiscovery.apply(p, discover(p), TaskMonitor.DUMMY)
            assertEquals("reviewed root", p.listing.getComment(CommentType.EOL, address(0x200)))
            assertTrue(p.symbolTable.getSymbols("named_root").hasNext())
            assertEquals(body, function.body)
            assertTrue(
                p.referenceManager.getReferencesFrom(address(0x350)).any {
                    it.toAddress == address(0x200) &&
                        it.source == SourceType.USER_DEFINED
                },
            )
        }

    @Test
    fun `interior user label and referenced byte block discovery without removal`() =
        fixture { p ->
            p.withTransaction { p.symbolTable.createLabel(address(0x201), "operand_claim", SourceType.USER_DEFINED) }
            assertThrows(IllegalArgumentException::class.java) { discover(p) }
            p.withTransaction {
                p.symbolTable
                    .getSymbols("operand_claim")
                    .next()
                    .delete()
            }
            p.withTransaction {
                p.referenceManager.addMemoryReference(
                    address(0x350),
                    address(0x201),
                    RefType.DATA,
                    SourceType.USER_DEFINED,
                    0,
                )
            }
            assertThrows(IllegalArgumentException::class.java) { discover(p) }
            assertTrue(p.referenceManager.getReferencesTo(address(0x201)).hasNext())
            assertNull(p.listing.getInstructionAt(address(0x200)))
        }

    @Test
    fun `undecoded root with conflicting user flow refuses speculative interpretation`() =
        fixture { p ->
            p.withTransaction {
                p.referenceManager.addMemoryReference(
                    address(0x200),
                    address(0x300),
                    RefType.CALL_OVERRIDE_UNCONDITIONAL,
                    SourceType.USER_DEFINED,
                    -1,
                )
            }
            val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            assertThrows(IllegalArgumentException::class.java) { discover(p) }
            assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
            assertTrue(p.referenceManager.getReferencesFrom(address(0x200)).any { it.referenceType.isOverride })
        }

    @Test
    fun `register context mutation invalidates a reviewed speculative plan`() =
        fixture { p ->
            val plan = discover(p)
            p.withTransaction {
                p.programContext.setValue(p.getRegister("A"), address(0x200), address(0x200), java.math.BigInteger.valueOf(42))
            }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallInstructionDiscovery.apply(p, plan, TaskMonitor.DUMMY) }
            assertNull(p.listing.getInstructionAt(address(0x200)))
        }

    @Test
    fun `stale bytes annotations permissions and context reject reviewed commit`() =
        fixture { p ->
            val plan = discover(p)
            p.withTransaction { p.listing.setComment(address(0x200), CommentType.EOL, "edited after review") }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallInstructionDiscovery.apply(p, plan, TaskMonitor.DUMMY) }
            assertNull(p.listing.getInstructionAt(address(0x200)))
            val next = discover(p)
            p.withTransaction { p.memory.setByte(address(0x201), 0x43) }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallInstructionDiscovery.apply(p, next, TaskMonitor.DUMMY) }
            val current = discover(p)
            p.withTransaction { p.memory.getBlock(address(0x200)).isExecute = false }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallInstructionDiscovery.apply(p, current, TaskMonitor.DUMMY) }
            assertThrows(IllegalArgumentException::class.java) { discover(p) }
        }

    @Test
    fun `cancelled preview and apply preserve fresh Program`() =
        fixture { p ->
            val plan = discover(p)
            val monitor = TaskMonitorAdapter(true)
            monitor.cancel()
            assertThrows(CancelledException::class.java) { SoftwareCallInstructionDiscovery.apply(p, plan, monitor) }
            assertThrows(CancelledException::class.java) { SoftwareCallInstructionDiscovery.begin(p, monitor) }
            assertNull(p.listing.getInstructionAt(address(0x200)))
            assertNull(SoftwareCallInstructionDiscovery.instructionAt(p, address(0x200), "NO_SESSION", TaskMonitor.DUMMY))
        }

    @Test
    fun `cancellation after first committed instruction rolls back all listing and reference changes`() =
        fixture { p ->
            val plan =
                SoftwareCallInstructionDiscovery.begin(p, TaskMonitor.DUMMY).use { session ->
                    SoftwareCallInstructionDiscovery.instructionAt(p, address(0x200), "CALLEE_ROOT", TaskMonitor.DUMMY)
                    SoftwareCallInstructionDiscovery.instructionAt(p, address(0x202), "FALLTHROUGH", TaskMonitor.DUMMY)
                    session.plan(TaskMonitor.DUMMY)
                }
            val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            val monitor =
                object : TaskMonitorAdapter(true) {
                    override fun checkCancelled() {
                        if (p.listing.getInstructionAt(address(0x200)) != null) throw CancelledException()
                        super.checkCancelled()
                    }
                }
            assertThrows(CancelledException::class.java) { SoftwareCallInstructionDiscovery.apply(p, plan, monitor) }
            assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
            assertNull(p.listing.getInstructionAt(address(0x200)))
            assertNull(p.listing.getInstructionAt(address(0x202)))
        }

    @Test
    fun `nested discovery scopes isolate candidates and restore previous scope`() =
        fixture { p ->
            SoftwareCallInstructionDiscovery.begin(p, TaskMonitor.DUMMY).use { outer ->
                SoftwareCallInstructionDiscovery.instructionAt(p, address(0x200), "OUTER_ROOT", TaskMonitor.DUMMY)
                SoftwareCallInstructionDiscovery.begin(p, TaskMonitor.DUMMY).use { inner ->
                    SoftwareCallInstructionDiscovery.instructionAt(p, address(0x202), "INNER_ROOT", TaskMonitor.DUMMY)
                    assertEquals(listOf("0202"), inner.plan(TaskMonitor.DUMMY).candidates().map { it.address() })
                }
                assertEquals(listOf("0200"), outer.plan(TaskMonitor.DUMMY).candidates().map { it.address() })
            }
            assertNull(SoftwareCallInstructionDiscovery.instructionAt(p, address(0x202), "NO_SESSION", TaskMonitor.DUMMY))
        }

    @Test
    fun `abandoned alternative discards its speculative candidates and reservations`() =
        fixture { p ->
            SoftwareCallInstructionDiscovery.begin(p, TaskMonitor.DUMMY).use { session ->
                SoftwareCallInstructionDiscovery.instructionAt(p, address(0x200), "ESTABLISHED_ROOT", TaskMonitor.DUMMY)
                val checkpoint = SoftwareCallInstructionDiscovery.checkpoint(p)
                SoftwareCallInstructionDiscovery.instructionAt(p, address(0x202), "ABANDONED_PATH", TaskMonitor.DUMMY)
                session.reserve(address(0x204), 1, "ABANDONED_RESERVATION")
                SoftwareCallInstructionDiscovery.rollback(p, checkpoint)
                SoftwareCallInstructionDiscovery.instructionAt(p, address(0x204), "ACTUAL_FALLBACK", TaskMonitor.DUMMY)
                assertEquals(listOf("0200", "0204"), session.plan(TaskMonitor.DUMMY).candidates().map { it.address() })
                assertTrue(session.plan(TaskMonitor.DUMMY).reservations().isEmpty())
                SoftwareCallInstructionDiscovery.begin(p, TaskMonitor.DUMMY).use {
                    assertThrows(IllegalStateException::class.java) { SoftwareCallInstructionDiscovery.rollback(p, checkpoint) }
                }
            }
            assertNull(p.listing.getInstructionAt(address(0x202)))
        }

    @Test
    fun `public fallback commits only final state proof candidates not abandoned finite branch`() =
        fixture { p ->
            val template = SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x28, 3, null)
            val target = ProgramMapping.fileToStatic(p, 0x8000).single()
            p.withTransaction {
                p.memory.setBytes(address(0x28), HexFormat.of().parseHex(template.bodyHex()))
                // Z is clear. The finite candidate visits 020d before its mapper-write veto;
                // the state proof follows 0206 -> 0208 -> 020b and never fetches 020d.
                p.memory.setBytes(address(0x200), HexFormat.of().parseHex("ef02004028073e02ea0020c900c9"))
                p.memory.setByte(target, 0xc9.toByte())
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x200,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(0, 0, 0, 0, 0),
                    MapperState.reset(),
                )
            SoftwareCallInstructionDiscovery.begin(p, TaskMonitor.DUMMY).use { session ->
                val validated = SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY)
                val effects = SoftwareCallEffects.deriveForReview(p, validated.frame(), TaskMonitor.DUMMY, listOf(config))
                assertThrows(IllegalArgumentException::class.java) {
                    SoftwareCallExecutionView.continuationSegments(p, effects.paths().single().returned(), TaskMonitor.DUMMY, false)
                }
                assertTrue(session.plan(TaskMonitor.DUMMY).candidates().any { it.address() == address(0x20d).toString() })
            }
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            assertTrue(review.stateContinuations().isNotEmpty())
            val candidates = review.instructionDiscovery().candidates().map { it.address() }
            assertTrue(candidates.contains(address(0x20b).toString()))
            assertFalse(candidates.contains(address(0x20d).toString()), candidates.toString())
            assertNull(p.listing.getInstructionAt(address(0x20d)))
        }

    @Test
    fun `banked candidates retain physical identity and enclosing rollback removes all commits`() =
        fixture { p ->
            val banked = ProgramMapping.fileToStatic(p, 0x8000).single()
            val plan =
                SoftwareCallInstructionDiscovery.begin(p, TaskMonitor.DUMMY).use { session ->
                    SoftwareCallInstructionDiscovery.instructionAt(p, banked, "MAPPER_JUSTIFIED_FETCH", TaskMonitor.DUMMY)
                    session.plan(TaskMonitor.DUMMY)
                }
            assertEquals(
                listOf(2, 2, 2),
                plan
                    .candidates()
                    .single()
                    .physicalBytes()
                    .map { it.bank() },
            )
            val transaction = p.startTransaction("Cancel whole reviewed software call application")
            try {
                SoftwareCallInstructionDiscovery.apply(p, plan, TaskMonitor.DUMMY)
                assertNotNull(p.listing.getInstructionAt(banked))
            } finally {
                p.endTransaction(transaction, false)
            }
            assertNull(p.listing.getInstructionAt(banked))
            assertFalse(p.referenceManager.getReferencesFrom(banked).isNotEmpty())
        }
}
