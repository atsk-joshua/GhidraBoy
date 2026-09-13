package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.data.UnsignedShortDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FiniteDispatchTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY

    private fun fixture(
        name: String,
        h: Int? = null,
        action: (ProgramDB, Function, SymbolicMemory.Declaration) -> Unit,
    ) {
        val bytes = requireNotNull(javaClass.getResourceAsStream("/dispatch/$name.gb")).use { it.readBytes() }
        val nibble = name.startsWith("nibble")
        val owner = Any()
        val p = ProgramDB(name, language, language.defaultCompilerSpec, owner)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, monitor, MessageLog())
            }
            p.withTransaction {
                for (at in listOf(0xc000L, 0xff80L)) p.memory.convertToInitialized(p.memory.getBlock(address(at)), 0.toByte())
                val body =
                    AddressSet(
                        address(0x100),
                        address(
                            if (nibble) {
                                0x116
                            } else if (name ==
                                "physical-banks"
                            ) {
                                0x113
                            } else if (name == "zero") {
                                0x108
                            } else {
                                0x12f
                            },
                        ),
                    )
                for (
                i in 0 until
                    if (nibble) {
                        16
                    } else if (name.startsWith("normalized")) {
                        6
                    } else {
                        0
                    }
                ) {
                    val at = if (nibble) 0x1000L + 8 * i else 0x300L + 3 * i
                    body.add(address(at), address(at + if (nibble) 6 else 2))
                }
                Disassembler.getDisassembler(p, monitor, null).disassemble(address(0x100), body)
                val f = p.functionManager.createFunction(name, address(0x100), body, SourceType.USER_DEFINED)
                f.updateFunction(
                    "default",
                    ReturnParameterImpl(
                        if (nibble) UnsignedShortDataType.dataType else ByteDataType.dataType,
                        p.getRegister(if (nibble) "HL" else "A"),
                        p,
                    ),
                    Function.FunctionUpdateType.CUSTOM_STORAGE,
                    true,
                    SourceType.USER_DEFINED,
                )
            }
            action(p, p.functionManager.getFunctionAt(address(0x100)), SymbolicMemory.declare(p, listOf(h ?: 0xff80), emptyList(), null, h))
        } finally {
            p.release(owner)
        }
    }

    @Test
    fun normalized() =
        fixture("normalized") { p, f, declaration ->
            val revision = p.modificationNumber
            val proof = PredicatedCallGraph.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, declaration, monitor)
            assertEquals(revision, p.modificationNumber)
            assertTrue(proof.complete(), proof.frontier().toString())
            val dispatch = proof.nodes().filter { it.transfer() == "BRANCHIND" }
            assertEquals(6, dispatch.sumOf { it.edges().size })
            val entry = PredicatedCalls.install(p, proof, monitor)
            val emitted = PredicatedCalls.emit(p, entry, 0x200000, monitor)
            assertFalse(emitted.any { it.opcode == PcodeOp.BRANCHIND })
            p.withTransaction { p.memory.setShort(address(0x203), 0x303.toShort()) }
            assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.emit(p, entry, 0x200000, monitor) }
        }

    @Test
    fun nibble() {
        for (h in listOf(0xc060, 0xc17f)) {
            fixture("nibble", h) { p, f, declaration ->
                val proof = PredicatedCallGraph.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, declaration, monitor)
                assertTrue(proof.complete(), proof.frontier().toString())
                val edges = proof.nodes().filter { it.transfer() == "BRANCHIND" }.flatMap { it.edges() }
                val targets = edges.map { edge -> proof.nodes().single { it.id() == edge.target() }.source() }.toSet()
                assertEquals((0..15).map { "%04x".format(0x1000 + it * 8) }.toSet(), targets)
                assertEquals(128, (0..127).count { p.memory.getShort(address(0x200L + it * 2)).toInt() == 0x1000 + it * 8 })
                val entry = PredicatedCalls.install(p, proof, monitor)
                assertFalse(PredicatedCalls.emit(p, entry, 0x200000, monitor).any { it.opcode == PcodeOp.BRANCHIND })
            }
        }
    }

    @Test
    fun incompleteBudget() =
        fixture("normalized") { p, f, declaration ->
            val proof = PredicatedCallGraph.preview(p, f, PredicatedCallGraph.Limits(8, 128, 1), declaration, monitor)
            assertFalse(proof.complete())
            assertTrue(proof.frontier().isNotEmpty())
            assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.install(p, proof, monitor) }
        }

    @Test
    fun relocatedAndDuplicateTargets() {
        for (name in listOf("normalized-relocated", "nibble-relocated")) {
            fixture(name, if (name.startsWith("nibble")) 0xc060 else null) { p, f, declaration ->
                val proof = PredicatedCallGraph.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, declaration, monitor)
                assertTrue(proof.complete(), proof.frontier().toString())
                val targets =
                    proof
                        .nodes()
                        .filter { it.transfer() == "BRANCHIND" }
                        .flatMap { it.edges() }
                        .map { edge ->
                            proof
                                .nodes()
                                .single {
                                    it.id() ==
                                        edge.target()
                                }.cpu()
                        }.toSet()
                val order =
                    if (name.startsWith(
                            "nibble",
                        )
                    ) {
                        listOf(15, 4, 4, 0, 3, 9, 2, 7, 11, 1, 10, 6, 12, 13, 14, 8)
                    } else {
                        listOf(5, 2, 2, 0, 4, 1)
                    }
                assertEquals(order.map { if (name.startsWith("nibble")) 0x1000 + 8 * it else 0x300 + 3 * it }.toSet(), targets)
            }
        }
    }

    @Test
    fun mutableTableAndStaleGuardRefuse() =
        fixture("normalized") { p, f, declaration ->
            p.withTransaction { p.memory.getBlock(address(0x203)).isWrite = true }
            assertFalse(PredicatedCallGraph.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, declaration, monitor).complete())
        }

    @Test
    fun refreshAndEditedRemoval() =
        fixture("normalized") { p, f, declaration ->
            val proof = PredicatedCallGraph.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, declaration, monitor)
            val entry = PredicatedCalls.install(p, proof, monitor)
            p.withTransaction { p.memory.setShort(address(0x203), 0x303.toShort()) }
            val fresh = PredicatedCallGraph.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, declaration, monitor)
            PredicatedCalls.refresh(p, entry, fresh, monitor)
            assertTrue(PredicatedCalls.emit(p, entry, 0x200000, monitor).isNotEmpty())
            val owned = p.functionManager.getFunctionAt(entry)
            p.withTransaction { owned.setName("later_user_name", SourceType.USER_DEFINED) }
            val diagnostics = PredicatedCalls.remove(p, entry, monitor)
            assertTrue(diagnostics.any { it.contains("Preserved") })
            assertEquals("later_user_name", p.functionManager.getFunctionAt(entry).name)
            assertFalse(PredicatedCalls.registered(p, entry))
            assertEquals(f, p.functionManager.getFunctionAt(address(0x100)))
        }

    @Test
    fun physicalBanksAndZeroSingleton() {
        for (name in listOf("physical-banks", "zero")) {
            fixture(name) { p, f, declaration ->
                val proof = PredicatedCallGraph.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, declaration, monitor)
                assertTrue(proof.complete(), proof.frontier().toString())
                val jumps = proof.nodes().filter { it.transfer() == "BRANCHIND" }
                val targets =
                    jumps
                        .flatMap { it.edges() }
                        .map { edge ->
                            proof.nodes().single { it.id() == edge.target() }.source()
                        }.toSet()
                assertEquals(if (name == "zero") setOf("0300") else setOf("rom1::4000", "rom2::4000"), targets)
                if (name != "zero") assertEquals(1, jumps.map { it.cpu() }.distinct().size)
                val entry = PredicatedCalls.install(p, proof, monitor)
                assertFalse(PredicatedCalls.emit(p, entry, 0x200000, monitor).any { it.opcode == PcodeOp.BRANCHIND })
            }
        }
    }

    @Test
    fun genuinePriorRecordRejectsBeforeInterpretation() =
        fixture("zero") { p, f, declaration ->
            val old = requireNotNull(javaClass.getResourceAsStream("/dispatch/prior-stock2.json")).bufferedReader().use { it.readText() }
            val at = f.entryPoint
            p.withTransaction { p.getOptions(PredicatedCalls.STOCK_OPTIONS).setString(at.toString(), old) }
            val revision = p.modificationNumber
            val failure = assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.registeredProof(p, at) }
            assertTrue(failure.message.orEmpty().contains("Unsupported predicated graph version"))
            assertEquals(revision, p.modificationNumber)
            assertEquals(old, p.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(at.toString(), null))
        }

    @Test
    fun cancellationAfterOwnedWriteRollsBack() =
        fixture("zero") { p, f, declaration ->
            val proof = PredicatedCallGraph.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, declaration, monitor)
            val functions = p.functionManager.functionCount
            val blocks = p.memory.blocks.map { it.start.toString() }
            var observed = false
            val cancellation =
                object : ghidra.util.task.TaskMonitorAdapter() {
                    override fun checkCancelled() {
                        if (p.memory.blocks.any { it.name.startsWith("gb_ordinary_pred_") }) {
                            observed = true
                            throw ghidra.util.exception.CancelledException()
                        }
                    }
                }
            assertThrows(ghidra.util.exception.CancelledException::class.java) { PredicatedCalls.install(p, proof, cancellation) }
            assertTrue(observed)
            assertEquals(functions, p.functionManager.functionCount)
            assertEquals(blocks, p.memory.blocks.map { it.start.toString() })
            assertTrue(p.getOptions(PredicatedCalls.STOCK_OPTIONS).optionNames.isEmpty())
        }

    @Test
    fun consumedGuardAndTargetEditsRejectOldAuthority() {
        for (at in listOf(0x104L, 0x301L)) {
            fixture("normalized") { p, f, declaration ->
                val proof = PredicatedCallGraph.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, declaration, monitor)
                val entry = PredicatedCalls.install(p, proof, monitor)
                p.withTransaction {
                    val ins = p.listing.getInstructionContaining(address(at))
                    val range = AddressSet(ins.minAddress, ins.maxAddress)
                    p.listing.clearCodeUnits(ins.minAddress, ins.maxAddress, false)
                    p.memory.setByte(address(at), (p.memory.getByte(address(at)) + 1).toByte())
                    Disassembler.getDisassembler(p, monitor, null).disassemble(range.minAddress, range, false)
                }
                val failure = assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.emit(p, entry, 0x200000, monitor) }
                assertTrue(failure.message.orEmpty().contains("Stale predicated graph"))
            }
        }
    }

    @Test
    fun mutableTargetPointerIsUnproved() =
        fixture("normalized") { p, f, declaration ->
            p.withTransaction {
                p.listing.clearCodeUnits(address(0x122), address(0x124), false)
                p.memory.setShort(address(0x123), 0xc200.toShort())
                Disassembler
                    .getDisassembler(
                        p,
                        monitor,
                        null,
                    ).disassemble(address(0x122), AddressSet(address(0x122), address(0x124)), false)
            }
            val proof = PredicatedCallGraph.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, declaration, monitor)
            assertFalse(proof.complete())
            assertTrue(proof.frontier().any { it.reason().contains("mutable table/read pointer") }, proof.frontier().toString())
            assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.install(p, proof, monitor) }
        }

    @Test
    fun compiledLogicalShiftHasCompleteByteDomain() =
        fixture("zero") { p, _, _ ->
            p.withTransaction {
                p.listing.clearCodeUnits(address(0x103), address(0x104), false)
                p.memory.setBytes(address(0x103), byteArrayOf(0xcb.toByte(), 0x3f))
                val range = AddressSet(address(0x103), address(0x104))
                Disassembler.getDisassembler(p, monitor, null).disassemble(address(0x103), range, false)
            }
            val storage = AbstractValues.Storage("compiled-SRL")
            val instruction = p.listing.getInstructionAt(address(0x103))
            assertEquals("SRL", instruction.mnemonicString)
            for (op in instruction.getPcode(false)) {
                val args = op.inputs.map { storage.get(it) }
                val value = AbstractValues.evaluate(op.opcode, op.output.size, args, "compiled-SRL")
                storage.put(op.output, value)
            }
            val a =
                ghidra.program.model.pcode
                    .Varnode(p.getRegister("A").address, 1)
            assertEquals((0L..127L).toSet(), storage.get(a).values())
        }

    @Test
    fun rootReturnStorageEditsReject() {
        for (source in listOf(false, true)) {
            fixture("zero") { p, f, declaration ->
                val proof = PredicatedCallGraph.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, declaration, monitor)
                val entry = PredicatedCalls.install(p, proof, monitor)
                val changed = if (source) f else p.functionManager.getFunctionAt(entry)
                p.withTransaction {
                    val result = ReturnParameterImpl(ByteDataType.dataType, p.getRegister("B"), p)
                    changed.updateFunction(
                        changed.callingConventionName,
                        result,
                        Function.FunctionUpdateType.CUSTOM_STORAGE,
                        true,
                        SourceType.USER_DEFINED,
                    )
                }
                assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.emit(p, entry, 0x200000, monitor) }
            }
        }
    }

    @Test
    fun replacedOuterReturnWordIsNotAnOrdinaryReturn() =
        fixture("zero") { p, f, declaration ->
            p.withTransaction {
                p.listing.clearCodeUnits(address(0x100), address(0x108), false)
                p.memory.setBytes(address(0x100), byteArrayOf(0x33, 0x33, 0xe5.toByte(), 0xc9.toByte()))
                val range = AddressSet(address(0x100), address(0x103))
                Disassembler.getDisassembler(p, monitor, null).disassemble(address(0x100), range, false)
            }
            val proof = PredicatedCallGraph.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, declaration, monitor)
            assertFalse(proof.complete())
            assertTrue(proof.frontier().any { it.reason().contains("Outer return word was replaced") }, proof.frontier().toString())
        }
}
