package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.FlowOverride
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class InstructionInterpretationTest : IntegrationTest() {
    private fun program(test: (ProgramDB) -> Unit) {
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        bytes[0x149] = 3
        byteArrayOf(0x31, 0, 0xc1.toByte(), 0xcd.toByte(), 0, 0x20, 0xc9.toByte()).copyInto(bytes, 0x150)
        byteArrayOf(0xc3.toByte(), 0, 0x20).copyInto(bytes, 0x180)
        byteArrayOf(0xca.toByte(), 0, 0x20, 0xc9.toByte()).copyInto(bytes, 0x190)
        byteArrayOf(0xef.toByte(), 2, 0, 0x40, 0xc9.toByte()).copyInto(bytes, 0x200)
        java.util.HexFormat
            .of()
            .parseHex(FarCallConvention.SUPPORTED_BODY)
            .copyInto(bytes, 0x28)
        bytes[0x2000] = 0xc9.toByte()
        val consumer = Any()
        val p = ProgramDB("SA-00 self-authored interpretation", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                for ((start, end) in listOf(
                    0x150L to 0x156L,
                    0x180L to 0x182L,
                    0x190L to 0x193L,
                    0x200L to 0x200L,
                    0x204L to 0x204L,
                    0x2000L to 0x2000L,
                )) {
                    d.disassemble(address(start), AddressSet(address(start), address(end)))
                }
            }
            test(p)
        } finally {
            p.release(consumer)
        }
    }

    private fun preview(
        p: ProgramDB,
        start: Long,
    ) = BankAnalysis.preview(p, address(start), MapperState.reset(), AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY)

    private fun assertStopped(
        p: ProgramDB,
        start: Long,
        expected: String,
    ) {
        val r = preview(p, start)
        assertEquals(1, r.exploredStates(), r.toString())
        assertEquals(AnalysisResult.Confidence.UNKNOWN, r.findings().single().confidence())
        assertTrue(
            r
                .findings()
                .single()
                .reason()
                .contains(expected),
            r.toString(),
        )
    }

    @Test
    fun `compiled call stack effects stay architectural and modified call and branch stop`() =
        program { p ->
            val call = p.listing.getInstructionAt(address(0x153))
            val jump = p.listing.getInstructionAt(address(0x180))
            val rawCall = call.getPcode(false)
            assertEquals(2, rawCall.count { it.opcode == PcodeOp.STORE })
            assertEquals(address(0x2000), rawCall.single { it.opcode == PcodeOp.CALL }.getInput(0).address)
            val regs = HashMap<Long, Int>()
            val unique = HashMap<Long, Int>()
            val sp = p.getRegister("SP")
            PcodeConstants.put(
                ghidra.program.model.pcode
                    .Varnode(sp.address, sp.minimumByteSize),
                0xc100L,
                regs,
                unique,
            )
            val writes = ArrayList<Pair<Long?, Long?>>()
            for (op in rawCall) {
                if (op.opcode ==
                    PcodeOp.STORE
                ) {
                    writes +=
                        PcodeConstants.value(op.getInput(1), regs, unique) to PcodeConstants.value(op.getInput(2), regs, unique)
                }
                if (op.output != null) PcodeConstants.put(op.output, PcodeConstants.evaluate(op, regs, unique), regs, unique)
            }
            assertEquals(listOf(0xc0ffL to 1L, 0xc0feL to 0x56L), writes)
            assertEquals(
                0xc0feL,
                PcodeConstants.value(
                    ghidra.program.model.pcode
                        .Varnode(sp.address, sp.minimumByteSize),
                    regs,
                    unique,
                ),
            )
            assertEquals(0, jump.getPcode(false).count { it.opcode == PcodeOp.STORE })
            p.withTransaction {
                call.flowOverride = FlowOverride.BRANCH
                jump.flowOverride = FlowOverride.CALL
            }
            assertEquals(rawCall.map { it.toString() }, call.getPcode(false).map { it.toString() })
            assertTrue(call.getPcode(true).any { it.opcode == PcodeOp.BRANCH })
            assertTrue(jump.getPcode(true).any { it.opcode == PcodeOp.CALL })
            // Reclassifying a JP as a CALL does not synthesize an SM83 return push.
            assertEquals(0, jump.getPcode(true).count { it.opcode == PcodeOp.STORE })
            assertStopped(p, 0x153, "flow override")
            assertStopped(p, 0x180, "flow override")
        }

    @Test
    fun `conditional decoded edge retains conditional pcode and both destinations`() =
        program { p ->
            val ins = p.listing.getInstructionAt(address(0x190))
            assertTrue(ins.getPcode(false).any { it.opcode == PcodeOp.CBRANCH })
            assertEquals(0, ins.getPcode(false).count { it.opcode == PcodeOp.STORE })
            assertEquals(listOf(address(0x2000)), ins.defaultFlows.toList())
            assertEquals(address(0x193), ins.fallThrough)
            val r = preview(p, 0x190)
            assertTrue(r.findings().any { it.source() == "0190" && it.access() == "jump" && it.targets() == listOf("2000") })
            assertEquals(3, r.exploredStates())
            p.withTransaction {
                p.referenceManager.addMemoryReference(
                    ins.address,
                    address(0x2100),
                    RefType.JUMP_OVERRIDE_UNCONDITIONAL,
                    SourceType.USER_DEFINED,
                    -1,
                )
            }
            assertTrue(ins.getPcode(false).any { it.opcode == PcodeOp.CBRANCH })
            assertFalse(ins.getPcode(true).any { it.opcode == PcodeOp.CBRANCH })
            assertStopped(p, 0x190, "stored flow annotation")
        }

    @Test
    fun `inline payload convention annotations require unresolved effect summary`() =
        program { p ->
            val rst = p.listing.getInstructionAt(address(0x200))
            val raw = rst.getPcode(false).map { it.toString() }
            val regs = HashMap<Long, Int>()
            val unique = HashMap<Long, Int>()
            val pushed = ArrayList<Long?>()
            for (op in rst.getPcode(false)) {
                if (op.opcode == PcodeOp.STORE) pushed += PcodeConstants.value(op.getInput(2), regs, unique)
                if (op.output != null) PcodeConstants.put(op.output, PcodeConstants.evaluate(op, regs, unique), regs, unique)
            }
            assertEquals(listOf(2L, 1L), pushed) // Hardware return 0201, not annotated continuation 0204.
            assertEquals(address(0x201), rst.fallThrough)
            val before = ProgramFingerprint.capture(p, TaskMonitor.DUMMY)
            FarCallConvention("0028", FarCallConvention.SUPPORTED_BODY, listOf("0200"), 0xc100).apply(p, TaskMonitor.DUMMY)
            assertEquals(address(0x204), rst.fallThrough)
            assertEquals(raw, rst.getPcode(false).map { it.toString() })
            assertNotEquals(before, ProgramFingerprint.capture(p, TaskMonitor.DUMMY))
            assertStopped(p, 0x200, "continuation summary")
            AnalysisOwnership.remove(p, "far-call", TaskMonitor.DUMMY)
            assertEquals(before, ProgramFingerprint.capture(p, TaskMonitor.DUMMY))
        }

    @Test
    fun `banked physical callee fixup is unresolved before architectural effects`() =
        program { p ->
            val target = ProgramMapping.fileToStatic(p, 0x8000).single()
            p.withTransaction {
                p.memory.setBytes(address(0x220), byteArrayOf(0xcd.toByte(), 0, 0x40))
                p.memory.setByte(target, 0xc9.toByte())
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                d.disassemble(address(0x220), AddressSet(address(0x220), address(0x222)))
                d.disassemble(target, AddressSet(target))
                p.functionManager.createFunction("banked_helper", target, AddressSet(target), SourceType.USER_DEFINED).callFixup =
                    "unmodeled_bank_fixup"
            }
            assertStopped(p, 0x220, "callfixup")
        }

    @Test
    fun `callfixup dependency invalidates preview without hashing bare discovered functions`() =
        program { p ->
            val before = preview(p, 0x150)
            val function =
                p.withTransaction {
                    p.functionManager.createFunction("helper", address(0x2000), AddressSet(address(0x2000)), SourceType.USER_DEFINED)
                }
            assertEquals(before, preview(p, 0x150))
            p.withTransaction { function.callFixup = "unmodeled_sa00_fixup" }
            assertThrows(IllegalStateException::class.java) { BankAnalysis.apply(p, before, TaskMonitor.DUMMY) }
            assertStopped(p, 0x153, "callfixup")
            p.withTransaction { function.callFixup = null }
            assertEquals(before, preview(p, 0x150))
        }
}
