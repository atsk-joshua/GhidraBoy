package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.pcode.PcodeOp
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

class SoftwareCallContinuationPreservationTest : IntegrationTest() {
    @Test
    fun `later configured manually pushed continuation retains physical native call and wrapper effects`() {
        val outerHelper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val innerHelper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x38, 0, null)
        val regions =
            linkedMapOf(
                0x28 to outerHelper.bodyHex(),
                0x38 to innerHelper.bodyHex(),
                0x4500 to "ef",
                0x8000 to "c9",
                0x8501 to "c30003",
                // LD A,3; LD HL,4300; LD BC,030c; PUSH BC; JP 0038; LD(c200),A; RET.
                0x300 to "3e03210043010c03c5c33800",
                // Ordinary disassembly stops at JP helper; this raw/native lowering fixture gives
                // the separately justified encoded continuation its own decoding root.
                0x30c to "ea00c2c9",
                0xc300 to "3e5bea02c237c9",
            )
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                for ((offset, code) in regions) HexFormat.of().parseHex(code).copyInto(this, offset)
            }
        val consumer = Any()
        val p = ProgramDB("continuation manual call preservation", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, TaskMonitor.DUMMY, MessageLog())
            }

            fun physical(offset: Long) =
                ProgramMapping.fileToStatic(p, offset).single {
                    SoftwareCallExecutionView.canonical(p, it) && it.offset == if (offset < 0x4000) offset else 0x4000 + offset % 0x4000
                }
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                for ((offset, code) in regions) {
                    val at = physical(offset.toLong())
                    disassembler.disassemble(at, AddressSet(at, at.add(code.length.toLong() / 2 - 1)))
                }
            }
            val outer =
                SoftwareCallValidation.Configuration(
                    0x4500,
                    outerHelper,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 0, 0, 0x4000),
                    MapperState.reset(),
                )
            val inner =
                SoftwareCallValidation.Configuration(
                    0x305,
                    innerHelper,
                    SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION,
                    0xc100,
                    SoftwareCallModel.Registers(3, 0, 0x30c, 0, 0x4300),
                    MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, 2),
                )
            val configurations = listOf(outer, inner)
            val validated = SoftwareCallValidation.preview(p, outer, TaskMonitor.DUMMY)
            val effects = SoftwareCallEffects.deriveForReview(p, validated.frame(), TaskMonitor.DUMMY, configurations)
            assertTrue(effects.complete(), effects.unresolved().toString())
            val graph =
                SoftwareCallEffects.deriveContinuationForReview(
                    p,
                    validated.frame(),
                    effects.paths().single(),
                    configurations,
                    TaskMonitor.DUMMY,
                )
            assertTrue(graph.complete(), graph.unresolved().toString())
            val transfer = graph.steps().single { it.softwareCall() != null }
            assertEquals(address(0x309).toString(), transfer.address())
            assertEquals("BRANCH", transfer.transfer())
            assertEquals(0xc0fe, transfer.before().sp())
            assertNotNull(transfer.afterCall())
            assertEquals(0xc100, transfer.afterCall().sp())
            assertEquals(0x30c, transfer.afterCall().cpu())
            assertEquals(0x5b, transfer.afterCall().registers().a())
            assertEquals(0x10, transfer.afterCall().registers().f())
            val target = physical(0xc300)
            val emitted = SoftwareCallContinuationView.emit(p, physical(0x4500), graph, configurations, 0x70000000)
            assertTrue(
                emitted.any {
                    it.opcode == PcodeOp.CALL && it.getInput(0).address == target
                },
                "Manual software call must retain its physical callee in native p-code",
            )
            assertTrue(emitted.any { it.opcode == PcodeOp.RETURN }, "Actual outer live return must remain")
        } finally {
            p.release(consumer)
        }
    }
}
