package fi.gekkio.ghidraboy

import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.plugin.core.analysis.FindNoReturnFunctionsAnalyzer
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayload
import ghidra.program.model.listing.FlowOverride
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

class SoftwareCallMayReturnInjectionTest : IntegrationTest() {
    @Test
    fun `code-derived returning target survives three suspicious ordinary callers without recurring repair`() {
        val monitor = TaskMonitor.DUMMY
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x200, 0, null)
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        HexFormat.of().parseHex(template.bodyHex()).copyInto(bytes, 0x200)
        HexFormat.of().parseHex("cd0002c9").copyInto(bytes, 0x150)
        bytes[0x8100] = 0xc9.toByte()
        for (file in listOf(0x8200, 0x8210, 0x8220)) HexFormat.of().parseHex("cd0041dd").copyInto(bytes, file)
        val consumer = Any()
        val program = ProgramDB("neutral-may-return-threshold", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(program, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog())
            }
            val target = ProgramMapping.fileToStatic(program, 0x8100).single()
            val ordinary = listOf(0x8200L, 0x8210L, 0x8220L).map { ProgramMapping.fileToStatic(program, it).single() }
            val ordinarySet = AddressSet()
            program.withTransaction {
                val d = Disassembler.getDisassembler(program, monitor, null)
                d.disassemble(address(0x150), AddressSet(address(0x150), address(0x153)))
                d.disassemble(address(0x200), AddressSet(address(0x200), address(0x203)))
                d.disassemble(target, AddressSet(target))
                program.functionManager.createFunction(
                    "reviewed_caller",
                    address(0x150),
                    AddressSet(address(0x150), address(0x153)),
                    SourceType.USER_DEFINED,
                )
                program.functionManager.createFunction("returning_target", target, AddressSet(target), SourceType.USER_DEFINED)
                for (site in ordinary) {
                    d.disassemble(site, AddressSet(site, site.add(2)))
                    program.listing
                        .createData(site.add(3), ByteDataType.dataType)
                        .setComment(ghidra.program.model.listing.CommentType.EOL, "unreviewed caller data")
                    ordinarySet.add(site, site.add(2))
                    assertTrue(
                        program.listing
                            .getInstructionAt(site)
                            .defaultFlows
                            .contains(target),
                    )
                }
            }
            // Real stock negative control. Its threshold ignores the target's architectural RET.
            program.withTransaction {
                assertTrue(FindNoReturnFunctionsAnalyzer().added(program, ordinarySet, monitor, MessageLog()))
            }
            assertTrue(program.functionManager.getFunctionAt(target).hasNoReturn())
            for (site in ordinary) assertEquals(FlowOverride.CALL_RETURN, program.listing.getInstructionAt(site).flowOverride)
            // Restore only this negative control's terminal call edits so the same three indicators
            // are still active in every subsequent run. The production fix must prevent recurrence.
            program.withTransaction {
                for (site in ordinary) program.listing.getInstructionAt(site).flowOverride = FlowOverride.NONE
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x150,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 0, 0, 0x4100),
                    MapperState.reset(),
                )
            SoftwareCallApplication.apply(program, SoftwareCallApplication.preview(program, listOf(config), monitor), monitor)
            assertEquals(SoftwareCallMayReturnInjection.NAME, program.functionManager.getFunctionAt(target).callFixup)
            assertFalse(program.functionManager.getFunctionAt(target).hasNoReturn())
            val payload =
                program.compilerSpec.pcodeInjectLibrary.getPayload(
                    InjectPayload.CALLFIXUP_TYPE,
                    SoftwareCallMayReturnInjection.NAME,
                )
            assertTrue(payload is SoftwareCallMayReturnInjection)
            assertTrue(payload.isFallThru)
            val context = InjectContext()
            context.baseAddr = ordinary[0]
            context.nextAddr = ordinary[0].add(3)
            context.callAddr = target
            val neutral = payload.getPcode(program, context)
            assertEquals(1, neutral.size)
            assertEquals(PcodeOp.CALL, neutral[0].opcode)
            assertEquals(target, neutral[0].getInput(0).address)
            assertNull(neutral[0].output)
            assertNull(InstructionInterpretation.unresolved(program.listing.getInstructionAt(ordinary[0])))
            val manager = AutoAnalysisManager.getAnalysisManager(program)
            repeat(2) {
                program.withTransaction {
                    manager.reAnalyzeAll(ordinarySet)
                    manager.startAnalysis(monitor)
                }
                assertFalse(program.functionManager.getFunctionAt(target).hasNoReturn())
                assertFalse(program.functionManager.getFunctionAt(address(0x200)).hasNoReturn())
                assertEquals(address(0x153), program.listing.getInstructionAt(address(0x150)).fallThrough)
                for (site in ordinary) {
                    assertEquals(FlowOverride.NONE, program.listing.getInstructionAt(site).flowOverride)
                    val data = program.listing.getDefinedDataAt(site.add(3))
                    assertNotNull(data)
                    assertEquals("byte", data.dataType.name)
                    assertEquals("unreviewed caller data", data.getComment(ghidra.program.model.listing.CommentType.EOL))
                    assertEquals(0xdd, program.memory.getByte(site.add(3)).toInt() and 255)
                }
            }
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(program))
                val result = decompiler.decompileFunction(program.functionManager.getFunctionAt(address(0x150)), 30, monitor)
                assertTrue(result.decompileCompleted(), result.errorMessage)
                assertTrue(result.decompiledFunction.c.contains("returning_target("), result.decompiledFunction.c)
                assertEquals(
                    1,
                    result.highFunction.pcodeOps.asSequence().count {
                        it.opcode == PcodeOp.CALL &&
                            it.getInput(0).address == target
                    },
                )
            } finally {
                decompiler.dispose()
            }
            // Neutral metadata may never outlive its independently consumed returning witness.
            program.withTransaction { program.getOptions(ProgramMapping.OPTIONS).removeOption(SoftwareCallRegistry.KEY) }
            assertThrows(IllegalArgumentException::class.java) { payload.getPcode(program, context) }
            assertNotNull(InstructionInterpretation.unresolved(program.listing.getInstructionAt(ordinary[0])))
        } finally {
            program.release(consumer)
        }
    }
}
