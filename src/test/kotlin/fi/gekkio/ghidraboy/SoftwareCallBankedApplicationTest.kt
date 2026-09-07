package fi.gekkio.ghidraboy

import ghidra.app.decompiler.DecompInterface
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

class SoftwareCallBankedApplicationTest : IntegrationTest() {
    @Test
    fun `ordinary production view carries nonrestoring banked continuation into native function`() {
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        HexFormat.of().parseHex(template.bodyHex()).copyInto(bytes, 0x28)
        bytes[0x4100] = 0xef.toByte()
        bytes[0x4101] = 0x76
        bytes[0x8000] = 0xc9.toByte()
        bytes[0x8101] = 0xc9.toByte()
        val consumer = Any()
        val p = ProgramDB("banked production continuation", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            val caller = ProgramMapping.fileToStatic(p, 0x4100).single()
            val target = ProgramMapping.fileToStatic(p, 0x8000).single()
            val continuation = ProgramMapping.fileToStatic(p, 0x8101).single()
            p.withTransaction {
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                d.disassemble(address(0x28), AddressSet(address(0x28), address(0x28 + template.bodyHex().length / 2 - 1L)))
                for (at in listOf(caller, target, continuation)) d.disassemble(at, AddressSet(at))
                p.functionManager.createFunction("banked_caller", caller, AddressSet(caller), SourceType.USER_DEFINED)
                p.functionManager.createFunction("banked_target", target, AddressSet(target), SourceType.USER_DEFINED)
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x4100,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 0, 0, 0x4000),
                    MapperState.reset(),
                )
            p.withTransaction { p.functionManager.getFunctionAt(caller).isInline = true }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            p.withTransaction {
                p.functionManager.getFunctionAt(caller).isInline = false
                p.functionManager.getFunctionAt(caller).stackPurgeSize = 0
            }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            p.withTransaction {
                p.functionManager.removeFunction(caller)
                p.memory.setByte(caller.subtract(1), 0x7e)
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(caller.subtract(1), AddressSet(caller.subtract(1)))
                p.functionManager.createFunction(
                    "caller_with_indirect_load",
                    caller.subtract(1),
                    AddressSet(caller.subtract(1), caller),
                    SourceType.USER_DEFINED,
                )
            }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            p.withTransaction {
                p.functionManager.removeFunction(caller.subtract(1))
                p.listing.clearCodeUnits(caller.subtract(3), caller.subtract(1), false)
                p.memory.setBytes(caller.subtract(3), HexFormat.of().parseHex("fa0050"))
                Disassembler
                    .getDisassembler(p, TaskMonitor.DUMMY, null)
                    .disassemble(caller.subtract(3), AddressSet(caller.subtract(3), caller.subtract(1)))
                p.functionManager.createFunction(
                    "caller_with_banked_absolute_load",
                    caller.subtract(3),
                    AddressSet(caller.subtract(3), caller),
                    SourceType.USER_DEFINED,
                )
            }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            p.withTransaction {
                p.functionManager.removeFunction(caller.subtract(3))
                p.functionManager.createFunction("banked_caller", caller, AddressSet(caller), SourceType.USER_DEFINED)
            }
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            assertEquals(1, review.executionViews().size)
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val viewName =
                review
                    .executionViews()
                    .values
                    .single()
                    .name()
            val view = p.addressFactory.getAddressSpace(viewName)
            val function = p.functionManager.getFunctionAt(view.getAddress(0x4100))
            assertNotNull(function)
            assertEquals(view.getAddress(0x4101), p.listing.getInstructionAt(view.getAddress(0x4100)).fallThrough)
            assertEquals(caller, p.listing.getInstructionAt(caller).fallThrough)
            assertEquals(ghidra.program.model.listing.FlowOverride.NONE, p.listing.getInstructionAt(caller).flowOverride)
            assertTrue(p.functionManager.getFunctionAt(caller).isThunk)
            assertEquals(function, p.functionManager.getFunctionAt(caller).getThunkedFunction(false))
            assertEquals(MapperState.Physical("ROM", 2, 0x101), ProgramMapping.staticToPhysical(p, view.getAddress(0x4101)).single())
            assertEquals(0x76.toByte(), p.memory.getByte(caller.add(1)))
            assertTrue(AnalysisOwnership.softwareCallCurrent(p, view.getAddress(0x4100)))
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                val result = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY)
                assertTrue(result.decompileCompleted(), result.errorMessage)
                assertTrue(result.decompiledFunction.c.contains("banked_target("), result.decompiledFunction.c)
                assertTrue(
                    result.highFunction.pcodeOps
                        .asSequence()
                        .any { it.opcode == PcodeOp.CALL && it.getInput(0).address == target },
                )
                assertTrue(
                    result.highFunction.pcodeOps
                        .asSequence()
                        .any { it.opcode == PcodeOp.RETURN },
                )
                val canonicalResult = decompiler.decompileFunction(p.functionManager.getFunctionAt(caller), 30, TaskMonitor.DUMMY)
                assertTrue(canonicalResult.decompileCompleted(), canonicalResult.errorMessage)
                assertTrue(canonicalResult.decompiledFunction.c.contains("banked_target("), canonicalResult.decompiledFunction.c)
            } finally {
                decompiler.dispose()
            }
            p.withTransaction {
                p.symbolTable.createLabel(address(0x300), "unrelated_saved_label", SourceType.USER_DEFINED)
                p.referenceManager.addMemoryReference(
                    view.getAddress(0x4100),
                    address(0xc0fe),
                    ghidra.program.model.symbol.RefType.READ,
                    SourceType.ANALYSIS,
                    0,
                )
            }
            AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            assertTrue(p.symbolTable.getSymbols("unrelated_saved_label").hasNext())
            assertNotNull(p.memory.getBlock(view.getAddress(0x4100)))
            assertTrue(!p.memory.getBlock(view.getAddress(0x4100)).isExecute)
            assertNull(p.listing.getInstructionAt(view.getAddress(0x4100)))
            assertNull(p.functionManager.getFunctionAt(view.getAddress(0x4100)))
            assertEquals(0xef.toByte(), p.memory.getByte(view.getAddress(0x4100)))
            val reapplied = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            SoftwareCallApplication.apply(p, reapplied, TaskMonitor.DUMMY)
            val editedSpace =
                p.addressFactory.getAddressSpace(
                    reapplied
                        .executionViews()
                        .values
                        .single()
                        .name(),
                )
            p.withTransaction {
                p.listing.getInstructionAt(editedSpace.getAddress(0x4101)).flowOverride = ghidra.program.model.listing.FlowOverride.BRANCH
            }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallRegistry.resolve(p, editedSpace.getAddress(0x4100)) }
            p.withTransaction {
                p.listing
                    .getInstructionAt(editedSpace.getAddress(0x4101))
                    .setComment(ghidra.program.model.listing.CommentType.EOL, "user continuation note")
            }
            val removal = AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            assertTrue(removal.any { it.contains("Preserved edited or uncertain execution view") })
            assertNotNull(p.memory.getBlock(editedSpace.getAddress(0x4101)))
            assertEquals(
                "user continuation note",
                p.listing.getInstructionAt(editedSpace.getAddress(0x4101)).getComment(ghidra.program.model.listing.CommentType.EOL),
            )
        } finally {
            p.release(consumer)
        }
    }
}
