package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AnalysisLifecycleTest : IntegrationTest() {
    private fun program(test: (ProgramDB) -> Unit) {
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        bytes[0x149] = 3
        bytes[0x143] = 0x80.toByte()
        byteArrayOf(0x31, 0, 0xc1.toByte(), 0x3e, 2, 0xea.toByte(), 0, 0x20, 0xcd.toByte(), 0, 0x40, 0xc9.toByte()).copyInto(bytes, 0x150)
        bytes[0x8000] = 0xc9.toByte()
        val consumer = Any()
        val p = ProgramDB("lifecycle", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.CGB, true, true, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                d.disassemble(address(0x150), AddressSet(address(0x150), address(0x15b)))
                val target = ProgramMapping.fileToStatic(p, 0x8000).single()
                d.disassemble(target, AddressSet(target))
            }
            test(p)
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `partial MBC3 ROM selection does not invent unrelated hardware state`() =
        program { p ->
            val r = BankAnalysis.preview(p, address(0x150), null, AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY)
            assertTrue(
                r.findings().any {
                    it.access() == "call" && it.targets() == listOf("rom2::4000") &&
                        it.confidence() == AnalysisResult.Confidence.PROVEN
                },
                r.toString(),
            )
            val knowledge = MapperKnowledge.unknown().write(ProgramMapping.cartridge(p), 0x2000, 2)
            assertEquals("unknown", knowledge.translate(ProgramMapping.cartridge(p), 0xa000, false).status())
            assertEquals("unknown", knowledge.translate(ProgramMapping.cartridge(p), 0xd000, false).status())
            assertEquals("unknown", knowledge.translate(ProgramMapping.cartridge(p), 0x8000, false).status())
        }

    @Test
    fun `apply reapply remove cleans unchanged additions and preserves edits`() =
        program { p ->
            val r = BankAnalysis.preview(p, address(0x150), null, AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY)
            BankAnalysis.apply(p, r, TaskMonitor.DUMMY)
            val count = p.bookmarkManager.bookmarkCount
            BankAnalysis.apply(p, r, TaskMonitor.DUMMY)
            assertEquals(count, p.bookmarkManager.bookmarkCount)
            FunctionDiscovery.discover(p, listOf(), r, TaskMonitor.DUMMY)
            val target = ProgramMapping.fileToStatic(p, 0x8000).single()
            assertTrue(p.functionManager.getFunctionAt(target) != null)
            AnalysisOwnership.removeAll(p, TaskMonitor.DUMMY)
            assertTrue(p.functionManager.getFunctionAt(target) == null)
            assertFalse(p.referenceManager.getReferencesFrom(address(0x158)).any { it.operandIndex == -1 })
            assertEquals(0, p.bookmarkManager.bookmarkCount)
            BankAnalysis.apply(p, r, TaskMonitor.DUMMY)
            FunctionDiscovery.discover(p, listOf(), r, TaskMonitor.DUMMY)
            p.withTransaction {
                p.functionManager.getFunctionAt(target).setName("UserEditedFunction", SourceType.USER_DEFINED)
                p.bookmarkManager
                    .getBookmarksIterator("Analysis")
                    .next()
                    .set("User", "Edited bookmark")
            }
            AnalysisOwnership.removeAll(p, TaskMonitor.DUMMY)
            assertEquals("UserEditedFunction", p.functionManager.getFunctionAt(target).name)
            assertEquals(1, p.bookmarkManager.bookmarkCount)
        }

    @Test
    fun `far convention rejects switchable callers and restores only owned overrides`() =
        program { p ->
            p.withTransaction {
                p.memory.setBytes(
                    address(0x28),
                    java.util.HexFormat
                        .of()
                        .parseHex(FarCallConvention.SUPPORTED_BODY),
                )
                p.memory.setBytes(address(0x200), byteArrayOf(0xef.toByte(), 2, 0, 0x40, 0xc9.toByte()))
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                d.disassemble(address(0x200), AddressSet(address(0x200)))
            }
            val convention = FarCallConvention("0028", FarCallConvention.SUPPORTED_BODY, listOf("0200"), 0xc100)
            assertTrue(convention.preview(p, TaskMonitor.DUMMY).single().contains("return 0204"))
            convention.apply(p, TaskMonitor.DUMMY)
            assertEquals(address(0x204), p.listing.getInstructionAt(address(0x200)).fallThrough)
            AnalysisOwnership.remove(p, "far-call", TaskMonitor.DUMMY)
            assertFalse(p.listing.getInstructionAt(address(0x200)).isFallThroughOverridden)
            val target = ProgramMapping.fileToStatic(p, 0x8010).single()
            p.withTransaction {
                p.memory.setBytes(target, byteArrayOf(0xef.toByte(), 2, 0, 0x40))
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(target, AddressSet(target))
            }
            assertThrows(IllegalArgumentException::class.java) {
                FarCallConvention("0028", FarCallConvention.SUPPORTED_BODY, listOf(target.toString()), 0xc100).preview(p, TaskMonitor.DUMMY)
            }
            assertThrows(IllegalArgumentException::class.java) {
                FarCallConvention("0028", FarCallConvention.SUPPORTED_BODY, listOf("0200")).preview(p, TaskMonitor.DUMMY)
            }
        }

    @Test
    fun `mapper control stores stay visible in decompiler and receive access annotations`() =
        program { p ->
            val decompiler = ghidra.app.decompiler.DecompInterface()
            try {
                p.withTransaction {
                    p.memory.setBytes(address(0x300), byteArrayOf(0x3e, 2, 0xea.toByte(), 0, 0x20, 0xc9.toByte()))
                    p.symbolTable.createLabel(address(0x2000), "MBC_ROM_CONTROL", SourceType.USER_DEFINED)
                    Disassembler
                        .getDisassembler(
                            p,
                            TaskMonitor.DUMMY,
                            null,
                        ).disassemble(address(0x300), AddressSet(address(0x300), address(0x305)))
                }
                val function =
                    p.withTransaction {
                        p.functionManager.createFunction(
                            "select_bank",
                            address(0x300),
                            AddressSet(address(0x300), address(0x305)),
                            SourceType.USER_DEFINED,
                        )
                    }
                CompilerAbi.apply(p, function, CompilerAbi.Request("sdcc451-call1", "void", null, listOf(), null, null))
                val result = BankAnalysis.preview(p, address(0x300), null, AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY)
                BankAnalysis.apply(p, result, TaskMonitor.DUMMY)
                assertTrue(result.findings().any { it.source() == "0302" && it.access() == "write" && it.reason().startsWith("device:") })
                assertTrue(decompiler.openProgram(p))
                val decompiled = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY)
                assertTrue(decompiled.decompileCompleted(), decompiled.errorMessage)
                val c = decompiled.decompiledFunction.c
                assertTrue(c.contains("MBC_ROM_CONTROL = 2"), c)
                assertTrue(!p.memory.getBlock(address(0x2000)).isWrite)
            } finally {
                decompiler.dispose()
            }
        }

    @Test
    fun `cancellation after mutation rolls back apply discovery and removal`() =
        program { p ->
            val r = BankAnalysis.preview(p, address(0x150), null, AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY)

            fun cancelWhen(condition: () -> Boolean) =
                object : ghidra.util.task.TaskMonitorAdapter() {
                    override fun checkCancelled() {
                        if (condition()) throw ghidra.util.exception.CancelledException()
                    }
                }
            assertThrows(ghidra.util.exception.CancelledException::class.java) {
                BankAnalysis.apply(p, r, cancelWhen { p.bookmarkManager.bookmarkCount > 0 })
            }
            assertEquals(0, p.bookmarkManager.bookmarkCount)
            assertFalse(p.referenceManager.getReferencesFrom(address(0x158)).any { it.operandIndex == -1 })
            BankAnalysis.apply(p, r, TaskMonitor.DUMMY)
            val marks = p.bookmarkManager.bookmarkCount
            val target = ProgramMapping.fileToStatic(p, 0x8000).single()
            assertThrows(ghidra.util.exception.CancelledException::class.java) {
                FunctionDiscovery.discover(
                    p,
                    listOf(address(0x150), target),
                    r,
                    cancelWhen { p.functionManager.functionCount > 0 },
                )
            }
            assertEquals(0, p.functionManager.functionCount)
            FunctionDiscovery.discover(p, listOf(), r, TaskMonitor.DUMMY)
            assertThrows(ghidra.util.exception.CancelledException::class.java) {
                AnalysisOwnership.removeAll(p, cancelWhen { p.bookmarkManager.bookmarkCount < marks })
            }
            assertEquals(marks, p.bookmarkManager.bookmarkCount)
            assertTrue(p.functionManager.getFunctionAt(target) != null)
            assertTrue(p.referenceManager.getReferencesFrom(address(0x158)).any { it.operandIndex == -1 })
            AnalysisOwnership.removeAll(p, TaskMonitor.DUMMY)
            assertEquals(0, p.bookmarkManager.bookmarkCount)
            assertEquals(0, p.functionManager.functionCount)
        }

    @Test
    fun `cancelled far application rolls back a previously changed site`() =
        program { p ->
            p.withTransaction {
                p.memory.setBytes(
                    address(0x28),
                    java.util.HexFormat
                        .of()
                        .parseHex(FarCallConvention.SUPPORTED_BODY),
                )
                for (site in listOf(0x200L, 0x210L)) {
                    p.memory.setBytes(address(site), byteArrayOf(0xef.toByte(), 2, 0, 0x40, 0xc9.toByte()))
                    Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(address(site), AddressSet(address(site)))
                }
            }
            val convention = FarCallConvention("0028", FarCallConvention.SUPPORTED_BODY, listOf("0200", "0210"), 0xc100)
            val monitor =
                object : ghidra.util.task.TaskMonitorAdapter() {
                    override fun checkCancelled() {
                        if (p.listing.getInstructionAt(address(0x200)).isFallThroughOverridden) {
                            throw ghidra.util.exception.CancelledException()
                        }
                    }
                }
            assertThrows(ghidra.util.exception.CancelledException::class.java) { convention.apply(p, monitor) }
            for (site in listOf(0x200L, 0x210L)) {
                assertFalse(p.listing.getInstructionAt(address(site)).isFallThroughOverridden)
                assertFalse(p.referenceManager.getReferencesFrom(address(site)).any { it.operandIndex == -1 })
            }
            assertEquals(0, p.bookmarkManager.bookmarkCount)
        }
}
