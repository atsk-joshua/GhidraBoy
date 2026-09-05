package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BankAnalysisTest : IntegrationTest() {
    @Test
    fun `constant mapper writes resolve bank two while unknown state stays explicit`() {
        val data = ByteArray(0x10000)
        data[0x147] = 0x19
        data[0x148] = 1
        byteArrayOf(0x3e, 2, 0xea.toByte(), 0, 0x20, 0xc3.toByte(), 0, 0x40).copyInto(data, 0x150)
        val consumer = Any()
        val p = ProgramDB("analysis", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(data).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                Disassembler
                    .getDisassembler(
                        p,
                        TaskMonitor.DUMMY,
                        null,
                    ).disassemble(address(0x150), AddressSet(address(0x150), address(0x157)))
            }
            val known = BankAnalysis.analyze(p, address(0x150), MapperState.reset(), TaskMonitor.DUMMY, true)
            assertTrue(known.any { it.access() == "jump" && it.targets().singleOrNull() == "rom2::4000" }, known.toString())
            val unknown = BankAnalysis.analyze(p, address(0x155), null, TaskMonitor.DUMMY, false)
            assertTrue(unknown.none { it.targets().isNotEmpty() }, unknown.toString())
            assertTrue(unknown.any { it.reason().contains("Unknown") })
            assertNull(p.listing.getInstructionAt(ProgramMapping.fileToStatic(p, 0x8000).single()))
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `branch merge retains two candidate banks and preserves user references`() {
        val data = ByteArray(0x10000)
        data[0x147] = 0x19
        data[0x148] = 1
        byteArrayOf(
            0x3e,
            1,
            0x28,
            6,
            0x3e,
            2,
            0xc3.toByte(),
            0x5a,
            1,
            0,
            0xea.toByte(),
            0,
            0x20,
            0xc3.toByte(),
            0,
            0x40,
        ).copyInto(data, 0x150)
        val consumer = Any()
        val p = ProgramDB("merged", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(data).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true, TaskMonitor.DUMMY, MessageLog())
            }
            val userTarget = ProgramMapping.fileToStatic(p, 0xc000).single()
            p.withTransaction {
                Disassembler
                    .getDisassembler(
                        p,
                        TaskMonitor.DUMMY,
                        null,
                    ).disassemble(address(0x150), AddressSet(address(0x150), address(0x15f)))
                p.referenceManager.addMemoryReference(
                    address(0x15d),
                    userTarget,
                    ghidra.program.model.symbol.RefType.DATA,
                    ghidra.program.model.symbol.SourceType.USER_DEFINED,
                    0,
                )
            }
            val findings = BankAnalysis.analyze(p, address(0x150), MapperState.reset(), TaskMonitor.DUMMY, true)
            val merge = findings.single { it.source() == "015d" && it.access() == "jump" }
            assertTrue(merge.targets().toSet() == setOf("rom1::4000", "rom2::4000"), merge.toString())
            assertTrue(
                p.referenceManager.getReferencesFrom(address(0x15d)).any {
                    it.toAddress == userTarget &&
                        it.source == ghidra.program.model.symbol.SourceType.USER_DEFINED
                },
            )
            assertTrue(p.referenceManager.getReferencesFrom(address(0x15d)).none { it.operandIndex == -1 })
            FunctionDiscovery.discover(p, listOf(address(0x150)), findings, TaskMonitor.DUMMY)
            assertTrue(p.functionManager.getFunctionAt(address(0x150)) != null)
            assertNull(p.functionManager.getFunctionAt(ProgramMapping.fileToStatic(p, 0x8000).single()))
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `overlay execution context resolves same window without guessing other banks`() {
        val data = ByteArray(0x10000)
        data[0x147] = 0x19
        data[0x148] = 1
        byteArrayOf(0xc3.toByte(), 0x10, 0x40).copyInto(data, 0x8000)
        val consumer = Any()
        val p = ProgramDB("context", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(data).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true, TaskMonitor.DUMMY, MessageLog())
            }
            val start = ProgramMapping.fileToStatic(p, 0x8000).single()
            p.withTransaction {
                Disassembler
                    .getDisassembler(
                        p,
                        TaskMonitor.DUMMY,
                        null,
                    ).disassemble(start, AddressSet(start, start.add(2)))
            }
            val findings = BankAnalysis.analyze(p, start, null, TaskMonitor.DUMMY, false)
            assertTrue(findings.any { it.access() == "jump" && it.targets() == listOf("rom2::4010") }, findings.toString())
        } finally {
            p.release(consumer)
        }
    }
}
