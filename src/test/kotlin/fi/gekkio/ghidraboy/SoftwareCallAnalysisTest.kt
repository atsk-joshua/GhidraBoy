package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

class SoftwareCallAnalysisTest : IntegrationTest() {
    @Test
    fun `disconnected roots consume only their own complete register context`() {
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x200, 3, null)
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        HexFormat.of().parseHex("cd0002020041ea00c1c9").copyInto(bytes, 0x150)
        HexFormat.of().parseHex(template.bodyHex()).copyInto(bytes, 0x200)
        HexFormat.of().parseHex("3e5a37c9").copyInto(bytes, 0x8100)
        bytes[0xc100] = 0xc9.toByte()
        val roots = listOf(address(0x300), address(0x320), address(0x340))
        roots.forEach { HexFormat.of().parseHex("ea0020c30041").copyInto(bytes, it.offset.toInt()) }
        val consumer = Any()
        val p = ProgramDB("root-register-premises", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                p.programContext.setValue(p.getRegister("A"), roots[0], roots[0], java.math.BigInteger.valueOf(2))
                p.programContext.setValue(p.getRegister("A"), roots[1], roots[1], java.math.BigInteger.valueOf(3))
                val dis = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                dis.disassemble(address(0x150), AddressSet(address(0x150), address(0x152)))
                dis.disassemble(address(0x156), AddressSet(address(0x156), address(0x159)))
                dis.disassemble(address(0x200), AddressSet(address(0x200), address(0x20b)))
                val target = ProgramMapping.fileToStatic(p, 0x8100).single()
                dis.disassemble(target, AddressSet(target, target.add(3)))
                roots.forEach { dis.disassemble(it, AddressSet(it, it.add(5))) }
            }
            assertNull(p.programContext.getRegisterValue(p.getRegister("A"), roots[2])?.unsignedValue)
            val config =
                SoftwareCallValidation.Configuration(
                    0x150,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    SoftwareCallModel.Registers(0, 0x80, 0, 0, 0),
                    MapperState.reset(),
                )
            // Context is established before the legitimate applied registry fingerprints it.
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            assertTrue(SoftwareCallRegistry.configurationIdentity(p) != "absent")
            val result = BankAnalysis.preview(p, roots, AnalysisResult.Configuration.DEFAULT, null, TaskMonitor.DUMMY)
            assertTrue(result.complete())
            assertThrows(IllegalArgumentException::class.java) {
                val contaminated =
                    ProgramMapping.JSON
                        .toJson(result)
                        .replace(AnalysisResult.ENGINE_VERSION, "20260916-m2-native-analysis-2")
                AnalysisResult.read(contaminated)
            }

            fun jumps(root: ghidra.program.model.address.Address) =
                result.findings().filter { it.source() == root.add(3).toString() && it.access() == "jump" }

            assertEquals(listOf("rom2::4100"), jumps(roots[0]).single().targets())
            assertEquals(AnalysisResult.Confidence.PROVEN, jumps(roots[0]).single().confidence())
            assertEquals(listOf("rom3::4100"), jumps(roots[1]).single().targets())
            assertEquals(AnalysisResult.Confidence.PROVEN, jumps(roots[1]).single().confidence())
            assertTrue(jumps(roots[2]).isNotEmpty(), result.findings().toString())
            assertTrue(jumps(roots[2]).none { it.confidence() == AnalysisResult.Confidence.PROVEN }, result.findings().toString())
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `bounded analysis consumes effects only after caller instructions establish premises`() {
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x200, 3, null)
        val prefix = HexFormat.of().parseHex("3100c13e00af010000110000210000")
        val site = 0x150 + prefix.size
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        prefix.copyInto(bytes, 0x150)
        HexFormat.of().parseHex("cd0002020041ea00c1c9").copyInto(bytes, site)
        HexFormat.of().parseHex(template.bodyHex()).copyInto(bytes, 0x200)
        HexFormat.of().parseHex("3e5a37c9").copyInto(bytes, 0x8100)
        val consumer = Any()
        val p = ProgramDB("premise-flow", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            val target = ProgramMapping.fileToStatic(p, 0x8100).single()
            p.withTransaction {
                p.programContext.setValue(p.getRegister("F"), address(0x150), address(0x150), java.math.BigInteger.ZERO)
                val dis = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                dis.disassemble(address(0x150), AddressSet(address(0x150), address(site + 2L)))
                dis.disassemble(address(site + 6L), AddressSet(address(site + 6L), address(site + 9L)))
                dis.disassemble(address(0x200), AddressSet(address(0x200), address(0x20b)))
                dis.disassemble(target, AddressSet(target, target.add(3)))
            }
            val config =
                SoftwareCallValidation.Configuration(
                    site,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    SoftwareCallModel.Registers(0, 0x80, 0, 0, 0),
                    MapperState.reset(),
                )
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            val result =
                BankAnalysis.preview(
                    p,
                    address(0x150),
                    MapperState.reset(),
                    AnalysisResult.Configuration.DEFAULT,
                    TaskMonitor.DUMMY,
                )
            assertTrue(
                result.findings().any {
                    it.source() == address(site.toLong()).toString() && it.targets().contains(target.toString())
                },
                result.findings().toString(),
            )
            assertTrue(result.findings().none { it.reason().contains("premises") }, result.findings().toString())
            assertTrue(result.exploredStates() > prefix.size / 3 + 2)
        } finally {
            p.release(consumer)
        }
    }
}
