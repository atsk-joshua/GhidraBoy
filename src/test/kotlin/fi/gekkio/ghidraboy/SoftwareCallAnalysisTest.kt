package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

class SoftwareCallAnalysisTest : IntegrationTest() {
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
