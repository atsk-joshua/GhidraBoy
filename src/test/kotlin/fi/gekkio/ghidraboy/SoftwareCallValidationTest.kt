package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.util.HexFormat

class SoftwareCallValidationTest : IntegrationTest() {
    private fun fixture(action: (ProgramDB, SoftwareCallValidation.Configuration) -> Unit) {
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x200, 4, null)
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                byteArrayOf(0xcd.toByte(), 0, 2, 2, 0x67, 0x45, 0).copyInto(this, 0x150)
                HexFormat.of().parseHex(template.bodyHex()).copyInto(this, 0x200)
            }
        val consumer = Any()
        val p = ProgramDB("software-call-preview", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                disassembler.disassemble(address(0x150), AddressSet(address(0x150), address(0x152)))
                disassembler.disassemble(address(0x200), AddressSet(address(0x200), address(0x20c)))
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x150,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    SoftwareCallModel.Registers(0, 0, 0, 0, 0),
                    MapperState.reset(),
                )
            action(p, config)
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `banked inline payload follows selector transition and leaves unconsumed old bank annotations intact`() {
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x200, 4, null)
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        HexFormat.of().parseHex(template.bodyHex()).copyInto(bytes, 0x200)
        HexFormat.of().parseHex("cd000202dead66").copyInto(bytes, 0x4500)
        HexFormat.of().parseHex("6745f0").copyInto(bytes, 0x8504)
        val consumer = Any()
        val p = ProgramDB("banked-inline-payload", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            val oldPayload = SoftwareCallValidation.executionAddress(p, MapperState.reset(), 0x4504)
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                val caller = oldPayload.subtract(4)
                disassembler.disassemble(caller, AddressSet(caller, caller.add(2)))
                disassembler.disassemble(address(0x200), AddressSet(address(0x200), address(0x200 + template.bodyHex().length / 2 - 1L)))
                p.listing.createData(oldPayload, ghidra.program.model.data.WordDataType.dataType)
                p.symbolTable.createLabel(oldPayload, "unconsumed_old_bank_word", SourceType.USER_DEFINED)
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x4500,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    SoftwareCallModel.Registers(0, 0, 0, 0, 0),
                    MapperState.reset(),
                )
            val preview = SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY)
            assertEquals("026745f0", HexFormat.of().formatHex(preview.frame().entry().payload()))
            assertEquals(MapperState.Physical("ROM", 2, 0x567), preview.frame().target())
            assertEquals(
                listOf(MapperState.Physical("ROM", 1, 0x503), MapperState.Physical("ROM", 2, 0x504), MapperState.Physical("ROM", 2, 0x505)),
                preview.frame().reads().map { it.physical() },
            )
            val segments = SoftwareCallValidation.payloadSegments(p, config, TaskMonitor.DUMMY)
            assertEquals(listOf(1, 3), segments.map { it.length() })
            assertEquals(listOf(1, 2), segments.map { it.readLength() })
            assertEquals("unconsumed_old_bank_word", p.symbolTable.getPrimarySymbol(oldPayload).name)
            assertEquals(2, p.listing.getDefinedDataAt(oldPayload).length)
            val consumedPayload = SoftwareCallValidation.executionAddress(p, preview.frame().targetMapper(), 0x4504)
            p.withTransaction { p.memory.getBlock(consumedPayload).isVolatile = true }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY) }
            p.withTransaction { p.memory.getBlock(consumedPayload).isVolatile = false }
            p.withTransaction {
                val consumed = SoftwareCallValidation.executionAddress(p, preview.frame().targetMapper(), 0x4504)
                p.symbolTable.createLabel(consumed, "conflicting_consumed_word", SourceType.USER_DEFINED)
            }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY) }
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `Program preview consumes real payload and preserves listing`() =
        fixture { p, config ->
            val modification = p.modificationNumber
            val preview = SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY)
            assertEquals(MapperState.Physical("ROM", 2, 0x567), preview.frame().target())
            assertEquals(0x157, preview.frame().continuationCpu())
            assertEquals(modification, p.modificationNumber)
            preview.requireCurrent(p, TaskMonitor.DUMMY)
        }

    @Test
    fun `reference only edits invalidate preview and payload references conflict`() =
        fixture { p, config ->
            val preview = SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY)
            p.withTransaction {
                p.referenceManager.addMemoryReference(address(0x160), address(0x154), RefType.DATA, SourceType.USER_DEFINED, 0)
            }
            assertThrows(IllegalArgumentException::class.java) { preview.requireCurrent(p, TaskMonitor.DUMMY) }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY) }
        }

    @Test
    fun `helper byte mutation invalidates saved preview and new recognition`() =
        fixture { p, config ->
            val preview = SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY)
            p.withTransaction {
                p.listing.clearCodeUnits(address(0x200), address(0x200), false)
                p.memory.setByte(address(0x200), 0)
            }
            assertThrows(IllegalArgumentException::class.java) { preview.requireCurrent(p, TaskMonitor.DUMMY) }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY) }
        }

    @Test
    fun `forged preview configuration or frame does not validate`() =
        fixture { p, config ->
            val original = SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY)
            val changed =
                SoftwareCallValidation.Configuration(
                    config.callCpu(),
                    config.template(),
                    config.transfer(),
                    0xc200,
                    config.registers(),
                    config.mapper(),
                )
            val forgedConfig = SoftwareCallValidation.Preview(original.version(), changed, original.dependencies(), original.frame())
            assertThrows(IllegalArgumentException::class.java) { forgedConfig.requireCurrent(p, TaskMonitor.DUMMY) }
            val differentFrame = SoftwareCallValidation.preview(p, changed, TaskMonitor.DUMMY).frame()
            val forgedFrame = SoftwareCallValidation.Preview(original.version(), config, original.dependencies(), differentFrame)
            assertThrows(IllegalArgumentException::class.java) { forgedFrame.requireCurrent(p, TaskMonitor.DUMMY) }
        }

    @Test
    fun `helper interpretation overrides do not become raw template evidence`() =
        fixture { p, config ->
            p.withTransaction {
                p.listing.getInstructionAt(address(0x200)).setFlowOverride(ghidra.program.model.listing.FlowOverride.RETURN)
            }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY) }
        }

    @Test
    fun `entry premises cannot contradict known Program context`() =
        fixture { p, config ->
            p.withTransaction {
                p.programContext.setValue(p.getRegister("A"), address(0x200), address(0x200), java.math.BigInteger.ONE)
            }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY) }
        }

    @Test
    fun `Program validates exact manual RST restoring and constant entries`() {
        val cases =
            listOf(
                SoftwareCallModel.Family.REGISTER_JP to SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION,
                SoftwareCallModel.Family.REGISTER_JP to SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                SoftwareCallModel.Family.RESTORING_REGISTER_JP to SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                SoftwareCallModel.Family.CONSTANT_REGISTER_JP to SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
            )
        for ((family, transfer) in cases) {
            val helper = if (transfer == SoftwareCallModel.EntryTransfer.HARDWARE_RST) 0x28 else 0x200
            val template =
                SoftwareCallModel.Template(
                    family,
                    helper,
                    0,
                    if (family ==
                        SoftwareCallModel.Family.CONSTANT_REGISTER_JP
                    ) {
                        0x80
                    } else {
                        null
                    },
                )
            val caller =
                when (transfer) {
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL -> byteArrayOf(0xcd.toByte(), 0, 2)
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST -> byteArrayOf(0xef.toByte())
                    else -> byteArrayOf(1, 0x57, 1, 0xc5.toByte(), 0xc3.toByte(), 0, 2)
                }
            val body = HexFormat.of().parseHex(template.bodyHex())
            val bytes =
                ByteArray(0x10000).apply {
                    this[0x147] = 0x13
                    this[0x148] = 1
                    caller.copyInto(this, 0x150)
                    body.copyInto(this, helper)
                }
            val consumer = Any()
            val p = ProgramDB("software-call-entry", language, language.defaultCompilerSpec, consumer)
            try {
                ByteArrayProvider(bytes).use {
                    CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
                }
                p.withTransaction {
                    val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                    disassembler.disassemble(address(0x150), AddressSet(address(0x150), address((0x150 + caller.size - 1).toLong())))
                    val helperRange = AddressSet(address(helper.toLong()), address((helper + body.size - 1).toLong()))
                    disassembler.disassemble(address(helper.toLong()), helperRange)
                    if (template.epilogueCpu() >= 0) disassembler.disassemble(address(template.epilogueCpu().toLong()), helperRange)
                }
                val config =
                    SoftwareCallValidation.Configuration(
                        0x150,
                        template,
                        transfer,
                        0xc100,
                        SoftwareCallModel.Registers(
                            2,
                            0xb0,
                            if (transfer ==
                                SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION
                            ) {
                                0x157
                            } else {
                                3
                            },
                            0x1234,
                            0x4567,
                        ),
                        MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, 2),
                    )
                val preview = SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY)
                assertEquals(0x150 + caller.size, preview.frame().continuationCpu())
                assertEquals(if (family == SoftwareCallModel.Family.RESTORING_REGISTER_JP) 3 else 2, preview.frame().target().bank())
                preview.requireCurrent(p, TaskMonitor.DUMMY)
            } finally {
                p.release(consumer)
            }
        }
    }
}
