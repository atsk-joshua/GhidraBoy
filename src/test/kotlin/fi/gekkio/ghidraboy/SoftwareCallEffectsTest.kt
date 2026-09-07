package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

class SoftwareCallEffectsTest : IntegrationTest() {
    private fun fixture(
        family: SoftwareCallModel.Family = SoftwareCallModel.Family.REGISTER_JP,
        caller: Int = 0x150,
        callee: String,
        action: (ProgramDB, SoftwareCallModel.Frame) -> Unit,
    ) {
        val template =
            SoftwareCallModel.Template(
                family,
                0x200,
                0,
                if (family ==
                    SoftwareCallModel.Family.CONSTANT_REGISTER_JP
                ) {
                    3
                } else {
                    null
                },
            )
        val target = HexFormat.of().parseHex(callee)
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                HexFormat.of().parseHex(template.bodyHex()).copyInto(this, 0x200)
                target.copyInto(this, 0x8000)
                this[0x8010] = 0x3c
                this[0x8011] = 0xc9.toByte()
            }
        val consumer = Any()
        val p = ProgramDB("callee-effects", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            val mapper = MapperState.reset()
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                val a = SoftwareCallValidation.executionAddress(p, mapper.write(ProgramMapping.cartridge(p), 0x2000, 2), 0x4000)
                disassembler.disassemble(a, AddressSet(a, a.add(target.size.toLong() - 1)))
                disassembler.disassemble(a.add(0x10), AddressSet(a.add(0x10), a.add(0x11)))
            }
            val entry =
                SoftwareCallModel.Entry(
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    caller + 3,
                    SoftwareCallModel.Registers(
                        if (family ==
                            SoftwareCallModel.Family.RESTORING_REGISTER_JP
                        ) {
                            1
                        } else {
                            2
                        },
                        0,
                        2,
                        0x1234,
                        0x4000,
                    ),
                    mapper,
                    byteArrayOf(),
                )
            action(p, SoftwareCallModel.enter(ProgramMapping.cartridge(p), template, HexFormat.of().parseHex(template.bodyHex()), entry))
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `raw nested callee derives flags memory registers and balanced stack`() =
        fixture(callee = "afcd1040ea00c237c9") { p, frame ->
            val result = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertTrue(result.complete(), result.unresolved().toString())
            assertTrue(result.nativeCompatible(), result.nativeIncompatibilities().toString())
            assertTrue(
                result.returningNativeFunctions().contains(
                    SoftwareCallValidation.executionAddress(p, frame.targetMapper(), 0x4010).toString(),
                ),
            )
            assertTrue(
                result.returningNativeFunctions().contains(
                    SoftwareCallValidation.executionAddress(p, frame.targetMapper(), 0x4000).toString(),
                ),
            )
            val path = result.paths().single()
            assertEquals(1, path.returned().registers().a())
            assertEquals(0x10, path.returned().registers().f())
            assertEquals(0xc100, path.returned().sp())
            assertTrue(path.writes().any { it.cpu() == 0xc200 && it.value() == 1 })
        }

    @Test
    fun `identical banked caller distinguishes restoring nonrestoring and constant physical return`() {
        for ((family, bank) in listOf(
            SoftwareCallModel.Family.REGISTER_JP to 2,
            SoftwareCallModel.Family.RESTORING_REGISTER_JP to 1,
            SoftwareCallModel.Family.CONSTANT_REGISTER_JP to 3,
        )) {
            fixture(family, 0x4500, "af37c9") { p, frame ->
                val result = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
                assertTrue(result.complete(), result.unresolved().toString())
                assertEquals(
                    MapperState.Physical("ROM", bank, 0x503),
                    result
                        .paths()
                        .single()
                        .returned()
                        .physical(),
                )
                assertEquals(
                    0x90,
                    result
                        .paths()
                        .single()
                        .returned()
                        .registers()
                        .f(),
                )
            }
        }
    }

    @Test
    fun `conditional return is conditional on entry flags and exact loop is nonreturning`() {
        fixture(callee = "c8c9") { p, frame ->
            assertTrue(SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY).mayReturn())
        }
        fixture(callee = "18fe") { p, frame ->
            val result = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertTrue(result.complete(), result.unresolved().toString())
            assertEquals(
                SoftwareCallModel.Exit.NONRETURNING,
                result
                    .paths()
                    .single()
                    .returned()
                    .exit(),
            )
        }
    }

    @Test
    fun `nested software wrapper RET epilogue is an architectural frame not a nonlocal exit`() =
        fixture(callee = "3e02010300210041cd3002c9") { p, frame ->
            val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.RESTORING_REGISTER_JP, 0x230, 0, null)
            val inner =
                SoftwareCallValidation.executionAddress(
                    p,
                    MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, 3),
                    0x4100,
                )
            p.withTransaction {
                val helperAddress = address(0x230)
                val helperBytes = HexFormat.of().parseHex(helper.bodyHex())
                p.memory.setBytes(helperAddress, helperBytes)
                p.memory.setBytes(inner, HexFormat.of().parseHex("3e0737c9"))
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                val range = AddressSet(helperAddress, helperAddress.add(helperBytes.size.toLong() - 1))
                disassembler.disassemble(helperAddress, range)
                disassembler.disassemble(address(helper.epilogueCpu().toLong()), range)
                disassembler.disassemble(inner, AddressSet(inner, inner.add(3)))
            }
            val result = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertTrue(result.complete(), result.unresolved().toString())
            assertFalse(result.nativeCompatible())
            val innerConfig =
                SoftwareCallValidation.Configuration(
                    0x4008,
                    helper,
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc0fe,
                    SoftwareCallModel.Registers(2, 0, 3, 0x1234, 0x4100),
                    frame.targetMapper(),
                )
            val reviewed = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY, listOf(innerConfig))
            assertTrue(reviewed.complete(), reviewed.unresolved().toString())
            assertTrue(reviewed.nativeCompatible(), reviewed.nativeIncompatibilities().toString())
            assertFalse(reviewed.returningNativeFunctions().contains(address(0x230).toString()))
            val contradicted =
                SoftwareCallValidation.Configuration(
                    innerConfig.callCpu(),
                    innerConfig.template(),
                    innerConfig.transfer(),
                    innerConfig.callerSp(),
                    SoftwareCallModel.Registers(2, 0, 4, 0x1234, 0x4100),
                    innerConfig.mapper(),
                )
            val rejected = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY, listOf(contradicted))
            assertFalse(rejected.complete())
            assertTrue(rejected.unresolved().single().contains("premises disagree"))
            assertEquals(
                2,
                result
                    .paths()
                    .single()
                    .returned()
                    .registers()
                    .a(),
            )
            assertEquals(
                0x10,
                result
                    .paths()
                    .single()
                    .returned()
                    .registers()
                    .f(),
            )
            assertEquals(
                0xc100,
                result
                    .paths()
                    .single()
                    .returned()
                    .sp(),
            )
            assertEquals(
                2,
                result
                    .paths()
                    .single()
                    .returned()
                    .mapper()
                    .romLow(),
            )
        }

    @Test
    fun `altered return word records actual nonlocal machine state without wrapper epilogue`() =
        fixture(callee = "f8003680233601c9") { p, frame ->
            p.withTransaction {
                val target = address(0x180)
                p.memory.setByte(target, 0xc9.toByte())
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(target, AddressSet(target))
            }
            val summary = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertTrue(summary.complete(), summary.unresolved().toString())
            assertTrue(summary.nativeCompatible(), summary.nativeIncompatibilities().toString())
            val returned = summary.paths().single().returned()
            assertTrue(summary.returningNativeFunctions().isEmpty())
            assertEquals(SoftwareCallModel.Exit.NONLOCAL, returned.exit())
            assertEquals(0x180, returned.cpu())
            assertEquals(MapperState.Physical("ROM", 0, 0x180), returned.physical())
            assertEquals(0xc100, returned.sp())
            assertEquals(0xc0ff, returned.registers().hl())
            assertEquals(0, returned.registers().f())
            assertEquals(2, returned.mapper().romLow())
            assertEquals(listOf(0x180), returned.pops().map { it.value() })
            assertTrue(returned.writes().isEmpty())
        }

    @Test
    fun `saved wrapper frame mutation is unresolved rather than a fabricated nonlocal exit`() =
        fixture(SoftwareCallModel.Family.RESTORING_REGISTER_JP, callee = "f8023603c9") { p, frame ->
            val summary = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertFalse(summary.complete())
            assertTrue(summary.paths().isEmpty())
            assertTrue(summary.unresolved().single().contains("live-frame mutation"))
        }

    @Test
    fun `returning continuation rechecks same-byte code-to-data edits`() =
        fixture(callee = "c9") { p, frame ->
            val continuation = address(0x153)
            p.withTransaction {
                p.memory.setByte(continuation, 0xc9.toByte())
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(continuation, AddressSet(continuation))
            }
            assertTrue(SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY).nativeCompatible())
            p.withTransaction {
                p.listing.clearCodeUnits(continuation, continuation, false)
                p.listing.createData(continuation, ghidra.program.model.data.ByteDataType.dataType)
            }
            val changed = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertTrue(changed.complete(), changed.unresolved().toString())
            assertFalse(changed.nativeCompatible())
            assertTrue(changed.nativeIncompatibilities().any { it.contains("continuation boundary conflicts") })
        }

    @Test
    fun `tracked volatile RAM write does not establish a stable following read`() =
        fixture(callee = "3e2aea00c2fa00c2c9") { p, frame ->
            p.withTransaction {
                val block =
                    p.memory.createInitializedBlock(
                        "volatile_fixture_wram0",
                        p.addressFactory.defaultAddressSpace.getAddress(0xc000),
                        0x1000,
                        0,
                        TaskMonitor.DUMMY,
                        false,
                    )
                ProgramMapping.anchor(p, block, "WRAM", 0)
                block.isVolatile = true
            }
            val summary = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertFalse(summary.complete())
            assertTrue(summary.unresolved().single().contains("Volatile physical memory"))
        }

    @Test
    fun `indirect same-bank control write lacks native bus lowering while direct write is supported`() {
        for ((body, compatible) in listOf("21002077c9" to false, "ea0020c9" to true)) {
            fixture(callee = "cd4002c9") { p, frame ->
                p.withTransaction {
                    val helper = address(0x240)
                    val bytes = HexFormat.of().parseHex(body)
                    p.memory.setBytes(helper, bytes)
                    Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(
                        helper,
                        AddressSet(
                            helper,
                            helper.add(bytes.size.toLong() - 1),
                        ),
                    )
                }
                val summary = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
                assertTrue(summary.complete(), summary.unresolved().toString())
                assertEquals(
                    2,
                    summary
                        .paths()
                        .single()
                        .returned()
                        .mapper()
                        .romLow(),
                )
                assertEquals(compatible, summary.nativeCompatible(), summary.nativeIncompatibilities().toString())
                if (!compatible) assertTrue(summary.nativeIncompatibilities().any { it.contains("native bus lowering") })
            }
        }
    }

    @Test
    fun `generic bank-register store requires actual native volatile port transport`() =
        fixture(callee = "cd4002c9") { p, frame ->
            p.withTransaction {
                val helper = address(0x240)
                p.memory.setBytes(helper, HexFormat.of().parseHex("2170ff77c9"))
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(helper, AddressSet(helper, helper.add(4)))
            }
            val summary = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertTrue(summary.complete(), summary.unresolved().toString())
            assertFalse(summary.nativeCompatible())
            assertTrue(summary.nativeIncompatibilities().any { it.contains("volatile I/O transport") })
        }

    @Test
    fun `ordinary nested call rejects an explicit contradictory native stack purge`() =
        fixture(callee = "afcd1040c9") { p, frame ->
            p.withTransaction {
                val target = SoftwareCallValidation.executionAddress(p, frame.targetMapper(), 0x4010)
                val function =
                    p.functionManager.createFunction(
                        "nested_purge",
                        target,
                        AddressSet(target, target.add(1)),
                        ghidra.program.model.symbol.SourceType.USER_DEFINED,
                    )
                function.stackPurgeSize = 4
            }
            val result = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertTrue(result.complete(), result.unresolved().toString())
            assertFalse(result.nativeCompatible())
            assertTrue(result.nativeIncompatibilities().any { it.contains("stack purge") })
        }

    @Test
    fun `fixed callee helper banked data read needs a native physical memory view`() =
        fixture(callee = "cd4002c9") { p, frame ->
            p.withTransaction {
                val helper = address(0x240)
                p.memory.setBytes(helper, HexFormat.of().parseHex("fa0050c9"))
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(helper, AddressSet(helper, helper.add(3)))
            }
            val result = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertTrue(result.complete(), result.unresolved().toString())
            assertFalse(result.nativeCompatible())
            assertTrue(result.nativeIncompatibilities().any { it.contains("memory access lacks native physical identity") })
        }

    @Test
    fun `callee selector write changes the physical instruction fetch before return`() =
        fixture(caller = 0x4500, callee = "3e03ea0020") { p, frame ->
            val next = SoftwareCallValidation.executionAddress(p, MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, 3), 0x4005)
            p.withTransaction {
                p.memory.setBytes(next, byteArrayOf(0x37, 0xc9.toByte()))
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(next, AddressSet(next, next.add(1)))
            }
            val result = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertTrue(result.complete(), result.unresolved().toString())
            assertFalse(result.nativeCompatible())
            assertTrue(result.nativeIncompatibilities().any { it.contains("intrafunction fetch") })
            assertTrue(result.fetches().any { it.physical() == MapperState.Physical("ROM", 3, 5) })
            assertEquals(
                MapperState.Physical("ROM", 3, 0x503),
                result
                    .paths()
                    .single()
                    .returned()
                    .physical(),
            )
            assertEquals(
                0x10,
                result
                    .paths()
                    .single()
                    .returned()
                    .registers()
                    .f(),
            )
            assertTrue(
                result
                    .paths()
                    .single()
                    .writes()
                    .any { it.cpu() == 0x2000 && it.value() == 3 },
            )
        }

    @Test
    fun `written RAM code cannot reuse a different preexisting listing instruction`() =
        fixture(callee = "3ec9ea00c2c300c2") { p, frame ->
            p.withTransaction {
                val ram = p.addressFactory.defaultAddressSpace.getAddress(0xc200)
                val block =
                    p.memory.createInitializedBlock(
                        "mutable_fixture_wram0",
                        p.addressFactory.defaultAddressSpace.getAddress(0xc000),
                        0x1000,
                        0,
                        TaskMonitor.DUMMY,
                        false,
                    )
                ProgramMapping.anchor(p, block, "WRAM", 0)
                p.memory.setBytes(ram, byteArrayOf(0, 0xc9.toByte()))
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(ram, AddressSet(ram, ram.add(1)))
            }
            val result = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertFalse(result.complete())
            assertTrue(result.unresolved().single().contains("immutable initialized ROM"))
        }

    @Test
    fun `writable instruction ROM is not an immutable callee proof`() =
        fixture(callee = "c9") { p, frame ->
            val target = SoftwareCallValidation.executionAddress(p, frame.targetMapper(), frame.targetCpu())
            p.withTransaction { p.memory.getBlock(target).isWrite = true }
            val result = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertFalse(result.complete())
            assertTrue(result.unresolved().single().contains("immutable initialized ROM"))
        }

    @Test
    fun `unknown RAM and nonlocal return never fabricate returning target`() {
        fixture(callee = "fa00c2c9") { p, frame ->
            val result = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertFalse(result.complete())
            assertFalse(result.mayReturn())
        }
        fixture(callee = "e1c9") { p, frame ->
            val result = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertFalse(result.mayReturn())
        }
    }
}
