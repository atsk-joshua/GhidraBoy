package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.model.data.EndianSettingsDefinition
import ghidra.program.model.scalar.Scalar
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CartridgeTest : IntegrationTest() {
    private fun rom(
        banks: Int = 4,
        type: Int = 0x1b,
    ): ByteArray {
        val bytes = ByteArray(banks * 0x4000) { (it / 0x4000).toByte() }
        bytes[0x143] = 0x80.toByte()
        bytes[0x147] = type.toByte()
        bytes[0x148] = Integer.numberOfTrailingZeros(banks / 2).toByte()
        bytes[0x149] = 3
        bytes[0x14e] = 0x12
        bytes[0x14f] = 0x34
        return bytes
    }

    private fun loaded(
        bytes: ByteArray,
        mode: String = "CARTRIDGE",
        action: (ProgramDB) -> Unit,
    ) {
        val consumer = Any()
        val program = ProgramDB("synthetic", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(program, it, mode, "AUTO", GameBoyKind.CGB, true, true, TaskMonitor.DUMMY, MessageLog())
            }
            action(program)
        } finally {
            program.release(consumer)
        }
    }

    @Test
    fun `header big endian identity patches and renamed split mappings`() {
        val input = rom()
        assertEquals(0x1234, Cartridge.parse(input, "AUTO").globalChecksum())
        loaded(input) { p ->
            val checksum = p.listing.getDataAt(address(0x134)).getComponentContaining(0x1a)
            assertEquals(0x1234L, (checksum.value as Scalar).unsignedValue)
            assertEquals(EndianSettingsDefinition.BIG, EndianSettingsDefinition.DEF.getChoice(checksum))
            assertArrayEquals(input, ProgramMapping.exportBytes(p, false, false, TaskMonitor.DUMMY))
            assertArrayEquals(input, ProgramMapping.exportBytes(p, true, false, TaskMonitor.DUMMY))
            val target = ProgramMapping.fileToStatic(p, 0x8012).single()
            p.withTransaction {
                val b = p.memory.getBlock(target)
                b.name = "user renamed bank"
                val tailAddress = b.start.add(0x100)
                p.memory.split(b, tailAddress)
                p.memory.join(b, p.memory.getBlock(tailAddress))
                p.memory.setByte(target, 0x5a)
            }
            assertEquals(target, ProgramMapping.fileToStatic(p, 0x8012).single())
            val patched = input.copyOf().also { it[0x8012] = 0x5a }
            assertArrayEquals(patched, ProgramMapping.exportBytes(p, true, false, TaskMonitor.DUMMY))
            assertArrayEquals(input, ProgramMapping.exportBytes(p, false, false, TaskMonitor.DUMMY))
        }
    }

    @Test
    fun `boot code readable with no fabricated header and hole offsets preserved`() {
        loaded(ByteArray(0x900) { it.toByte() }, "CGB_BOOT") { p ->
            assertTrue(p.memory.getBlock(address(0)).isRead)
            assertTrue(p.memory.getBlock(address(0)).isExecute)
            assertNull(p.memory.getBlock(address(0x100)))
            assertNull(p.listing.getDataAt(address(0x134)))
            assertNull(ProgramMapping.cartridge(p))
            assertEquals(address(0x234), ProgramMapping.fileToStatic(p, 0x234).single())
            assertArrayEquals(ByteArray(0x900) { it.toByte() }, ProgramMapping.exportBytes(p, true, false, TaskMonitor.DUMMY))
        }
    }

    @Test
    fun `distinct WRAM banks and echoes share storage`() {
        loaded(rom()) { p ->
            val w3 = p.memory.getBlock("wram3")
            val w4 = p.memory.getBlock("wram4")
            p.withTransaction {
                p.memory.convertToInitialized(w3, 0)
                p.memory.convertToInitialized(w4, 0)
                p.memory.setByte(w3.start.add(0x34), 0x33)
                p.memory.setByte(w4.start.add(0x34), 0x44)
            }
            assertEquals(
                0x33.toByte(),
                p.memory.getByte(
                    p.memory
                        .getBlock("echo3")
                        .start
                        .add(0x34),
                ),
            )
            assertEquals(
                0x44.toByte(),
                p.memory.getByte(
                    p.memory
                        .getBlock("echo4")
                        .start
                        .add(0x34),
                ),
            )
            assertEquals(3, ProgramMapping.staticToPhysical(p, w3.start.add(0x34)).single().bank())
            assertEquals(4, ProgramMapping.staticToPhysical(p, w4.start.add(0x34)).single().bank())
        }
    }

    @Test
    fun `MBC5 nine bits bank zero and MBC1 substitution before mask`() {
        val c = Cartridge.parse(rom(512), "AUTO")
        for (bank in listOf(0, 255, 256, 511)) {
            val state = MapperState.reset().write(c, 0x2000, bank and 255).write(c, 0x3000, bank shr 8)
            assertEquals(bank, MapperState.translate(c, state, 0x4034, false).physical().bank())
        }
        val mbc1 = Cartridge.parse(rom(16, 3), "AUTO")
        val s = MapperState.reset().write(mbc1, 0x2000, 16)
        assertEquals(0, MapperState.translate(mbc1, s, 0x4000, false).physical().bank())
        assertEquals("unknown", MapperState.translate(mbc1, null, 0x4000, false).status())
        assertEquals("device", MapperState.translate(mbc1, s, 0x2000, true).status())
    }

    @Test
    fun `MBC2 nibble address selection RTC and rumble distinctions`() {
        val c = Cartridge.parse(rom(16, 6), "AUTO")
        assertEquals(512, c.ramBytes())
        assertEquals(3, MapperState.ramWriteValue(c, 0xa3))
        assertEquals(0xf3, MapperState.ramReadValue(c, 3))
        val s = MapperState.reset().write(c, 0, 10).write(c, 0x2100, 3)
        assertEquals(3, MapperState.translate(c, s, 0x4000, false).physical().bank())
        assertEquals(0x12, MapperState.translate(c, s, 0xb212, false).physical().offset())
        val rtc = Cartridge.parse(rom(4, 0x10), "AUTO")
        assertEquals(
            "device",
            MapperState.translate(rtc, MapperState.reset().write(rtc, 0, 10).write(rtc, 0x4000, 8), 0xa000, false).status(),
        )
        val rumble = Cartridge.parse(rom(4, 0x1e), "AUTO")
        assertEquals(0, MapperState.reset().write(rumble, 0x4000, 8).ramSelect())
    }

    @Test
    fun `malformed and cancelled loads leave no partial program`() {
        for (bytes in listOf(ByteArray(10), ByteArray(0x8001), rom().also { it[0x148] = 0xff.toByte() })) {
            assertThrows(IllegalArgumentException::class.java) { Cartridge.parse(bytes, "AUTO") }
        }
        val consumer = Any()
        val p = ProgramDB("cancelled", language, language.defaultCompilerSpec, consumer)
        try {
            val monitor =
                object : TaskMonitorAdapter(true) {
                    var checks = 0

                    override fun checkCancelled() {
                        if (++checks >= 4) throw CancelledException()
                    }
                }
            ByteArrayProvider(rom()).use {
                assertThrows(CancelledException::class.java) {
                    CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.CGB, true, true, monitor, MessageLog())
                }
            }
            assertEquals(0, p.memory.blocks.size)
            assertEquals(0, p.memory.allFileBytes.size)
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `512 physical ROM banks and upper window zero have exact source mappings`() {
        loaded(rom(512)) { p ->
            for (bank in listOf(255, 256, 511)) {
                val fileOffset = bank * 0x4000L + 0x34
                val a = ProgramMapping.fileToStatic(p, fileOffset).single()
                assertEquals(bank, ProgramMapping.staticToPhysical(p, a).single().bank())
                assertEquals(fileOffset, ProgramMapping.staticToFile(p, a).single())
                assertEquals((bank and 255).toByte(), p.memory.getByte(a))
            }
            val views = ProgramMapping.physicalToStatic(p, MapperState.Physical("ROM", 0, 0x34))
            assertEquals(setOf(0x34L, 0x4034L), views.map { it.offset }.toSet())
            val high = views.single { it.offset == 0x4034L }
            p.withTransaction { p.memory.setByte(high, 0x55) }
            assertEquals(0x55.toByte(), p.memory.getByte(address(0x34)))
            assertEquals(0x55.toByte(), ProgramMapping.exportBytes(p, true, false, TaskMonitor.DUMMY)[0x34])
        }
    }

    @Test
    fun `symbols reimport reload and current export preserve user edits`() {
        loaded(rom()) { p ->
            val source = "synthetic.sym"
            val parsed = SymbolFile.parse("2:4010 Imported\n2:4011 Imported.local\n4002 AnyBank\n".toByteArray())
            p.withTransaction {
                p.symbolTable.createLabel(
                    address(0x151),
                    "UserLabel",
                    ghidra.program.model.symbol.SourceType.USER_DEFINED,
                )
            }
            SymbolService.importSymbols(p, parsed, source, TaskMonitor.DUMMY)
            val before = p.symbolTable.numSymbols
            SymbolService.importSymbols(p, parsed, source, TaskMonitor.DUMMY)
            assertEquals(before, p.symbolTable.numSymbols)
            val imported = p.symbolTable.getSymbols("Imported").next()
            p.withTransaction { imported.setName("UserEdited", ghidra.program.model.symbol.SourceType.USER_DEFINED) }
            SymbolService.importSymbols(p, SymbolFile.parse("2:4012 Replacement\n".toByteArray()), source, TaskMonitor.DUMMY)
            assertTrue(p.symbolTable.getSymbols("UserEdited").hasNext())
            assertTrue(p.symbolTable.getSymbols("UserLabel").hasNext())
            assertTrue(!p.symbolTable.getSymbols("Imported.local").hasNext())
            val exported = SymbolService.exportSymbols(p, TaskMonitor.DUMMY)
            assertTrue(exported.text().contains("2:4010 UserEdited"), exported.toString())
            assertTrue(exported.text().contains("0:0151 UserLabel"), exported.toString())
            SymbolService.removeOwned(p, source, TaskMonitor.DUMMY)
            assertTrue(p.symbolTable.getSymbols("UserEdited").hasNext())
            assertTrue(!p.symbolTable.getSymbols("Replacement").hasNext())
        }
    }

    @Test
    fun `required block creation failure rolls back instead of reporting success`() {
        val consumer = Any()
        val p = ProgramDB("failed-block", language, language.defaultCompilerSpec, consumer)
        try {
            val monitor =
                object : TaskMonitorAdapter(true) {
                    var checks = 0

                    override fun checkCancelled() {
                        if (++checks == 4) p.memory.createUninitializedBlock("injected conflict", address(0xc000), 0x1000, false)
                    }
                }
            ByteArrayProvider(rom()).use {
                assertThrows(java.io.IOException::class.java) {
                    CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.CGB, true, true, monitor, MessageLog())
                }
            }
            assertEquals(0, p.memory.blocks.size)
            assertEquals(0, p.memory.allFileBytes.size)
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `detached conflicting ROM copy is rejected and checksum repair is explicit`() {
        loaded(rom()) { p ->
            val before = ProgramMapping.exportBytes(p, true, false, TaskMonitor.DUMMY)
            val repaired = ProgramMapping.exportBytes(p, true, true, TaskMonitor.DUMMY)
            val descriptor = Cartridge.parse(repaired, "AUTO")
            assertEquals(descriptor.headerChecksum(), descriptor.computedHeaderChecksum())
            assertEquals(descriptor.globalChecksum(), descriptor.computedGlobalChecksum())
            assertArrayEquals(before, ProgramMapping.exportBytes(p, true, false, TaskMonitor.DUMMY))
            p.withTransaction {
                val b =
                    p.memory.createInitializedBlock(
                        "detached ROM copy",
                        address(0x4000),
                        0x4000,
                        0x55.toByte(),
                        TaskMonitor.DUMMY,
                        true,
                    )
                b.isExecute = true
            }
            assertThrows(java.io.IOException::class.java) { ProgramMapping.exportBytes(p, true, false, TaskMonitor.DUMMY) }
            assertArrayEquals(before, ProgramMapping.exportBytes(p, false, false, TaskMonitor.DUMMY))
        }
    }
}
