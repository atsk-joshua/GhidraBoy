package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SalvageTest : IntegrationTest() {
    @Test
    fun `salvage preserves short headers partial banks and unknown size codes without invented geometry`() {
        for (size in listOf(10, 0x5100, 0x8013, 0x100003)) {
            val bytes = ByteArray(size) { (it * 7).toByte() }
            if (size >= 0x150) { bytes[0x147] = 0x19; bytes[0x148] = 0; bytes[0x149] = 0 }
            val consumer = Any()
            val p = ProgramDB("salvage", language, language.defaultCompilerSpec, consumer)
            try {
                ByteArrayProvider(bytes).use { CartridgeLayout.load(p, it, "SALVAGE", "AUTO", GameBoyKind.GB, false, true, TaskMonitor.DUMMY, MessageLog()) }
                assertArrayEquals(bytes, ProgramMapping.exportBytes(p, false, false, TaskMonitor.DUMMY))
                assertArrayEquals(bytes, ProgramMapping.exportBytes(p, true, false, TaskMonitor.DUMMY))
                val snapshot = ProgramMapping.inspect(p)
                val output = java.nio.file.Path.of("build", "test-fixtures", "salvage-$size.json")
                java.nio.file.Files.createDirectories(output.parent)
                java.nio.file.Files.writeString(output, ProgramMapping.JSON.toJson(snapshot))
                assertTrue(snapshot.originalUnmapped().isNotEmpty())
                assertEquals(bytes.size.toLong(), snapshot.originalLength())
                if (size < 0x8000) assertEquals(Cartridge.Mapper.RAW, snapshot.cartridge().mapper())
                if (size < 0x150) assertEquals(0, p.memory.blocks.size)
            } finally { p.release(consumer) }
        }
        val unsupported = ByteArray(0x8001).also { it[0x147] = 0x19; it[0x148] = 0xff.toByte() }
        val descriptor = Cartridge.parse(unsupported, "MBC5", Cartridge.InputPolicy.SALVAGE)
        assertEquals(Cartridge.Mapper.RAW, descriptor.mapper())
        assertEquals(Cartridge.HeaderStatus.UNKNOWN_SIZE, descriptor.headerStatus())
        assertEquals(-1, descriptor.declaredRomBanks())
    }
    @Test
    fun `rumble RAM geometry is not advertised as ordinary sixteen bank SRAM`() {
        val bytes = ByteArray(0x8000).also { it[0x147] = 0x1e; it[0x149] = 4 }
        val c = Cartridge.parse(bytes, "AUTO")
        assertEquals(Cartridge.Mapper.RAW, c.mapper())
        assertEquals(0, c.ramBytes())
    }
    @Test
    fun `legacy hardware remains unknown or preserves an explicit historical choice`() {
        for (choice in listOf("UNKNOWN", "GB")) {
            val bytes = ByteArray(0x8000).also { it[0x143] = 0x80.toByte() }
            val consumer = Any()
            val p = ProgramDB("legacy", language, language.defaultCompilerSpec, consumer)
            try {
                p.withTransaction {
                    ByteArrayProvider(bytes).use {
                        val file = ghidra.app.util.MemoryBlockUtils.createFileBytes(p, it, TaskMonitor.DUMMY)
                        p.memory.createInitializedBlock("renamed ROM", address(0), file, 0, bytes.size.toLong(), false)
                    }
                    p.memory.createUninitializedBlock("manual RAM", address(0xd000), 0x1000, true)
                    if (choice != "UNKNOWN") p.getOptions(ProgramMapping.OPTIONS).setString("hardware", choice)
                }
                val snapshot = LegacyEnhancement.enhance(p, "AUTO", TaskMonitor.DUMMY)
                assertEquals(choice, snapshot.cartridge().hardware())
                if (choice == "UNKNOWN") assertEquals("unknown", MapperState.translate(snapshot.cartridge(), MapperState.reset(), 0xd034, false).status())
                val ram = p.memory.getBlock("manual RAM")
                ProgramMapping.identifyRam(p, ram.start, 0x1000, "WRAM", 3, 0, TaskMonitor.DUMMY)
                ProgramMapping.identifyRam(p, ram.start, 0x1000, "WRAM", 3, 0, TaskMonitor.DUMMY)
                assertEquals(3, ProgramMapping.staticToPhysical(p, ram.start.add(0x34)).single().bank())
                assertThrows(IllegalArgumentException::class.java) { ProgramMapping.identifyRam(p, ram.start, 0x1000, "WRAM", 4, 0, TaskMonitor.DUMMY) }
            } finally { p.release(consumer) }
        }
    }
}
