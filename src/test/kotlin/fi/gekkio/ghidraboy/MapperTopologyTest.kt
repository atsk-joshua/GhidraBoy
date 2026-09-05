package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class MapperTopologyTest : IntegrationTest() {
    @Test
    fun `every supported reachable ROM window has shared physical backing`() {
        for ((banks, type) in listOf(2 to 0, 16 to 3, 64 to 3, 8 to 6, 16 to 6, 16 to 0x13, 128 to 0x13, 512 to 0x19)) {
            val bytes = ByteArray(banks * 0x4000) { (it / 0x4000).toByte() }
            bytes[0x147] = type.toByte()
            bytes[0x148] = Integer.numberOfTrailingZeros(banks / 2).toByte()
            bytes[0x149] = 0
            val consumer = Any()
            val p = ProgramDB("topology", language, language.defaultCompilerSpec, consumer)
            try {
                ByteArrayProvider(bytes).use { CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog()) }
                val c = ProgramMapping.cartridge(p)
                for (view in MapperTopology.romViews(c)) {
                    val physical = MapperState.Physical("ROM", view.bank(), 0x34)
                    val addresses = ProgramMapping.physicalToStatic(p, physical).filter { it.offset == view.cpuWindow() + 0x34L }
                    assertTrue(addresses.isNotEmpty(), "$banks type=$type view=$view")
                    for (a in addresses) {
                        assertEquals(listOf(physical), ProgramMapping.staticToPhysical(p, a))
                        assertEquals(listOf(view.bank() * 0x4000L + 0x34), ProgramMapping.staticToFile(p, a))
                    }
                }
                val zeroHigh = ProgramMapping.physicalToStatic(p, MapperState.Physical("ROM", 0, 0x34)).find { it.offset == 0x4034L }
                if (zeroHigh != null) {
                    p.withTransaction { p.memory.setByte(zeroHigh, 0x55) }
                    assertEquals(0x55.toByte(), p.memory.getByte(address(0x34)))
                    assertEquals(0x55.toByte(), ProgramMapping.exportBytes(p, true, false, TaskMonitor.DUMMY)[0x34])
                }
            } finally { p.release(consumer) }
        }
    }
}
