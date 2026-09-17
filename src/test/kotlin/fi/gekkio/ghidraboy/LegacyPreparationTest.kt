package fi.gekkio.ghidraboy

import ghidra.app.util.MemoryBlockUtils
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.framework.data.OpenMode
import ghidra.framework.store.db.PackedDatabase
import ghidra.program.database.ProgramDB
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class LegacyPreparationTest : IntegrationTest() {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `coherent historical topology is prepared once without fabricating SRAM banks`() {
        fixture().useProgram { program ->
            val before = LegacyPreparation.preview(program, TaskMonitor.DUMMY)
            assertTrue(before.ready())
            assertTrue(before.descriptorChange())
            assertEquals(12, before.candidates().size)
            assertEquals(3, before.devices().size)

            val prepared = LegacyPreparation.prepare(program, TaskMonitor.DUMMY)
            assertTrue(prepared.ready())
            assertEquals(0, prepared.mutationCount())
            val snapshot = ProgramMapping.inspect(program)
            assertEquals(Cartridge.Mapper.MBC5, snapshot.cartridge().mapper())
            assertEquals("CGB", snapshot.cartridge().hardware())
            assertEquals((0..3).toSet(), banks(snapshot, "ROM"))
            assertEquals(setOf(0, 1), banks(snapshot, "VRAM"))
            assertEquals((0..7).toSet(), banks(snapshot, "WRAM"))
            assertEquals(setOf(0), banks(snapshot, "SRAM"))
            assertEquals(setOf(0), banks(snapshot, "HRAM"))
            assertFalse(snapshot.ranges().any { it.region() == "SRAM" && it.bank() > 0 })
            assertTrue(snapshot.diagnostics().all { it.startsWith("Expected device region") })

            val revision = program.modificationNumber
            LegacyPreparation.prepare(program, TaskMonitor.DUMMY)
            assertEquals(revision, program.modificationNumber)
        }
    }

    @Test
    fun `ambiguous block and conflicting anchor refuse before descriptor mutation`() {
        fixture(xramName = "student ram").useProgram { program ->
            val plan = LegacyPreparation.preview(program, TaskMonitor.DUMMY)
            assertFalse(plan.ready())
            assertTrue(plan.diagnostics().any { it.contains("Ambiguous historical SRAM0") })
            assertThrows(IllegalArgumentException::class.java) {
                LegacyPreparation.prepare(program, TaskMonitor.DUMMY)
            }
            assertNull(ProgramMapping.cartridge(program))
        }

        fixture().useProgram { program ->
            ProgramMapping.identifyRam(program, address(0xc000), 0x1000, "WRAM", 3, 0, TaskMonitor.DUMMY)
            val revision = program.modificationNumber
            val plan = LegacyPreparation.preview(program, TaskMonitor.DUMMY)
            assertFalse(plan.ready())
            assertThrows(IllegalArgumentException::class.java) {
                LegacyPreparation.prepare(program, TaskMonitor.DUMMY)
            }
            assertEquals(revision, program.modificationNumber)
            assertNull(ProgramMapping.cartridge(program))
        }
    }

    @Test
    fun `cancellation leaves preparation transaction rolled back`() {
        fixture().useProgram { program ->
            val monitor =
                object : TaskMonitorAdapter(true) {
                    private var checks = 0

                    override fun checkCancelled() {
                        checks++
                        if (checks == 43) throw CancelledException()
                        super.checkCancelled()
                    }
                }
            assertThrows(CancelledException::class.java) {
                LegacyPreparation.prepare(program, monitor)
            }
            assertNull(ProgramMapping.cartridge(program))
            assertTrue(ProgramMapping.staticToPhysical(program, address(0xc000)).isEmpty())
        }
    }

    @Test
    fun `prepared identities and marker persist across packed reopen`() {
        fixture().useProgram { program ->
            LegacyPreparation.prepare(program, TaskMonitor.DUMMY)
            val packed = temporary.resolve("prepared.gzf").toFile()
            program.saveToPackedFile(packed, TaskMonitor.DUMMY)
            val database = PackedDatabase.getPackedDatabase(packed, true, TaskMonitor.DUMMY)
            val consumer = Any()
            var reopened: ProgramDB? = null
            try {
                reopened =
                    ProgramDB(
                        database.open(TaskMonitor.DUMMY),
                        OpenMode.IMMUTABLE,
                        TaskMonitor.DUMMY,
                        consumer,
                    )
                assertEquals("PREPARED", reopened.getOptions(ProgramMapping.OPTIONS).getString("legacyPreparationState", null))
                assertEquals((0..7).toSet(), banks(ProgramMapping.inspect(reopened), "WRAM"))
                assertEquals(setOf(0), banks(ProgramMapping.inspect(reopened), "SRAM"))
                assertNotNull(GhidraBoyProgramStatus.inspect(reopened, TaskMonitor.DUMMY))
            } finally {
                reopened?.release(consumer)
                database.dispose()
            }
        }
    }

    private fun banks(
        snapshot: ProgramMapping.Snapshot,
        region: String,
    ): Set<Int> =
        snapshot
            .ranges()
            .filter { it.region() == region }
            .map { it.bank() }
            .toSet()

    private fun fixture(xramName: String = "xram"): Fixture {
        val consumer = Any()
        val program = ProgramDB("historical", language, language.defaultCompilerSpec, consumer)
        program.withTransaction<Unit>("historical GhidraBoy topology") {
            val bytes =
                ByteArray(0x10000).also {
                    it[0x143] = 0xc0.toByte()
                    it[0x147] = 0x1b
                    it[0x148] = 1
                    it[0x149] = 4
                }
            ByteArrayProvider(bytes).use { provider ->
                val file = MemoryBlockUtils.createFileBytes(program, provider, TaskMonitor.DUMMY)
                program.memory.createInitializedBlock("rom0", address(0), file, 0, 0x4000, false).apply {
                    isRead = true
                    isWrite = false
                    isExecute = true
                }
                for (bank in 1..3) {
                    program.memory
                        .createInitializedBlock(
                            "rom$bank",
                            address(0x4000),
                            file,
                            bank * 0x4000L,
                            0x4000,
                            true,
                        ).apply {
                            isRead = true
                            isWrite = false
                            isExecute = true
                        }
                }
            }

            fun ordinary(block: ghidra.program.model.mem.MemoryBlock) =
                block.apply {
                    isRead = true
                    isWrite = true
                    isExecute = true
                }
            ordinary(program.memory.createUninitializedBlock(xramName, address(0xa000), 0x2000, false))
            ordinary(program.memory.createUninitializedBlock("wram0", address(0xc000), 0x1000, false))
            val oam = program.memory.createUninitializedBlock("oam", address(0xfe00), 0xa0, false)
            val io = program.memory.createUninitializedBlock("io", address(0xff00), 0x80, false)
            ordinary(program.memory.createUninitializedBlock("hram", address(0xff80), 0x7f, false))
            val ie = program.memory.createUninitializedBlock("ie", address(0xffff), 1, false)
            for (block in listOf(oam, io, ie)) {
                block.isRead = true
                block.isWrite = true
            }
            oam.isExecute = false
            io.isExecute = false
            io.isVolatile = true
            ie.isExecute = false
            ie.isVolatile = true
            for (bank in 0..1) {
                val block = program.memory.createUninitializedBlock("vram$bank", address(0x8000), 0x2000, true)
                block.isRead = true
                block.isWrite = true
                block.isExecute = false
            }
            for (bank in 1..7) {
                ordinary(program.memory.createUninitializedBlock("wram$bank", address(0xd000), 0x1000, true))
            }
        }
        return Fixture(program, consumer)
    }

    private class Fixture(
        val program: ProgramDB,
        private val consumer: Any,
    ) {
        fun <T> useProgram(block: (ProgramDB) -> T): T =
            try {
                block(program)
            } finally {
                program.release(consumer)
            }
    }
}
