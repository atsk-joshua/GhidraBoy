package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class SymbolBoundaryTest : IntegrationTest() {
    @TempDir lateinit var directory: Path

    @Test
    fun `explicit end markers retain overlay space through rename reload and export`() {
        val consumer = Any()
        val p = ProgramDB("boundary symbols", language, language.defaultCompilerSpec, consumer)
        try {
            val bytes =
                ByteArray(0x10000).also {
                    it[0x147] = 0x1b
                    it[0x148] = 1
                    it[0x149] = 3
                }
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.CGB, true, true, TaskMonitor.DUMMY, MessageLog())
            }
            val parsed = SymbolFile.parse("0:a000 VramEnd\n".toByteArray())
            val candidates = SymbolService.boundaryCandidates(p, parsed.symbols().single())
            assertTrue(candidates.any { it.toString() == "vram0::a000" }, candidates.toString())
            val choices = mapOf(SymbolService.entryKey(parsed.symbols().single()) to "vram0::a000")
            SymbolService.importSymbols(p, parsed, "boundaries.sym", choices, TaskMonitor.DUMMY)
            assertEquals(
                "vram0::a000",
                p.symbolTable
                    .getSymbols("VramEnd")
                    .next()
                    .address
                    .toString(),
            )
            p.withTransaction { p.renameOverlaySpace("vram0", "renamed_vram") }
            SymbolService.importSymbols(p, parsed, "boundaries.sym", TaskMonitor.DUMMY)
            assertEquals(
                "renamed_vram::a000",
                p.symbolTable
                    .getSymbols("VramEnd")
                    .next()
                    .address
                    .toString(),
            )
            assertTrue(SymbolService.exportSymbols(p, TaskMonitor.DUMMY).text().contains("0:a000 VramEnd"))
            val input = directory.resolve("image.gb")
            Files.write(input, bytes)
            p.withTransaction { p.executablePath = input.toString() }
            assertTrue(SymbolService.companion(p).isEmpty)
            Files.writeString(directory.resolve("unrelated.sym"), "0:0100 Wrong\n")
            assertTrue(SymbolService.companion(p).isEmpty)
            val companion = directory.resolve("image.sym")
            Files.writeString(companion, "0:0100 Right\n")
            assertEquals(companion, SymbolService.companion(p).get())
        } finally {
            p.release(consumer)
        }
    }
}
