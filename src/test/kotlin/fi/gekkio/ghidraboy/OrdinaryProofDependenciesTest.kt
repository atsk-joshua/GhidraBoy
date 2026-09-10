package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.util.HexFormat

class OrdinaryProofDependenciesTest : IntegrationTest() {
    private fun fixture(action: (ProgramDB, Function) -> Unit) {
        val bytes = requireNotNull(javaClass.getResourceAsStream("/ordinary/P.gb")).use { it.readBytes() }
        val consumer = Any()
        val p = ProgramDB("dependency-equivalence", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                val body = AddressSet(address(0x150), address(0x16d))
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(address(0x150), body)
                p.functionManager.createFunction("retained_kernel", address(0x150), body, SourceType.USER_DEFINED)
            }
            action(p, p.functionManager.getFunctionAt(address(0x150)))
        } finally {
            p.release(consumer)
        }
    }

    private fun compare(p: ProgramDB): String {
        val baseline = BaselineOrdinaryProofDependencies.fingerprint(p, TaskMonitor.DUMMY)
        assertEquals(baseline, OrdinaryProofDependencies.fingerprint(p, TaskMonitor.DUMMY))
        return baseline
    }

    @Test
    fun `frozen baseline and extracted policy match across consumed mutation restore and durable emission`() =
        fixture { p, function ->
            val before = compare(p)
            val canonicalBody = function.body.toString()
            val canonicalSignature = function.signature.toString()
            val canonicalComment = function.comment
            val proof = OrdinaryEntryAccess.preview(p, function, TaskMonitor.DUMMY)
            assertEquals(before, proof.dependencies())
            val alias = OrdinaryEntryAccess.install(p, proof, TaskMonitor.DUMMY)
            val registered = p.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS).getString(alias.toString(), "")
            val current = compare(p)
            val payload = OrdinaryEntryAccess.emit(p, alias, 0x200000, TaskMonitor.DUMMY).map { it.toString() }
            val at = ProgramMapping.fileToStatic(p, 0xa000).first { it.addressSpace.name == "rom2" }
            val original = p.memory.getByte(at)
            p.withTransaction { p.memory.setByte(at, 0xd4.toByte()) }
            assertNotEquals(current, compare(p))
            assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.emit(p, alias, 0x200000, TaskMonitor.DUMMY) }
            p.withTransaction { p.memory.setByte(at, original) }
            assertEquals(current, compare(p))
            assertEquals(registered, p.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS).getString(alias.toString(), ""))
            assertEquals(payload, OrdinaryEntryAccess.emit(p, alias, 0x200000, TaskMonitor.DUMMY).map { it.toString() })
            assertEquals(canonicalBody, function.body.toString())
            assertEquals(canonicalSignature, function.signature.toString())
            assertEquals(canonicalComment, function.comment)
            // Restoring content between requests remains legal; do not invent a new live-preview policy.
        }

    @Test
    fun `change then restore during preview retains the original revision race rejection`() =
        fixture { p, function ->
            val before = compare(p)
            val revision = p.modificationNumber
            val at = ProgramMapping.fileToStatic(p, 0xa000).first { it.addressSpace.name == "rom2" }
            var changed = false
            val monitor =
                object : TaskMonitorAdapter() {
                    override fun checkCancelled() {
                        if (!changed) {
                            changed = true
                            val original = p.memory.getByte(at)
                            p.withTransaction {
                                p.memory.setByte(at, 0xd4.toByte())
                                p.memory.setByte(at, original)
                            }
                        }
                    }
                }
            val error = assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.preview(p, function, monitor) }
            assertEquals("Program changed during ordinary-entry proof", error.message)
            assertTrue(changed && revision != p.modificationNumber)
            assertEquals(before, compare(p))
            assertEquals(before, OrdinaryEntryAccess.preview(p, function, TaskMonitor.DUMMY).dependencies())
        }

    @Test
    fun `all retained fixture resources exist with their original exact identities`() {
        val manifest =
            requireNotNull(javaClass.getResourceAsStream("/ordinary/PROVENANCE.json"))
                .reader()
                .use {
                    com.google.gson.JsonParser
                        .parseReader(it)
                        .asJsonArray
                }
        assertEquals(20, manifest.size())
        for (row in manifest) {
            val name = row.asJsonObject["path"].asString
            val bytes =
                requireNotNull(javaClass.getResourceAsStream("/ordinary/$name")) { "Missing ordinary fixture: $name" }
                    .use { it.readBytes() }
            assertEquals(
                row.asJsonObject["sha256"].asString,
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)),
                name,
            )
        }
    }
}
