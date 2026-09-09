package fi.gekkio.ghidraboy

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotSame
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.util.HexFormat

/** EX-02-05 admission negatives through the unchanged provider; native isolation is captured separately. */
class OrdinaryIsolationAccessTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY
    private val hashes =
        mapOf(
            "P" to "6af7ff922913418033058056b9475099e56ca564d23e9434ed8fcde797c983c5",
            "Q" to "e29b08db7e3a6ed8c9ea8df228887d5de6006e28710f9e72e30ee135d35e53a5",
            "I_BD" to "387f2abed61607878f6d8d6b6dbbebfa135c11c285e93584fa5685f5f9564949",
        )

    private fun fixture(
        name: String,
        action: (ProgramDB) -> Unit,
    ) {
        val bytes =
            requireNotNull(javaClass.getResourceAsStream("/ordinary/$name.gb")) { "Missing ordinary fixture: $name.gb" }
                .use { it.readBytes() }
        assertEquals(hashes.getValue(name), HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)))
        val consumer = Any()
        val p = ProgramDB("iso.gb", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog())
            }
            p.withTransaction {
                for (entry in if (name == "I_BD") listOf(0x150L, 0x250L) else listOf(0x150L)) {
                    val start = address(entry)
                    val body = AddressSet(start, start.add(29))
                    Disassembler.getDisassembler(p, monitor, null).disassemble(start, body)
                    p.functionManager.createFunction("kernel_${entry.toString(16)}", start, body, SourceType.USER_DEFINED)
                }
            }
            for (entry in if (name == "I_BD") listOf(0x150L, 0x250L) else listOf(0x150L)) {
                for (register in listOf("A", "F", "BC", "DE", "HL", "SP")) {
                    assertNull(p.programContext.getValue(p.getRegister(register), address(entry), false))
                }
            }
            action(p)
        } finally {
            p.release(consumer)
        }
    }

    private fun function(
        p: ProgramDB,
        entry: Long = 0x150,
    ): Function = p.functionManager.getFunctionAt(address(entry))

    private fun preview(
        p: ProgramDB,
        entry: Long = 0x150,
    ) = OrdinaryEntryAccess.preview(p, function(p, entry), monitor)

    private fun install(
        p: ProgramDB,
        entry: Long = 0x150,
    ): Address = OrdinaryEntryAccess.install(p, preview(p, entry), monitor)

    private fun emit(
        p: ProgramDB,
        alias: Address,
    ): List<String> = OrdinaryEntryAccess.emit(p, alias, 0x200000, monitor).map { it.toString() }

    private fun registration(
        p: ProgramDB,
        alias: Address,
    ): JsonObject = JsonParser.parseString(p.getOptions(OrdinaryEntryAccess.OPTIONS).getString(alias.toString(), "")).asJsonObject

    private data class Snapshot(
        val revision: Long,
        val fingerprint: String,
        val blocks: List<String>,
        val functions: List<String>,
        val options: Map<String, Map<String, String>>,
    )

    private fun snapshot(p: ProgramDB) =
        Snapshot(
            p.modificationNumber,
            ProgramFingerprint.capture(p, monitor),
            p.memory.blocks.map { "${it.start}:${it.size}:${it.isRead}:${it.isWrite}:${it.isExecute}:${it.isVolatile}" },
            p.functionManager.getFunctions(true).map { "${it.entryPoint}:${it.body}:${it.signature}:${it.comment}" },
            p.optionsNames.associateWith { category ->
                val options = p.getOptions(category)
                options.optionNames.associateWith { options.getObject(it, null).toString() }
            },
        )

    private fun rejectReadOnly(
        p: ProgramDB,
        label: String,
        expectedMessage: String? = null,
        action: () -> Unit,
    ) {
        val before = snapshot(p)
        val failure = assertThrows(IllegalArgumentException::class.java, { action() }, label)
        assertFalse(failure.message.isNullOrBlank(), label)
        if (expectedMessage != null) assertEquals(expectedMessage, failure.message, label)
        assertEquals(before, snapshot(p), "$label must not mutate its receiving Program")
        println("EX0205 provider rejection [$label]: ${failure.message}")
    }

    private fun maliciousRegistration(
        p: ProgramDB,
        alias: Address,
        label: String,
        changed: JsonObject,
        expectedMessage: String? = null,
    ) {
        val options = p.getOptions(OrdinaryEntryAccess.OPTIONS)
        val original = options.getString(alias.toString(), "")
        val valid = emit(p, alias)
        try {
            p.withTransaction { options.setString(alias.toString(), changed.toString()) }
            rejectReadOnly(p, label, expectedMessage) { emit(p, alias) }
        } finally {
            p.withTransaction { options.setString(alias.toString(), original) }
        }
        assertEquals(valid, emit(p, alias), "$label restoration retains the valid provider route")
    }

    @Test
    fun `live proof rejects different bytes and an independently imported byte identical twin`() =
        fixture("P") { p ->
            val proof = preview(p)
            for (name in listOf("Q", "P")) {
                fixture(name) { other ->
                    val ownProof = preview(other)
                    assertNotSame(p, other)
                    assertEquals(p.name, other.name)
                    assertEquals(function(p).entryPoint.toString(), function(other).entryPoint.toString())
                    assertNotEquals(proof.programInstance(), ownProof.programInstance())
                    if (name == "P") assertEquals(proof.dependencies(), ownProof.dependencies())
                    rejectReadOnly(other, "live P proof into $name", "Stale or foreign ordinary-entry proof") {
                        OrdinaryEntryAccess.install(other, proof, monitor)
                    }
                    assertFalse(OrdinaryEntryAccess.registered(other, address(0x150)))
                    assertTrue(emit(other, OrdinaryEntryAccess.install(other, ownProof, monitor)).isNotEmpty())
                }
            }
            assertTrue(emit(p, OrdinaryEntryAccess.install(p, proof, monitor)).isNotEmpty())
        }

    @Test
    fun `serialized P registration rejects Q transplant and superficial owner dependency relabelling`() =
        fixture("P") { p ->
            val pAlias = install(p)
            fixture("Q") { q ->
                val qAlias = install(q)
                assertEquals(pAlias.toString(), qAlias.toString())
                assertNotEquals(p.uniqueProgramID, q.uniqueProgramID)
                val foreign = registration(p, pAlias)
                maliciousRegistration(q, qAlias, "serialized foreign owner", foreign, "Missing or foreign ordinary-entry registration")
                val own = registration(q, qAlias)
                val relabelled = foreign.deepCopy()
                for (field in listOf("programId", "alias", "dependencies", "comment", "nativeIdentity")) {
                    relabelled.add(field, own[field].deepCopy())
                }
                val current = preview(q)
                relabelled.getAsJsonObject("proof").apply {
                    addProperty("programInstance", current.programInstance())
                    addProperty("revision", current.revision())
                    addProperty("dependencies", current.dependencies())
                }
                maliciousRegistration(
                    q,
                    qAlias,
                    "serialized foreign derivation with current Q labels",
                    relabelled,
                    "Changed ordinary proof record or physical access identity",
                )
                assertTrue(emit(p, pAlias).isNotEmpty())
            }
        }

    @Test
    fun `live foreign proof with relabelled owner and dependencies reaches production rederivation`() =
        fixture("P") { p ->
            val foreign = ProgramMapping.JSON.toJsonTree(preview(p)).asJsonObject
            fixture("Q") { q ->
                val own = preview(q)
                foreign.addProperty("programInstance", own.programInstance())
                foreign.addProperty("revision", own.revision())
                foreign.addProperty("dependencies", own.dependencies())
                val relabelled = ProgramMapping.JSON.fromJson(foreign, OrdinaryEntryAccess.Proof::class.java)
                rejectReadOnly(q, "live relabelled P proof in Q", "Ordinary-entry proof does not match current production derivation") {
                    OrdinaryEntryAccess.install(q, relabelled, monitor)
                }
                assertTrue(emit(q, OrdinaryEntryAccess.install(q, own, monitor)).isNotEmpty())
            }
        }

    @Test
    fun `two current aliases reject same Program proof substitution including extent relabelling`() =
        fixture("I_BD") { p ->
            val bAlias = install(p, 0x150)
            val dAlias = install(p, 0x250)
            rejectReadOnly(
                p,
                "first registration after second alias setup",
                "Stale ordinary-entry registration; preview and refresh required",
            ) {
                emit(p, bAlias)
            }
            OrdinaryEntryAccess.refresh(p, bAlias, preview(p, 0x150), monitor)
            val bValid = emit(p, bAlias)
            val dValid = emit(p, dAlias)
            val own = registration(p, dAlias)
            val changed = own.deepCopy()
            changed.add("proof", registration(p, bAlias).getAsJsonObject("proof").deepCopy())
            maliciousRegistration(p, dAlias, "same Program B proof at D alias", changed)
            val relabelled = changed.deepCopy()
            val oldProof = relabelled.getAsJsonObject("proof")
            val newProof = own.getAsJsonObject("proof")
            for (field in listOf("entry", "end", "segments")) oldProof.add(field, newProof[field].deepCopy())
            maliciousRegistration(
                p,
                dAlias,
                "same Program B derivation with D extent labels",
                relabelled,
                "Changed ordinary proof record or physical access identity",
            )
            rejectReadOnly(p, "live B proof refreshing D alias", "Refresh may not change the represented Function extent") {
                OrdinaryEntryAccess.refresh(p, dAlias, preview(p, 0x150), monitor)
            }
            assertEquals(bValid, emit(p, bAlias))
            assertEquals(dValid, emit(p, dAlias))
        }

    @Test
    fun `edited owner physical source and finite domain records reject read only then restore`() =
        fixture("P") { p ->
            val alias = install(p)
            val original = registration(p, alias)
            for (field in listOf("owner", "physical-source", "source-address", "domain", "finite-selector-domain")) {
                val changed = original.deepCopy()
                val proof = changed.getAsJsonObject("proof")
                when (field) {
                    "owner" -> changed.addProperty("programId", p.uniqueProgramID xor 1L)
                    "domain" -> proof.getAsJsonObject("domain").addProperty("bootBypassed", false)
                    "finite-selector-domain" ->
                        proof
                            .getAsJsonObject("finite")
                            .getAsJsonArray("choices")[0]
                            .asJsonObject
                            .add("values", ProgramMapping.JSON.toJsonTree(listOf(1L)))
                    else -> {
                        val source =
                            proof
                                .getAsJsonObject("finite")
                                .getAsJsonArray("reads")[0]
                                .asJsonObject
                                .getAsJsonArray("alternatives")[0]
                                .asJsonObject
                                .getAsJsonArray("sources")[0]
                                .asJsonObject
                        if (field == "physical-source") {
                            source.getAsJsonObject("physical").addProperty("bank", 3)
                        } else {
                            source.addProperty("address", ProgramMapping.fileToStatic(p, 0xe000).single().toString())
                        }
                    }
                }
                maliciousRegistration(p, alias, field, changed)
            }
        }
}
