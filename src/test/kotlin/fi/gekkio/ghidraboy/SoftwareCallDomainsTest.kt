package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

class SoftwareCallDomainsTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY

    private fun fixture(
        prepared: Boolean = true,
        action: (ProgramDB, List<SoftwareCallValidation.Configuration>) -> Unit,
    ) {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val chunks =
            linkedMapOf(
                0x28 to helper.bodyHex(),
                0x200 to "efc9",
                0x8100 to "ca20413e03ea0020",
                0xc108 to "c30042",
                0x8120 to "3e02ea0020c30042",
                0x8200 to "3e22ea10c2c9",
                0xc200 to "3e33ea10c2c9",
            )
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                for ((offset, hex) in chunks) HexFormat.of().parseHex(hex).copyInto(this, offset)
            }
        val owner = Any()
        val p = ProgramDB("same configured site domains", language, language.defaultCompilerSpec, owner)
        try {
            ByteArrayProvider(
                bytes,
            ).use { CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, monitor, MessageLog()) }
            if (prepared) {
                p.withTransaction {
                    val disassembler = Disassembler.getDisassembler(p, monitor, null)
                    for ((offset, hex) in chunks) {
                        val bank = offset / 0x4000
                        val cpu = if (bank == 0) offset else 0x4000 + offset % 0x4000
                        val at =
                            SoftwareCallValidation.executionAddress(
                                p,
                                MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, bank),
                                cpu,
                            )
                        disassembler.disassemble(at, AddressSet(at, at.add(hex.length / 2L - 1)))
                    }
                }
            }
            val configs =
                listOf(0, 0x80).map { flags ->
                    SoftwareCallValidation.Configuration(
                        0x200,
                        helper,
                        SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                        0xc100,
                        SoftwareCallModel.Registers(2, flags, 0, 0, 0x4100),
                        MapperState.reset(),
                    )
                }
            action(p, configs)
        } finally {
            p.release(owner)
        }
    }

    private fun state(p: ProgramDB): List<Any> =
        listOf(
            FarCallEvidence.capture(p, monitor),
            p.listing
                .getInstructions(true)
                .iterator()
                .asSequence()
                .map { it.address.toString() }
                .toList(),
            p.functionManager.functionCount,
            p.memory.blocks.map { it.start.toString() },
            if (p.optionsNames.contains(SoftwareCallDomains.STOCK_OPTIONS)) {
                p.getOptions(SoftwareCallDomains.STOCK_OPTIONS).getString("registration", "absent")
            } else {
                "absent"
            },
        )

    private fun semantics(proof: SoftwareCallDomains.Proof): String =
        SoftwareCallDomains.semanticJson(ProgramMapping.JSON.toJsonTree(proof.domains()))

    @Test
    fun `fresh domains preserve complete discovery for canonical and anti canonical callers through pristine installs`() =
        fixture(prepared = false) { p, configs ->
            assertFalse(p.listing.getInstructions(true).hasNext())
            val before = state(p)
            val revision = p.modificationNumber
            val order = SoftwareCallDomains.preview(p, configs, monitor).domains().map { it.configuration() }
            val canonical = SoftwareCallDomains.preview(p, order, monitor)
            val antiCanonical = SoftwareCallDomains.preview(p, order.reversed(), monitor)
            assertNotEquals(order, order.reversed())
            assertTrue(canonical.discovery().candidates().isNotEmpty())
            assertTrue(antiCanonical.discovery().candidates().isNotEmpty())
            for (candidate in canonical.discovery().candidates() + antiCanonical.discovery().candidates()) {
                assertTrue(p.listing.getInstructionAt(p.addressFactory.getAddress(candidate.address())) == null)
            }
            assertEquals(before, state(p))
            assertEquals(revision, p.modificationNumber)
            assertEquals(semantics(canonical), semantics(antiCanonical))
            assertAll(
                { assertEquals(canonical.discovery(), antiCanonical.discovery(), "Complete ordered discovery authority") },
                {
                    for (callerOrder in listOf(order.reversed(), order)) {
                        assertEquals(before, state(p), "Each arm starts from the same pristine unregistered listing")
                        assertFalse(p.listing.getInstructions(true).hasNext())
                        val fresh = SoftwareCallDomains.preview(p, callerOrder, monitor)
                        assertTrue(fresh.discovery().candidates().isNotEmpty())
                        val transaction = p.startTransaction("Exercise domain install with complete rollback")
                        try {
                            val views = SoftwareCallDomains.install(p, fresh, monitor)
                            assertEquals(4, views.size)
                            assertEquals(semantics(fresh), semantics(SoftwareCallDomains.proof(p)))
                            assertTrue(views.all { SoftwareCallDomains.registered(p, p.addressFactory.getAddress(it.entry())) })
                        } finally {
                            p.endTransaction(transaction, false)
                        }
                        assertEquals(before, state(p), "Rollback restores bytes, annotations, listing, views and registration")
                    }
                },
            )
        }

    @Test
    fun `altered real discovery bytes reject at retained domain discovery guard before application`() =
        fixture(prepared = false) { p, configs ->
            val order = SoftwareCallDomains.preview(p, configs, monitor).domains().map { it.configuration() }
            val proof = SoftwareCallDomains.preview(p, order, monitor)
            val candidate = proof.discovery().candidates().first()
            val changedBytes = (if (candidate.bytes().startsWith("00")) "ff" else "00") + candidate.bytes().drop(2)
            val altered =
                SoftwareCallInstructionDiscovery.Candidate(
                    candidate.address(),
                    candidate.length(),
                    changedBytes,
                    candidate.physicalBytes(),
                    candidate.reason(),
                    candidate.mnemonic(),
                    candidate.comments(),
                )
            val forged =
                SoftwareCallDomains.Proof(
                    proof.version(),
                    proof.programId(),
                    proof.dependencies(),
                    proof.domains(),
                    SoftwareCallInstructionDiscovery.Plan(
                        proof.discovery().version(),
                        proof.discovery().dependencies(),
                        listOf(altered) + proof.discovery().candidates().drop(1),
                        proof.discovery().reservations(),
                    ),
                )
            assertNotEquals(proof.discovery(), forged.discovery())
            assertEquals(semantics(proof), semantics(forged))
            assertEquals(proof.dependencies(), FarCallEvidence.capture(p, monitor))
            val before = state(p)
            val revision = p.modificationNumber
            val refusal = assertThrows(IllegalArgumentException::class.java) { SoftwareCallDomains.install(p, forged, monitor) }
            assertEquals("Domain discovery differs from rooted proof", refusal.message)
            assertEquals(before, state(p))
            assertEquals(revision, p.modificationNumber)
            assertFalse(p.listing.getInstructions(true).hasNext())
        }

    @Test
    fun `domain v1 registration retains configuration semantics and rederives either persisted order`() =
        fixture(prepared = false) { p, configs ->
            val order = SoftwareCallDomains.preview(p, configs, monitor).domains().map { it.configuration() }
            val proof = SoftwareCallDomains.preview(p, order, monitor)
            val views = SoftwareCallDomains.install(p, proof, monitor)
            val options = p.getOptions(SoftwareCallDomains.STOCK_OPTIONS)
            val saved =
                com.google.gson.JsonParser
                    .parseString(options.getString("registration", ""))
                    .asJsonObject
            assertEquals(
                setOf("version", "programId", "configurations", "semantics", "views", "dependencies", "transport"),
                saved.keySet(),
            )
            // Retain this checkpoint test identity; current authority is explicitly versioned.
            assertEquals(SoftwareCallDomains.STOCK_VERSION, saved.get("version").asString)
            assertEquals(p.uniqueProgramID, saved.get("programId").asLong)
            assertEquals(semantics(proof), saved.get("semantics").asString)
            assertEquals(semantics(proof), semantics(SoftwareCallDomains.proof(p)))
            val reversed = com.google.gson.JsonArray()
            saved.getAsJsonArray("configurations").reversed().forEach(reversed::add)
            saved.add("configurations", reversed)
            p.withTransaction { options.setString("registration", saved.toString()) }
            assertEquals(semantics(proof), semantics(SoftwareCallDomains.proof(p)))
            assertEquals(views, SoftwareCallDomains.views(p))
            for (view in views.filter { it.kind() == "root" }) {
                assertTrue(SoftwareCallDomains.emit(p, p.addressFactory.getAddress(view.entry()), 0x200000, monitor).isNotEmpty())
            }
        }

    @Test
    fun `legacy domain v1 rejects before proof or native use without changing saved registration`() =
        fixture { p, configs ->
            val views = SoftwareCallDomains.install(p, SoftwareCallDomains.preview(p, configs, monitor), monitor)
            val options = p.getOptions(SoftwareCallDomains.STOCK_OPTIONS)
            val legacy =
                com.google.gson.JsonParser
                    .parseString(options.getString("registration", ""))
                    .asJsonObject
            legacy.addProperty("version", "software-call-domains-1")
            p.withTransaction { options.setString("registration", legacy.toString()) }
            val revision = p.modificationNumber
            val refusal = assertThrows(IllegalArgumentException::class.java) { SoftwareCallDomains.proof(p) }
            assertEquals("Unsupported software domain record version", refusal.message)
            for (view in views) {
                val nativeRefusal =
                    assertThrows(IllegalArgumentException::class.java) {
                        SoftwareCallDomains.emit(p, p.addressFactory.getAddress(view.entry()), 0x200000, monitor)
                    }
                assertEquals("Unsupported software domain record version", nativeRefusal.message)
            }
            assertEquals(legacy.toString(), options.getString("registration", ""))
            assertEquals(revision, p.modificationNumber)
        }

    @Test
    fun `same address stored reference rebinding rejects installed domain authority`() =
        fixture { p, configs ->
            val source = address(0x350)
            val target = address(0x360)
            val replacement =
                p.withTransaction {
                    val first = p.symbolTable.createLabel(target, "binding_A", ghidra.program.model.symbol.SourceType.USER_DEFINED)
                    val second = p.symbolTable.createLabel(target, "binding_B", ghidra.program.model.symbol.SourceType.USER_DEFINED)
                    val ref =
                        p.referenceManager.addMemoryReference(
                            source,
                            target,
                            ghidra.program.model.symbol.RefType.DATA,
                            ghidra.program.model.symbol.SourceType.USER_DEFINED,
                            -1,
                        )
                    p.referenceManager.setAssociation(first, ref)
                    second
                }
            val views = SoftwareCallDomains.install(p, SoftwareCallDomains.preview(p, configs, monitor), monitor)
            val before = ProgramFingerprint.capture(p, monitor)
            p.withTransaction { p.referenceManager.setAssociation(replacement, p.referenceManager.getReferencesFrom(source).single()) }
            assertEquals(before, ProgramFingerprint.capture(p, monitor))
            for (view in views) {
                val refusal =
                    assertThrows(IllegalArgumentException::class.java) {
                        SoftwareCallDomains.emit(p, p.addressFactory.getAddress(view.entry()), 0x200000, monitor)
                    }
                assertEquals("Stale software domain registration; explicit refresh required", refusal.message)
            }
        }

    @Test
    fun `same physical configured RST keeps both domains through reverse request and display order`() =
        fixture { p, configs ->
            val proof = SoftwareCallDomains.preview(p, configs, monitor)
            val reversed = SoftwareCallDomains.preview(p, configs.reversed(), monitor)
            assertEquals(ProgramMapping.JSON.toJson(proof.domains()), ProgramMapping.JSON.toJson(reversed.domains()))
            assertEquals(
                1,
                proof
                    .domains()
                    .map { it.physicalSite() }
                    .distinct()
                    .size,
            )
            assertEquals(
                setOf(0x22, 0x33),
                proof
                    .domains()
                    .map {
                        it
                            .effects()
                            .paths()
                            .single()
                            .returned()
                            .registers()
                            .a()
                    }.toSet(),
            )
            val views = SoftwareCallDomains.install(p, proof, monitor)
            W3bCapture.domains(p)
            val roots = views.filter { it.kind() == "root" }
            val payloads =
                roots.associate { view ->
                    view.domain() to
                        SoftwareCallDomains.emit(p, p.addressFactory.getAddress(view.entry()), 0x200000, monitor).map { it.toString() }
                }
            for (selected in roots) {
                SoftwareCallDomains.selectDisplay(p, selected.domain())
                for (view in roots.reversed()) {
                    assertEquals(
                        payloads.getValue(
                            view.domain(),
                        ),
                        SoftwareCallDomains.emit(p, p.addressFactory.getAddress(view.entry()), 0x200000, monitor).map {
                            it.toString()
                        },
                    )
                }
            }
            val keyedOnlyBySite = proof.domains().associateBy { it.physicalSite() }
            val requested = proof.domains().first { keyedOnlyBySite.getValue(it.physicalSite()).id() != it.id() }
            val wrong = keyedOnlyBySite.getValue(requested.physicalSite())
            val wrongEntry = p.addressFactory.getAddress(roots.single { it.domain() == wrong.id() }.entry())
            val refused =
                assertThrows(IllegalArgumentException::class.java) { SoftwareCallDomains.emit(p, wrongEntry, requested, 0x200000, monitor) }
            assertTrue(refused.message.orEmpty().contains("Wrong requested"))
            assertNotEquals(payloads.values.first(), payloads.values.last())
        }

    @Test
    fun `foreign and stale configured domain proofs cannot be consumed`() =
        fixture { p, configs ->
            val proof = SoftwareCallDomains.preview(p, configs, monitor)
            fixture {
                foreign,
                _,
                ->
                assertThrows(IllegalArgumentException::class.java) { SoftwareCallDomains.install(foreign, proof, monitor) }
            }
            val roots = SoftwareCallDomains.install(p, proof, monitor).filter { it.kind() == "root" }
            val mutation = p.addressFactory.getAddress("rom3::4201")
            p.withTransaction {
                val instructions =
                    p.listing
                        .getInstructions(true)
                        .iterator()
                        .asSequence()
                        .filter {
                            it.address.offset == 0x4200L &&
                                ProgramMapping.staticToPhysical(p, it.address).any { physical -> physical.bank() == 3 }
                        }.toList()
                for (instruction in instructions) p.listing.clearCodeUnits(instruction.minAddress, instruction.maxAddress, false)
                p.memory.setByte(mutation, 0x44.toByte())
            }
            for (view in roots) {
                val refusal =
                    assertThrows(IllegalArgumentException::class.java) {
                        SoftwareCallDomains.emit(p, p.addressFactory.getAddress(view.entry()), 0x200000, monitor)
                    }
                assertTrue(refusal.message.orEmpty().contains("Stale"))
            }
        }

    @Test
    fun `wrong domain alias record and changed native contract reject`() =
        fixture { p, configs ->
            val proof = SoftwareCallDomains.preview(p, configs, monitor)
            val roots = SoftwareCallDomains.install(p, proof, monitor).filter { it.kind() == "root" }
            val options = p.getOptions(SoftwareCallDomains.STOCK_OPTIONS)
            val saved = options.getString("registration", "")
            val json =
                com.google.gson.JsonParser
                    .parseString(saved)
                    .asJsonObject
            val first = json.getAsJsonArray("views").first().asJsonObject
            first.addProperty("domain", proof.domains().single { it.id() != first.get("domain").asString }.id())
            p.withTransaction { options.setString("registration", json.toString()) }
            assertThrows(IllegalArgumentException::class.java) {
                SoftwareCallDomains.emit(p, p.addressFactory.getAddress(roots.first().entry()), 0x200000, monitor)
            }
            p.withTransaction { options.setString("registration", saved) }
            val function = p.functionManager.getFunctionAt(p.addressFactory.getAddress(roots.first().entry()))
            p.withTransaction { function.isInline = true }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallDomains.emit(p, function.entryPoint, 0x200000, monitor) }
        }

    @Test
    fun `durable domain identity ignores map and set order but retains effect order`() =
        fixture { p, configs ->
            val proof = SoftwareCallDomains.preview(p, configs, monitor)
            val json = ProgramMapping.JSON.toJsonTree(proof.domains())

            fun permute(
                value: com.google.gson.JsonElement,
                field: String = "",
            ): com.google.gson.JsonElement {
                if (value.isJsonObject) {
                    val next = com.google.gson.JsonObject()
                    value.asJsonObject
                        .entrySet()
                        .reversed()
                        .forEach { (key, child) -> next.add(key, permute(child, key)) }
                    return next
                }
                if (value.isJsonArray) {
                    val values = value.asJsonArray.map { permute(it) }.let { if (field == "changedRegisters") it.reversed() else it }
                    return com.google.gson
                        .JsonArray()
                        .also { array -> values.forEach(array::add) }
                }
                return value.deepCopy()
            }
            assertEquals(SoftwareCallDomains.semanticJson(json), SoftwareCallDomains.semanticJson(permute(json)))
            val altered = json.deepCopy()
            val events =
                altered.asJsonArray
                    .first()
                    .asJsonObject
                    .getAsJsonObject("frame")
                    .getAsJsonArray("events")
            assertTrue(events.size() > 1)
            val first = events.remove(0)
            events.add(first)
            assertNotEquals(SoftwareCallDomains.semanticJson(json), SoftwareCallDomains.semanticJson(altered))
        }
}
