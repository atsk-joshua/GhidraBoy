package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

class SoftwareCallDomainsTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY

    private fun fixture(action: (ProgramDB, List<SoftwareCallValidation.Configuration>) -> Unit) {
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
            val options = p.getOptions(SoftwareCallDomains.OPTIONS)
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
