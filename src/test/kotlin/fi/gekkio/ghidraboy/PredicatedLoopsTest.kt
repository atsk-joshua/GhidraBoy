package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

class PredicatedLoopsTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY

    private fun fixture(
        mask: Int = 7,
        instructions: String? = null,
        callee: String? = null,
        action: (ProgramDB, Function) -> Unit,
    ) {
        val bytes = requireNotNull(javaClass.getResourceAsStream("/ordinary/PREDICATED_CALLS.gb")).use { it.readBytes() }
        val body = HexFormat.of().parseHex(instructions ?: "78e6074f1600b72804140d20fc7aea64c0e60120043e0118023e02ea0020cd0040ea65c0c9")
        if (instructions == null) body[2] = mask.toByte()
        body.copyInto(bytes, 0x150)
        if (callee != null) HexFormat.of().parseHex(callee).copyInto(bytes, 0x4000)
        val owner = Any()
        val p = ProgramDB("cyclic-predicate", language, language.defaultCompilerSpec, owner)
        try {
            ByteArrayProvider(
                bytes,
            ).use { CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog()) }
            p.withTransaction {
                val range = AddressSet(address(0x150), address(0x150L + body.size - 1))
                Disassembler.getDisassembler(p, monitor, null).disassemble(address(0x150), range)
                p.functionManager.createFunction("cyclic_root", address(0x150), range, SourceType.USER_DEFINED)
            }
            action(p, p.functionManager.getFunctionAt(address(0x150)))
        } finally {
            p.release(owner)
        }
    }

    @Test
    fun `unknown input loop closes actual transfer worklist with physical calls`() =
        fixture { p, f ->
            val proof = PredicatedCalls.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, monitor)
            println(
                "W3B LOOP " + ProgramMapping.JSON.toJson(proof.convergence()) + " nodes=" + proof.nodes().size + " frontier=" +
                    proof.frontier(),
            )
            assertTrue(proof.complete(), proof.frontier().toString())
            assertTrue(proof.convergence().postFixedPoint())
            assertTrue(
                proof.nodes().any { n ->
                    n.cpu() == 0x15b &&
                        n.edges().any { e -> proof.nodes().any { it.id() == e.target() && it.cpu() == 0x159 } }
                },
            )
            assertEquals(setOf("rom1::4000", "rom2::4000"), proof.invocations().map { it.target() }.toSet())
            val entry = PredicatedCalls.install(p, proof, monitor)
            assertTrue(PredicatedCalls.emit(p, entry, 0x200000, monitor).isNotEmpty())
            W3bCapture.loop(p, entry)
        }

    @Test
    fun `wider trip domain reuses loop control topology`() {
        val counts = mutableListOf<Int>()
        val depths = mutableListOf<Int>()
        for (mask in listOf(7, 31)) {
            fixture(mask) { p, f ->
                val proof = PredicatedCalls.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, monitor)
                println(
                    "W3B WIDE mask=$mask " +
                        ProgramMapping.JSON.toJson(
                            proof.convergence(),
                        ) + " nodes=" + proof.nodes().size + " frontier=" +
                        proof.frontier(),
                )
                assertTrue(proof.complete(), proof.frontier().toString())
                counts.add(proof.nodes().size)

                fun depth(id: Int): Int = 1 + (proof.origins()[id].inputs().maxOfOrNull(::depth) ?: 0)
                depths.add(proof.origins().indices.maxOf(::depth))
                for (row in proof.joins().filter { r -> proof.nodes().any { it.id() == r.node() && it.cpu() == 0x159 } }) {
                    val count =
                        row
                            .before()
                            .single { it.offset() == 2L }
                            .cover()
                            .single()
                            .toInt()
                    val accumulator =
                        row
                            .before()
                            .single { it.offset() == 5L }
                            .cover()
                            .single()
                            .toInt()
                    val bColumn = proof.joinDomains()[row.domain()].roots().indexOfFirst { it.input().endsWith("entry-register-byte@3") }
                    assertTrue(bColumn >= 0)
                    for (input in proof.joinDomains()[row.domain()].assignments()) {
                        assertEquals(input[bColumn].toInt() and mask, count + accumulator)
                        assertTrue(count > 0)
                    }
                }
                val entry = PredicatedCalls.install(p, proof, monitor)
                val registration = p.getOptions(PredicatedCalls.OPTIONS).getString(entry.toString(), "")
                val output =
                    java.nio.file.Path
                        .of("build", "w3b")
                java.nio.file.Files
                    .createDirectories(output)
                java.nio.file.Files
                    .writeString(output.resolve("loop-$mask-proof.json"), ProgramMapping.JSON.toJson(proof))
                java.nio.file.Files.writeString(
                    output.resolve("loop-$mask-metrics.json"),
                    ProgramMapping.JSON.toJson(
                        mapOf(
                            "mask" to mask,
                            "nodes" to proof.nodes().size,
                            "edges" to proof.nodes().sumOf { it.edges().size },
                            "originDepth" to depths.last(),
                            "originNodes" to proof.origins().size,
                            "proofBytes" to
                                ProgramMapping.JSON
                                    .toJson(proof)
                                    .toByteArray()
                                    .size,
                            "graphBytes" to
                                ProgramMapping.JSON
                                    .toJson(proof.nodes())
                                    .toByteArray()
                                    .size,
                            "registrationBytes" to registration.toByteArray().size,
                            "convergence" to proof.convergence(),
                            "frontiers" to proof.frontier().size,
                        ),
                    ),
                )
            }
        }
        assertEquals(counts[0], counts[1])
        assertEquals(depths[0], depths[1])
    }

    @Test
    fun `budget retains partial justified nodes and unresolved reachable obligations`() =
        fixture { p, f ->
            for (limits in listOf(PredicatedCallGraph.Limits(2, 262144, 1), PredicatedCallGraph.Limits(256, 48, 1))) {
                val proof = PredicatedCalls.preview(p, f, limits, monitor)
                assertFalse(proof.complete())
                assertFalse(proof.convergence().postFixedPoint())
                assertTrue(proof.nodes().isNotEmpty())
                assertTrue(proof.frontier().isNotEmpty())
                assertTrue(proof.frontier().all { it.domain() >= 0 && it.before().isNotEmpty() })
                val output =
                    java.nio.file.Path
                        .of("build", "w3b")
                java.nio.file.Files
                    .createDirectories(output)
                java.nio.file.Files.writeString(
                    output.resolve("frontier-${limits.nodes()}-${limits.operations()}.json"),
                    ProgramMapping.JSON.toJson(proof),
                )
                assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.install(p, proof, monitor) }
            }
        }

    @Test
    fun `possible infinite path retains returning path without a termination claim`() =
        fixture(instructions = "78e601280218fec9") { p, f ->
            val proof = PredicatedCalls.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, monitor)
            assertTrue(proof.complete(), proof.frontier().toString())
            assertTrue(proof.convergence().possibleNontermination())
            val output =
                java.nio.file.Path
                    .of("build", "w3b")
            java.nio.file.Files
                .createDirectories(output)
            java.nio.file.Files
                .writeString(output.resolve("possible-nontermination.json"), ProgramMapping.JSON.toJson(proof))
            assertTrue(proof.nodes().any { it.transfer() == "EXTERNAL_RETURN" })
            assertTrue(proof.nodes().any { n -> n.edges().any { it.target() == n.id() } })
        }

    @Test
    fun `changed loop body refuses old authority before refreshed semantics`() =
        fixture { p, f ->
            val proof = PredicatedCalls.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, monitor)
            assertTrue(proof.complete(), proof.frontier().toString())
            val root = PredicatedCalls.install(p, proof, monitor)
            val source = address(0x159)
            p.withTransaction {
                p.listing.clearCodeUnits(source, source, false)
                val alias = root.addressSpace.getAddress(0x159)
                p.listing.clearCodeUnits(alias, alias, false)
                p.memory.setByte(source, 0x15.toByte())
                Disassembler.getDisassembler(p, monitor, null).disassemble(source, AddressSet(source, source), false)
                Disassembler.getDisassembler(p, monitor, null).disassemble(alias, AddressSet(alias, alias), false)
            }
            val old = assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.emit(p, root, 0x200000, monitor) }
            assertTrue(old.message.orEmpty().contains("Stale"))
            val fresh = PredicatedCalls.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, monitor)
            assertTrue(fresh.complete(), fresh.frontier().toString())
            assertNotEquals(proof.joins(), fresh.joins())
            PredicatedCalls.refresh(p, root, fresh, monitor)
            assertTrue(PredicatedCalls.emit(p, root, 0x200000, monitor).isNotEmpty())
        }

    @Test
    fun `backedge predecessor domain effect and premature convergence forgeries reject`() =
        fixture { p, f ->
            val proof = PredicatedCalls.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, monitor)
            assertTrue(proof.complete(), proof.frontier().toString())
            for (kind in listOf("backedge", "predecessor", "path", "physical", "mapper", "convergence")) {
                val json = ProgramMapping.JSON.toJsonTree(proof).asJsonObject
                val nodes = json.getAsJsonArray("nodes").map { it.asJsonObject }
                val loop = nodes.first { it.get("cpu").asInt == 0x15b }
                when (kind) {
                    "backedge" -> loop.getAsJsonArray("edges").remove(0)
                    "predecessor" ->
                        json
                            .getAsJsonArray("joins")
                            .first()
                            .asJsonObject
                            .getAsJsonArray("successors")
                            .remove(0)
                    "path" -> json.getAsJsonArray("joins").remove(10)
                    "physical" -> loop.addProperty("source", "rom1::015b")
                    "mapper" -> nodes.first { it.get("transfer").asString == "CALL" }.getAsJsonArray("edges").remove(0)
                    "convergence" -> json.getAsJsonObject("convergence").addProperty("replayTransfers", 0)
                }
                val forged = ProgramMapping.JSON.fromJson(json, PredicatedCallGraph.Proof::class.java)
                assertThrows(IllegalArgumentException::class.java, { PredicatedCalls.install(p, forged, monitor) }, kind)
            }
        }

    @Test
    fun `joined callee data effects cannot bypass byte A contract`() =
        fixture(callee = "3e31ea66c0c9") { p, f ->
            val proof = PredicatedCalls.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, monitor)
            assertFalse(proof.complete())
            assertTrue(proof.frontier().any { it.reason().contains("data effect") }, proof.frontier().toString())
        }

    @Test
    fun `joined returned flag use stays unresolved through unrelated branch split`() {
        val prefix = "78e6074f1600b72804140d20fc7aea64c03e01ea0020cd0040"
        for (tail in listOf("28023e44ea65c0c9", "ce004f7be60128023e2279ea65c0c9")) {
            fixture(instructions = prefix + tail, callee = "3e3137c9") { p, f ->
                val proof = PredicatedCalls.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, monitor)
                assertFalse(proof.complete())
                assertTrue(proof.frontier().any { it.reason().contains("live returned flags") }, proof.frontier().toString())
            }
        }
    }
}
