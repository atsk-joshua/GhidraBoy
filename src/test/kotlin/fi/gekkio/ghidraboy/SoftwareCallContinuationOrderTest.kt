package fi.gekkio.ghidraboy

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary
import ghidra.pcode.exec.BytesPcodeArithmetic
import ghidra.pcode.exec.BytesPcodeExecutorState
import ghidra.pcode.exec.PcodeExecutor
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason
import ghidra.pcode.exec.PcodeProgram
import ghidra.pcode.exec.PcodeStateCallbacks
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

class SoftwareCallContinuationOrderTest : IntegrationTest() {
    private fun fixture(
        continuation: String,
        caller: Int = 0x150,
        extra: Map<Int, String> = emptyMap(),
        action: (ProgramDB, SoftwareCallModel.Frame, SoftwareCallEffects.Path) -> Unit,
    ) {
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x200, 0, null)
        val regions = linkedMapOf(0x200 to template.bodyHex(), 0x8000 to "c9")
        val continuationOffset = if (caller < 0x4000) caller + 3 else 0x8000 + caller + 3 - 0x4000
        regions[continuationOffset] = continuation
        regions.putAll(extra)
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                for ((offset, hex) in regions) HexFormat.of().parseHex(hex).copyInto(this, offset)
            }
        val consumer = Any()
        val p = ProgramDB("continuation-effects", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                for ((offset, hex) in regions) {
                    val bank = offset / 0x4000
                    val cpu = if (bank == 0) offset else 0x4000 + offset % 0x4000
                    val mapper = MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, bank)
                    val at = SoftwareCallValidation.executionAddress(p, mapper, cpu)
                    disassembler.disassemble(at, AddressSet(at, at.add(hex.length.toLong() / 2 - 1)))
                }
            }
            val entry =
                SoftwareCallModel.Entry(
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    caller + 3,
                    SoftwareCallModel.Registers(2, 0, 2, 0x1234, 0x4000),
                    MapperState.reset(),
                    byteArrayOf(),
                )
            val frame = SoftwareCallModel.enter(ProgramMapping.cartridge(p), template, HexFormat.of().parseHex(template.bodyHex()), entry)
            val effects = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY)
            assertTrue(effects.complete(), effects.unresolved().toString())
            action(p, frame, effects.paths().single())
        } finally {
            p.release(consumer)
        }
    }

    private fun trace(
        p: ProgramDB,
        frame: SoftwareCallModel.Frame,
        path: SoftwareCallEffects.Path,
        candidates: List<SoftwareCallValidation.Configuration> = emptyList(),
    ): SoftwareCallEffects.ContinuationSummary = SoftwareCallEffects.deriveContinuation(p, frame, path, candidates, TaskMonitor.DUMMY)

    @Test
    fun `production lower id continuation survives complete graph permutation`() =
        fixture("c35001", extra = mapOf(0x150 to "cd4002", 0x240 to "c9")) { p, frame, path ->
            val graph = trace(p, frame, path)
            assertTrue(graph.complete(), graph.unresolved().toString())
            val call = graph.steps().first { it.afterCall() != null && SoftwareCallEffects.postCallSuccessor(graph, it) < it.index() }
            val next = SoftwareCallEffects.postCallSuccessor(graph, call)
            assertEquals(call.afterCall(), graph.steps().single { it.index() == next }.before())
            assertEquals(call.callDepth(), graph.steps().single { it.index() == next }.callDepth())
            assertEquals("LOOP", graph.exit())
            assertFalse(
                graph.steps().any {
                    it.index() > call.index() && it.callDepth() == call.callDepth() &&
                        it.before() == call.afterCall()
                },
            )
            for (kind in listOf("physical", "mapper", "depth", "invocation", "backedge")) {
                val altered = ProgramMapping.JSON.toJsonTree(graph).asJsonObject
                val records = altered.getAsJsonArray("steps").map { it.asJsonObject }
                val resumed = records.single { it.get("index").asInt == next }
                when (kind) {
                    "physical" -> resumed.getAsJsonObject("before").getAsJsonObject("physical").addProperty("bank", 1)
                    "mapper" -> resumed.getAsJsonObject("before").getAsJsonObject("mapper").addProperty("romLow", 3)
                    "depth" -> resumed.addProperty("callDepth", call.callDepth() + 1)
                    "invocation" -> resumed.addProperty("nativeFunctionEntry", "foreign::0153")
                    "backedge" ->
                        records
                            .first {
                                it
                                    .get(
                                        "transfer",
                                    ).asString == "RETURN" && it.get("successor")?.asInt == next
                            }.remove("successor")
                }
                val invalid = ProgramMapping.JSON.fromJson(altered, SoftwareCallEffects.ContinuationSummary::class.java)
                assertThrows(IllegalArgumentException::class.java, { SoftwareCallEffects.postCallSuccessor(invalid, call) }, kind)
            }

            val payload = SoftwareCallContinuationView.emit(p, address(0x153), graph, emptyList(), 0x70000000L)
            assertTrue(payload.any { it.opcode == ghidra.program.model.pcode.PcodeOp.CALL })
            assertFalse(payload.any { it.opcode == ghidra.program.model.pcode.PcodeOp.RETURN })
            val ids = graph.steps().mapIndexed { index, step -> step.index() to (3000 - index * 7) }.toMap()
            val json = ProgramMapping.JSON.toJsonTree(graph).asJsonObject
            val steps = json.getAsJsonArray("steps").map { it.asJsonObject }.reversed()
            for (step in steps) {
                step.addProperty("index", ids.getValue(step.get("index").asInt))
                if (step.has("successor")) step.addProperty("successor", ids.getValue(step.get("successor").asInt))
            }
            val reordered = com.google.gson.JsonArray()
            steps.forEach(reordered::add)
            json.add("steps", reordered)
            json.addProperty("entryStep", ids.getValue(graph.entryStep()))
            for (veto in json.getAsJsonArray("transportVetoes")) {
                val record = veto.asJsonObject
                val id = record.get("step").asInt
                if (id >= 0) record.addProperty("step", ids.getValue(id))
            }
            val permuted = ProgramMapping.JSON.fromJson(json, SoftwareCallEffects.ContinuationSummary::class.java)
            val sameCall = permuted.steps().single { it.index() == ids.getValue(call.index()) }
            assertEquals(ids.getValue(next), SoftwareCallEffects.postCallSuccessor(permuted, sameCall))
            val again = SoftwareCallContinuationView.emit(p, address(0x153), permuted, emptyList(), 0x70000000L)
            assertEquals(payload.map { it.toString() }, again.map { it.toString() })
            val output =
                java.nio.file.Path
                    .of("build", "w3b")
            java.nio.file.Files
                .createDirectories(output)
            java.nio.file.Files.writeString(
                output.resolve("continuation-order.json"),
                ProgramMapping.JSON.toJson(
                    mapOf(
                        "original" to graph,
                        "permuted" to permuted,
                        "call" to call.index(),
                        "successor" to next,
                        "originalPayload" to payload.map { it.toString() },
                        "permutedPayload" to again.map { it.toString() },
                    ),
                ),
            )
            assertEquals(SoftwareCallEffects.calleeInvocations(graph).size, SoftwareCallEffects.calleeInvocations(permuted).size)
        }

    @Test
    fun `completed callee occurrence cannot prove a later invocation nonreturning`() =
        fixture("c35301", caller = 0x120, extra = mapOf(0x150 to "cd4002c35001", 0x240 to "c9")) { p, frame, path ->
            val graph = trace(p, frame, path)
            assertTrue(graph.complete(), graph.unresolved().toString())
            val calls = graph.steps().filter { it.transfer() == "CALL" }
            assertEquals(2, calls.size)
            assertTrue(calls.all { it.afterCall() != null && it.callOutcome() == null }, calls.toString())
            assertTrue(calls.any { SoftwareCallEffects.postCallSuccessor(graph, it) < it.index() })
            assertEquals(2, SoftwareCallEffects.calleeInvocations(graph).size)
        }
}
