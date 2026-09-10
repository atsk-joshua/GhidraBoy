package fi.gekkio.ghidraboy

import com.google.gson.JsonParser
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Function
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

class PredicatedCallsTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY

    private fun fixture(
        instructions: ByteArray? = null,
        prepare: (ByteArray) -> Unit = {},
        action: (ProgramDB, Function) -> Unit,
    ) {
        val bytes = requireNotNull(javaClass.getResourceAsStream("/ordinary/PREDICATED_CALLS.gb")).use { it.readBytes() }
        if (instructions != null) instructions.copyInto(bytes, 0x150)
        prepare(bytes)
        val owner = Any()
        val p = ProgramDB("predicate-call", language, language.defaultCompilerSpec, owner)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog())
            }
            p.withTransaction {
                val body = AddressSet(address(0x150), address(0x150L + (instructions?.size ?: 21) - 1))
                Disassembler.getDisassembler(p, monitor, null).disassemble(address(0x150), body)
                p.functionManager.createFunction("predicate_root", address(0x150), body, SourceType.USER_DEFINED)
            }
            action(p, p.functionManager.getFunctionAt(address(0x150)))
        } finally {
            p.release(owner)
        }
    }

    private fun preview(
        p: ProgramDB,
        f: Function,
    ) = PredicatedCalls.preview(p, f, PredicatedCallGraph.Limits.PRIMARY, monitor)

    @Test
    fun `one unknown root discovers both physical callees and matched symbolic frames`() =
        fixture { p, f ->
            assertNull(p.listing.getInstructionAt(p.addressFactory.getAddress("rom1::4000")))
            val proof = preview(p, f)
            assertTrue(proof.complete(), proof.frontier().toString())
            assertEquals(setOf("rom1::4000", "rom2::4000"), proof.invocations().map { it.target() }.toSet())
            assertEquals(2, proof.invocations().size)
            assertTrue(proof.invocations().all { it.returnCpu() == 0x161 && it.byteAContract() })
            val callNodes = proof.nodes().filter { it.transfer() == "CALL" }
            assertEquals(2, callNodes.size)
            assertEquals(1, callNodes.map { it.cpu() }.distinct().size)
            assertEquals(2, callNodes.map { it.id() }.distinct().size)
            for (call in callNodes) {
                assertEquals(listOf(-1, -2), call.frameAccesses().map { it.delta() })
                assertEquals(listOf(1, 0x61), call.frameAccesses().map { it.value() })
                assertEquals(setOf("CALL", "RESUME"), call.edges().map { it.kind() }.toSet())
            }
            assertEquals(2, proof.nodes().count { it.transfer() == "EXTERNAL_RETURN" })
            assertTrue(proof.discovery().candidates().any { it.address() == "rom1::4000" })
            assertNull(p.listing.getInstructionAt(p.addressFactory.getAddress("rom1::4000")))
            for (name in listOf("B", "F", "SP", "DE")) assertNull(p.programContext.getValue(p.getRegister(name), f.entryPoint, false))
        }

    @Test
    fun `qualified native calls retain physical Functions and actual pushes`() =
        fixture { p, f ->
            val proof = preview(p, f)
            assertTrue(proof.complete(), proof.frontier().toString())
            val root = PredicatedCalls.install(p, proof, monitor)
            val payload = PredicatedCalls.emit(p, root, 0x200000, monitor)
            val calls = payload.filter { it.opcode == PcodeOp.CALL }
            assertEquals(2, calls.size)
            assertEquals(
                setOf(1, 2),
                calls
                    .map { call ->
                        ProgramMapping
                            .staticToPhysical(
                                p,
                                p.addressFactory.getAddress(
                                    StockEntries
                                        .entries(p)
                                        .single {
                                            it.carrier() ==
                                                call.getInput(0).address.toString()
                                        }.source(),
                                ),
                            ).single()
                            .bank()
                    }.toSet(),
            )
            assertEquals(4, payload.count { it.opcode == PcodeOp.STORE })
            assertTrue(payload.any { it.opcode == PcodeOp.CBRANCH && it.getInput(0).isConstant })
            for (view in PredicatedCalls.views(p, root).filter { it.byteAContract() }) {
                val child = p.addressFactory.getAddress(view.entry())
                val function = p.functionManager.getFunctionAt(child)
                assertEquals(
                    "A",
                    p
                        .getRegister(
                            function
                                .getReturn()
                                .variableStorage.varnodes
                                .single(),
                        ).name,
                )
                assertFalse(function.isInline)
                assertEquals(1, PredicatedCalls.emit(p, child, 0x400000, monitor).count { it.opcode == PcodeOp.RETURN })
            }
            assertEquals(
                HexFormat.of().parseHex("3e31c9").toList(),
                ByteArray(3)
                    .also {
                        p.memory.getBytes(p.addressFactory.getAddress("rom1::4000"), it)
                    }.toList(),
            )
        }

    @Test
    fun `unresolved target and reduced work budget keep explicit frontiers`() {
        fixture(prepare = {
            it[0x15c] = 0
            it[0x15d] = 0xc0.toByte()
        }) { p, f ->
            val proof = preview(p, f)
            assertFalse(proof.complete())
            assertTrue(proof.frontier().any { it.reason().contains("Unresolved") })
            assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.install(p, proof, monitor) }
        }
        fixture { p, f ->
            val proof = PredicatedCalls.preview(p, f, PredicatedCallGraph.Limits(2, 8192, 1), monitor)
            assertFalse(proof.complete())
            assertTrue(proof.frontier().any { it.reason().contains("budget") })
        }
    }

    @Test
    fun `foreign omitted edges swapped physical nodes and frame forgery reject`() =
        fixture { p, f ->
            val proof = preview(p, f)
            assertTrue(proof.complete(), proof.frontier().toString())
            fixture { other, _ -> assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.install(other, proof, monitor) } }
            val root = PredicatedCalls.install(p, proof, monitor)
            val options = p.getOptions(PredicatedCalls.STOCK_OPTIONS)
            val saved = options.getString(root.toString(), "")
            for (kind in listOf("edge", "physical", "push", "identity")) {
                val record = JsonParser.parseString(saved).asJsonObject
                val nodes = record.getAsJsonObject("proof").getAsJsonArray("nodes")
                val call = nodes.map { it.asJsonObject }.first { it.get("transfer").asString == "CALL" }
                when (kind) {
                    "edge" -> call.getAsJsonArray("edges").remove(0)
                    "physical" -> call.addProperty("source", "rom2::4000")
                    "push" -> call.getAsJsonArray("frameAccesses").remove(0)
                    "identity" -> call.addProperty("id", call.get("cpu").asString)
                }
                p.withTransaction { options.setString(root.toString(), record.toString()) }
                assertThrows(IllegalArgumentException::class.java, { PredicatedCalls.emit(p, root, 0x200000, monitor) }, kind)
                p.withTransaction { options.setString(root.toString(), saved) }
            }
        }

    @Test
    fun `old graph envelope rejects without mutating stored authority`() =
        fixture { p, f ->
            val proof = preview(p, f)
            assertTrue(proof.complete(), proof.frontier().toString())
            val root = PredicatedCalls.install(p, proof, monitor)
            val options = p.getOptions(PredicatedCalls.STOCK_OPTIONS)
            val record = JsonParser.parseString(options.getString(root.toString(), "")).asJsonObject
            record.addProperty("version", "predicated-ordinary-calls-2")
            p.withTransaction { options.setString(root.toString(), record.toString()) }
            val revision = p.modificationNumber
            assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.emit(p, root, 0x200000, monitor) }
            assertEquals(revision, p.modificationNumber)
            assertEquals(record.toString(), options.getString(root.toString(), ""))
        }

    @Test
    fun `overlapping SP-derived register write invalidates symbolic frame authority`() {
        val original = HexFormat.of().parseHex("78e60120043e0118023e02ea0020cd0040ea60c0c9")
        val prefix = HexFormat.of().parseHex("f80026c0f9")
        fixture(prefix + original) { p, f ->
            val proof = preview(p, f)
            assertFalse(proof.complete())
            assertTrue(proof.frontier().any { it.reason().contains("Non-affine SP") }, proof.frontier().toString())
        }
    }

    @Test
    fun `existing listing still requires immutable executable physical fetch`() {
        for (kind in listOf("write", "volatile", "execute", "read")) {
            fixture { p, f ->
                p.withTransaction {
                    val block = p.memory.getBlock(address(0x150))
                    when (kind) {
                        "write" -> block.isWrite = true
                        "volatile" -> block.isVolatile = true
                        "execute" -> block.isExecute = false
                        "read" -> block.isRead = false
                    }
                }
                val proof = preview(p, f)
                assertFalse(proof.complete(), kind)
                assertTrue(proof.frontier().any { it.reason().contains("immutable") }, proof.frontier().toString())
            }
        }
    }

    @Test
    fun `graph admission binds discovery inventory rather than trusting a separately valid plan`() =
        fixture { p, f ->
            val proof = preview(p, f)
            assertTrue(proof.complete(), proof.frontier().toString())
            val extra =
                SoftwareCallInstructionDiscovery.begin(p, monitor).use { session ->
                    SoftwareCallInstructionDiscovery.instructionAt(
                        p,
                        p.addressFactory.getAddress("rom3::4000"),
                        "unrelated candidate",
                        monitor,
                    )
                    session.plan(monitor).candidates().single()
                }
            for (candidates in listOf(proof.discovery().candidates().drop(1), proof.discovery().candidates() + extra)) {
                val plan =
                    SoftwareCallInstructionDiscovery.Plan(
                        proof.discovery().version(),
                        proof.discovery().dependencies(),
                        candidates,
                        proof.discovery().reservations(),
                    )
                plan.requireCurrent(p, monitor)
                val json = ProgramMapping.JSON.toJsonTree(proof).asJsonObject
                json.add("discovery", ProgramMapping.JSON.toJsonTree(plan))
                val forged = ProgramMapping.JSON.fromJson(json, PredicatedCallGraph.Proof::class.java)
                val revision = p.modificationNumber
                val error = assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.install(p, forged, monitor) }
                assertTrue(error.message.orEmpty().contains("Discovery inventory"), error.message)
                assertEquals(revision, p.modificationNumber)
                assertNull(p.listing.getInstructionAt(p.addressFactory.getAddress("rom3::4000")))
            }
        }

    @Test
    fun `caller returned-flag control refuses byte-A-only native contract`() {
        fixture(HexFormat.of().parseHex("78e60120043e0118023e02ea0020cd004028023e44ea60c0c9")) { p, f ->
            val proof = preview(p, f)
            assertFalse(proof.complete())
            assertTrue(proof.frontier().any { it.reason().contains("live returned flags") }, proof.frontier().toString())
        }
    }

    @Test
    fun `effect-derived native inputs preserve unknown and caller-known register definitions`() {
        for ((body, input) in listOf("783cc9" to 3L, "3cc9" to 1L)) {
            fixture(prepare = {
                HexFormat.of().parseHex(body).copyInto(it, 0x4000)
            }) { p, f ->
                val proof = preview(p, f)
                assertTrue(proof.complete(), proof.frontier().toString())
                assertEquals(listOf(input), proof.invocations().first { it.target() == "rom1::4000" }.inputBytes())
                val root = PredicatedCalls.install(p, proof, monitor)
                val child = PredicatedCalls.views(p, root).first { it.inputBytes() == listOf(input) }
                val function = p.functionManager.getFunctionAt(p.addressFactory.getAddress(child.entry()))
                assertEquals(
                    input,
                    function.parameters
                        .single()
                        .variableStorage.varnodes
                        .single()
                        .offset,
                )
                assertTrue(PredicatedCalls.emit(p, root, 0x200000, monitor).isNotEmpty())
            }
        }
    }

    @Test
    fun `native frame and parameter contracts cannot change behind saved proof`() {
        for (kind in listOf("purge", "parameter")) {
            fixture { p, f ->
                val alias = PredicatedCalls.install(p, preview(p, f), monitor)
                val child = PredicatedCalls.views(p, alias).first { it.byteAContract() }
                val function = p.functionManager.getFunctionAt(p.addressFactory.getAddress(child.entry()))
                p.withTransaction {
                    if (kind == "purge") {
                        function.stackPurgeSize = 1
                    } else {
                        function.addParameter(
                            ghidra.program.model.listing
                                .ParameterImpl("unproved", ghidra.program.model.data.ByteDataType.dataType, p),
                            SourceType.USER_DEFINED,
                        )
                    }
                }
                assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.emit(p, alias, 0x200000, monitor) }
            }
        }
    }

    @Test
    fun `same physical callee has distinct current inputs frames and continuations`() {
        val code = HexFormat.of().parseHex("3e01ea0020cd0040ea61c004cd0040ea62c0c9")
        fixture(code, prepare = { HexFormat.of().parseHex("783cc9").copyInto(it, 0x4000) }) { p, f ->
            val proof = PredicatedCalls.preview(p, f, PredicatedCallGraph.Limits(256, 8192, 2), monitor)
            assertTrue(proof.complete(), proof.frontier().toString())
            assertEquals(2, proof.invocations().size)
            assertEquals(setOf("rom1::4000"), proof.invocations().map { it.target() }.toSet())
            assertEquals(setOf(0x158, 0x15f), proof.invocations().map { it.returnCpu() }.toSet())
            assertTrue(proof.invocations().all { it.inputBytes() == listOf(3L) })
            assertEquals(
                2,
                proof
                    .invocations()
                    .map { it.id() }
                    .distinct()
                    .size,
            )
            val alias = PredicatedCalls.install(p, proof, monitor)
            val children = PredicatedCalls.views(p, alias).filter { it.byteAContract() }
            assertEquals(2, children.map { it.entry() }.distinct().size)
            assertEquals(2, PredicatedCalls.emit(p, alias, 0x200000, monitor).count { it.opcode == PcodeOp.CALL })
            val options = p.getOptions(PredicatedCalls.STOCK_OPTIONS)
            val saved = options.getString(alias.toString(), "")
            val changed = JsonParser.parseString(saved).asJsonObject
            val calls = changed.getAsJsonObject("proof").getAsJsonArray("invocations")
            calls[0].asJsonObject.add("continuation", calls[1].asJsonObject.get("continuation"))
            p.withTransaction { options.setString(alias.toString(), changed.toString()) }
            assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.emit(p, alias, 0x200000, monitor) }
        }
    }

    @Test
    fun `serialized child view cannot turn off proven native contract checks`() =
        fixture { p, f ->
            val root = PredicatedCalls.install(p, preview(p, f), monitor)
            val options = p.getOptions(PredicatedCalls.STOCK_OPTIONS)
            val saved = options.getString(root.toString(), "")
            for (kind in listOf("contract", "duplicate")) {
                val record = JsonParser.parseString(saved).asJsonObject
                val views = record.getAsJsonArray("views")
                if (kind == "contract") {
                    views.first { it.asJsonObject.get("byteAContract").asBoolean }.asJsonObject.addProperty("byteAContract", false)
                } else {
                    views.add(views[1].deepCopy())
                }
                p.withTransaction { options.setString(root.toString(), record.toString()) }
                assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.emit(p, root, 0x200000, monitor) }
                p.withTransaction { options.setString(root.toString(), saved) }
            }
        }
}
