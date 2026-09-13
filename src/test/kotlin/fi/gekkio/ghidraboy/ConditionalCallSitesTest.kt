package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.FlowOverride
import ghidra.program.model.pcode.PcodeOp
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ConditionalCallSitesTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY

    private fun fixture(action: (ProgramDB, ConditionalCallSites.Request) -> Unit) {
        val owner = Any()
        val p = ProgramDB("conditional", language, language.defaultCompilerSpec, owner)
        try {
            val bytes = requireNotNull(javaClass.getResourceAsStream("/conditional/carry.gb")).readBytes()
            ByteArrayProvider(
                bytes,
            ).use { CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, monitor, MessageLog()) }
            val request =
                ConditionalCallSites.Request(
                    p.uniqueProgramID,
                    ProgramMapping.inspect(p).originalSha256(),
                    "rom1::42fd",
                    MapperKnowledge(1, 0, null, null, null, null, null, null),
                    0xffa1,
                    1,
                    emptyList(),
                    SymbolicMemory.Footprint(0xc110, 0xc7f8, -16, 1),
                    listOf(0, 1),
                    0,
                    true,
                    true,
                    "Explicit synchronous fixture premises",
                )
            action(p, request)
        } finally {
            p.release(owner)
        }
    }

    @Test
    fun derivesCallAndFlagSensitiveContinuationWithoutFunction() =
        fixture { p, request ->
            assertEquals(0, p.functionManager.functionCount)
            val revision = p.modificationNumber
            val proof = ConditionalCallSites.preview(p, request, monitor)
            assertTrue(proof.complete(), proof.frontier().toString())
            assertEquals(revision, p.modificationNumber)
            val target = proof.boundaries().single { it.kind() == "RET_DISPATCH" }
            assertEquals("rom2::5210", target.physical())
            assertEquals(listOf(0L), target.registers().single { it.offset() == 0L }.cover())
            val completed = proof.boundaries().single { it.kind() == "MATCHED_CALL_COMPLETION" }
            assertEquals("rom1::4301", completed.physical())
            assertEquals(0, completed.spDelta())
            val a = completed.registers().single { it.offset() == 1L }.origin()
            assertEquals(256, AbstractValues.relation(listOf(a)).reachable().size)
            assertEquals(2, proof.boundaries().count { it.kind() == "SOURCE_RETURN" })
            val entry = PredicatedCalls.install(p, proof, monitor)
            val emitted = PredicatedCalls.emit(p, entry, 0x200000, monitor)
            assertFalse(emitted.any { it.opcode == PcodeOp.CALL })
            assertTrue(emitted.any { it.opcode == PcodeOp.CBRANCH })
            assertEquals(2, emitted.count { it.opcode == PcodeOp.RETURN })
        }

    @Test
    fun rawSourceIgnoresSavedCallReturn() =
        fixture { p, request ->
            val at = ProgramMapping.staticAddress(p, request.site())
            p.withTransaction {
                Disassembler.getDisassembler(p, monitor, null).disassemble(at, AddressSet(at), false)
                p.listing.getInstructionAt(at).flowOverride = FlowOverride.CALL_RETURN
            }
            val proof = ConditionalCallSites.preview(p, request, monitor)
            assertTrue(proof.complete(), proof.frontier().toString())
            assertEquals(FlowOverride.CALL_RETURN, p.listing.getInstructionAt(at).flowOverride)
        }

    @Test
    fun overlapAndBadCalleeDoNotBecomeReturning() =
        fixture { p, request ->
            assertThrows(IllegalArgumentException::class.java) {
                SymbolicMemory.declare(p, listOf(0xe120), emptyList(), null, null, request.footprint())
            }
            p.withTransaction { p.memory.setBytes(ProgramMapping.staticAddress(p, "rom2::5210"), byteArrayOf(0x18, 0xfe.toByte())) }
            val proof = ConditionalCallSites.preview(p, request, monitor)
            assertFalse(proof.complete())
            assertTrue(proof.frontier().isNotEmpty())
            assertFalse(proof.boundaries().any { it.kind() == "MATCHED_CALL_COMPLETION" })
            assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.install(p, proof, monitor) }
        }

    @Test
    fun staleAndForeignProofCannotBeApplied() =
        fixture { p, request ->
            val proof = ConditionalCallSites.preview(p, request, monitor)
            p.withTransaction { p.memory.setByte(ProgramMapping.staticAddress(p, "rom2::5212"), 0x3d) }
            assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.install(p, proof, monitor) }
            fixture {
                foreign,
                _,
                ->
                assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.install(foreign, proof, monitor) }
            }
        }

    @Test
    fun independentDomainsHaveDistinctOwnedEntries() =
        fixture { p, request ->
            val first = PredicatedCalls.install(p, ConditionalCallSites.preview(p, request, monitor), monitor)
            val secondRequest =
                ConditionalCallSites.Request(
                    request.programId(),
                    request.imageSha256(),
                    request.site(),
                    request.mapper(),
                    request.shadowCpu(),
                    request.shadowValue(),
                    request.memoryInputs(),
                    SymbolicMemory.Footprint(0xc200, 0xc500, -16, 1),
                    request.incomingStackBytes(),
                    request.continuationSteps(),
                    true,
                    true,
                    request.provenance(),
                )
            val second = PredicatedCalls.install(p, ConditionalCallSites.preview(p, secondRequest, monitor), monitor)
            assertNotEquals(first, second)
            PredicatedCalls.refresh(p, first, ConditionalCallSites.preview(p, request, monitor), monitor)
            assertTrue(PredicatedCalls.emit(p, first, 0x200000, monitor).isNotEmpty())
            assertTrue(PredicatedCalls.emit(p, second, 0x200000, monitor).isNotEmpty())
        }

    @Test
    fun explicitPremisesAndAllConsumedMutationsAreSensitive() =
        fixture { p, request ->
            val encoded = ProgramMapping.JSON.toJson(request)
            for (field in listOf("shadowValue", "continuationSteps", "provenance", "bootInactive")) {
                val json =
                    com.google.gson.JsonParser
                        .parseString(encoded)
                        .asJsonObject
                json.remove(field)
                assertThrows(RuntimeException::class.java) { ConditionalCallSites.readRequest(json.toString()) }
            }
            for (high in listOf<Int?>(null, 1)) {
                assertThrows(IllegalArgumentException::class.java) {
                    ConditionalCallSites.Request(
                        request.programId(),
                        request.imageSha256(),
                        request.site(),
                        MapperKnowledge(1, high, null, null, null, null, null, null),
                        0xffa1,
                        1,
                        emptyList(),
                        request.footprint(),
                        listOf(0, 1),
                        0,
                        true,
                        true,
                        request.provenance(),
                    )
                }
            }
            assertThrows(IllegalArgumentException::class.java) {
                ConditionalCallSites.Request(
                    request.programId(),
                    request.imageSha256(),
                    request.site(),
                    request.mapper(),
                    0xffa1,
                    2,
                    emptyList(),
                    request.footprint(),
                    listOf(0, 1),
                    0,
                    true,
                    true,
                    request.provenance(),
                )
            }
            val wrong =
                ConditionalCallSites.Request(
                    request.programId(),
                    request.imageSha256(),
                    "rom2::42fd",
                    request.mapper(),
                    0xffa1,
                    1,
                    emptyList(),
                    request.footprint(),
                    listOf(0, 1),
                    0,
                    true,
                    true,
                    request.provenance(),
                )
            assertThrows(IllegalArgumentException::class.java) { ConditionalCallSites.preview(p, wrong, monitor) }
            val proof = ConditionalCallSites.preview(p, request, monitor)
            for (text in listOf("0030", "0800", "rom1::42fe", "rom2::5212")) {
                val at = ProgramMapping.staticAddress(p, text)
                val old = p.memory.getByte(at)
                p.withTransaction { p.memory.setByte(at, (old.toInt() xor 1).toByte()) }
                assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.install(p, proof, monitor) }
                p.withTransaction { p.memory.setByte(at, old) }
            }
        }

    @Test
    fun cleanupAndAdjustedReturnCorruptionHaveSpecificFrontiers() {
        fixture { p, request ->
            p.withTransaction {
                p.memory.setBytes(
                    ProgramMapping.staticAddress(p, "rom2::5210"),
                    java.util.HexFormat
                        .of()
                        .parseHex("f8003644c9"),
                )
            }
            val proof = ConditionalCallSites.preview(p, request, monitor)
            assertFalse(proof.complete())
            assertTrue(proof.frontier().any { it.reason().contains("Corrupt cleanup return") }, proof.frontier().toString())
        }
        fixture { p, request ->
            p.withTransaction { p.memory.setByte(address(0x810), 4) }
            val proof = ConditionalCallSites.preview(p, request, monitor)
            assertFalse(proof.complete())
            assertTrue(proof.frontier().any { it.reason().contains("Adjusted return") }, proof.frontier().toString())
        }
    }

    @Test
    fun cancellationAfterOwnedWriteAndLaterEditPreservation() =
        fixture { p, request ->
            val proof = ConditionalCallSites.preview(p, request, monitor)
            val blocks = p.memory.blocks.map { it.start.toString() }
            var observed = false
            val cancel =
                object : ghidra.util.task.TaskMonitorAdapter() {
                    override fun checkCancelled() {
                        if (p.memory.blocks.any { it.name.startsWith("gb_ordinary_pred_") }) {
                            observed = true
                            throw ghidra.util.exception.CancelledException()
                        }
                    }
                }
            assertThrows(ghidra.util.exception.CancelledException::class.java) { PredicatedCalls.install(p, proof, cancel) }
            assertTrue(observed)
            assertEquals(blocks, p.memory.blocks.map { it.start.toString() })
            assertEquals(0, p.functionManager.functionCount)
            val entry = PredicatedCalls.install(p, ConditionalCallSites.preview(p, request, monitor), monitor)
            p.withTransaction { p.functionManager.getFunctionAt(entry).comment = "Later user explanation" }
            val diagnostics = PredicatedCalls.remove(p, entry, monitor)
            assertTrue(diagnostics.any { it.contains("Preserved") }, diagnostics.toString())
            assertEquals("Later user explanation", p.functionManager.getFunctionAt(entry).comment)
            assertFalse(PredicatedCalls.registered(p, entry))
        }

    @Test
    fun hramAdoptionIsBoundedAndRollsBackAfterRealWrite() =
        fixture { p, _ ->
            val map = p.usrPropertyManager.getStringPropertyMap("GhidraBoy.Physical")
            p.withTransaction { map.remove(address(0xff80)) }
            var observed = false
            val cancel =
                object : ghidra.util.task.TaskMonitorAdapter() {
                    override fun checkCancelled() {
                        if (map.hasProperty(address(0xff80))) {
                            observed = true
                            throw ghidra.util.exception.CancelledException()
                        }
                    }
                }
            assertThrows(ghidra.util.exception.CancelledException::class.java) {
                ProgramMapping.identifyRam(p, address(0xff80), 0x7f, "HRAM", 0, 0, cancel)
            }
            assertTrue(observed)
            assertFalse(map.hasProperty(address(0xff80)))
            ProgramMapping.identifyRam(p, address(0xff80), 0x7f, "HRAM", 0, 0, monitor)
            assertEquals(listOf(MapperState.Physical("HRAM", 0, 126)), ProgramMapping.staticToPhysical(p, address(0xfffe)))
            assertTrue(ProgramMapping.staticToPhysical(p, address(0xffff)).none { it.region() == "HRAM" })
            assertThrows(
                IllegalArgumentException::class.java,
            ) { ProgramMapping.identifyRam(p, address(0xff80), 0x80, "HRAM", 0, 0, monitor) }
            assertThrows(IllegalArgumentException::class.java) { ProgramMapping.identifyRam(p, address(0xff81), 1, "HRAM", 0, 0, monitor) }
        }

    @Test
    fun incompatibleAndSubstitutedBoundariesRefuseAndUnknownReadsStayUnproved() {
        fixture { p, request ->
            val proof = ConditionalCallSites.preview(p, request, monitor)
            val encoded = ProgramMapping.JSON.toJsonTree(proof).asJsonObject
            encoded.addProperty("version", "conditional-call-site-2")
            assertThrows(IllegalArgumentException::class.java) {
                PredicatedCalls.install(p, PredicatedCalls.readProof(encoded.toString()), monitor)
            }
            encoded.addProperty("version", ConditionalCallSites.VERSION)
            val boundary =
                encoded
                    .getAsJsonArray(
                        "boundaries",
                    ).first { it.asJsonObject.get("kind").asString == "MATCHED_CALL_COMPLETION" }
                    .asJsonObject
            boundary.addProperty("physical", "rom2::4301")
            assertThrows(IllegalArgumentException::class.java) {
                PredicatedCalls.install(p, PredicatedCalls.readProof(encoded.toString()), monitor)
            }
        }
        fixture { p, request ->
            p.withTransaction {
                p.memory.setBytes(
                    ProgramMapping.staticAddress(p, "rom2::5210"),
                    byteArrayOf(0xfa.toByte(), 0x30, 0xca.toByte(), 0xc9.toByte()),
                )
            }
            val proof = ConditionalCallSites.preview(p, request, monitor)
            assertFalse(proof.complete())
            assertTrue(
                proof.frontier().any {
                    it.reason().contains("memory", ignoreCase = true) ||
                        it.reason().contains("input", ignoreCase = true)
                },
                proof.frontier().toString(),
            )
        }
    }

    @Test
    fun committedSourceChangeAtInstallBoundaryCannotBecomeCurrentAuthority() =
        fixture { p, request ->
            val proof = ConditionalCallSites.preview(p, request, monitor)
            val before = p.memory.blocks.map { it.name }
            var changed = false
            val proxy =
                java.lang.reflect.Proxy.newProxyInstance(
                    javaClass.classLoader,
                    arrayOf(ghidra.program.model.listing.Program::class.java),
                ) { _, method, args ->
                    if (!changed && method.name == "startTransaction") {
                        changed = true
                        p.withTransaction { p.memory.setByte(ProgramMapping.staticAddress(p, "rom2::5212"), 0x3d) }
                    }
                    try {
                        method.invoke(p, *(args ?: emptyArray()))
                    } catch (e: java.lang.reflect.InvocationTargetException) {
                        throw e.cause!!
                    }
                } as ghidra.program.model.listing.Program
            assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.install(proxy, proof, monitor) }
            assertTrue(changed)
            assertEquals(0x3d.toByte(), p.memory.getByte(ProgramMapping.staticAddress(p, "rom2::5212")))
            assertEquals(before, p.memory.blocks.map { it.name })
        }

    @Test
    fun explanationNeverPublishesAnUnvalidatedSecondRegistration() =
        fixture { p, request ->
            val entry = PredicatedCalls.install(p, ConditionalCallSites.preview(p, request, monitor), monitor)
            var changed = false
            val proxy =
                java.lang.reflect.Proxy.newProxyInstance(
                    javaClass.classLoader,
                    arrayOf(ghidra.program.model.listing.Program::class.java),
                ) { _, method, args ->
                    if (!changed && method.name == "getOptions" &&
                        Thread.currentThread().stackTrace.any { it.methodName == "registeredProof" }
                    ) {
                        changed = true
                        p.withTransaction {
                            val options = p.getOptions(PredicatedCalls.STOCK_OPTIONS)
                            val record =
                                com.google.gson.JsonParser
                                    .parseString(options.getString(entry.toString(), null))
                                    .asJsonObject
                            record
                                .getAsJsonObject("proof")
                                .getAsJsonArray("boundaries")
                                .first {
                                    it.asJsonObject.get("kind").asString == "MATCHED_CALL_COMPLETION"
                                }.asJsonObject
                                .addProperty("physical", "rom2::4301")
                            options.setString(entry.toString(), record.toString())
                        }
                    }
                    try {
                        method.invoke(p, *(args ?: emptyArray()))
                    } catch (e: java.lang.reflect.InvocationTargetException) {
                        throw e.cause!!
                    }
                } as ghidra.program.model.listing.Program
            try {
                val boundaries = ConditionalCallSites.explain(proxy, entry, monitor)
                assertEquals("rom1::4301", boundaries.single { it.kind() == "MATCHED_CALL_COMPLETION" }.physical())
            } catch (e: IllegalArgumentException) {
                assertTrue(changed)
            }
        }

    @Test
    fun committedLaterAnnotationAtRefreshBoundaryIsPreserved() =
        fixture { p, request ->
            val entry = PredicatedCalls.install(p, ConditionalCallSites.preview(p, request, monitor), monitor)
            val proof = ConditionalCallSites.preview(p, request, monitor)
            val saved = p.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(entry.toString(), null)
            var changed = false
            val proxy =
                java.lang.reflect.Proxy.newProxyInstance(
                    javaClass.classLoader,
                    arrayOf(ghidra.program.model.listing.Program::class.java),
                ) { _, method, args ->
                    if (!changed && method.name == "startTransaction") {
                        changed = true
                        p.withTransaction { p.functionManager.getFunctionAt(entry).comment = "Later user annotation" }
                    }
                    try {
                        method.invoke(p, *(args ?: emptyArray()))
                    } catch (e: java.lang.reflect.InvocationTargetException) {
                        throw e.cause!!
                    }
                } as ghidra.program.model.listing.Program
            assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.refresh(proxy, entry, proof, monitor) }
            assertTrue(changed)
            assertEquals("Later user annotation", p.functionManager.getFunctionAt(entry).comment)
            assertEquals(saved, p.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(entry.toString(), null))
        }

    @Test
    fun operationSnapshotRejectsChangedAndForeignProgramsAndUndoRedoUsesDurableAuthority() =
        fixture { p, request ->
            val entry = PredicatedCalls.install(p, ConditionalCallSites.preview(p, request, monitor), monitor)
            val snapshot = ConditionalCallSites.explanation(p, entry, monitor)
            snapshot.requireCurrent(p)
            fixture { other, _ ->
                assertThrows(IllegalArgumentException::class.java) { snapshot.requireCurrent(other) }
            }
            p.undo()
            assertFalse(PredicatedCalls.registered(p, entry))
            assertThrows(IllegalArgumentException::class.java) { snapshot.requireCurrent(p) }
            p.redo()
            assertTrue(PredicatedCalls.registered(p, entry))
            assertTrue(PredicatedCalls.emit(p, entry, 0x200000, monitor).isNotEmpty())
            assertThrows(IllegalArgumentException::class.java) { snapshot.requireCurrent(p) }
        }

    @Test
    fun fullAffineFrameAndPhysicalAliasEndpointsAreValidatedIndependently() =
        fixture { p, request ->
            for (cpu in listOf(0xc000, 0xcfff, 0xe000, 0xefff, 0xff80, 0xfffe)) {
                val declared = SymbolicMemory.declare(p, listOf(cpu), emptyList(), null, null, request.footprint())
                SymbolicMemory.validate(p, declared)
            }
            for (cpu in listOf(0xd000, 0xf000, 0xfdff, 0xffff, 0xc100, 0xe100, 0xc7f9)) {
                assertThrows(IllegalArgumentException::class.java) {
                    SymbolicMemory.declare(p, listOf(cpu), emptyList(), null, null, request.footprint())
                }
            }
            for (delta in -16..1) ConditionalCallSites.frame(p, request.footprint(), delta, monitor)
            assertThrows(IllegalArgumentException::class.java) { ConditionalCallSites.frame(p, request.footprint(), -17, monitor) }
            assertThrows(IllegalArgumentException::class.java) { ConditionalCallSites.frame(p, request.footprint(), 2, monitor) }
        }
}
