package fi.gekkio.ghidraboy

import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.pcode.exec.BytesPcodeArithmetic
import ghidra.pcode.exec.BytesPcodeExecutorState
import ghidra.pcode.exec.PcodeExecutor
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason
import ghidra.pcode.exec.PcodeProgram
import ghidra.pcode.exec.PcodeStateCallbacks
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayload
import ghidra.program.model.listing.FlowOverride
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

/** Independent counterexamples to the retained SA-01 production handoff. */
class SoftwareCallAdversarialTest : IntegrationTest() {
    private fun fixture(
        callCpu: Int = 0x200,
        callee: String = "c9",
        prepareHelper: Boolean = true,
        prepareCallee: Boolean = true,
        action: (ProgramDB, SoftwareCallValidation.Configuration) -> Unit,
    ) {
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val targetBytes = HexFormat.of().parseHex(callee)
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        HexFormat.of().parseHex(template.bodyHex()).copyInto(bytes, 0x28)
        bytes[callCpu] = 0xef.toByte()
        bytes[callCpu + 1] = 0xc9.toByte()
        targetBytes.copyInto(bytes, 0x8100)
        HexFormat.of().parseHex("3c37c9").copyInto(bytes, 0x8120)
        val consumer = Any()
        val p = ProgramDB("SA-01 adversarial", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                if (prepareHelper) {
                    d.disassemble(address(0x28), AddressSet(address(0x28), address(0x28 + template.bodyHex().length / 2 - 1L)))
                }
                d.disassemble(address(callCpu.toLong()), AddressSet(address(callCpu.toLong()), address(callCpu + 1L)))
                if (prepareCallee) {
                    val target = ProgramMapping.fileToStatic(p, 0x8100).single()
                    d.disassemble(target, AddressSet(target, target.add(targetBytes.size - 1L)))
                    d.disassemble(target.add(0x20), AddressSet(target.add(0x20), target.add(0x22)))
                }
            }
            action(
                p,
                SoftwareCallValidation.Configuration(
                    callCpu,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 0, 0, 0x4100),
                    MapperState.reset(),
                ),
            )
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `initial wrong CALL override is rejected before ownership can bless it`() =
        fixture { p, config ->
            p.withTransaction {
                val ref =
                    p.referenceManager.addMemoryReference(
                        address(0x200),
                        address(0x38),
                        RefType.CALL_OVERRIDE_UNCONDITIONAL,
                        SourceType.USER_DEFINED,
                        -1,
                    )
                p.referenceManager.setPrimary(ref, true)
            }
            val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
            assertNull(p.functionManager.getFunctionAt(address(0x28)))
            assertTrue(p.referenceManager.getReferencesFrom(address(0x200)).any { it.toAddress == address(0x38) && it.isPrimary })
        }

    @Test
    fun `initial wrong primary ordinary CALL reference is rejected without silent normalization`() =
        fixture { p, config ->
            p.withTransaction {
                val ref =
                    p.referenceManager.addMemoryReference(
                        address(0x200),
                        address(0x38),
                        RefType.UNCONDITIONAL_CALL,
                        SourceType.IMPORTED,
                        0,
                    )
                p.referenceManager.setPrimary(ref, true)
            }
            val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
        }

    @Test
    fun `legacy far-call supplemental endpoint cannot silently become a helper endpoint`() =
        fixture { p, _ ->
            val template = SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x28, 3, null)
            p.withTransaction {
                p.listing.clearCodeUnits(address(0x28), address(0x60), false)
                p.listing.clearCodeUnits(address(0x200), address(0x204), false)
                p.memory.setBytes(address(0x28), HexFormat.of().parseHex(template.bodyHex()))
                p.memory.setBytes(address(0x200), HexFormat.of().parseHex("ef020041c9"))
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                d.disassemble(address(0x28), AddressSet(address(0x28), address(0x28 + template.bodyHex().length / 2 - 1L)))
                d.disassemble(address(0x200), AddressSet(address(0x200)))
                d.disassemble(address(0x204), AddressSet(address(0x204)))
            }
            val legacy = FarCallConvention("0028", FarCallConvention.SUPPORTED_BODY, listOf("0200"), 0xc100)
            legacy.apply(p, legacy.previewReviewed(p, TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            val target = ProgramMapping.fileToStatic(p, 0x8100).single()
            assertTrue(p.referenceManager.getReferencesFrom(address(0x200)).any { it.toAddress == target && it.referenceType.isCall })
            val config =
                SoftwareCallValidation.Configuration(
                    0x200,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(0, 0, 0, 0, 0),
                    MapperState.reset(),
                )
            val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
            assertTrue(p.getOptions(ProgramMapping.OPTIONS).contains("farCallConvention"))
        }

    @Test
    fun `same-space first continuation still needs banked view for later window crossing`() =
        fixture(callCpu = 0x3ffd) { p, config ->
            p.withTransaction {
                p.listing.clearCodeUnits(address(0x3ffe), address(0x3fff), false)
                p.memory.setBytes(address(0x3ffe), byteArrayOf(0, 0))
                val selected = ProgramMapping.fileToStatic(p, 0x8000).single()
                p.memory.setByte(selected, 0xc9.toByte())
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                d.disassemble(address(0x3ffe), AddressSet(address(0x3ffe), address(0x3fff)))
                d.disassemble(selected, AddressSet(selected))
                p.functionManager.createFunction(
                    "window_caller",
                    address(0x3ffd),
                    AddressSet(address(0x3ffd), address(0x3fff)),
                    SourceType.USER_DEFINED,
                )
                val target = ProgramMapping.fileToStatic(p, 0x8100).single()
                p.functionManager.createFunction("window_target", target, AddressSet(target), SourceType.USER_DEFINED)
            }
            val validated = SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY)
            val effects = SoftwareCallEffects.derive(p, validated.frame(), TaskMonitor.DUMMY, listOf(config))
            assertTrue(effects.nativeCompatible(), effects.nativeIncompatibilities().toString())
            val returned = effects.paths().single().returned()
            assertEquals(0x3ffe, returned.cpu())
            val segments = SoftwareCallExecutionView.continuationSegments(p, returned, TaskMonitor.DUMMY)
            assertTrue(segments.any { ProgramMapping.staticAddress(p, it.source()).addressSpace != address(0x3ffd).addressSpace })
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            assertEquals(1, review.executionViews().size, "Scanning only first continuation misses physical bank2 fetch at CPU 4000")
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val view =
                p.addressFactory.getAddressSpace(
                    review
                        .executionViews()
                        .values
                        .single()
                        .name(),
                )
            assertEquals(MapperState.Physical("ROM", 2, 0), ProgramMapping.staticToPhysical(p, view.getAddress(0x4000)).single())
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                for (entry in listOf(address(0x3ffd), view.getAddress(0x3ffd))) {
                    val result = decompiler.decompileFunction(p.functionManager.getFunctionAt(entry), 30, TaskMonitor.DUMMY)
                    assertTrue(result.decompileCompleted(), result.errorMessage)
                    assertTrue(
                        result.highFunction.pcodeOps
                            .asSequence()
                            .any { it.opcode == PcodeOp.RETURN },
                    )
                    assertTrue(result.decompiledFunction.c.contains("window_target("), result.decompiledFunction.c)
                }
            } finally {
                decompiler.dispose()
            }
            val entries = listOf(address(0x3ffd), view.getAddress(0x3ffd))
            val payload = p.compilerSpec.pcodeInjectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, SoftwareCallInjection.NAME)
            for (edited in entries) {
                for (entry in entries) assertNotNull(SoftwareCallRegistry.resolve(p, entry))
                val reference =
                    p.withTransaction {
                        p.referenceManager.addMemoryReference(
                            edited,
                            address(0x38),
                            RefType.CALL_OVERRIDE_UNCONDITIONAL,
                            SourceType.USER_DEFINED,
                            -1,
                        )
                    }
                for (entry in entries) {
                    assertThrows(IllegalArgumentException::class.java) { SoftwareCallRegistry.resolve(p, entry) }
                    val context = InjectContext()
                    context.baseAddr = entry
                    context.nextAddr = entry
                    context.callAddr = address(0x28)
                    assertThrows(IllegalArgumentException::class.java) { payload.getPcode(p, context) }
                }
                p.withTransaction { p.referenceManager.delete(reference) }
            }
            for (entry in entries) assertNotNull(SoftwareCallRegistry.resolve(p, entry))
        }

    @Test
    fun `matched ordinary nested RET permits precise reversible false noReturn and CALL_RETURN repair`() =
        fixture(callee = "afcd2041c9") { p, config ->
            val target = ProgramMapping.fileToStatic(p, 0x8100).single()
            val nested = target.add(0x20)
            p.withTransaction {
                p.functionManager.createFunction("outer_target", target, AddressSet(target, target.add(4)), SourceType.USER_DEFINED)
                p.functionManager
                    .createFunction(
                        "nested_returning",
                        nested,
                        AddressSet(nested, nested.add(2)),
                        SourceType.IMPORTED,
                    ).setNoReturn(true)
                p.listing.getInstructionAt(target.add(1)).flowOverride = FlowOverride.CALL_RETURN
            }
            val validated = SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY)
            val raw = SoftwareCallEffects.derive(p, validated.frame(), TaskMonitor.DUMMY, listOf(config))
            assertTrue(raw.complete(), raw.unresolved().toString())
            assertTrue(raw.returningNativeFunctions().contains(nested.toString()))
            assertEquals(
                1,
                raw
                    .paths()
                    .single()
                    .returned()
                    .registers()
                    .a(),
            )
            assertEquals(
                0x10,
                raw
                    .paths()
                    .single()
                    .returned()
                    .registers()
                    .f(),
            )
            assertEquals(
                0xc100,
                raw
                    .paths()
                    .single()
                    .returned()
                    .sp(),
            )
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            val planned = review.nestedRepairs().single()
            assertEquals(target.add(1).toString(), planned.site())
            assertEquals(nested.toString(), planned.target())
            assertEquals("CALL_RETURN", planned.originalFlow())
            assertEquals("NONE", planned.appliedFlow())
            assertTrue(planned.originalNoReturn())
            assertNull(planned.originalFixup())
            assertEquals(SoftwareCallMayReturnInjection.NAME, planned.appliedFixup())
            assertTrue(planned.witness().contains("MATCHED_ARCHITECTURAL_RET"))
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            assertFalse(p.functionManager.getFunctionAt(nested).hasNoReturn())
            assertEquals(FlowOverride.NONE, p.listing.getInstructionAt(target.add(1)).flowOverride)
            val installed = SoftwareCallRegistry.resolve(p, address(0x200))
            assertNotNull(installed)
            val installedEffects = SoftwareCallRegistry.effects(p, installed, TaskMonitor.DUMMY)
            assertTrue(
                installedEffects.nativeCompatible(),
                installedEffects.nativeIncompatibilities().toString() + installedEffects.unresolved(),
            )
            assertTrue(
                installedEffects.returningNativeFunctions().contains(nested.toString()),
                installedEffects.returningNativeFunctions().toString(),
            )
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                val result = decompiler.decompileFunction(p.functionManager.getFunctionAt(target), 30, TaskMonitor.DUMMY)
                assertTrue(result.decompileCompleted(), result.errorMessage)
                assertTrue(result.decompiledFunction.c.contains("nested_returning("), result.decompiledFunction.c)
                assertTrue(
                    result.highFunction.pcodeOps
                        .asSequence()
                        .any { it.opcode == PcodeOp.RETURN },
                )
            } finally {
                decompiler.dispose()
            }
            AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            assertTrue(p.functionManager.getFunctionAt(nested).hasNoReturn())
            assertEquals(FlowOverride.CALL_RETURN, p.listing.getInstructionAt(target.add(1)).flowOverride)
        }

    @Test
    fun `nested returning witness never excuses an unrelated BRANCH override`() =
        fixture(callee = "afcd2041c9") { p, config ->
            val target = ProgramMapping.fileToStatic(p, 0x8100).single()
            p.withTransaction { p.listing.getInstructionAt(target.add(1)).flowOverride = FlowOverride.BRANCH }
            val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
        }

    @Test
    fun `unprepared helper requires explicit rooted discovery before executable validation`() =
        fixture(prepareHelper = false) { p, config ->
            assertNull(p.listing.getInstructionAt(address(0x28)))
            val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            val failure =
                assertThrows(IllegalArgumentException::class.java) { SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY) }
            assertTrue(failure.message.orEmpty().contains("instruction", ignoreCase = true), failure.message)
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            assertTrue(review.instructionDiscovery().candidates().any { it.address() == address(0x28).toString() })
            assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
            assertNull(p.listing.getInstructionAt(address(0x28)))
        }

    @Test
    fun `unprepared callee requires explicit rooted discovery before executable validation`() =
        fixture(prepareCallee = false) { p, config ->
            val target = ProgramMapping.fileToStatic(p, 0x8100).single()
            assertNull(p.listing.getInstructionAt(target))
            val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            val raw = SoftwareCallEffects.derive(p, SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY).frame(), TaskMonitor.DUMMY)
            assertTrue(raw.unresolved().any { it.contains("Missing architectural callee boundary") })
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            assertTrue(review.instructionDiscovery().candidates().any { it.address() == target.toString() })
            assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
            assertNull(p.listing.getInstructionAt(target))
        }

    @Test
    fun `continuation fetch permissions are proof premises rather than only later drift checks`() =
        fixture(callCpu = 0x3ffd) { p, config ->
            p.withTransaction {
                // Isolate the continuation permissions; helper, caller and callee remain immutable.
                p.memory.split(p.memory.getBlock(address(0x3ffe)), address(0x3ffe))
                p.memory.getBlock(address(0x3ffe)).isWrite = true
            }
            val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
            val failure =
                assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            assertTrue(failure.message.orEmpty().contains("Returning continuation boundary conflicts"), failure.message)
            assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
        }

    @Test
    fun `later continuation fetches and instruction operand bytes also require immutable ROM`() {
        for (tail in listOf("00c9", "3e55")) {
            fixture(callCpu = 0x3ffd) { p, config ->
                p.withTransaction {
                    p.listing.clearCodeUnits(address(0x3ffe), address(0x3fff), false)
                    p.memory.setBytes(address(0x3ffe), HexFormat.of().parseHex(tail))
                    Disassembler
                        .getDisassembler(p, TaskMonitor.DUMMY, null)
                        .disassemble(address(0x3ffe), AddressSet(address(0x3ffe), address(0x3fff)))
                    p.memory.split(p.memory.getBlock(address(0x3fff)), address(0x3fff))
                    p.memory.getBlock(address(0x3fff)).isWrite = true
                }
                val validated = SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY)
                val effects = SoftwareCallEffects.derive(p, validated.frame(), TaskMonitor.DUMMY, listOf(config))
                assertTrue(effects.nativeCompatible(), effects.nativeIncompatibilities().toString())
                val before = FarCallEvidence.capture(p, TaskMonitor.DUMMY)
                val failure =
                    assertThrows(
                        IllegalArgumentException::class.java,
                    ) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
                assertTrue(failure.message.orEmpty().contains("immutable", ignoreCase = true), failure.message)
                assertEquals(before, FarCallEvidence.capture(p, TaskMonitor.DUMMY))
            }
        }
    }

    @Test
    fun `canonical local branches and conditional RET preserve raw flags registers and live return words`() {
        // JR NZ has both outcomes; RET C has both outcomes. Expected effects come from these
        // explicit instructions and are also compared with separately executed raw architectural p-code.
        for ((callee, expectedA) in listOf("af37c9" to 0, "3e0137c9" to 0x66, "afc9" to 0x55)) {
            fixture(callCpu = 0x3ffd, callee = callee) { p, config ->
                val selected = ProgramMapping.fileToStatic(p, 0x8000).single()
                val target = ProgramMapping.fileToStatic(p, 0x8100).single()
                p.withTransaction {
                    p.listing.clearCodeUnits(address(0x3ffe), address(0x3fff), false)
                    p.memory.setBytes(address(0x3ffe), HexFormat.of().parseHex("2004"))
                    p.memory.setBytes(selected, HexFormat.of().parseHex("d83e55c93e66c9"))
                    val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                    d.disassemble(address(0x3ffe), AddressSet(address(0x3ffe), address(0x3fff)))
                    d.disassemble(selected, AddressSet(selected, selected.add(6)))
                    d.disassemble(selected.add(4), AddressSet(selected.add(4), selected.add(6)))
                    p.functionManager.createFunction(
                        "conditional_caller",
                        address(0x3ffd),
                        AddressSet(address(0x3ffd), address(0x3fff)),
                        SourceType.USER_DEFINED,
                    )
                    p.functionManager.createFunction(
                        "conditional_target",
                        target,
                        AddressSet(target, target.add(callee.length / 2 - 1L)),
                        SourceType.USER_DEFINED,
                    )
                }
                val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
                assertEquals(1, review.executionViews().size)
                SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
                val payload = p.compilerSpec.pcodeInjectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, SoftwareCallInjection.NAME)
                val context = InjectContext()
                context.baseAddr = address(0x3ffd)
                context.nextAddr = context.baseAddr
                context.callAddr = address(0x28)
                val injected = payload.getPcode(p, context)
                val callIndex = injected.indexOfFirst { it.opcode == PcodeOp.CALL }
                assertEquals(target, injected[callIndex].getInput(0).address)
                assertTrue(injected.any { it.opcode == PcodeOp.CBRANCH && it.getInput(0).isConstant })
                val rawCaller = PcodeProgram.fromInstruction(p.listing.getInstructionAt(address(0x3ffd)), false)

                fun execute(
                    lowered: Boolean,
                    returnWord: Int,
                ): Map<String, Int> {
                    val arithmetic = BytesPcodeArithmetic.forLanguage(language)
                    val state = BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE)
                    val executor = PcodeExecutor(language as SleighLanguage, arithmetic, state, Reason.EXECUTE_READ)
                    val bus = SoftwareCallInjectionInstalledTest.SelectorLibrary()
                    for ((name, value) in mapOf("A" to 2, "F" to 0, "BC" to 0, "DE" to 0, "HL" to 0x4100, "SP" to 0xc100, "PC" to 0x3ffd)) {
                        val register = language.getRegister(name)
                        state.setVar(register, arithmetic.fromConst(value, register.minimumByteSize))
                    }
                    state.setVar(address(0xc100), 2, true, arithmetic.fromConst(returnWord, 2))

                    fun raw(at: ghidra.program.model.address.Address) {
                        executor.execute(PcodeProgram.fromInstruction(p.listing.getInstructionAt(at), false), bus)
                    }

                    fun value(name: String): Int =
                        state
                            .getVar(language.getRegister(name), Reason.INSPECT)
                            .foldIndexed(0) { index, accumulated, byte -> accumulated or ((byte.toInt() and 255) shl (index * 8)) }
                    executor.execute(rawCaller, bus)
                    if (lowered) {
                        executor.execute(PcodeProgram(rawCaller, injected.take(callIndex + 1)), bus)
                    } else {
                        var helper = address(0x28)
                        while (helper.offset < 0x28 + config.template().bodyHex().length / 2) {
                            raw(helper)
                            helper =
                                helper.add(
                                    p.listing
                                        .getInstructionAt(helper)
                                        .length
                                        .toLong(),
                                )
                        }
                    }
                    assertEquals(0xc0fe, value("SP"))
                    assertEquals(0x4100, value("PC"))
                    assertEquals(listOf(0xfe, 0x3f), state.getVar(address(0xc0fe), 2, true, Reason.INSPECT).map { it.toInt() and 255 })
                    var at = target
                    while (at.offset < target.offset + callee.length / 2) {
                        raw(at)
                        at =
                            at.add(
                                p.listing
                                    .getInstructionAt(at)
                                    .length
                                    .toLong(),
                            )
                    }
                    assertEquals(0xc100, value("SP"))
                    assertEquals(0x3ffe, value("PC"))
                    if (lowered) {
                        executor.execute(PcodeProgram(rawCaller, injected.drop(callIndex + 1)), bus)
                    } else {
                        val flags = value("F")
                        raw(address(0x3ffe))
                        if (flags and 0x80 == 0) {
                            raw(selected.add(4))
                            raw(selected.add(6))
                        } else {
                            raw(selected)
                            if (flags and 0x10 == 0) {
                                raw(selected.add(1))
                                raw(selected.add(3))
                            }
                        }
                    }
                    assertEquals(expectedA, value("A"))
                    assertEquals(0xc102, value("SP"))
                    assertEquals(returnWord, value("PC"))
                    assertEquals(listOf(0x2000L to 2L), bus.writes)
                    return listOf("A", "F", "BC", "DE", "HL", "SP", "PC").associateWith { value(it) }
                }
                for (returnWord in listOf(0x3456, 0x6789)) assertEquals(execute(false, returnWord), execute(true, returnWord))
                val view =
                    p.addressFactory.getAddressSpace(
                        review
                            .executionViews()
                            .values
                            .single()
                            .name(),
                    )
                val decompiler = DecompInterface()
                try {
                    assertTrue(decompiler.openProgram(p))
                    for (entry in listOf(address(0x3ffd), view.getAddress(0x3ffd))) {
                        val result = decompiler.decompileFunction(p.functionManager.getFunctionAt(entry), 30, TaskMonitor.DUMMY)
                        assertTrue(result.decompileCompleted(), result.errorMessage)
                        assertTrue(
                            result.highFunction.pcodeOps
                                .asSequence()
                                .any { it.opcode == PcodeOp.RETURN },
                        )
                        assertTrue(result.decompiledFunction.c.contains("conditional_target("), result.decompiledFunction.c)
                    }
                } finally {
                    decompiler.dispose()
                }
            }
        }
    }

    @Test
    fun `same native interface rejects changed canonical and alias payload then follows reviewed new physical target`() =
        fixture(callCpu = 0x3ffa, callee = "3e11c9") { p, _ ->
            val template = SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x28, 3, null)
            val originalTarget = ProgramMapping.fileToStatic(p, 0x8100).single()
            val changedTarget = ProgramMapping.fileToStatic(p, 0x8120).single()
            val selected = ProgramMapping.fileToStatic(p, 0x8000).single()
            p.withTransaction {
                p.listing.clearCodeUnits(address(0x28), address(0x60), false)
                p.listing.clearCodeUnits(address(0x3ffa), address(0x3fff), false)
                p.listing.clearCodeUnits(changedTarget, changedTarget.add(2), false)
                p.memory.setBytes(address(0x28), HexFormat.of().parseHex(template.bodyHex()))
                p.memory.setBytes(address(0x3ffa), HexFormat.of().parseHex("ef0200410000"))
                p.memory.setBytes(changedTarget, HexFormat.of().parseHex("3e22c9"))
                p.memory.setBytes(selected, HexFormat.of().parseHex("ea00c2c9"))
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                d.disassemble(address(0x28), AddressSet(address(0x28), address(0x28 + template.bodyHex().length / 2 - 1L)))
                d.disassemble(address(0x3ffa), AddressSet(address(0x3ffa)))
                d.disassemble(address(0x3ffe), AddressSet(address(0x3ffe), address(0x3fff)))
                d.disassemble(selected, AddressSet(selected, selected.add(3)))
                d.disassemble(changedTarget, AddressSet(changedTarget, changedTarget.add(2)))
                p.functionManager.createFunction(
                    "before_payload_target",
                    originalTarget,
                    AddressSet(originalTarget, originalTarget.add(2)),
                    SourceType.USER_DEFINED,
                )
                p.functionManager.createFunction(
                    "after_payload_target",
                    changedTarget,
                    AddressSet(changedTarget, changedTarget.add(2)),
                    SourceType.USER_DEFINED,
                )
                val body = AddressSet(address(0x3ffa))
                body.add(address(0x3ffe), address(0x3fff))
                p.functionManager.createFunction("payload_mutation_caller", address(0x3ffa), body, SourceType.USER_DEFINED)
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x3ffa,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(0, 0, 0, 0, 0),
                    MapperState.reset(),
                )
            val initialReview = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            assertEquals("BOUNDED_SELF_FALLTHROUGH_EXPANSION", initialReview.inventory().single().canonicalTransport())
            assertEquals("NONE", initialReview.inventory().single().appliedCanonicalFlow())
            assertTrue(
                initialReview
                    .inventory()
                    .single()
                    .disposition()
                    .contains("exit=MAY_RETURN"),
            )
            SoftwareCallApplication.apply(p, initialReview, TaskMonitor.DUMMY)
            val initialAlias =
                p.addressFactory
                    .getAddressSpace(
                        initialReview
                            .executionViews()
                            .values
                            .single()
                            .name(),
                    ).getAddress(0x3ffa)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))

                fun verify(
                    entry: ghidra.program.model.address.Address,
                    target: ghidra.program.model.address.Address,
                    name: String,
                    expected: Long,
                ) {
                    val result = decompiler.decompileFunction(p.functionManager.getFunctionAt(entry), 30, TaskMonitor.DUMMY)
                    assertTrue(result.decompileCompleted(), result.errorMessage)
                    assertTrue(result.decompiledFunction.c.contains(name + "("), result.decompiledFunction.c)
                    assertFalse(result.decompiledFunction.c.contains("bad instruction", ignoreCase = true), result.decompiledFunction.c)
                    assertFalse(
                        result.decompiledFunction.c.contains("truncating control flow", ignoreCase = true),
                        result.decompiledFunction.c,
                    )
                    assertFalse(result.decompiledFunction.c.contains("halt_baddata"), result.decompiledFunction.c)
                    assertTrue(result.decompiledFunction.c.contains("c200"), result.decompiledFunction.c)
                    assertTrue(
                        result.highFunction.pcodeOps
                            .asSequence()
                            .any { it.opcode == PcodeOp.CALL && it.getInput(0).address == target },
                    )
                    assertTrue(
                        result.highFunction.pcodeOps.asSequence().any { op ->
                            (
                                op.opcode == PcodeOp.COPY && op.output?.address == address(0xc200) && op.getInput(0).isConstant &&
                                    op.getInput(0).offset == expected
                            ) ||
                                (
                                    op.opcode == PcodeOp.STORE && op.getInput(1).isConstant && op.getInput(1).offset == 0xc200L &&
                                        op.getInput(2).isConstant &&
                                        op.getInput(2).offset == expected
                                )
                        },
                        result.decompiledFunction.c,
                    )
                }
                for (entry in listOf(address(0x3ffa), initialAlias)) verify(entry, originalTarget, "before_payload_target", 0x11)
                // Change an actually consumed payload byte only; retain the same DecompInterface.
                p.withTransaction { p.memory.setByte(address(0x3ffc), 0x20) }
                for (entry in listOf(address(0x3ffa), initialAlias)) {
                    val failed = decompiler.decompileFunction(p.functionManager.getFunctionAt(entry), 30, TaskMonitor.DUMMY)
                    assertFalse(failed.decompileCompleted(), failed.decompiledFunction?.c)
                    assertTrue(failed.errorMessage.contains("Unresolved software-call injection"), failed.errorMessage)
                    assertThrows(IllegalArgumentException::class.java) { SoftwareCallRegistry.resolve(p, entry) }
                }
                AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
                val reapplied = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
                SoftwareCallApplication.apply(p, reapplied, TaskMonitor.DUMMY)
                val newAlias =
                    p.addressFactory
                        .getAddressSpace(
                            reapplied
                                .executionViews()
                                .values
                                .single()
                                .name(),
                        ).getAddress(0x3ffa)
                for (entry in listOf(address(0x3ffa), newAlias)) verify(entry, changedTarget, "after_payload_target", 0x22)
                assertEquals(0x20.toByte(), p.memory.getByte(address(0x3ffc)))
            } finally {
                decompiler.dispose()
            }
        }

    @Test
    fun `unsupported or corrupt registry refuses ownership writes without changing raw records`() =
        fixture { p, config ->
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            val options = p.getOptions(ProgramMapping.OPTIONS)
            val ownership = options.getString("analysis.ownership.v1", "")
            assertTrue(ownership.orEmpty().isNotBlank())
            for (raw in listOf("{", "null", "{\"version\":\"unknown\",\"sites\":[]}")) {
                p.withTransaction { options.setString(SoftwareCallRegistry.STOCK_KEY, raw) }
                assertThrows(RuntimeException::class.java) { AnalysisOwnership.removeAll(p, TaskMonitor.DUMMY) }
                assertThrows(RuntimeException::class.java) { SoftwareCallRegistry.remove(p) }
                assertEquals(raw, options.getString(SoftwareCallRegistry.STOCK_KEY, ""))
                assertEquals(ownership, options.getString("analysis.ownership.v1", ""))
            }
        }

    @Test
    fun `registry v3 record is rejected then public removal and reviewed reapplication produce current semantics`() =
        fixture { p, config ->
            val first = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            SoftwareCallApplication.apply(p, first, TaskMonitor.DUMMY)
            assertNotNull(SoftwareCallRegistry.resolve(p, address(0x200)))
            p.withTransaction {
                val options = p.getOptions(ProgramMapping.OPTIONS)
                val syntheticOld =
                    com.google.gson.JsonParser
                        .parseString(options.getString(SoftwareCallRegistry.STOCK_KEY, ""))
                        .asJsonObject
                // Synthetic compatibility negative, not an actual archived-v3 Program migration.
                syntheticOld.addProperty("version", "software-call-registry-3")
                for (site in syntheticOld.getAsJsonArray("sites")) site.asJsonObject.remove("canonicalAddress")
                options.setString(SoftwareCallRegistry.STOCK_KEY, ProgramMapping.JSON.toJson(syntheticOld))
            }
            val failure = assertThrows(IllegalArgumentException::class.java) { SoftwareCallRegistry.resolve(p, address(0x200)) }
            assertTrue(failure.message.orEmpty().contains("Incompatible software-call registry"), failure.message)
            val payload = p.compilerSpec.pcodeInjectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, SoftwareCallInjection.NAME)
            val context = InjectContext()
            context.baseAddr = address(0x200)
            context.nextAddr = context.baseAddr
            context.callAddr = address(0x28)
            assertThrows(IllegalArgumentException::class.java) { payload.getPcode(p, context) }
            // Retain this incumbent case identity; removal is no longer a proof conversion route.
            val before = p.getOptions(ProgramMapping.OPTIONS).getString(SoftwareCallRegistry.STOCK_KEY, "")
            assertThrows(IllegalArgumentException::class.java) {
                AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            }
            assertThrows(IllegalArgumentException::class.java) { AnalysisOwnership.removeAll(p, TaskMonitor.DUMMY) }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallRegistry.remove(p) }
            assertEquals(before, p.getOptions(ProgramMapping.OPTIONS).getString(SoftwareCallRegistry.STOCK_KEY, ""))
        }

    @Test
    fun `ordinary analysis refines decoder operand DATA into WRITE without invalidating the view but user references remain protected`() =
        fixture(callCpu = 0x3ffd) { p, config ->
            val selected = ProgramMapping.fileToStatic(p, 0x8000).single()
            val target = ProgramMapping.fileToStatic(p, 0x8100).single()
            p.withTransaction {
                p.listing.clearCodeUnits(address(0x3ffe), address(0x3fff), false)
                p.memory.setBytes(address(0x3ffe), byteArrayOf(0, 0))
                p.memory.setBytes(selected, HexFormat.of().parseHex("ea00c2c9"))
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                d.disassemble(address(0x3ffe), AddressSet(address(0x3ffe), address(0x3fff)))
                d.disassemble(selected, AddressSet(selected, selected.add(3)))
                p.functionManager.createFunction(
                    "reference_caller",
                    address(0x3ffd),
                    AddressSet(address(0x3ffd), address(0x3fff)),
                    SourceType.USER_DEFINED,
                )
                p.functionManager.createFunction("reference_target", target, AddressSet(target), SourceType.USER_DEFINED)
            }
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val space =
                p.addressFactory.getAddressSpace(
                    review
                        .executionViews()
                        .values
                        .single()
                        .name(),
                )
            val alias = space.getAddress(0x3ffd)
            val writeSite = space.getAddress(0x4000)
            val decoded =
                p.referenceManager.getReferencesFrom(writeSite).single {
                    it.source == SourceType.DEFAULT && it.referenceType == RefType.DATA && it.toAddress.offset == 0xc200L
                }
            val destination = decoded.toAddress
            val operand = decoded.operandIndex
            assertTrue(operand >= 0)
            p.withTransaction {
                p.referenceManager.delete(decoded)
                p.referenceManager.addMemoryReference(writeSite, destination, RefType.WRITE, SourceType.ANALYSIS, operand)
            }
            for (entry in listOf(address(0x3ffd), alias)) assertNotNull(SoftwareCallRegistry.resolve(p, entry))
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                for (entry in listOf(address(0x3ffd), alias)) {
                    val result = decompiler.decompileFunction(p.functionManager.getFunctionAt(entry), 30, TaskMonitor.DUMMY)
                    assertTrue(result.decompileCompleted(), result.errorMessage)
                    assertTrue(
                        result.highFunction.pcodeOps
                            .asSequence()
                            .any { it.opcode == PcodeOp.CALL && it.getInput(0).address == target },
                    )
                }
            } finally {
                decompiler.dispose()
            }
            // An unrelated DEFAULT annotation is not decoder output merely because of its source.
            val arbitrary =
                p.withTransaction {
                    p.referenceManager.addMemoryReference(writeSite, address(0xc300), RefType.DATA, SourceType.DEFAULT, -1)
                }
            for (entry in listOf(
                address(0x3ffd),
                alias,
            )) {
                assertThrows(IllegalArgumentException::class.java) { SoftwareCallRegistry.resolve(p, entry) }
            }
            p.withTransaction { p.referenceManager.delete(arbitrary) }
            for (entry in listOf(address(0x3ffd), alias)) assertNotNull(SoftwareCallRegistry.resolve(p, entry))
            // Matching the store's destination is insufficient on operand 1, which is register A.
            assertEquals(
                "A",
                p.listing
                    .getInstructionAt(writeSite)
                    .getRegister(1)
                    .name,
            )
            val wrongOperand =
                p.withTransaction {
                    val ref = p.referenceManager.addMemoryReference(writeSite, destination, RefType.DATA, SourceType.DEFAULT, 1)
                    p.referenceManager.setPrimary(ref, true)
                    ref
                }
            for (entry in listOf(address(0x3ffd), alias)) {
                assertThrows(IllegalArgumentException::class.java) { SoftwareCallRegistry.resolve(p, entry) }
            }
            p.withTransaction { p.referenceManager.delete(wrongOperand) }
            for (entry in listOf(address(0x3ffd), alias)) assertNotNull(SoftwareCallRegistry.resolve(p, entry))
            p.withTransaction {
                p.referenceManager.addMemoryReference(writeSite, address(0xc300), RefType.READ, SourceType.USER_DEFINED, -1)
                val ref = p.referenceManager.addMemoryReference(writeSite, destination, RefType.DATA, SourceType.DEFAULT, 1)
                p.referenceManager.setPrimary(ref, true)
            }
            for (entry in listOf(
                address(0x3ffd),
                alias,
            )) {
                assertThrows(IllegalArgumentException::class.java) { SoftwareCallRegistry.resolve(p, entry) }
            }
            val removal = AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            assertTrue(removal.any { it.contains("Preserved edited or uncertain execution view") }, removal.toString())
            assertTrue(
                p.referenceManager.getReferencesFrom(writeSite).any {
                    it.toAddress == address(0xc300) &&
                        it.source == SourceType.USER_DEFINED
                },
            )
            assertTrue(
                p.referenceManager.getReferencesFrom(writeSite).any {
                    it.toAddress == destination && it.operandIndex == 1 && it.source == SourceType.DEFAULT &&
                        it.referenceType == RefType.DATA && it.isPrimary
                },
            )
            assertNotNull(p.memory.getBlock(writeSite))
        }

    @Test
    fun `backwards conditional continuation edge preserves finite loop in canonical and mapped native roots`() =
        fixture(callCpu = 0x3ffd, callee = "0603afc9") { p, config ->
            val selected = ProgramMapping.fileToStatic(p, 0x8000).single()
            val target = ProgramMapping.fileToStatic(p, 0x8100).single()
            p.withTransaction {
                p.listing.clearCodeUnits(address(0x3ffe), address(0x3fff), false)
                p.memory.setBytes(address(0x3ffe), byteArrayOf(0, 0))
                // INC A; DEC B; JR NZ,-4; RET. B=3 and A=0 at entry imply three iterations.
                p.memory.setBytes(selected, HexFormat.of().parseHex("3c0520fcc9"))
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                d.disassemble(address(0x3ffe), AddressSet(address(0x3ffe), address(0x3fff)))
                d.disassemble(selected, AddressSet(selected, selected.add(4)))
                p.functionManager.createFunction(
                    "backwards_caller",
                    address(0x3ffd),
                    AddressSet(address(0x3ffd), address(0x3fff)),
                    SourceType.USER_DEFINED,
                )
                p.functionManager.createFunction("backwards_target", target, AddressSet(target, target.add(3)), SourceType.USER_DEFINED)
            }
            val validated = SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY)
            val effects = SoftwareCallEffects.derive(p, validated.frame(), TaskMonitor.DUMMY, listOf(config))
            assertTrue(effects.nativeCompatible(), effects.nativeIncompatibilities().toString())
            assertEquals(
                0x0300,
                effects
                    .paths()
                    .single()
                    .returned()
                    .registers()
                    .bc(),
            )
            assertEquals(
                0,
                effects
                    .paths()
                    .single()
                    .returned()
                    .registers()
                    .a(),
            )
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            assertEquals(1, review.executionViews().size)
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val view =
                p.addressFactory.getAddressSpace(
                    review
                        .executionViews()
                        .values
                        .single()
                        .name(),
                )
            assertEquals(MapperState.Physical("ROM", 2, 0), ProgramMapping.staticToPhysical(p, view.getAddress(0x4000)).single())
            val context = InjectContext()
            context.baseAddr = address(0x3ffd)
            context.nextAddr = context.baseAddr
            context.callAddr = address(0x28)
            val payload = p.compilerSpec.pcodeInjectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, SoftwareCallInjection.NAME)
            val injected = payload.getPcode(p, context)
            assertTrue(
                injected.any { it.opcode == PcodeOp.CBRANCH && it.getInput(0).isConstant && it.getInput(0).offset.toInt() < 0 },
                "The fixture must exercise a genuinely backwards local conditional edge",
            )
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                for (entry in listOf(address(0x3ffd), view.getAddress(0x3ffd))) {
                    val result = decompiler.decompileFunction(p.functionManager.getFunctionAt(entry), 30, TaskMonitor.DUMMY)
                    assertTrue(result.decompileCompleted(), result.errorMessage)
                    val c = result.decompiledFunction.c
                    assertTrue(c.contains("backwards_target("), c)
                    assertFalse(c.contains("bad relative", ignoreCase = true), c)
                    assertFalse(c.contains("bad instruction", ignoreCase = true), c)
                    assertFalse(c.contains("truncating", ignoreCase = true), c)
                    assertFalse(c.contains("halt_baddata"), c)
                    assertTrue(
                        result.highFunction.pcodeOps
                            .asSequence()
                            .any { it.opcode == PcodeOp.CALL && it.getInput(0).address == target },
                    )
                    assertTrue(
                        result.highFunction.pcodeOps
                            .asSequence()
                            .any { it.opcode == PcodeOp.RETURN },
                    )
                }
            } finally {
                decompiler.dispose()
            }
        }
}
