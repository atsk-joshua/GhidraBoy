package fi.gekkio.ghidraboy

import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
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
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayload
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

/** Production compiler declarations, with no runtime XML registration. */
class SoftwareCallInjectionInstalledTest : IntegrationTest() {
    class SelectorLibrary : AnnotatedPcodeUseropLibrary<ByteArray>() {
        val writes = mutableListOf<Pair<Long, Long>>()

        @PcodeUserop
        fun gb_direct_write8(
            cpu: Long,
            value: Long,
        ) {
            require(cpu == 0x2000L)
            writes.add(cpu to value)
        }
    }

    @Test
    fun `installed compiler provides dynamic payload and refuses an unvalidated caller`() {
        val consumer = Any()
        val program = ProgramDB("production-injection", language, language.defaultCompilerSpec, consumer)
        try {
            val payload =
                program.compilerSpec.pcodeInjectLibrary.getPayload(
                    InjectPayload.CALLFIXUP_TYPE,
                    SoftwareCallInjection.NAME,
                )
            assertNotNull(payload)
            assertTrue(payload is SoftwareCallInjection)
            assertTrue(payload.isFallThru)
            val context = InjectContext()
            context.baseAddr = address(0x150)
            context.nextAddr = address(0x150)
            context.callAddr = address(8)
            val failure = assertThrows(IllegalArgumentException::class.java) { payload.getPcode(program, context) }
            assertTrue(failure.message.orEmpty().contains("Unresolved software-call injection"), failure.message)
        } finally {
            program.release(consumer)
        }
    }

    @Test
    fun `reviewed production workflow separates two sites sharing a helper across banks`() {
        val monitor = TaskMonitor.DUMMY
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x200, 3, null)
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        HexFormat.of().parseHex(template.bodyHex()).copyInto(bytes, 0x200)
        for ((site, bank) in listOf(0x150 to 1, 0x160 to 2)) {
            byteArrayOf(
                0xcd.toByte(),
                0,
                2,
                bank.toByte(),
                0,
                0x41,
                0x30,
                4,
                0xea.toByte(),
                0,
                0xc1.toByte(),
                0xc9.toByte(),
                0xea.toByte(),
                1,
                0xc1.toByte(),
                0xc9.toByte(),
            ).copyInto(bytes, site)
            byteArrayOf(0x3e, (0x50 + bank).toByte(), 0x37, 0xc9.toByte()).copyInto(bytes, bank * 0x4000 + 0x100)
        }
        val consumer = Any()
        val program = ProgramDB("production-sites", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(program, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog())
            }
            val targets = listOf(0x4100L, 0x8100L).map { ProgramMapping.fileToStatic(program, it).single() }
            program.withTransaction {
                val disassembler = Disassembler.getDisassembler(program, monitor, null)
                disassembler.disassemble(address(0x200), AddressSet(address(0x200), address(0x20b)))
                for ((index, site) in listOf(0x150L, 0x160L).withIndex()) {
                    disassembler.disassemble(address(site), AddressSet(address(site), address(site + 2)))
                    disassembler.disassemble(address(site + 6), AddressSet(address(site + 6), address(site + 15)))
                    disassembler.disassemble(targets[index], AddressSet(targets[index], targets[index].add(3)))
                    program.functionManager.createFunction(
                        "physical_target_$index",
                        targets[index],
                        AddressSet(targets[index], targets[index].add(3)),
                        SourceType.USER_DEFINED,
                    )
                    val body = AddressSet(address(site), address(site + 2))
                    body.add(address(site + 6), address(site + 15))
                    program.functionManager.createFunction("caller_$index", address(site), body, SourceType.USER_DEFINED)
                }
            }
            val configurations =
                listOf(0x150, 0x160).map { site ->
                    SoftwareCallValidation.Configuration(
                        site,
                        template,
                        SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                        0xc100,
                        SoftwareCallModel.Registers(0, 0x80, 0, 0, 0),
                        MapperState.reset(),
                    )
                }
            val review = SoftwareCallApplication.preview(program, configurations, monitor)
            SoftwareCallApplication.apply(program, review, monitor)
            val payload = program.compilerSpec.pcodeInjectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, SoftwareCallInjection.NAME)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(program))
                for ((index, site) in listOf(0x150L, 0x160L, 0x150L).withIndex()) {
                    val expected = if (site == 0x150L) 0 else 1
                    val context = InjectContext()
                    context.baseAddr = address(site)
                    context.nextAddr = address(site)
                    context.callAddr = address(0x200)
                    assertEquals(
                        targets[expected],
                        payload
                            .getPcode(program, context)
                            .single { it.opcode == PcodeOp.CALL }
                            .getInput(0)
                            .address,
                    )
                    val result = decompiler.decompileFunction(program.functionManager.getFunctionAt(address(site)), 30, monitor)
                    assertTrue(result.decompileCompleted(), result.errorMessage)
                    assertTrue(result.decompiledFunction.c.contains("physical_target_$expected("), result.decompiledFunction.c)
                    assertTrue(result.decompiledFunction.c.contains("c100"), result.decompiledFunction.c)
                    assertTrue(!result.decompiledFunction.c.contains("c101"), result.decompiledFunction.c)
                    assertTrue(
                        result.highFunction.pcodeOps.asSequence().any {
                            it.opcode == PcodeOp.CALL && it.getInput(0).address == targets[expected]
                        },
                        "native physical identity on request $index: ${result.decompiledFunction.c}",
                    )
                }
                // Keep the same native interface alive across a new consumed payload dependency.
                program.withTransaction { program.memory.setByte(address(0x153), 2) }
                val changedContext = InjectContext()
                changedContext.baseAddr = address(0x150)
                changedContext.nextAddr = address(0x150)
                changedContext.callAddr = address(0x200)
                assertThrows(IllegalArgumentException::class.java) { payload.getPcode(program, changedContext) }
                SoftwareCallApplication.apply(program, SoftwareCallApplication.preview(program, configurations, monitor), monitor)
                val changedPcode = payload.getPcode(program, changedContext)
                assertEquals(targets[1], changedPcode.single { it.opcode == PcodeOp.CALL }.getInput(0).address)
                val changedResult = decompiler.decompileFunction(program.functionManager.getFunctionAt(address(0x150)), 30, monitor)
                assertTrue(changedResult.decompileCompleted(), changedResult.errorMessage)
                assertTrue(changedResult.decompiledFunction.c.contains("physical_target_1("), changedResult.decompiledFunction.c)
                assertTrue(!changedResult.decompiledFunction.c.contains("physical_target_0("), changedResult.decompiledFunction.c)
                assertTrue(
                    changedResult.highFunction.pcodeOps.asSequence().any {
                        it.opcode == PcodeOp.CALL && it.getInput(0).address == targets[1]
                    },
                    changedResult.decompiledFunction.c,
                )
                assertTrue(
                    changedResult.highFunction.pcodeOps.asSequence().any {
                        (
                            it.opcode == PcodeOp.COPY && it.output?.address?.offset == 0xc100L &&
                                it.getInput(0).isConstant && it.getInput(0).offset == 0x52L
                        ) ||
                            (
                                it.opcode == PcodeOp.STORE && it.getInput(1).isConstant && it.getInput(1).offset == 0xc100L &&
                                    it.getInput(2).isConstant && it.getInput(2).offset == 0x52L
                            )
                    },
                    changedResult.decompiledFunction.c,
                )
            } finally {
                decompiler.dispose()
            }
            // A code/data edit alone must invalidate the actual returning continuation.
            program.withTransaction {
                program.listing.clearCodeUnits(address(0x156), address(0x157), false)
                program.listing.createData(address(0x156), ghidra.program.model.data.ByteDataType.dataType)
            }
            val boundaryContext = InjectContext()
            boundaryContext.baseAddr = address(0x150)
            boundaryContext.nextAddr = address(0x150)
            boundaryContext.callAddr = address(0x200)
            assertThrows(IllegalArgumentException::class.java) { payload.getPcode(program, boundaryContext) }
            program.withTransaction {
                program.listing.clearCodeUnits(address(0x156), address(0x156), false)
                Disassembler.getDisassembler(program, monitor, null).disassemble(address(0x156), AddressSet(address(0x156), address(0x157)))
            }
            val bounded = BankAnalysis.preview(program, address(0x150), MapperState.reset(), AnalysisResult.Configuration.DEFAULT, monitor)
            assertTrue(
                bounded.findings().any { it.confidence() == AnalysisResult.Confidence.UNKNOWN && it.reason().contains("premise") },
                bounded.findings().toString(),
            )
            program.withTransaction {
                program.listing.clearCodeUnits(targets[0], targets[0].add(1), false)
                program.memory.setByte(targets[0], 0)
            }
            val context = InjectContext()
            context.baseAddr = address(0x150)
            context.callAddr = address(0x200)
            assertThrows(IllegalArgumentException::class.java) { payload.getPcode(program, context) }
        } finally {
            program.release(consumer)
        }
    }

    @Test
    fun `production register helpers preserve restoring constant and manual frame effects`() {
        val monitor = TaskMonitor.DUMMY
        val cases =
            listOf(
                SoftwareCallModel.Family.REGISTER_JP to SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION,
                SoftwareCallModel.Family.RESTORING_REGISTER_JP to SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                SoftwareCallModel.Family.CONSTANT_REGISTER_JP to SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
            )
        for ((family, transfer) in cases) {
            val manual = transfer == SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION
            val next = if (manual) 0x157 else 0x153
            val template =
                SoftwareCallModel.Template(
                    family,
                    0x200,
                    0,
                    if (family == SoftwareCallModel.Family.CONSTANT_REGISTER_JP) 1 else null,
                )
            val bytes = ByteArray(0x10000)
            bytes[0x147] = 0x13
            bytes[0x148] = 1
            HexFormat.of().parseHex(template.bodyHex()).copyInto(bytes, 0x200)
            val call =
                if (manual) {
                    byteArrayOf(1, next.toByte(), 1, 0xc5.toByte(), 0xc3.toByte(), 0, 2)
                } else {
                    byteArrayOf(0xcd.toByte(), 0, 2)
                }
            call.copyInto(bytes, 0x150)
            byteArrayOf(0xea.toByte(), 0, 0xc1.toByte(), 0xc9.toByte()).copyInto(bytes, next)
            byteArrayOf(0x3e, 0x5a, 0x37, 0xc9.toByte()).copyInto(bytes, 0x8100)
            val consumer = Any()
            val program = ProgramDB("production-$family-$transfer", language, language.defaultCompilerSpec, consumer)
            try {
                ByteArrayProvider(bytes).use {
                    CartridgeLayout.load(program, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog())
                }
                val target = ProgramMapping.fileToStatic(program, 0x8100).single()
                program.withTransaction {
                    val disassembler = Disassembler.getDisassembler(program, monitor, null)
                    disassembler.disassemble(
                        address(0x200),
                        AddressSet(address(0x200), address(0x200 + template.bodyHex().length / 2L - 1)),
                    )
                    // JP HL terminates discovery before the separately entered wrapper epilogue.
                    if (template.epilogueCpu() >= 0) {
                        disassembler.disassemble(
                            address(template.epilogueCpu().toLong()),
                            AddressSet(address(template.epilogueCpu().toLong()), address(0x200 + template.bodyHex().length / 2L - 1)),
                        )
                    }
                    disassembler.disassemble(address(0x150), AddressSet(address(0x150), address(next - 1L)))
                    disassembler.disassemble(address(next.toLong()), AddressSet(address(next.toLong()), address(next + 3L)))
                    disassembler.disassemble(target, AddressSet(target, target.add(3)))
                    program.functionManager.createFunction(
                        "register_target",
                        target,
                        AddressSet(target, target.add(3)),
                        SourceType.USER_DEFINED,
                    )
                    program.functionManager.createFunction(
                        "register_caller",
                        address(0x150),
                        AddressSet(address(0x150), address(next + 3L)),
                        SourceType.USER_DEFINED,
                    )
                }
                val config =
                    SoftwareCallValidation.Configuration(
                        0x150,
                        template,
                        transfer,
                        0xc100,
                        SoftwareCallModel.Registers(
                            if (family == SoftwareCallModel.Family.RESTORING_REGISTER_JP) 1 else 2,
                            0x80,
                            if (manual) next else 2,
                            0,
                            0x4100,
                        ),
                        MapperState.reset(),
                    )
                SoftwareCallApplication.apply(program, SoftwareCallApplication.preview(program, listOf(config), monitor), monitor)
                val source = address(if (manual) 0x154L else 0x150L)
                val payload = program.compilerSpec.pcodeInjectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, SoftwareCallInjection.NAME)
                val context = InjectContext()
                context.baseAddr = source
                context.nextAddr = source
                context.callAddr = address(0x200)
                val injected = payload.getPcode(program, context)
                assertEquals(target, injected.single { it.opcode == PcodeOp.CALL }.getInput(0).address)
                val flag = injected.last { it.output?.address == program.getRegister("F").address }
                assertEquals(PcodeOp.COPY, flag.opcode)
                assertEquals(0x90L, flag.getInput(0).offset)
                // Execute the actual installed payload on Ghidra's executor, pausing at its CALL
                // to execute the real callee RET before resuming the architectural wrapper.
                val arithmetic = BytesPcodeArithmetic.forLanguage(language)
                val state = BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE)
                val executor = PcodeExecutor(language as SleighLanguage, arithmetic, state, Reason.EXECUTE_READ)
                val bus = SelectorLibrary()
                val initial = config.registers()
                for ((name, value) in mapOf(
                    "A" to initial.a(),
                    "F" to initial.f(),
                    "BC" to initial.bc(),
                    "DE" to initial.de(),
                    "HL" to initial.hl(),
                    "SP" to 0xc100,
                    "PC" to 0x150,
                )) {
                    val register = language.getRegister(name)
                    state.setVar(register, arithmetic.fromConst(value, register.minimumByteSize))
                }
                var callerCpu = 0x150L
                while (callerCpu <= source.offset) {
                    val instruction = program.listing.getInstructionAt(address(callerCpu))
                    executor.execute(PcodeProgram.fromInstruction(instruction, false), bus)
                    callerCpu += instruction.length
                }
                val sourceProgram = PcodeProgram.fromInstruction(program.listing.getInstructionAt(source), false)
                val callIndex = injected.indexOfFirst { it.opcode == PcodeOp.CALL }
                executor.execute(PcodeProgram(sourceProgram, injected.take(callIndex + 1)), bus)

                fun value(name: String): Int =
                    state
                        .getVar(language.getRegister(name), Reason.INSPECT)
                        .foldIndexed(0) { index, accumulated, byte -> accumulated or ((byte.toInt() and 255) shl (index * 8)) }
                val expectedSp =
                    when (family) {
                        SoftwareCallModel.Family.RESTORING_REGISTER_JP -> 0xc0fa
                        SoftwareCallModel.Family.CONSTANT_REGISTER_JP -> 0xc0fc
                        else -> 0xc0fe
                    }
                assertEquals(expectedSp, value("SP"))
                assertEquals(0x4100, value("PC"))
                val continuationBytes = state.getVar(address(0xc0fe), 2, true, Reason.INSPECT)
                assertEquals(next and 255, continuationBytes[0].toInt() and 255)
                assertEquals(1, continuationBytes[1].toInt() and 255)
                for (offset in listOf(0L, 2L, 3L)) {
                    executor.execute(PcodeProgram.fromInstruction(program.listing.getInstructionAt(target.add(offset)), false), bus)
                }
                executor.execute(PcodeProgram(sourceProgram, injected.drop(callIndex + 1)), bus)
                assertEquals(0xc100, value("SP"))
                assertEquals(0x90, value("F"))
                assertEquals(if (family == SoftwareCallModel.Family.REGISTER_JP) 0x5a else 1, value("A"))
                assertEquals(0x4100, value("HL"))
                assertEquals(0, value("DE"))
                assertEquals(
                    when (family) {
                        SoftwareCallModel.Family.RESTORING_REGISTER_JP -> 0x180
                        SoftwareCallModel.Family.CONSTANT_REGISTER_JP -> 0x208
                        else -> next
                    },
                    value("BC"),
                )
                assertEquals(
                    if (family == SoftwareCallModel.Family.REGISTER_JP) listOf(2L) else listOf(2L, 1L),
                    bus.writes.map { it.second },
                )
                val decompiler = DecompInterface()
                try {
                    assertTrue(decompiler.openProgram(program))
                    val result = decompiler.decompileFunction(program.functionManager.getFunctionAt(address(0x150)), 30, monitor)
                    assertTrue(result.decompileCompleted(), result.errorMessage)
                    assertTrue(result.decompiledFunction.c.contains("register_target("), result.decompiledFunction.c)
                } finally {
                    decompiler.dispose()
                }
            } finally {
                program.release(consumer)
            }
        }
    }

    @Test
    fun `proven nonreturn uses reviewed terminal call without a fabricated wrapper return`() {
        val monitor = TaskMonitor.DUMMY
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.CONSTANT_REGISTER_JP, 0x200, 0, 1)
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        HexFormat.of().parseHex(template.bodyHex()).copyInto(bytes, 0x200)
        byteArrayOf(0xcd.toByte(), 0, 2, 0xea.toByte(), 0, 0xc1.toByte(), 0xc9.toByte()).copyInto(bytes, 0x150)
        byteArrayOf(0x18, 0xfe.toByte()).copyInto(bytes, 0x8100)
        val consumer = Any()
        val program = ProgramDB("production-nonreturn", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(program, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog())
            }
            val target = ProgramMapping.fileToStatic(program, 0x8100).single()
            program.withTransaction {
                val disassembler = Disassembler.getDisassembler(program, monitor, null)
                disassembler.disassemble(address(0x200), AddressSet(address(0x200), address(0x20d)))
                disassembler.disassemble(
                    address(template.epilogueCpu().toLong()),
                    AddressSet(address(template.epilogueCpu().toLong()), address(0x20d)),
                )
                disassembler.disassemble(address(0x150), AddressSet(address(0x150), address(0x156)))
                disassembler.disassemble(target, AddressSet(target, target.add(1)))
                program.functionManager.createFunction("endless_target", target, AddressSet(target, target.add(1)), SourceType.USER_DEFINED)
                program.functionManager.createFunction(
                    "terminal_caller",
                    address(0x150),
                    AddressSet(address(0x150), address(0x156)),
                    SourceType.USER_DEFINED,
                )
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x150,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0x80, 0, 0, 0x4100),
                    MapperState.reset(),
                )
            SoftwareCallApplication.apply(program, SoftwareCallApplication.preview(program, listOf(config), monitor), monitor)
            assertEquals(
                ghidra.program.model.listing.FlowOverride.CALL_RETURN,
                program.listing.getInstructionAt(address(0x150)).flowOverride,
            )
            assertEquals(null, program.listing.getInstructionAt(address(0x150)).fallThrough)
            assertTrue(!program.functionManager.getFunctionAt(target).hasNoReturn())
            val context = InjectContext()
            context.baseAddr = address(0x150)
            context.nextAddr = address(0x150)
            context.callAddr = address(0x200)
            val payload = program.compilerSpec.pcodeInjectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, SoftwareCallInjection.NAME)
            val injected = payload.getPcode(program, context)
            assertEquals(PcodeOp.CALL, injected.last().opcode)
            assertEquals(target, injected.last().getInput(0).address)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(program))
                val result = decompiler.decompileFunction(program.functionManager.getFunctionAt(address(0x150)), 30, monitor)
                assertTrue(result.decompileCompleted(), result.errorMessage)
                assertTrue(result.decompiledFunction.c.contains("endless_target("), result.decompiledFunction.c)
                assertTrue(!result.decompiledFunction.c.contains("c100"), result.decompiledFunction.c)
            } finally {
                decompiler.dispose()
            }
        } finally {
            program.release(consumer)
        }
    }

    @Test
    fun `banked inline reads target after selector change in native and actual injection`() {
        val monitor = TaskMonitor.DUMMY
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x28, 3, null)
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        HexFormat.of().parseHex(template.bodyHex()).copyInto(bytes, 0x28)
        // Old-bank target bytes deliberately spell 5000. Actual helper switches before reading them.
        byteArrayOf(0xef.toByte(), 2, 0, 0x50, 0x76).copyInto(bytes, 0x4100)
        byteArrayOf(0, 0, 0, 0x40, 0xc9.toByte()).copyInto(bytes, 0x8100)
        byteArrayOf(0x3e, 0x5a, 0x37, 0xc9.toByte()).copyInto(bytes, 0x8000)
        val consumer = Any()
        val program = ProgramDB("banked-inline-payload-order", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(program, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog())
            }
            val caller = ProgramMapping.fileToStatic(program, 0x4100).single()
            val target = ProgramMapping.fileToStatic(program, 0x8000).single()
            val continuation = ProgramMapping.fileToStatic(program, 0x8104).single()
            program.withTransaction {
                val d = Disassembler.getDisassembler(program, monitor, null)
                d.disassemble(address(0x28), AddressSet(address(0x28), address(0x33)))
                d.disassemble(caller, AddressSet(caller))
                d.disassemble(target, AddressSet(target, target.add(3)))
                d.disassemble(continuation, AddressSet(continuation))
                program.functionManager.createFunction("inline_banked_caller", caller, AddressSet(caller), SourceType.USER_DEFINED)
                program.functionManager.createFunction(
                    "post_switch_target",
                    target,
                    AddressSet(target, target.add(3)),
                    SourceType.USER_DEFINED,
                )
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x4100,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(0, 0x80, 0, 0, 0),
                    MapperState.reset(),
                )
            val validated = SoftwareCallValidation.preview(program, config, monitor)
            assertEquals(0x4000, validated.frame().targetCpu())
            assertEquals(listOf(1, 2, 2), validated.frame().reads().map { it.physical().bank() })
            val review = SoftwareCallApplication.preview(program, listOf(config), monitor)
            SoftwareCallApplication.apply(program, review, monitor)
            val view =
                program.addressFactory.getAddressSpace(
                    review
                        .executionViews()
                        .values
                        .single()
                        .name(),
                )
            val site = view.getAddress(0x4100)
            val context = InjectContext()
            context.baseAddr = site
            context.nextAddr = site
            context.callAddr = address(0x28)
            val payload = program.compilerSpec.pcodeInjectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, SoftwareCallInjection.NAME)
            val injected = payload.getPcode(program, context)
            val callIndex = injected.indexOfFirst { it.opcode == PcodeOp.CALL }
            assertEquals(target, injected[callIndex].getInput(0).address)
            val arithmetic = BytesPcodeArithmetic.forLanguage(language)
            val state = BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE)
            val executor = PcodeExecutor(language as SleighLanguage, arithmetic, state, Reason.EXECUTE_READ)
            val bus = SelectorLibrary()
            for ((name, value) in mapOf("A" to 0, "F" to 0x80, "BC" to 0, "DE" to 0, "HL" to 0, "SP" to 0xc100, "PC" to 0x4100)) {
                val register = language.getRegister(name)
                state.setVar(register, arithmetic.fromConst(value, register.minimumByteSize))
            }
            val rawCaller = PcodeProgram.fromInstruction(program.listing.getInstructionAt(caller), false)
            executor.execute(rawCaller, bus)
            executor.execute(PcodeProgram(rawCaller, injected.take(callIndex + 1)), bus)

            fun value(name: String): Int =
                state
                    .getVar(language.getRegister(name), Reason.INSPECT)
                    .foldIndexed(0) { index, accumulated, byte -> accumulated or ((byte.toInt() and 255) shl (index * 8)) }
            assertEquals(0x4000, value("PC"))
            assertEquals(0xc0fe, value("SP"))
            assertEquals(0x4000, value("DE"))
            assertEquals(0x4104, value("HL"))
            assertEquals(2, value("A"))
            assertEquals(listOf(0x2000L to 2L), bus.writes)
            assertEquals(listOf(4, 0x41), state.getVar(address(0xc0fe), 2, true, Reason.INSPECT).map { it.toInt() and 255 })
            for (offset in listOf(0L, 2L, 3L)) {
                executor.execute(PcodeProgram.fromInstruction(program.listing.getInstructionAt(target.add(offset)), false), bus)
            }
            executor.execute(PcodeProgram(rawCaller, injected.drop(callIndex + 1)), bus)
            assertEquals(0xc100, value("SP"))
            assertEquals(0x90, value("F"))
            assertEquals(0x5a, value("A"))
            assertEquals(0x50, program.memory.getByte(caller.add(3)).toInt() and 255)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(program))
                val result = decompiler.decompileFunction(program.functionManager.getFunctionAt(site), 30, monitor)
                assertTrue(result.decompileCompleted(), result.errorMessage)
                assertTrue(result.decompiledFunction.c.contains("post_switch_target("), result.decompiledFunction.c)
                assertTrue(
                    result.highFunction.pcodeOps
                        .asSequence()
                        .any { it.opcode == PcodeOp.CALL && it.getInput(0).address == target },
                )
            } finally {
                decompiler.dispose()
            }
            val targetByte = ProgramMapping.fileToStatic(program, 0x8102).first { SoftwareCallExecutionView.canonical(program, it) }
            program.withTransaction { program.memory.setByte(targetByte, 1) }
            assertThrows(IllegalArgumentException::class.java) { payload.getPcode(program, context) }
        } finally {
            program.release(consumer)
        }
    }

    @Test
    fun `two reviewed sites integrate nested software frames through ordinary native calls`() {
        val monitor = TaskMonitor.DUMMY
        val outer = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x200, 0, null)
        val inner = SoftwareCallModel.Template(SoftwareCallModel.Family.RESTORING_REGISTER_JP, 0x280, 0, null)
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        HexFormat.of().parseHex(outer.bodyHex()).copyInto(bytes, 0x200)
        HexFormat.of().parseHex(inner.bodyHex()).copyInto(bytes, 0x280)
        HexFormat.of().parseHex("cd0002c9").copyInto(bytes, 0x150)
        HexFormat.of().parseHex("3e02010300210043cd8002c9").copyInto(bytes, 0x8100)
        HexFormat.of().parseHex("37c9").copyInto(bytes, 0xc300)
        val consumer = Any()
        val program = ProgramDB("nested-production-software-calls", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(program, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog())
            }
            val outerTarget = ProgramMapping.fileToStatic(program, 0x8100).single()
            val innerTarget = ProgramMapping.fileToStatic(program, 0xc300).single()
            program.withTransaction {
                val d = Disassembler.getDisassembler(program, monitor, null)
                for (template in listOf(outer, inner)) {
                    val begin = address(template.helperCpu().toLong())
                    val body = AddressSet(begin, begin.add(template.bodyHex().length / 2L - 1))
                    d.disassemble(begin, body)
                    if (template.epilogueCpu() >= 0) d.disassemble(address(template.epilogueCpu().toLong()), body)
                }
                d.disassemble(address(0x150), AddressSet(address(0x150), address(0x153)))
                d.disassemble(outerTarget, AddressSet(outerTarget, outerTarget.add(11)))
                d.disassemble(innerTarget, AddressSet(innerTarget, innerTarget.add(1)))
                program.functionManager.createFunction(
                    "nested_root",
                    address(0x150),
                    AddressSet(address(0x150), address(0x153)),
                    SourceType.USER_DEFINED,
                )
                program.functionManager.createFunction(
                    "nested_outer_target",
                    outerTarget,
                    AddressSet(outerTarget, outerTarget.add(11)),
                    SourceType.USER_DEFINED,
                )
                program.functionManager.createFunction(
                    "nested_inner_target",
                    innerTarget,
                    AddressSet(innerTarget, innerTarget.add(1)),
                    SourceType.USER_DEFINED,
                )
            }
            val mapper2 = MapperState.reset().write(ProgramMapping.cartridge(program), 0x2000, 2)
            val configurations =
                listOf(
                    SoftwareCallValidation.Configuration(
                        0x150,
                        outer,
                        SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                        0xc100,
                        SoftwareCallModel.Registers(2, 0x80, 0, 0, 0x4100),
                        MapperState.reset(),
                    ),
                    SoftwareCallValidation.Configuration(
                        0x4108,
                        inner,
                        SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                        0xc0fe,
                        SoftwareCallModel.Registers(2, 0x80, 3, 0, 0x4300),
                        mapper2,
                    ),
                )
            val review = SoftwareCallApplication.preview(program, configurations, monitor)
            SoftwareCallApplication.apply(program, review, monitor)
            val payload = program.compilerSpec.pcodeInjectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, SoftwareCallInjection.NAME)
            for ((site, helper, target) in listOf(
                Triple(address(0x150), 0x200, outerTarget),
                Triple(outerTarget.add(8), 0x280, innerTarget),
            )) {
                val context = InjectContext()
                context.baseAddr = site
                context.nextAddr = site
                context.callAddr = address(helper.toLong())
                val pcode = payload.getPcode(program, context)
                assertEquals(target, pcode.single { it.opcode == PcodeOp.CALL }.getInput(0).address)
                for ((name, expected) in mapOf("A" to 2L, "F" to 0x90L, "BC" to 0x280L, "DE" to 0L, "HL" to 0x4300L)) {
                    val output = pcode.last { it.output?.address == program.getRegister(name).address }
                    assertEquals(PcodeOp.COPY, output.opcode)
                    assertEquals(expected, output.getInput(0).offset)
                }
            }
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(program))
                for ((caller, target, name) in listOf(
                    Triple(address(0x150), outerTarget, "nested_outer_target"),
                    Triple(outerTarget, innerTarget, "nested_inner_target"),
                )) {
                    val result = decompiler.decompileFunction(program.functionManager.getFunctionAt(caller), 30, monitor)
                    assertTrue(result.decompileCompleted(), result.errorMessage)
                    assertTrue(result.decompiledFunction.c.contains("$name("), result.decompiledFunction.c)
                    assertTrue(
                        result.highFunction.pcodeOps
                            .asSequence()
                            .any { it.opcode == PcodeOp.CALL && it.getInput(0).address == target },
                        result.decompiledFunction.c,
                    )
                }
            } finally {
                decompiler.dispose()
            }
            program.withTransaction {
                program.listing.getInstructionAt(outerTarget.add(8)).flowOverride = ghidra.program.model.listing.FlowOverride.RETURN
            }
            val outerContext = InjectContext()
            outerContext.baseAddr = address(0x150)
            outerContext.nextAddr = address(0x150)
            outerContext.callAddr = address(0x200)
            assertThrows(IllegalArgumentException::class.java) { payload.getPcode(program, outerContext) }
        } finally {
            program.release(consumer)
        }
    }

    @Test
    fun `known nonlocal RET branches to proven destination without returning through ordinary continuation`() {
        val monitor = TaskMonitor.DUMMY
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x200, 0, null)
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        HexFormat.of().parseHex(template.bodyHex()).copyInto(bytes, 0x200)
        HexFormat.of().parseHex("cd00023e55c9").copyInto(bytes, 0x150)
        HexFormat.of().parseHex("3e66c9").copyInto(bytes, 0x180)
        HexFormat.of().parseHex("f8003680233601c9").copyInto(bytes, 0x8100)
        val consumer = Any()
        val program = ProgramDB("production-nonlocal-ret", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(program, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog())
            }
            val target = ProgramMapping.fileToStatic(program, 0x8100).single()
            program.withTransaction {
                val d = Disassembler.getDisassembler(program, monitor, null)
                d.disassemble(address(0x200), AddressSet(address(0x200), address(0x203)))
                d.disassemble(address(0x150), AddressSet(address(0x150), address(0x155)))
                d.disassemble(address(0x180), AddressSet(address(0x180), address(0x182)))
                d.disassemble(target, AddressSet(target, target.add(7)))
                program.functionManager.createFunction(
                    "nonlocal_caller",
                    address(0x150),
                    AddressSet(address(0x150), address(0x155)),
                    SourceType.USER_DEFINED,
                )
                program.functionManager.createFunction(
                    "nonlocal_target",
                    target,
                    AddressSet(target, target.add(7)),
                    SourceType.USER_DEFINED,
                )
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x150,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0x80, 0, 0, 0x4100),
                    MapperState.reset(),
                )
            SoftwareCallApplication.apply(program, SoftwareCallApplication.preview(program, listOf(config), monitor), monitor)
            val site = program.listing.getInstructionAt(address(0x150))
            assertEquals(address(0x180), site.fallThrough)
            assertEquals(ghidra.program.model.listing.FlowOverride.NONE, site.flowOverride)
            val context = InjectContext()
            context.baseAddr = address(0x150)
            context.nextAddr = address(0x150)
            context.callAddr = address(0x200)
            val payload = program.compilerSpec.pcodeInjectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, SoftwareCallInjection.NAME)
            val pcode = payload.getPcode(program, context)
            val callIndex = pcode.indexOfFirst { it.opcode == PcodeOp.CALL }
            assertEquals(target, pcode[callIndex].getInput(0).address)
            assertEquals(PcodeOp.BRANCH, pcode.last().opcode)
            assertEquals(address(0x180), pcode.last().getInput(0).address)
            assertTrue(pcode.none { it.opcode == PcodeOp.RETURN })
            val arithmetic = BytesPcodeArithmetic.forLanguage(language)
            val state = BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE)
            val executor = PcodeExecutor(language as SleighLanguage, arithmetic, state, Reason.EXECUTE_READ)
            val bus = SelectorLibrary()
            for ((name, value) in mapOf("A" to 2, "F" to 0x80, "BC" to 0, "DE" to 0, "HL" to 0x4100, "SP" to 0xc100, "PC" to 0x150)) {
                val register = language.getRegister(name)
                state.setVar(register, arithmetic.fromConst(value, register.minimumByteSize))
            }
            val raw = PcodeProgram.fromInstruction(site, false)
            executor.execute(raw, bus)
            executor.execute(PcodeProgram(raw, pcode.take(callIndex + 1)), bus)
            for (offset in listOf(0L, 2L, 4L, 5L, 7L)) {
                executor.execute(PcodeProgram.fromInstruction(program.listing.getInstructionAt(target.add(offset)), false), bus)
            }

            fun value(name: String): Int =
                state
                    .getVar(language.getRegister(name), Reason.INSPECT)
                    .foldIndexed(0) { index, accumulated, byte -> accumulated or ((byte.toInt() and 255) shl (index * 8)) }
            assertEquals(0x180, value("PC"))
            assertEquals(0xc100, value("SP"))
            assertEquals(0xc0ff, value("HL"))
            assertEquals(0, value("F"))
            executor.execute(PcodeProgram(raw, pcode.drop(callIndex + 1)), bus)
            assertEquals(0x180, value("PC"))
            assertEquals(0xc100, value("SP"))
            assertEquals(listOf(0x80, 1), state.getVar(address(0xc0fe), 2, true, Reason.INSPECT).map { it.toInt() and 255 })
            executor.execute(PcodeProgram.fromInstruction(program.listing.getInstructionAt(address(0x180)), false), bus)
            assertEquals(0x66, value("A"))
            val manager = AutoAnalysisManager.getAnalysisManager(program)
            repeat(2) {
                program.withTransaction {
                    manager.reAnalyzeAll(AddressSet(address(0x150), address(0x182)))
                    manager.startAnalysis(monitor)
                }
                assertEquals(address(0x180), program.listing.getInstructionAt(address(0x150)).fallThrough)
                assertEquals(ghidra.program.model.listing.FlowOverride.NONE, program.listing.getInstructionAt(address(0x150)).flowOverride)
                assertEquals(0x55, program.memory.getByte(address(0x154)).toInt() and 255)
                assertNotNull(program.listing.getInstructionAt(address(0x153)))
                assertTrue(!program.functionManager.getFunctionAt(address(0x200)).hasNoReturn())
            }
            val decompiler = DecompInterface()
            try {
                decompiler.setOptions(ghidra.app.decompiler.DecompileOptions())
                assertTrue(decompiler.openProgram(program))
                val debugDump = java.io.File.createTempFile("sa01-nonlocal-native-", ".xml")
                decompiler.enableDebug(debugDump)
                val result = decompiler.decompileFunction(program.functionManager.getFunctionAt(address(0x150)), 30, monitor)
                println("SA01_NONLOCAL_NATIVE_DEBUG=${debugDump.absolutePath}")
                println("SA01_NONLOCAL_NATIVE_C=${result.decompiledFunction?.c}")
                if (result.highFunction != null) {
                    for (op in result.highFunction.pcodeOps.asSequence()) {
                        println("SA01_NONLOCAL_HIGH ${op.seqnum} $op")
                    }
                }
                assertTrue(result.decompileCompleted(), result.errorMessage)
                assertTrue(result.decompiledFunction.c.contains("nonlocal_target("), result.decompiledFunction.c)
                // The default ABI may infer HL as the return value and eliminate dead A=66.
                // Native control must still reach the actual destination's RET, never the old RET.
                assertTrue(
                    result.highFunction.pcodeOps.asSequence().any {
                        it.opcode == PcodeOp.RETURN && it.seqnum.target == address(0x182)
                    },
                    result.decompiledFunction.c,
                )
                assertTrue(!result.decompiledFunction.c.contains("0x55"), result.decompiledFunction.c)
                assertTrue(
                    result.highFunction.pcodeOps
                        .asSequence()
                        .none { it.seqnum.target.offset in 0x153L..0x155L },
                    result.decompiledFunction.c,
                )
            } finally {
                decompiler.dispose()
            }
            program.withTransaction { program.functionManager.getFunctionAt(target).setNoReturn(true) }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(program, listOf(config), monitor) }
            assertTrue(program.functionManager.getFunctionAt(target).hasNoReturn())
        } finally {
            program.release(consumer)
        }
    }
}
