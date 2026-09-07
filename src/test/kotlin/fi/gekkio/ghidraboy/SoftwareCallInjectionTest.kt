package fi.gekkio.ghidraboy

import ghidra.app.decompiler.DecompInterface
import ghidra.app.emulator.EmulatorHelper
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.plugin.core.analysis.FindNoReturnFunctionsAnalyzer
import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.pcode.exec.BytesPcodeArithmetic
import ghidra.pcode.exec.BytesPcodeExecutorState
import ghidra.pcode.exec.PcodeExecutor
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason
import ghidra.pcode.exec.PcodeProgram
import ghidra.pcode.exec.PcodeStateCallbacks
import ghidra.pcode.exec.PcodeUseropLibrary
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
import ghidra.xml.XmlPullParserFactory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.xml.sax.helpers.DefaultHandler

/** Mechanism experiment, not a recognizer or production software-call acceptance claim. */
class SoftwareCallInjectionTest : IntegrationTest() {
    @Test
    fun `callfixup retains hardware frame and adjusted continuation through repeated analysis`() {
        val consumer = Any()
        val p = ProgramDB("software-call-mechanism", language, language.defaultCompilerSpec, consumer)
        val monitor = TaskMonitor.DUMMY
        try {
            p.withTransaction {
                p.memory.createInitializedBlock("memory", address(0), 0x10000, 0, monitor, false)
                // RST 08; inline target 0300; LD (c100), A; RET.
                p.memory.setBytes(address(0x100), byteArrayOf(0xcf.toByte(), 0, 3, 0xea.toByte(), 0, 0xc1.toByte(), 0xc9.toByte()))
                // POP HL; LD E,(HL); INC HL; LD D,(HL); INC HL; PUSH HL; PUSH DE; RET.
                p.memory.setBytes(
                    address(8),
                    byteArrayOf(0xe1.toByte(), 0x5e, 0x23, 0x56, 0x23, 0xe5.toByte(), 0xd5.toByte(), 0xc9.toByte()),
                )
                p.memory.setBytes(address(0x300), byteArrayOf(0x3e, 0x5a, 0x37, 0xc9.toByte()))
                val dis = Disassembler.getDisassembler(p, monitor, null)
                dis.disassemble(address(8), AddressSet(address(8), address(15)))
                dis.disassemble(address(0x100), AddressSet(address(0x100)))
                dis.disassemble(address(0x103), AddressSet(address(0x103), address(0x106)))
                dis.disassemble(address(0x300), AddressSet(address(0x300), address(0x303)))
                p.functionManager.createFunction(
                    "software_helper",
                    address(8),
                    AddressSet(address(8), address(15)),
                    SourceType.USER_DEFINED,
                )
                p.functionManager.createFunction(
                    "callee",
                    address(0x300),
                    AddressSet(address(0x300), address(0x303)),
                    SourceType.USER_DEFINED,
                )
                val body = AddressSet(address(0x100))
                body.add(address(0x103), address(0x106))
                p.functionManager.createFunction("caller", address(0x100), body, SourceType.USER_DEFINED)
                for (site in listOf(0x110L, 0x120L)) {
                    p.memory.setBytes(address(site), byteArrayOf(0xcf.toByte(), 0, 3))
                    dis.disassemble(address(site), AddressSet(address(site)))
                }
            }
            // Negative control: ordinary stock heuristic sees three calls followed by payload.
            // Exercise its actual decision before installing the verified returning specialization.
            p.withTransaction {
                val analyzer = FindNoReturnFunctionsAnalyzer()
                assertTrue(analyzer.added(p, AddressSet(address(0x100), address(0x120)), monitor, MessageLog()))
            }
            assertTrue(p.functionManager.getFunctionAt(address(8)).hasNoReturn())
            assertEquals(FlowOverride.CALL_RETURN, p.listing.getInstructionAt(address(0x100)).flowOverride)
            // Independent execution checks the real stack at helper entry, target entry and return.
            val emulator = EmulatorHelper(p)
            try {
                emulator.writeRegister("PC", 0x100)
                emulator.writeRegister("SP", 0xd000)
                emulator.writeRegister("F", 0x80)
                assertTrue(emulator.step(monitor), emulator.lastError)
                assertEquals(8, emulator.readRegister("PC").toInt())
                assertEquals(0xcffe, emulator.readRegister("SP").toInt())
                assertEquals(1, emulator.readMemoryByte(address(0xcffe)).toInt() and 255)
                assertEquals(1, emulator.readMemoryByte(address(0xcfff)).toInt() and 255)
                repeat(8) { assertTrue(emulator.step(monitor), emulator.lastError) }
                assertEquals(0x300, emulator.readRegister("PC").toInt())
                assertEquals(0xcffe, emulator.readRegister("SP").toInt())
                assertEquals(3, emulator.readMemoryByte(address(0xcffe)).toInt() and 255)
                assertEquals(1, emulator.readMemoryByte(address(0xcfff)).toInt() and 255)
                assertEquals(0, emulator.readMemoryByte(address(0xcffc)).toInt() and 255)
                assertEquals(3, emulator.readMemoryByte(address(0xcffd)).toInt() and 255)
                repeat(3) { assertTrue(emulator.step(monitor), emulator.lastError) }
                assertEquals(0x103, emulator.readRegister("PC").toInt())
                assertEquals(0xd000, emulator.readRegister("SP").toInt())
                assertEquals(0x5a, emulator.readRegister("A").toInt())
                assertEquals(0x90, emulator.readRegister("F").toInt())
            } finally {
                emulator.dispose()
            }
            // A single-site, exact payload specialization makes the injection experiment independent
            // of unresolved ROM-memory propagation. It is deliberately not a reusable convention.
            val xml =
                """
                <callfixup name="sa01_mechanism"><pcode><body><![CDATA[
                local nextbyte:2 = SP + 1;
                HL = zext(*:1 SP) | (zext(*:1 nextbyte) << 8); SP = SP + 2;
                E = 0; HL = HL + 1; D = 3; HL = HL + 1;
                SP = SP - 1; *:1 SP = H;
                SP = SP - 1; *:1 SP = L;
                SP = SP - 1; *:1 SP = D;
                SP = SP - 1; *:1 SP = E;
                SP = SP + 2;
                call 0x0300;
                ]]></body></pcode></callfixup>
                """.trimIndent()
            val parser = XmlPullParserFactory.create(xml, "SA01 mechanism", DefaultHandler(), false)
            val payload =
                try {
                    p.compilerSpec.pcodeInjectLibrary.restoreXmlInject(
                        "SA01 mechanism",
                        "sa01_mechanism",
                        InjectPayload.CALLFIXUP_TYPE,
                        parser,
                    )
                } finally {
                    parser.dispose()
                }
            p.withTransaction {
                val helper = p.functionManager.getFunctionAt(address(8))
                helper.callFixup = "sa01_mechanism"
                // One explicit repair, before ordinary repeated analysis. No analyzer is disabled.
                helper.setNoReturn(false)
                for (site in listOf(0x100L, 0x110L, 0x120L)) {
                    val instruction = p.listing.getInstructionAt(address(site))
                    instruction.flowOverride = FlowOverride.NONE
                    instruction.setFallThrough(address(site + 3))
                }
            }
            assertTrue(payload.isFallThru)
            val context = InjectContext()
            context.baseAddr = address(0x100)
            context.nextAddr = address(0x100)
            context.callAddr = address(8)
            val injected = payload.getPcode(p, context)
            assertEquals(4, injected.count { it.opcode == PcodeOp.STORE })
            assertEquals(1, injected.count { it.opcode == PcodeOp.CALL })
            val raw = p.listing.getInstructionAt(address(0x100)).getPcode(false)
            assertEquals(2, raw.count { it.opcode == PcodeOp.STORE })
            val executorState = BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE)
            val arithmetic = BytesPcodeArithmetic.forLanguage(language)
            val executor = PcodeExecutor(language as SleighLanguage, arithmetic, executorState, Reason.EXECUTE_READ)
            for (name in listOf("A", "F", "B", "C", "D", "E", "H", "L", "SP", "PC")) {
                val register = language.getRegister(name)
                val value =
                    when (name) {
                        "SP" -> 0xd000
                        "PC" -> 0x100
                        "F" -> 0x80
                        else -> 0
                    }
                executorState.setVar(register, arithmetic.fromConst(value, register.minimumByteSize))
            }
            val sourceProgram = PcodeProgram.fromInstruction(p.listing.getInstructionAt(address(0x100)), false)
            executor.execute(sourceProgram, PcodeUseropLibrary.nil())
            executor.execute(PcodeProgram(sourceProgram, injected.toList()), PcodeUseropLibrary.nil())

            fun registerValue(name: String): Int =
                executorState.getVar(language.getRegister(name), Reason.INSPECT).let { bytes ->
                    bytes.foldIndexed(0) { index, value, byte -> value or ((byte.toInt() and 255) shl (index * 8)) }
                }
            assertEquals(0x300, registerValue("PC"))
            assertEquals(0xcffe, registerValue("SP"))
            assertEquals(0x103, registerValue("HL"))
            assertEquals(0x300, registerValue("DE"))
            assertEquals(0, registerValue("BC"))
            assertEquals(0x80, registerValue("F"))
            for ((offset, expected) in listOf(0xcffcL to 0, 0xcffdL to 3, 0xcffeL to 3, 0xcfffL to 1)) {
                assertEquals(expected, executorState.getVar(address(offset), 1, true, Reason.INSPECT)[0].toInt() and 255)
            }
            for (offset in listOf(0x300L, 0x302L, 0x303L)) {
                executor.execute(PcodeProgram.fromInstruction(p.listing.getInstructionAt(address(offset)), false), PcodeUseropLibrary.nil())
            }
            assertEquals(0x103, registerValue("PC"))
            assertEquals(0xd000, registerValue("SP"))
            assertEquals(0x5a, registerValue("A"))
            assertEquals(0x90, registerValue("F"))
            assertTrue(InstructionInterpretation.unresolved(p.listing.getInstructionAt(address(0x100))) != null)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                val result = decompiler.decompileFunction(p.functionManager.getFunctionAt(address(0x100)), 15, monitor)
                assertTrue(result.decompileCompleted(), result.errorMessage)
                val c = result.decompiledFunction.c
                assertTrue(c.contains("callee("), c)
                assertTrue(c.contains("c100"), c)
                assertTrue(
                    result.highFunction.pcodeOps.asSequence().any {
                        it.opcode == PcodeOp.CALL &&
                            it.getInput(0).address == address(0x300)
                    },
                    c,
                )
            } finally {
                decompiler.dispose()
            }
            val manager = AutoAnalysisManager.getAnalysisManager(p)
            repeat(2) {
                p.withTransaction {
                    manager.reAnalyzeAll(AddressSet(address(0x100), address(0x106)))
                    manager.startAnalysis(monitor)
                }
                assertFalse(p.functionManager.getFunctionAt(address(8)).hasNoReturn())
                assertEquals(FlowOverride.NONE, p.listing.getInstructionAt(address(0x100)).flowOverride)
                assertEquals(address(0x103), p.listing.getInstructionAt(address(0x100)).fallThrough)
                assertNotNull(p.listing.getInstructionAt(address(0x103)))
            }
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `physical overlay call survives ordinary native transport after resolving reference precedence`() {
        val consumer = Any()
        val p = ProgramDB("software-call-overlay-mechanism", language, language.defaultCompilerSpec, consumer)
        val data = ByteArray(0x10000)
        data[0x147] = 0x19
        data[0x148] = 1
        byteArrayOf(0xcd.toByte(), 0, 0x40, 0xc9.toByte()).copyInto(data, 0x150)
        data[0x8000] = 0xc9.toByte()
        try {
            ByteArrayProvider(data).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true, TaskMonitor.DUMMY, MessageLog())
            }
            val target = ProgramMapping.fileToStatic(p, 0x8000).single()
            p.withTransaction {
                val dis = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                dis.disassemble(address(0x150), AddressSet(address(0x150), address(0x153)))
                dis.disassemble(target, AddressSet(target))
                p.functionManager.createFunction("physical_callee", target, AddressSet(target), SourceType.USER_DEFINED)
                p.functionManager.createFunction(
                    "physical_caller",
                    address(0x150),
                    AddressSet(address(0x150), address(0x153)),
                    SourceType.USER_DEFINED,
                )
                val ref =
                    p.referenceManager.addMemoryReference(
                        address(0x150),
                        target,
                        RefType.CALL_OVERRIDE_UNCONDITIONAL,
                        SourceType.USER_DEFINED,
                        -1,
                    )
                p.referenceManager.setPrimary(ref, true)
            }
            val instruction = p.listing.getInstructionAt(address(0x150))
            val physicalRef = instruction.referencesFrom.single { it.referenceType == RefType.CALL_OVERRIDE_UNCONDITIONAL }
            assertTrue(physicalRef.isPrimary)
            assertEquals(target, physicalRef.toAddress)
            assertEquals(
                address(0x4000),
                instruction
                    .getPcode(false)
                    .single { it.opcode == PcodeOp.CALL }
                    .getInput(0)
                    .address,
            )
            // Ghidra's backward-compatible primary ordinary CALL reference takes precedence over
            // the newer CALL_OVERRIDE_UNCONDITIONAL, even when it is just the decoded default.
            assertEquals(
                address(0x4000),
                instruction
                    .getPcode(true)
                    .single { it.opcode == PcodeOp.CALL }
                    .getInput(0)
                    .address,
            )
            val ordinaryDecompiler = DecompInterface()
            try {
                assertTrue(ordinaryDecompiler.openProgram(p))
                val result = ordinaryDecompiler.decompileFunction(p.functionManager.getFunctionAt(address(0x150)), 15, TaskMonitor.DUMMY)
                println(
                    "SA01_DEFAULT_PRIMARY_NATIVE completed=${result.decompileCompleted()} error=${result.errorMessage} c=${result.decompiledFunction?.c}",
                )
                if (result.decompileCompleted()) {
                    assertFalse(result.decompiledFunction.c.contains("physical_callee("), result.decompiledFunction.c)
                    assertTrue(
                        result.highFunction.pcodeOps.asSequence().none {
                            it.opcode == PcodeOp.CALL &&
                                it.getInput(0).address == target
                        },
                    )
                }
            } finally {
                ordinaryDecompiler.dispose()
            }
            p.withTransaction {
                // Preserve the decoded reference but explicitly remove its competing primary flag.
                for (ref in instruction.referencesFrom.filter { it.referenceType.isCall && !it.referenceType.isOverride }) {
                    p.referenceManager.setPrimary(ref, false)
                }
            }
            assertEquals(
                target,
                instruction
                    .getPcode(true)
                    .single { it.opcode == PcodeOp.CALL }
                    .getInput(0)
                    .address,
            )
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(p))
                val result = decompiler.decompileFunction(p.functionManager.getFunctionAt(address(0x150)), 15, TaskMonitor.DUMMY)
                assertTrue(result.decompileCompleted(), result.errorMessage)
                assertTrue(result.decompiledFunction.c.contains("physical_callee("), result.decompiledFunction.c)
                val nativeCall =
                    result.highFunction.pcodeOps
                        .asSequence()
                        .single { it.opcode == PcodeOp.CALL }
                println(
                    "SA01_PHYSICAL_NATIVE_CALL target=${nativeCall.getInput(
                        0,
                    ).address} spaceId=${nativeCall.getInput(
                        0,
                    ).address.addressSpace.spaceID} expected=$target expectedSpaceId=${target.addressSpace.spaceID}",
                )
                assertEquals(target, nativeCall.getInput(0).address)
                assertEquals(
                    p.functionManager
                        .getFunctionAt(target)
                        .symbol.id,
                    p.symbolTable.getPrimarySymbol(nativeCall.getInput(0).address).id,
                )
            } finally {
                decompiler.dispose()
            }
            // A separate representation limit concerns a single function's body, not calls.
            val mixedBody = AddressSet(address(0x150), address(0x153))
            mixedBody.add(target)
            val error =
                assertThrows(IllegalArgumentException::class.java) {
                    p.withTransaction { p.functionManager.getFunctionAt(address(0x150)).body = mixedBody }
                }
            assertTrue(error.message.orEmpty().contains("single address space"), error.message)
            assertEquals(AddressSet(address(0x150), address(0x153)), p.functionManager.getFunctionAt(address(0x150)).body)
        } finally {
            p.release(consumer)
        }
    }
}
