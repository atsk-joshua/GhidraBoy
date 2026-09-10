package fi.gekkio.ghidraboy

import com.google.gson.JsonParser
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
import ghidra.program.model.address.Address
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

/** Independent byte expectations and real p-code execution; native transport is a separate gate. */
class OrdinaryEntryAccessTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY
    private val kernel = "3e01ea00202100607eea00c03e02ea00207eea01c0fa0020ea02c0c9"

    private fun fixture(
        code: String = kernel,
        action: (ProgramDB, Function) -> Unit,
    ) {
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x19
        bytes[0x148] = 1
        bytes[0x2000] = 0x6e
        bytes[0x6000] = 0x31
        bytes[0xa000] = 0xa7.toByte()
        bytes[0xe000] = 0xd3.toByte()
        val instructions = HexFormat.of().parseHex(code)
        instructions.copyInto(bytes, 0x150)
        val owner = Any()
        val p = ProgramDB("ordinary-entry-access", language, language.defaultCompilerSpec, owner)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, monitor, MessageLog())
            }
            p.withTransaction {
                val body = AddressSet(address(0x150), address(0x150 + instructions.size.toLong() - 1))
                Disassembler.getDisassembler(p, monitor, null).disassemble(address(0x150), body)
                p.functionManager.createFunction("ordinary_kernel", address(0x150), body, SourceType.USER_DEFINED)
            }
            action(p, p.functionManager.getFunctionAt(address(0x150)))
        } finally {
            p.release(owner)
        }
    }

    /** This test bus implements only the self-authored four-bank specimen, independently of the proof. */
    class SpecimenBus(
        private val program: ProgramDB,
        private val state: BytesPcodeExecutorState,
        private val arithmetic: BytesPcodeArithmetic,
    ) : AnnotatedPcodeUseropLibrary<ByteArray>() {
        val writes = mutableListOf<Pair<Long, Long>>()

        @PcodeUserop
        fun gb_direct_write8(
            cpu: Long,
            value: Long,
        ) {
            writes.add(cpu to value)
            val ram = program.addressFactory.defaultAddressSpace
            if (cpu == 0x2000L) {
                // Independent MBC5 specimen oracle: low selector, four banks, CPU6000 => bank*4000+2000.
                val physical = ProgramMapping.fileToStatic(program, (value and 3) * 0x4000 + 0x2000).first()
                val byte = program.memory.getByte(physical).toLong() and 255
                state.setVar(ram.getAddress(0x6000), 1, true, arithmetic.fromConst(byte, 1))
            } else {
                require(cpu in 0xc000L..0xc002L)
                state.setVar(ram.getAddress(cpu), 1, true, arithmetic.fromConst(value, 1))
            }
        }
    }

    private data class Execution(
        val tuple: List<Int>,
        val writes: List<Pair<Long, Long>>,
        val registers: Map<String, Int>,
    )

    private fun execute(
        p: ProgramDB,
        f: Function,
        injected: Array<PcodeOp>?,
        stack: Int,
    ): Execution {
        val state = BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE)
        val arithmetic = BytesPcodeArithmetic.forLanguage(language)
        val executor = PcodeExecutor(language as SleighLanguage, arithmetic, state, Reason.EXECUTE_READ)
        // Concrete execution witnesses only: these values are never supplied to static preview/install.
        val initial =
            mapOf(
                "A" to 0x83,
                "F" to 0xb0,
                "BC" to 0x1234,
                "DE" to 0x5678,
                "HL" to 0x4321,
                "SP" to stack,
                "PC" to 0x150,
            )
        for ((name, value) in initial) {
            val register = language.getRegister(name)
            state.setVar(register, arithmetic.fromConst(value, register.minimumByteSize))
        }
        state.setVar(address(0x2000), 1, true, arithmetic.fromConst(0x6e, 1))
        state.setVar(address(stack.toLong()), 1, true, arithmetic.fromConst(0x90, 1))
        state.setVar(address(stack.toLong() + 1), 1, true, arithmetic.fromConst(1, 1))
        val bus = SpecimenBus(p, state, arithmetic)
        val source = PcodeProgram.fromInstruction(p.listing.getInstructionAt(f.entryPoint), false)
        if (injected != null) {
            executor.execute(PcodeProgram(source, injected.toList()), bus)
        } else {
            for (instruction in p.listing.getInstructions(f.body, true)) {
                executor.execute(PcodeProgram.fromInstruction(instruction, false), bus)
            }
        }

        fun value(bytes: ByteArray): Int = bytes.foldIndexed(0) { i, n, b -> n or ((b.toInt() and 255) shl (8 * i)) }

        return Execution(
            (0xc000L..0xc002L).map { value(state.getVar(address(it), 1, true, Reason.INSPECT)) },
            bus.writes.toList(),
            initial.keys.associateWith { value(state.getVar(language.getRegister(it), Reason.INSPECT)) },
        )
    }

    private fun emitted(
        p: ProgramDB,
        alias: Address,
    ): Array<PcodeOp> = OrdinaryEntryAccess.emit(p, alias, 0x200000, monitor)

    private fun rawPcode(
        p: ProgramDB,
        f: Function,
    ): List<String> =
        p.listing
            .getInstructions(f.body, true)
            .iterator()
            .asSequence()
            .flatMap { it.getPcode(false).asSequence() }
            .map { it.toString() }
            .toList()

    @Test
    fun `unknown entry proves physical bytes without mutating canonical program`() =
        fixture { p, f ->
            for (name in listOf("A", "F", "BC", "DE", "HL", "SP")) {
                assertNull(p.programContext.getValue(language.getRegister(name), f.entryPoint, false), name)
            }
            assertEquals("absent", SoftwareCallRegistry.configurationIdentity(p))
            val revision = p.modificationNumber
            val body = AddressSet(f.body)
            val raw = rawPcode(p, f)
            val proof = OrdinaryEntryAccess.preview(p, f, monitor)
            assertEquals(revision, p.modificationNumber)
            assertEquals(listOf(0x31, 0xa7, 0x6e), proof.replacements().map { it.value().toInt() })
            assertTrue(proof.replacements().all { it.width() == 1 })
            val physicalSources =
                proof.replacements().map {
                    it
                        .sources()
                        .single()
                        .physical()
                }
            assertEquals(listOf(1, 2, 0), physicalSources.map { it.bank() })
            assertTrue(physicalSources.all { it.offset() == 0x2000 })
            val alias = OrdinaryEntryAccess.install(p, proof, monitor)
            assertTrue(OrdinaryEntryAccess.registered(p, alias))
            assertFalse(OrdinaryEntryAccess.registered(p, f.entryPoint))
            assertEquals(body, f.body)
            assertEquals(raw, rawPcode(p, f))
            assertFalse(p.memory.getBlock(alias).isWrite)
            assertEquals("absent", SoftwareCallRegistry.configurationIdentity(p))
        }

    @Test
    fun `read replacement preserves ordered bus effects and symbolic return frame`() =
        fixture { p, f ->
            val alias = OrdinaryEntryAccess.install(p, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
            val ops = emitted(p, alias)
            assertEquals(2, ops.count { it.opcode == PcodeOp.LOAD }, "Only the two real RET stack reads remain")
            assertTrue(ops.filter { it.opcode == PcodeOp.LOAD }.all { it.output.size == 1 && it.getInput(1).size == 2 })
            assertEquals(1, ops.count { it.opcode == PcodeOp.RETURN })
            assertEquals(PcodeOp.RETURN, ops.last().opcode)
            assertTrue(ops.last().getInput(0).isRegister)
            for (stack in listOf(0xc080, 0xcffd)) {
                val original = execute(p, f, null, stack)
                val lowered = execute(p, f, ops, stack)
                assertEquals(listOf(0x31, 0xa7, 0x6e), original.tuple)
                assertEquals(original, lowered)
                assertEquals(
                    listOf(0x2000L to 1L, 0xc000L to 0x31L, 0x2000L to 2L, 0xc001L to 0xa7L, 0xc002L to 0x6eL),
                    lowered.writes,
                )
                assertEquals(0x190, lowered.registers["PC"])
                assertEquals(stack + 2, lowered.registers["SP"])
                assertEquals(0xb0, lowered.registers["F"])
                assertEquals(0x1234, lowered.registers["BC"])
                assertEquals(0x5678, lowered.registers["DE"])
            }
        }

    @Test
    fun `byte mutation rejects stale proof and refresh preserves neighbor independence`() =
        fixture { p, f ->
            val alias = OrdinaryEntryAccess.install(p, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
            assertEquals(listOf(0x31, 0xa7, 0x6e), execute(p, f, emitted(p, alias), 0xc080).tuple)
            val marker = ProgramMapping.fileToStatic(p, 0xa000).single()
            val headerBefore = ByteArray(3).also { p.memory.getBytes(address(0x14d), it) }
            p.withTransaction { p.memory.setByte(marker, 0xd4.toByte()) }
            assertFalse(p.memory.getBlock(marker).isWrite)
            assertThrows(IllegalArgumentException::class.java) { emitted(p, alias) }
            OrdinaryEntryAccess.refresh(p, alias, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
            assertEquals(listOf(0x31, 0xd4, 0x6e), execute(p, f, emitted(p, alias), 0xc080).tuple)
            val neighbor = ProgramMapping.fileToStatic(p, 0xa001).single()
            p.withTransaction { p.memory.setByte(neighbor, 0xb9.toByte()) }
            // A conservative full-image fingerprint may reject even an unused byte; refresh must retain the result.
            OrdinaryEntryAccess.refresh(p, alias, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
            assertEquals(listOf(0x31, 0xd4, 0x6e), execute(p, f, emitted(p, alias), 0xc080).tuple)
            assertTrue(headerBefore.contentEquals(ByteArray(3).also { p.memory.getBytes(address(0x14d), it) }))
        }

    @Test
    fun `same selector legitimately yields the same value twice`() =
        fixture(kernel.replace("3e02", "3e01")) { p, f ->
            val alias = OrdinaryEntryAccess.install(p, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
            val result = execute(p, f, emitted(p, alias), 0xc080)
            assertEquals(listOf(0x31, 0x31, 0x6e), result.tuple)
            assertEquals(execute(p, f, null, 0xc080), result)
        }

    @Test
    fun `actual unknown pointer and branching code refuse proof without mutations`() {
        // Remove the actual HL producer, preserving addresses with three NOPs.
        for (code in listOf(kernel.replace("210060", "000000"), "28003e017ec9")) {
            fixture(code) { p, f ->
                val revision = p.modificationNumber
                assertThrows(IllegalArgumentException::class.java) { OrdinaryEntryAccess.preview(p, f, monitor) }
                assertEquals(revision, p.modificationNumber)
                assertEquals(1, p.functionManager.functionCount)
            }
        }
    }

    @Test
    fun `serialized replacement values and sources cannot certify themselves`() =
        fixture { p, f ->
            val alias = OrdinaryEntryAccess.install(p, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
            val options = p.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS)
            val key = alias.toString()
            val original = options.getString(key, "")
            val dependencies = OrdinaryEntryAccess.preview(p, f, monitor).dependencies()
            for (field in listOf("value", "physical-source")) {
                val changed = JsonParser.parseString(original).asJsonObject
                val replacement =
                    changed.getAsJsonObject("proof").getAsJsonArray("replacements")[0].asJsonObject
                if (field == "value") {
                    replacement.addProperty("value", 0x99)
                } else {
                    replacement
                        .getAsJsonArray("sources")[0]
                        .asJsonObject
                        .getAsJsonObject("physical")
                        .addProperty("bank", 3)
                }
                p.withTransaction { options.setString(key, changed.toString()) }
                // Registration JSON is intentionally not a dependency: independent derivation must catch this.
                assertEquals(dependencies, OrdinaryEntryAccess.preview(p, f, monitor).dependencies())
                val failure = assertThrows(IllegalArgumentException::class.java) { emitted(p, alias) }
                assertTrue(failure.message.orEmpty().contains("Changed ordinary proof record"), failure.message)
                p.withTransaction { options.setString(key, original) }
                assertEquals(listOf(0x31, 0xa7, 0x6e), execute(p, f, emitted(p, alias), 0xc080).tuple)
            }
        }

    @Test
    fun `same bytes in another Program do not confer proof ownership`() =
        fixture { first, firstFunction ->
            val proof = OrdinaryEntryAccess.preview(first, firstFunction, monitor)
            fixture { second, secondFunction ->
                val revision = second.modificationNumber
                val body = AddressSet(secondFunction.body)
                val count = second.functionManager.functionCount
                val failure =
                    assertThrows(IllegalArgumentException::class.java) {
                        OrdinaryEntryAccess.install(second, proof, monitor)
                    }
                assertTrue(failure.message.orEmpty().contains("foreign"), failure.message)
                assertEquals(revision, second.modificationNumber)
                assertEquals(body, secondFunction.body)
                assertEquals(count, second.functionManager.functionCount)
                assertFalse(OrdinaryEntryAccess.registered(second, secondFunction.entryPoint))
            }
        }

    @Test
    fun `a valid alternate function proof cannot replace the aliased source`() =
        fixture { p, f ->
            // Both sources exist before registration; only the later proof JSON is changed by the attack.
            val otherBytes = HexFormat.of().parseHex(kernel)
            otherBytes[1] = 2
            otherBytes[13] = 1
            val otherStart = address(0x250)
            val otherBody = AddressSet(otherStart, otherStart.add(otherBytes.size.toLong() - 1))
            p.withTransaction {
                p.memory.setBytes(otherStart, otherBytes)
                Disassembler.getDisassembler(p, monitor, null).disassemble(otherStart, otherBody)
                p.functionManager.createFunction("other_ordinary_kernel", otherStart, otherBody, SourceType.USER_DEFINED)
            }
            val alias = OrdinaryEntryAccess.install(p, OrdinaryEntryAccess.preview(p, f, monitor), monitor)
            val otherFunction = p.functionManager.getFunctionAt(otherStart)
            val otherProof = OrdinaryEntryAccess.preview(p, otherFunction, monitor)
            assertEquals(listOf(0xa7, 0x31, 0x6e), otherProof.replacements().map { it.value().toInt() })
            val options = p.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS)
            val original = options.getString(alias.toString(), "")
            val substitution = JsonParser.parseString(original).asJsonObject
            substitution.add("proof", ProgramMapping.JSON.toJsonTree(otherProof))
            val dependencies = OrdinaryEntryAccess.preview(p, f, monitor).dependencies()
            p.withTransaction { options.setString(alias.toString(), substitution.toString()) }
            assertEquals(dependencies, OrdinaryEntryAccess.preview(p, f, monitor).dependencies())
            assertThrows(IllegalArgumentException::class.java) { emitted(p, alias) }
            p.withTransaction { options.setString(alias.toString(), original) }
            assertEquals(listOf(0x31, 0xa7, 0x6e), execute(p, f, emitted(p, alias), 0xc080).tuple)
        }
}
