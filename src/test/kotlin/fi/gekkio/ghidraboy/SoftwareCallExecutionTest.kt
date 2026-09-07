package fi.gekkio.ghidraboy

import ghidra.app.emulator.EmulatorHelper
import ghidra.app.plugin.assembler.Assemblers
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Architectural frame oracle: no software-call overrides or injected call summaries. */
class SoftwareCallExecutionTest : IntegrationTest() {
    private fun fixture(action: (ProgramDB, EmulatorHelper, CartridgeBusEmulation.Context) -> Unit) {
        val consumer = Any()
        val program = ProgramDB("self-authored software call execution", language, language.defaultCompilerSpec, consumer)
        try {
            val bytes = ByteArray(0x10000)
            bytes[0x147] = 0x11 // MBC3, four physical ROM banks.
            bytes[0x148] = 1
            var checksum = 0
            for (index in 0x134..0x14c) checksum = (checksum - (bytes[index].toInt() and 255) - 1) and 255
            bytes[0x14d] = checksum.toByte()
            val global = bytes.indices.filter { it != 0x14e && it != 0x14f }.sumOf { bytes[it].toInt() and 255 }
            bytes[0x14e] = (global ushr 8).toByte()
            bytes[0x14f] = global.toByte()
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(program, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, TaskMonitor.DUMMY, MessageLog())
            }
            val emulator = EmulatorHelper(program)
            try {
                CartridgeBusEmulation.attach(emulator, MapperState.reset()).use { bus ->
                    emulator.writeRegister("PC", 0x150)
                    emulator.writeRegister("SP", 0xc100)
                    emulator.writeRegister("AF", 0x12b0)
                    emulator.writeRegister("BC", 0x4567)
                    action(program, emulator, bus)
                }
            } finally {
                emulator.dispose()
            }
        } finally {
            program.release(consumer)
        }
    }

    private fun code(
        program: ProgramDB,
        at: Int,
        vararg instructions: String,
    ) = program.withTransaction { Assemblers.getAssembler(program).assemble(address(at.toLong()), *instructions).toList() }

    private fun runTo(
        emulator: EmulatorHelper,
        pc: Int,
        limit: Int = 100,
    ) {
        repeat(limit) {
            if (emulator.readRegister("PC").toInt() == pc) return
            assertTrue(emulator.step(TaskMonitor.DUMMY), emulator.lastError)
        }
        assertEquals(pc, emulator.readRegister("PC").toInt(), "bounded execution did not reach checkpoint")
    }

    private fun word(
        emulator: EmulatorHelper,
        at: Int,
    ): Int =
        (emulator.readMemoryByte(address(at.toLong())).toInt() and 255) or
            ((emulator.readMemoryByte(address((at + 1).toLong())).toInt() and 255) shl 8)

    @Test
    fun `hardware CALL and register transfer retain both real return frames`() =
        fixture { p, e, _ ->
            code(p, 0x150, "LD HL, 0x300", "CALL 0x200", "NOP")
            code(p, 0x200, "LD DE, 0x220", "PUSH DE", "JP HL")
            code(p, 0x220, "RET")
            code(p, 0x300, "XOR A", "SCF", "RET")
            runTo(e, 0x300)
            assertEquals(0xc0fc, e.readRegister("SP").toInt())
            assertEquals(0x220, word(e, 0xc0fc))
            assertEquals(0x156, word(e, 0xc0fe))
            runTo(e, 0x156)
            assertEquals(0xc100, e.readRegister("SP").toInt())
            assertEquals(0x0090, e.readRegister("AF").toInt())
            assertEquals(0x4567, e.readRegister("BC").toInt())
        }

    @Test
    fun `manual continuation and RET target transfer consume distinct pushed words`() =
        fixture { p, e, _ ->
            code(p, 0x150, "LD DE, 0x180", "PUSH DE", "LD HL, 0x300", "PUSH HL", "RET")
            code(p, 0x180, "NOP")
            code(p, 0x300, "LD B, 0x99", "RET")
            runTo(e, 0x300)
            assertEquals(0xc0fe, e.readRegister("SP").toInt())
            assertEquals(0x180, word(e, 0xc0fe))
            assertEquals(0x300, word(e, 0xc0fc))
            runTo(e, 0x180)
            assertEquals(0xc100, e.readRegister("SP").toInt())
            assertEquals(0x9967, e.readRegister("BC").toInt())
            assertEquals(0x12b0, e.readRegister("AF").toInt())
        }

    @Test
    fun `three and four inline bytes adjust continuation without executing payload`() {
        for (length in listOf(3, 4)) {
            fixture { p, e, bus ->
                code(p, 0x150, "RST 0x28")
                p.withTransaction { p.memory.setBytes(address(0x151), byteArrayOf(2, 0, 3, 0xff.toByte())) }
                val body = mutableListOf("POP HL", "LD A, (HL+)", "LD (0x2000), A", "LD E, (HL)", "INC HL", "LD D, (HL)", "INC HL")
                if (length == 4) body.add("INC HL")
                body.addAll(listOf("PUSH HL", "PUSH DE", "RET"))
                code(p, 0x28, *body.toTypedArray())
                code(p, 0x300, "XOR A", "SCF", "RET")
                runTo(e, 0x300)
                assertEquals(0xc0fe, e.readRegister("SP").toInt())
                assertEquals(0x151 + length, word(e, 0xc0fe))
                assertEquals(0x300, word(e, 0xc0fc))
                assertEquals(2, bus.state().romLow())
                runTo(e, 0x151 + length)
                assertEquals(0xc100, e.readRegister("SP").toInt())
                assertEquals(0x0090, e.readRegister("AF").toInt())
            }
        }
    }

    @Test
    fun `nested wrappers distinguish restoring nonrestoring and constant return banks while preserving result flags`() {
        for (policy in listOf("restoring", "nonrestoring", "constant")) {
            fixture { p, e, bus ->
                code(p, 0x150, "CALL 0x200", "NOP")
                val body = mutableListOf("PUSH BC", "LD A, (0xc080)", "PUSH AF", "LD A, 2", "LD (0x2000), A", "CALL 0x300")
                // Save result AF in DE while accessing the saved selector, then restore it.
                body.addAll(listOf("PUSH AF", "POP DE", "POP AF"))
                if (policy == "constant") body.add("LD A, 3")
                if (policy != "nonrestoring") body.add("LD (0x2000), A")
                body.addAll(listOf("PUSH DE", "POP AF", "POP BC", "RET"))
                code(p, 0x200, *body.toTypedArray())
                code(p, 0x300, "CALL 0x350", "RET")
                code(p, 0x350, "LD B, 0xee", "XOR A", "SCF", "RET")
                e.writeMemory(address(0xc080), byteArrayOf(0)) // MBC3 raw zero selector maps to effective bank one.
                runTo(e, 0x350)
                assertEquals(0xc0f6, e.readRegister("SP").toInt())
                assertEquals(0x303, word(e, 0xc0f6))
                assertEquals(0x153, word(e, 0xc0fe))
                assertEquals(0x4567, word(e, 0xc0fc))
                runTo(e, 0x153)
                assertEquals(0xc100, e.readRegister("SP").toInt())
                assertEquals(0x0090, e.readRegister("AF").toInt())
                assertEquals(0x4567, e.readRegister("BC").toInt())
                val raw =
                    when (policy) {
                        "restoring" -> 0
                        "constant" -> 3
                        else -> 2
                    }
                assertEquals(raw, bus.state().romLow())
                val physical = MapperState.translate(ProgramMapping.cartridge(p), bus.state(), 0x4000, false).physical()
                assertEquals(if (raw == 0) 1 else raw, physical.bank())
            }
        }
    }

    @Test
    fun `recognized register templates preserve callee flags and expose their actual register clobbers`() {
        for (policy in listOf("restoring", "nonrestoring", "constant")) {
            fixture { p, e, bus ->
                code(p, 0x150, "LD HL, 0x300", "CALL 0x200", "NOP")
                when (policy) {
                    "restoring" -> {
                        code(p, 0x200, "PUSH AF", "LD A, C", "LD (0x2000), A", "LD BC, 0x220", "PUSH BC", "JP HL")
                        code(p, 0x220, "POP BC", "LD A, B", "LD (0x2000), A", "RET")
                        e.writeRegister("A", 1)
                        e.writeRegister("C", 2)
                    }
                    "constant" -> {
                        code(p, 0x200, "LD (0x2000), A", "LD BC, 0x220", "PUSH BC", "JP HL")
                        code(p, 0x220, "LD A, 3", "LD (0x2000), A", "RET")
                        e.writeRegister("A", 2)
                    }
                    else -> {
                        code(p, 0x200, "LD (0x2000), A", "JP HL")
                        e.writeRegister("A", 2)
                    }
                }
                code(p, 0x300, "XOR A", "SCF", "RET")
                runTo(e, 0x300)
                val sp =
                    when (policy) {
                        "restoring" -> 0xc0fa
                        "constant" -> 0xc0fc
                        else -> 0xc0fe
                    }
                assertEquals(sp, e.readRegister("SP").toInt())
                assertEquals(if (policy == "nonrestoring") 0x156 else 0x220, word(e, sp))
                assertEquals(0x156, word(e, 0xc0fe))
                if (policy == "restoring") assertEquals(0x01b0, word(e, 0xc0fc))
                assertEquals(2, bus.state().romLow())
                runTo(e, 0x156)
                assertEquals(0xc100, e.readRegister("SP").toInt())
                assertEquals(0x90, e.readRegister("F").toInt())
                assertEquals(0x300, e.readRegister("HL").toInt())
                when (policy) {
                    "restoring" -> {
                        assertEquals(1, e.readRegister("A").toInt())
                        assertEquals(0x01b0, e.readRegister("BC").toInt())
                        assertEquals(1, bus.state().romLow())
                    }
                    "constant" -> {
                        assertEquals(3, e.readRegister("A").toInt())
                        assertEquals(0x220, e.readRegister("BC").toInt())
                        assertEquals(3, bus.state().romLow())
                    }
                    else -> {
                        assertEquals(0, e.readRegister("A").toInt())
                        assertEquals(0x4567, e.readRegister("BC").toInt())
                        assertEquals(2, bus.state().romLow())
                    }
                }
            }
        }
    }

    @Test
    fun `a stale bank shadow restores its value rather than the physical entry selector`() =
        fixture { p, e, bus ->
            code(p, 0x150, "LD A, (0xc080)", "PUSH AF", "LD A, 2", "LD (0x2000), A", "CALL 0x300", "POP AF", "LD (0x2000), A", "JP 0x180")
            code(p, 0x300, "RET")
            e.writeMemory(address(0xc080), byteArrayOf(3))
            assertEquals(1, bus.state().romLow())
            runTo(e, 0x180)
            assertEquals(3, bus.state().romLow())
            assertEquals(0xc100, e.readRegister("SP").toInt())
        }

    @Test
    fun `conditional target may return loop or discard its caller frame for a nonlocal exit`() {
        for (mode in 0..2) {
            fixture { p, e, _ ->
                code(p, 0x150, "CALL 0x300", "NOP")
                code(p, 0x300, "CP 0", "RET Z", "CP 1", "JP Z, 0x320", "POP HL", "JP 0x380")
                code(p, 0x320, "JP 0x320")
                e.writeRegister("A", mode.toLong())
                when (mode) {
                    0 -> {
                        runTo(e, 0x153)
                        assertEquals(0xc100, e.readRegister("SP").toInt())
                    }
                    1 -> {
                        runTo(e, 0x320)
                        repeat(8) { assertTrue(e.step(TaskMonitor.DUMMY), e.lastError) }
                        assertEquals(0x320, e.readRegister("PC").toInt())
                        assertEquals(0xc0fe, e.readRegister("SP").toInt())
                        assertEquals(0x153, word(e, 0xc0fe))
                    }
                    2 -> {
                        runTo(e, 0x380)
                        assertEquals(0xc100, e.readRegister("SP").toInt())
                        assertEquals(0x153, e.readRegister("HL").toInt())
                    }
                }
            }
        }
    }
}
