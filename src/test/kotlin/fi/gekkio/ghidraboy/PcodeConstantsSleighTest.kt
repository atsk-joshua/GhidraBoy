package fi.gekkio.ghidraboy

import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.pcode.Varnode
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test

/** Self-authored actual SM83 bytes, separate from synthetic evaluator-contract cases. */
class PcodeConstantsSleighTest : IntegrationTest() {
    @Test
    fun `compiled instructions propagate overlap arithmetic wrap and arithmetic right shift`() {
        val consumer = Any()
        val p = ProgramDB("evaluator-sleigh", language, language.defaultCompilerSpec, consumer)
        val regs = mutableMapOf<Long, Int>()
        val unique = mutableMapOf<Long, Int>()
        try {
            p.withTransaction {
                p.memory.createInitializedBlock("code", address(0x200), 0x100, 0.toByte(), TaskMonitor.DUMMY, false)
                // LD HL,12ff; INC L; LD H,80; SRA H; LD A,ff; ADD A,01.
                p.memory.setBytes(
                    address(0x200),
                    byteArrayOf(
                        0x21,
                        0xff.toByte(),
                        0x12,
                        0x2c,
                        0x26,
                        0x80.toByte(),
                        0xcb.toByte(),
                        0x2c,
                        0x3e,
                        0xff.toByte(),
                        0xc6.toByte(),
                        1,
                    ),
                )
                Disassembler
                    .getDisassembler(
                        p,
                        TaskMonitor.DUMMY,
                        null,
                    ).disassemble(address(0x200), AddressSet(address(0x200), address(0x20b)))
            }

            fun value(name: String): Long? {
                val r = p.getRegister(name)
                return PcodeConstants.value(Varnode(r.address, r.minimumByteSize), regs, unique)
            }
            for ((offset, expectedHL) in listOf(
                0x200L to 0x12ffL,
                0x203L to 0x1200L,
                0x204L to 0x8000L,
                0x206L to 0xc000L,
                0x208L to 0xc000L,
                0x20aL to 0xc000L,
            )) {
                val instruction = p.listing.getInstructionAt(address(offset))
                assertNotNull(instruction)
                unique.clear()
                for (op in instruction.getPcode(false)) {
                    op.output?.let { PcodeConstants.put(it, PcodeConstants.evaluate(op, regs, unique), regs, unique) }
                }
                assertEquals(expectedHL, value("HL"), "after $instruction")
            }
            assertEquals(0L, value("A"))
        } finally {
            p.release(consumer)
        }
    }
}
