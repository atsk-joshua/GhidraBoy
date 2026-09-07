package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

/** Architectural counterexamples, not qualification of their still-required native transport. */
class SoftwareCallStatePathsTest : IntegrationTest() {
    private data class Code(
        val bank: Int,
        val cpu: Int,
        val hex: String,
    )

    private fun fixture(
        code: List<Code>,
        flags: Int = 0,
        data: Map<Int, Int> = emptyMap(),
        action: (ProgramDB, SoftwareCallValidation.Configuration, SoftwareCallEffects.Summary) -> Unit,
    ) {
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val image = ByteArray(0x10000)
        image[0x147] = 0x13
        image[0x148] = 1
        HexFormat.of().parseHex(template.bodyHex()).copyInto(image, 0x28)
        HexFormat.of().parseHex("efc9").copyInto(image, 0x200)
        for (chunk in code) {
            HexFormat.of().parseHex(chunk.hex).copyInto(image, chunk.bank * 0x4000 + chunk.cpu - 0x4000)
        }
        for ((offset, value) in data) image[offset] = value.toByte()
        val consumer = Any()
        val p = ProgramDB("state-sensitive-paths", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(image).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                d.disassemble(address(0x28), AddressSet(address(0x28), address(0x28 + template.bodyHex().length / 2L - 1)))
                d.disassemble(address(0x200), AddressSet(address(0x200), address(0x201)))
                for (chunk in code) {
                    val at = ProgramMapping.fileToStatic(p, (chunk.bank * 0x4000 + chunk.cpu - 0x4000).toLong()).single()
                    d.disassemble(at, AddressSet(at, at.add(chunk.hex.length / 2L - 1)))
                }
            }
            val config =
                SoftwareCallValidation.Configuration(
                    0x200,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(2, flags, 0, 0, 0x4100),
                    MapperState.reset(),
                )
            val frame = SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY).frame()
            val summary = SoftwareCallEffects.derive(p, frame, TaskMonitor.DUMMY, listOf(config))
            assertTrue(summary.complete(), summary.unresolved().toString())
            assertEquals(
                SoftwareCallModel.Exit.MAY_RETURN,
                summary
                    .paths()
                    .single()
                    .returned()
                    .exit(),
            )
            assertEquals(
                0xc100,
                summary
                    .paths()
                    .single()
                    .returned()
                    .sp(),
            )
            assertEquals(
                0x201,
                summary
                    .paths()
                    .single()
                    .returned()
                    .cpu(),
            )
            action(p, config, summary)
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `revisited CPU instruction has two physical sources and both architectural effects survive`() =
        fixture(
            listOf(
                Code(2, 0x4100, "043e03ea0020"), // INC B; select bank 3, fetching the next instruction there.
                Code(3, 0x4106, "c30041"), // Revisit CPU 4100, now in bank 3.
                Code(3, 0x4100, "0cc30042"), // INC C; JP 4200.
                Code(3, 0x4200, "c9"),
            ),
        ) { p, _, summary ->
            assertEquals(
                0x0101,
                summary
                    .paths()
                    .single()
                    .returned()
                    .registers()
                    .bc(),
            )
            assertEquals(
                setOf(MapperState.Physical("ROM", 2, 0x100), MapperState.Physical("ROM", 3, 0x100)),
                summary
                    .fetches()
                    .filter { it.physical().offset() == 0x100 }
                    .map { it.physical() }
                    .toSet(),
            )
            val segments =
                listOf(2, 3).map { bank ->
                    val source = ProgramMapping.fileToStatic(p, (bank * 0x4000 + 0x100).toLong()).single()
                    SoftwareCallExecutionView.Segment(0x4100, 1, source.toString())
                }
            val rejection =
                assertThrows(IllegalArgumentException::class.java) {
                    SoftwareCallExecutionView.preview(p, "gb_call_view_competing_paths", segments, TaskMonitor.DUMMY)
                }
            assertEquals("A CPU address has multiple execution identities", rejection.message)
            assertFalse(summary.nativeCompatible(), "Raw success must not erase the current native transport failure")
        }

    @Test
    fun `conditional selector paths reach the same CPU PC with different physical results`() {
        val code =
            listOf(
                Code(2, 0x4100, "ca20413e03ea0020"), // JP Z,4120; otherwise select bank 3.
                Code(3, 0x4108, "c30042"),
                Code(2, 0x4120, "3e02ea0020c30042"), // Z path retains bank 2.
                Code(2, 0x4200, "3e22c9"),
                Code(3, 0x4200, "3e33c9"),
            )
        for ((flags, bank, value) in listOf(Triple(0, 3, 0x33), Triple(0x80, 2, 0x22))) {
            fixture(code, flags) { _, _, summary ->
                assertEquals(
                    value,
                    summary
                        .paths()
                        .single()
                        .returned()
                        .registers()
                        .a(),
                )
                assertTrue(summary.fetches().any { it.physical() == MapperState.Physical("ROM", bank, 0x200) })
                assertFalse(summary.fetches().any { it.physical() == MapperState.Physical("ROM", 5 - bank, 0x200) })
            }
        }
        // These are two explicit flag premises, not proof that a single unknown-flag CFG is supported.
    }

    @Test
    fun `two banked data reads at the same CPU address retain separate storage identities`() =
        fixture(
            listOf(
                Code(2, 0x4100, "fa0050473e03ea0020"), // B = bank 2 [5000], then select bank 3.
                Code(3, 0x4109, "fa00504fc9"), // C = bank 3 [5000].
            ),
            data = mapOf(0x9000 to 0x22, 0xd000 to 0x33),
        ) { p, _, summary ->
            assertEquals(
                0x2233,
                summary
                    .paths()
                    .single()
                    .returned()
                    .registers()
                    .bc(),
            )
            assertEquals(0x22, p.memory.getByte(ProgramMapping.fileToStatic(p, 0x9000).single()).toInt())
            assertEquals(0x33, p.memory.getByte(ProgramMapping.fileToStatic(p, 0xd000).single()).toInt())
            assertFalse(summary.nativeCompatible(), "Code-view membership cannot establish a banked data view")
        }

    @Test
    fun `nested calls restore prior bank before consuming each live return word`() =
        fixture(
            listOf(
                Code(2, 0x4100, "cd004247c9"), // CALL 4200; B = returned A; RET outer software frame.
                Code(2, 0x4200, "3e03ea0020"), // Select 3, next fetch 4205 in bank 3.
                Code(3, 0x4205, "cd00433e02ea0020"), // CALL 4300; restore 2, next fetch 420d there.
                Code(3, 0x4300, "0cc9"), // INC C; consume inner hardware frame.
                Code(2, 0x420d, "c9"), // Consume hardware frame back to bank 2 CPU 4103.
            ),
        ) { p, _, summary ->
            assertEquals(
                0x0201,
                summary
                    .paths()
                    .single()
                    .returned()
                    .registers()
                    .bc(),
            )
            assertTrue(summary.fetches().any { it.physical() == MapperState.Physical("ROM", 3, 0x300) && it.callDepth() == 2 })
            assertTrue(summary.fetches().any { it.physical() == MapperState.Physical("ROM", 2, 0x103) && it.callDepth() == 0 })
            assertEquals(
                MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, 2),
                summary
                    .paths()
                    .single()
                    .returned()
                    .mapper(),
            )
            assertFalse(summary.nativeCompatible(), "Nested raw frames need a corresponding native state-sensitive representation")
        }
}
