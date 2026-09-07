package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class SoftwareCallExecutionViewTest : IntegrationTest() {
    @Test
    fun `continuation permits exact fixed RAM writes but protects mapper devices and return word`() {
        val cases =
            listOf(
                Triple(0x4500, "ea00c2c9", true),
                Triple(0x4510, "e090c9", true),
                Triple(0x4520, "ea00c1c9", false),
                Triple(0x4530, "ea0020c9", false),
                Triple(0x4540, "e001c9", false),
                Triple(0x4550, "77c9", false),
                Triple(0x4560, "08ffcfc9", false),
                Triple(0x4570, "08feffc9", false),
            )
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        for ((cpu, hex, _) in cases) {
            java.util.HexFormat
                .of()
                .parseHex(hex)
                .copyInto(bytes, 0x8000 + cpu - 0x4000)
        }
        val consumer = Any()
        val p = ProgramDB("continuation-fixed-writes", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            val mapper = MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, 2)
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                for ((cpu, hex, _) in cases) {
                    val at = SoftwareCallValidation.executionAddress(p, mapper, cpu)
                    disassembler.disassemble(at, AddressSet(at, at.add(hex.length / 2L - 1)))
                }
            }
            for ((cpu, hex, accepted) in cases) {
                val returned =
                    SoftwareCallModel.Returned(
                        SoftwareCallModel.Exit.MAY_RETURN,
                        cpu,
                        MapperState.Physical("ROM", 2, cpu - 0x4000),
                        0xc100,
                        null,
                        mapper,
                        emptyList(),
                        emptyList(),
                        emptyList(),
                    )
                if (accepted) {
                    assertEquals(
                        hex.length / 2,
                        SoftwareCallExecutionView.continuationSegments(p, returned, TaskMonitor.DUMMY).single().length(),
                    )
                } else {
                    assertThrows(IllegalArgumentException::class.java) {
                        SoftwareCallExecutionView.continuationSegments(p, returned, TaskMonitor.DUMMY)
                    }
                }
            }
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `continuation requires a native physical data view for register indirect loads`() {
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        byteArrayOf(0x7e, 0xc9.toByte()).copyInto(bytes, 0x8500)
        byteArrayOf(0xfa.toByte(), 0, 1, 0xc9.toByte()).copyInto(bytes, 0x8510)
        byteArrayOf(0xfa.toByte(), 0, 0x50, 0xc9.toByte()).copyInto(bytes, 0x8520)
        val consumer = Any()
        val p = ProgramDB("continuation-data-views", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            val mapper = MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, 2)
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                for ((cpu, length) in listOf(0x4500 to 2, 0x4510 to 4, 0x4520 to 4)) {
                    val at = SoftwareCallValidation.executionAddress(p, mapper, cpu)
                    disassembler.disassemble(at, AddressSet(at, at.add(length.toLong() - 1)))
                }
            }

            fun returned(cpu: Int) =
                SoftwareCallModel.Returned(
                    SoftwareCallModel.Exit.MAY_RETURN,
                    cpu,
                    MapperState.Physical("ROM", 2, cpu - 0x4000),
                    0xc100,
                    null,
                    mapper,
                    emptyList(),
                    emptyList(),
                    emptyList(),
                )
            val failure =
                assertThrows(IllegalArgumentException::class.java) {
                    SoftwareCallExecutionView.continuationSegments(p, returned(0x4500), TaskMonitor.DUMMY)
                }
            assertEquals("Continuation LOAD requires a proven native physical data view", failure.message)
            assertEquals(4, SoftwareCallExecutionView.continuationSegments(p, returned(0x4510), TaskMonitor.DUMMY).single().length())
            assertThrows(IllegalArgumentException::class.java) {
                SoftwareCallExecutionView.continuationSegments(p, returned(0x4520), TaskMonitor.DUMMY)
            }
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `identical physical continuation fixture compares overlays segmented addresses and scoped execution view`() {
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                byteArrayOf(0xcd.toByte(), 0, 2).copyInto(this, 0x4500)
                byteArrayOf(0x3e, 0x42, 0xc9.toByte()).copyInto(this, 0xc503)
            }
        val consumer = Any()
        val p = ProgramDB("bank-continuation-alternatives", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            val entry = SoftwareCallValidation.executionAddress(p, MapperState.reset(), 0x4500)
            val continuation =
                SoftwareCallValidation.executionAddress(
                    p,
                    MapperState.reset().write(ProgramMapping.cartridge(p), 0x2000, 3),
                    0x4503,
                )
            p.withTransaction {
                val disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                disassembler.disassemble(entry, AddressSet(entry, entry.add(2)))
                disassembler.disassemble(continuation, AddressSet(continuation, continuation.add(2)))
                val mixed = AddressSet(entry, entry.add(2)).apply { add(continuation, continuation.add(2)) }
                assertThrows(IllegalArgumentException::class.java) {
                    p.functionManager.createFunction("mixed_bank", entry, mixed, SourceType.USER_DEFINED)
                }
                // Segmenting bank identity into the current CPU space cannot retain that value;
                // adopting it requires a language/address-space and saved-Program migration.
                assertThrows(ghidra.program.model.address.AddressOutOfBoundsException::class.java) {
                    p.addressFactory.defaultAddressSpace.getAddress(0x14503)
                }
                val segments =
                    listOf(
                        SoftwareCallExecutionView.Segment(0x4500, 3, entry.toString()),
                        SoftwareCallExecutionView.Segment(0x4503, 3, continuation.toString()),
                    )
                val preview = SoftwareCallExecutionView.preview(p, "gb_call_view_compare", segments, TaskMonitor.DUMMY)
                val created = SoftwareCallExecutionView.create(p, preview, TaskMonitor.DUMMY)
                val viewEntry = created.body().minAddress
                disassembler.disassemble(viewEntry, created.body())
                val function = p.functionManager.createFunction("view_bank", viewEntry, created.body(), SourceType.USER_DEFINED)
                assertEquals(6, function.body.numAddresses)
                assertEquals(0x42, p.memory.getByte(viewEntry.add(4)).toInt())
                assertEquals(MapperState.Physical("ROM", 3, 0x504), ProgramMapping.staticToPhysical(p, viewEntry.add(4)).single())
                // Storage is shared; this is not a snapshot that silently drifts after a patch.
                p.listing.clearCodeUnits(continuation, continuation.add(1), false)
                p.listing.clearCodeUnits(viewEntry.add(3), viewEntry.add(4), false)
                p.memory.setByte(continuation.add(1), 0x43)
                assertEquals(0x43, p.memory.getByte(viewEntry.add(4)).toInt())
                assertThrows(IllegalArgumentException::class.java) {
                    SoftwareCallExecutionView.preview(
                        p,
                        "gb_call_view_conflict",
                        listOf(segments[0], SoftwareCallExecutionView.Segment(0x4500, 3, continuation.subtract(3).toString())),
                        TaskMonitor.DUMMY,
                    )
                }
            }
        } finally {
            p.release(consumer)
        }
    }
}
