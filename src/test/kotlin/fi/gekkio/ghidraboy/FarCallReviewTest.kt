package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FarCallReviewTest : IntegrationTest() {
    private fun fixture(action: (ProgramDB, FarCallConvention) -> Unit) {
        val consumer = Any()
        val p = ProgramDB("reviewed generic software call", language, language.defaultCompilerSpec, consumer)
        try {
            val bytes = ByteArray(0x10000)
            bytes[0x147] = 0x13
            bytes[0x148] = 1
            bytes[0x149] = 3
            java.util.HexFormat
                .of()
                .parseHex(FarCallConvention.SUPPORTED_BODY)
                .copyInto(bytes, 0x28)
            java.util.HexFormat
                .of()
                .parseHex("ef020040c9")
                .copyInto(bytes, 0x200)
            bytes[0x8000] = 0xc9.toByte()
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(address(0x200), AddressSet(address(0x200)))
            }
            action(p, FarCallConvention("0028", FarCallConvention.SUPPORTED_BODY, listOf("0200"), 0xc100))
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `review rejects changed helper payload context reference and contract`() {
        val edits: List<(ProgramDB) -> Unit> =
            listOf(
                { it.memory.setByte(address(0x28), 0) },
                { it.memory.setByte(address(0x201), 3) },
                { it.programContext.setValue(it.getRegister("A"), address(0x200), address(0x200), java.math.BigInteger.TWO) },
                { it.referenceManager.addMemoryReference(address(0x300), address(0x201), RefType.DATA, SourceType.USER_DEFINED, -1) },
                {
                    it.functionManager
                        .createFunction(
                            "target",
                            ProgramMapping.fileToStatic(it, 0x8000).single(),
                            AddressSet(ProgramMapping.fileToStatic(it, 0x8000).single()),
                            SourceType.USER_DEFINED,
                        ).setNoReturn(true)
                },
            )
        for (edit in edits) {
            fixture { p, c ->
                val review = c.previewReviewed(p, TaskMonitor.DUMMY)
                p.withTransaction { edit(p) }
                assertThrows(IllegalStateException::class.java) { c.apply(p, review, TaskMonitor.DUMMY) }
                assertTrue(!p.listing.getInstructionAt(address(0x200)).isFallThroughOverridden)
            }
        }
    }

    @Test
    fun `payload data instruction label and function boundary conflicts are review failures`() {
        val edits: List<(ProgramDB) -> Unit> =
            listOf(
                { it.listing.createData(address(0x201), ByteDataType.dataType) },
                { Disassembler.getDisassembler(it, TaskMonitor.DUMMY, null).disassemble(address(0x201), AddressSet(address(0x201))) },
                { it.symbolTable.createLabel(address(0x202), "user_payload", SourceType.USER_DEFINED) },
                {
                    it.functionManager.createFunction(
                        "overlap",
                        address(0x200),
                        AddressSet(address(0x200), address(0x204)),
                        SourceType.USER_DEFINED,
                    )
                },
            )
        for (edit in edits) {
            fixture { p, c ->
                p.withTransaction { edit(p) }
                assertThrows(IllegalArgumentException::class.java) { c.previewReviewed(p, TaskMonitor.DUMMY) }
            }
        }
    }

    @Test
    fun `review apply remove reapply preserves later continuation edit`() =
        fixture { p, c ->
            val before = ProgramFingerprint.capture(p, TaskMonitor.DUMMY)
            c.apply(p, c.previewReviewed(p, TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            AnalysisOwnership.remove(p, "far-call", TaskMonitor.DUMMY)
            assertEquals(before, ProgramFingerprint.capture(p, TaskMonitor.DUMMY))
            c.apply(p, c.previewReviewed(p, TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            p.withTransaction { p.listing.getInstructionAt(address(0x200)).setFallThrough(address(0x205)) }
            AnalysisOwnership.remove(p, "far-call", TaskMonitor.DUMMY)
            assertEquals(address(0x205), p.listing.getInstructionAt(address(0x200)).fallThrough)
            assertThrows(IllegalArgumentException::class.java) { c.previewReviewed(p, TaskMonitor.DUMMY) }
        }

    @Test
    fun `final cancellation rolls back the single site and saved convention`() =
        fixture { p, c ->
            val monitor =
                object : ghidra.util.task.TaskMonitorAdapter() {
                    override fun checkCancelled() {
                        if (p.getOptions(ProgramMapping.OPTIONS).contains("farCallConvention")) {
                            throw ghidra.util.exception.CancelledException()
                        }
                    }
                }
            assertThrows(ghidra.util.exception.CancelledException::class.java) { c.apply(p, monitor) }
            assertTrue(!p.listing.getInstructionAt(address(0x200)).isFallThroughOverridden)
            assertEquals(0, p.bookmarkManager.bookmarkCount)
            assertTrue(!p.getOptions(ProgramMapping.OPTIONS).contains("farCallConvention"))
        }

    @Test
    fun `stale apply does not abort unrelated edits in an enclosing transaction`() =
        fixture { p, c ->
            val review = c.previewReviewed(p, TaskMonitor.DUMMY)
            p.withTransaction {
                p.symbolTable.createLabel(address(0x300), "unrelated_user_label", SourceType.USER_DEFINED)
                assertThrows(IllegalStateException::class.java) { c.apply(p, review, TaskMonitor.DUMMY) }
                p.listing.getInstructionAt(address(0x200)).setFallThrough(address(0x205))
            }
            assertTrue(p.symbolTable.getSymbols("unrelated_user_label").hasNext())
            assertEquals(address(0x205), p.listing.getInstructionAt(address(0x200)).fallThrough)
        }
}
