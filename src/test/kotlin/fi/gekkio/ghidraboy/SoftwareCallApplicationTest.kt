package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.data.WordDataType
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.FlowOverride
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

class SoftwareCallApplicationTest : IntegrationTest() {
    private fun fixture(action: (ProgramDB, SoftwareCallValidation.Configuration) -> Unit) {
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x28, 3, null)
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        HexFormat.of().parseHex(template.bodyHex()).copyInto(bytes, 0x28)
        HexFormat.of().parseHex("ef020040c9").copyInto(bytes, 0x200)
        bytes[0x8000] = 0xc9.toByte()
        val consumer = Any()
        val p = ProgramDB("production ownership", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                for ((start, length) in listOf(0x28 to (template.bodyHex().length / 2), 0x200 to 1, 0x204 to 1)) {
                    d.disassemble(address(start.toLong()), AddressSet(address(start.toLong()), address((start + length - 1).toLong())))
                }
                val target = ProgramMapping.fileToStatic(p, 0x8000).single()
                d.disassemble(target, AddressSet(target))
            }
            action(
                p,
                SoftwareCallValidation.Configuration(
                    0x200,
                    template,
                    SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(0, 0, 0, 0, 0),
                    MapperState.reset(),
                ),
            )
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `compatible payload data survives apply removal and reapplication`() =
        fixture { p, config ->
            p.withTransaction { p.listing.createData(address(0x202), WordDataType.dataType) }
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            assertTrue(
                review
                    .inventory()
                    .single()
                    .payload()
                    .any { it.disposition() == "PRESERVE_DATA" },
            )
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            assertNotNull(p.listing.getDefinedDataAt(address(0x201)))
            AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            assertNull(p.listing.getDefinedDataAt(address(0x201)))
            assertEquals(2, p.listing.getDefinedDataAt(address(0x202)).length)
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            assertEquals(address(0x204), p.listing.getInstructionAt(address(0x200)).fallThrough)
        }

    @Test
    fun `payload extent overlap and symbols conflict without clearing knowledge`() =
        fixture { p, config ->
            p.withTransaction { p.symbolTable.createLabel(address(0x202), "payload_claim", SourceType.USER_DEFINED) }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            assertTrue(p.symbolTable.getSymbols("payload_claim").hasNext())
            p.withTransaction {
                p.symbolTable
                    .getSymbols("payload_claim")
                    .next()
                    .delete()
            }
            p.withTransaction {
                p.listing.clearCodeUnits(address(0x204), address(0x204), false)
                p.listing.createData(address(0x203), WordDataType.dataType)
            }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            assertEquals(2, p.listing.getDefinedDataAt(address(0x203)).length)
        }

    @Test
    fun `later payload comment and continuation edits survive removal`() =
        fixture { p, config ->
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            p.withTransaction {
                p.listing.getDefinedDataAt(address(0x201)).setComment(CommentType.EOL, "user bank interpretation")
                p.listing.getInstructionAt(address(0x200)).setFallThrough(address(0x205))
            }
            assertFalse(AnalysisOwnership.softwareCallCurrent(p, address(0x200)))
            val diagnostics = AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            assertTrue(diagnostics.any { it.contains("Preserved edited payload") })
            assertEquals("user bank interpretation", p.listing.getDefinedDataAt(address(0x201)).getComment(CommentType.EOL))
            assertEquals(address(0x205), p.listing.getInstructionAt(address(0x200)).fallThrough)
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
        }

    @Test
    fun `review rejects new payload comments and preserves enclosing edits`() =
        fixture { p, config ->
            p.withTransaction { p.listing.createData(address(0x201), ByteDataType.dataType) }
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            p.withTransaction {
                p.listing.getDefinedDataAt(address(0x201)).setComment(CommentType.EOL, "review changed")
                assertThrows(IllegalStateException::class.java) { SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY) }
                p.symbolTable.createLabel(address(0x300), "saved_user_edit", SourceType.USER_DEFINED)
            }
            assertTrue(p.symbolTable.getSymbols("saved_user_edit").hasNext())
        }

    @Test
    fun `reviewed false CALL_RETURN and noReturn repairs have reversible inventory`() =
        fixture { p, config ->
            p.withTransaction {
                p.listing.getInstructionAt(address(0x200)).setFlowOverride(FlowOverride.CALL_RETURN)
                p.functionManager.createFunction("helper", address(0x28), AddressSet(address(0x28)), SourceType.ANALYSIS).setNoReturn(true)
                val target = ProgramMapping.fileToStatic(p, 0x8000).single()
                p.functionManager.createFunction("target", target, AddressSet(target), SourceType.USER_DEFINED).setNoReturn(true)
            }
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            assertEquals("CALL_RETURN", review.inventory().single().originalFlow())
            assertTrue(review.inventory().single().helperNoReturn())
            assertTrue(review.inventory().single().targetNoReturn())
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            assertEquals(FlowOverride.NONE, p.listing.getInstructionAt(address(0x200)).flowOverride)
            assertFalse(p.functionManager.getFunctionAt(address(0x28)).hasNoReturn())
            assertFalse(p.functionManager.getFunctionAt(ProgramMapping.fileToStatic(p, 0x8000).single()).hasNoReturn())
            AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            assertEquals(FlowOverride.CALL_RETURN, p.listing.getInstructionAt(address(0x200)).flowOverride)
            assertTrue(p.functionManager.getFunctionAt(address(0x28)).hasNoReturn())
            assertTrue(p.functionManager.getFunctionAt(ProgramMapping.fileToStatic(p, 0x8000).single()).hasNoReturn())
        }

    @Test
    fun `reviewed payload body and false thunk repairs preserve source knowledge`() =
        fixture { p, config ->
            p.withTransaction {
                p.functionManager.createFunction(
                    "caller",
                    address(0x200),
                    AddressSet(address(0x200), address(0x204)),
                    SourceType.USER_DEFINED,
                )
                val target = ProgramMapping.fileToStatic(p, 0x8000).single()
                val targetFunction = p.functionManager.createFunction("target", target, AddressSet(target), SourceType.USER_DEFINED)
                val helper = p.functionManager.createFunction("helper", address(0x28), AddressSet(address(0x28)), SourceType.ANALYSIS)
                helper.setThunkedFunction(targetFunction)
            }
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            assertFalse(p.functionManager.getFunctionAt(address(0x28)).isThunk)
            assertFalse(
                p.functionManager
                    .getFunctionAt(address(0x200))
                    .body
                    .contains(address(0x201)),
            )
            assertTrue(
                p.functionManager
                    .getFunctionAt(address(0x200))
                    .body
                    .contains(address(0x204)),
            )
            AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            assertTrue(p.functionManager.getFunctionAt(address(0x28)).isThunk)
            assertTrue(
                p.functionManager
                    .getFunctionAt(address(0x200))
                    .body
                    .contains(address(0x201)),
            )
        }

    @Test
    fun `final cancellation rolls back production registry payload and helper changes`() =
        fixture { p, config ->
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            val monitor =
                object : ghidra.util.task.TaskMonitorAdapter() {
                    override fun checkCancelled() {
                        if (p.getOptions(ProgramMapping.OPTIONS).contains("softwareCall.review.inventory.v1")) {
                            throw ghidra.util.exception.CancelledException()
                        }
                    }
                }
            assertThrows(ghidra.util.exception.CancelledException::class.java) { SoftwareCallApplication.apply(p, review, monitor) }
            assertNull(p.listing.getDefinedDataAt(address(0x201)))
            assertNull(p.functionManager.getFunctionAt(address(0x28)))
            assertFalse(p.listing.getInstructionAt(address(0x200)).isFallThroughOverridden)
        }

    @Test
    fun `later call reference edits veto live interpretation`() =
        fixture { p, config ->
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            assertTrue(AnalysisOwnership.softwareCallCurrent(p, address(0x200)))
            p.withTransaction {
                p.referenceManager.addMemoryReference(
                    address(0x200),
                    address(0x38),
                    ghidra.program.model.symbol.RefType.CALL_OVERRIDE_UNCONDITIONAL,
                    SourceType.USER_DEFINED,
                    -1,
                )
            }
            assertFalse(AnalysisOwnership.softwareCallCurrent(p, address(0x200)))
        }

    @Test
    fun `derived payload reads remain compatible without becoming recognition evidence`() =
        fixture { p, config ->
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            p.withTransaction {
                for (offset in 0x201L..0x203L) {
                    p.referenceManager.addMemoryReference(
                        address(0x200),
                        address(offset),
                        ghidra.program.model.symbol.RefType.READ,
                        SourceType.ANALYSIS,
                        0,
                    )
                }
            }
            assertTrue(AnalysisOwnership.softwareCallCurrent(p, address(0x200)))
            SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            p.withTransaction {
                p.referenceManager.addMemoryReference(
                    address(0x300),
                    address(0x201),
                    ghidra.program.model.symbol.RefType.READ,
                    SourceType.ANALYSIS,
                    0,
                )
            }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
        }

    @Test
    fun `explicit target purge and nested callfixup contracts reject without replacement`() =
        fixture { p, config ->
            val target = ProgramMapping.fileToStatic(p, 0x8000).single()
            p.withTransaction {
                p.functionManager.createFunction("custom_target", target, AddressSet(target), SourceType.USER_DEFINED).stackPurgeSize = 4
            }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            assertEquals(4, p.functionManager.getFunctionAt(target).stackPurgeSize)
            p.withTransaction {
                p.functionManager.getFunctionAt(target).stackPurgeSize = 0
                p.functionManager.getFunctionAt(target).callFixup = SoftwareCallInjection.NAME
            }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            assertEquals(SoftwareCallInjection.NAME, p.functionManager.getFunctionAt(target).callFixup)
            p.withTransaction {
                p.functionManager.getFunctionAt(target).callFixup = null
                p.functionManager.getFunctionAt(target).isInline = true
            }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            assertTrue(p.functionManager.getFunctionAt(target).isInline)
            p.withTransaction {
                p.functionManager.getFunctionAt(target).isInline = false
                val alternate =
                    p.functionManager.createFunction(
                        "alternate",
                        address(0x300),
                        AddressSet(address(0x300)),
                        SourceType.USER_DEFINED,
                    )
                p.functionManager.getFunctionAt(target).setThunkedFunction(alternate)
            }
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY) }
            assertTrue(p.functionManager.getFunctionAt(target).isThunk)
        }

    @Test
    fun `missing native target function is created before ordinary analysis and stays current`() =
        fixture { p, config ->
            val target = ProgramMapping.fileToStatic(p, 0x8000).single()
            assertNull(p.functionManager.getFunctionAt(target))
            p.withTransaction {
                val body = AddressSet(address(0x200))
                body.add(address(0x204))
                p.functionManager.createFunction("prepared_caller", address(0x200), body, SourceType.USER_DEFINED)
            }
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            val created = p.functionManager.getFunctionAt(target)
            assertNotNull(created)
            val identity = created.id
            val manager =
                ghidra.app.plugin.core.analysis.AutoAnalysisManager
                    .getAnalysisManager(p)
            repeat(2) {
                p.withTransaction {
                    val ranges = AddressSet(address(0x200), address(0x204))
                    ranges.add(address(0x28), address(0x33))
                    ranges.add(target)
                    manager.reAnalyzeAll(ranges)
                    manager.startAnalysis(TaskMonitor.DUMMY)
                }
                assertEquals(identity, p.functionManager.getFunctionAt(target).id)
                assertNotNull(SoftwareCallRegistry.resolve(p, address(0x200)))
                assertEquals(address(0x204), p.listing.getInstructionAt(address(0x200)).fallThrough)
                assertFalse(p.functionManager.getFunctionAt(address(0x28)).hasNoReturn())
            }
        }

    @Test
    fun `multiple payload repairs in one body restore the complete original inventory`() =
        fixture { p, config ->
            p.withTransaction {
                p.memory.setBytes(address(0x210), HexFormat.of().parseHex("ef020040c9"))
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                d.disassemble(address(0x210), AddressSet(address(0x210)))
                d.disassemble(address(0x214), AddressSet(address(0x214)))
                p.functionManager.createFunction(
                    "two_calls",
                    address(0x200),
                    AddressSet(address(0x200), address(0x214)),
                    SourceType.USER_DEFINED,
                )
            }
            val second =
                SoftwareCallValidation.Configuration(
                    0x210,
                    config.template(),
                    config.transfer(),
                    config.callerSp(),
                    config.registers(),
                    config.mapper(),
                )
            SoftwareCallApplication.apply(
                p,
                SoftwareCallApplication.preview(p, listOf(config, second), TaskMonitor.DUMMY),
                TaskMonitor.DUMMY,
            )
            val function = p.functionManager.getFunctionAt(address(0x200))
            assertFalse(function.body.contains(address(0x201)))
            assertFalse(function.body.contains(address(0x211)))
            AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            assertEquals(AddressSet(address(0x200), address(0x214)), function.body)
        }

    @Test
    fun `removal clears unchanged neutral marker while preserving user noReturn edit`() =
        fixture { p, config ->
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            val target = p.functionManager.getFunctionAt(ProgramMapping.fileToStatic(p, 0x8000).single())
            assertEquals(SoftwareCallMayReturnInjection.NAME, target.callFixup)
            p.withTransaction { target.setNoReturn(true) }
            AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            assertTrue(target.hasNoReturn())
            assertNull(target.callFixup)
        }

    @Test
    fun `helper signature edit survives removal without restoring false thunk`() =
        fixture { p, config ->
            p.withTransaction {
                val at = ProgramMapping.fileToStatic(p, 0x8000).single()
                val target = p.functionManager.createFunction("target", at, AddressSet(at), SourceType.USER_DEFINED)
                val helper =
                    p.functionManager.createFunction(
                        "false_thunk",
                        address(0x28),
                        AddressSet(address(0x28)),
                        SourceType.USER_DEFINED,
                    )
                helper.setThunkedFunction(target)
            }
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            val helper = p.functionManager.getFunctionAt(address(0x28))
            p.withTransaction { helper.setReturnType(ByteDataType.dataType, SourceType.USER_DEFINED) }
            val diagnostics = AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            assertFalse(helper.isThunk)
            assertTrue(helper.returnType.isEquivalent(ByteDataType.dataType))
            assertEquals(SourceType.USER_DEFINED, helper.signatureSource)
            assertNull(helper.callFixup)
            assertTrue(diagnostics.any { it.contains("Preserved edited or legacy helper semantic metadata") })
        }

    @Test
    fun `removal never delegates setters through a new user thunk`() =
        fixture { p, config ->
            SoftwareCallApplication.apply(p, SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY), TaskMonitor.DUMMY)
            val helper = p.functionManager.getFunctionAt(address(0x28))
            p.withTransaction {
                val target =
                    p.functionManager.createFunction(
                        "new_user_target",
                        address(0x300),
                        AddressSet(address(0x300)),
                        SourceType.USER_DEFINED,
                    )
                target.setNoReturn(true)
                helper.setThunkedFunction(target)
            }
            AnalysisOwnership.remove(p, SoftwareCallApplication.FEATURE, TaskMonitor.DUMMY)
            assertTrue(helper.isThunk)
            assertEquals(address(0x300), helper.getThunkedFunction(false).entryPoint)
            assertTrue(p.functionManager.getFunctionAt(address(0x300)).hasNoReturn())
            assertNull(p.functionManager.getFunctionAt(address(0x300)).callFixup)
        }

    @Test
    fun `forged reviewed inventory is rejected before opening a mutation transaction`() =
        fixture { p, config ->
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            val json = ProgramMapping.JSON.toJsonTree(review).asJsonObject
            json
                .getAsJsonArray("inventory")
                .first()
                .asJsonObject
                .addProperty("disposition", "forged no-op plan")
            val forged = ProgramMapping.JSON.fromJson(json, SoftwareCallApplication.Review::class.java)
            val before = p.modificationNumber
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallApplication.apply(p, forged, TaskMonitor.DUMMY) }
            assertEquals(before, p.modificationNumber)
            assertNull(p.listing.getDefinedDataAt(address(0x201)))
        }
}
