package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FlowIntegrityTest : IntegrationTest() {
    private fun program(test: (ProgramDB) -> Unit) {
        val bytes = ByteArray(0x10000)
        bytes[0x147] = 0x13
        bytes[0x148] = 1
        bytes[0x149] = 3
        byteArrayOf(0x31, 0, 0xc1.toByte(), 0xcd.toByte(), 0, 0x20, 0xc9.toByte()).copyInto(bytes, 0x150)
        bytes[0x2000] = 0xc9.toByte()
        bytes[0x2100] = 0xc9.toByte()
        val consumer = Any()
        val p = ProgramDB("SA-00 self-authored flow integrity", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true, TaskMonitor.DUMMY, MessageLog())
            }
            p.withTransaction {
                val d = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
                for (range in listOf(
                    AddressSet(address(0x150), address(0x156)),
                    AddressSet(address(0x2000)),
                    AddressSet(address(0x2100)),
                )) {
                    d.disassemble(range.minAddress, range)
                }
            }
            test(p)
        } finally {
            p.release(consumer)
        }
    }

    private fun preview(
        p: ProgramDB,
        monitor: TaskMonitor = TaskMonitor.DUMMY,
    ) = BankAnalysis.preview(p, address(0x150), MapperState.reset(), AnalysisResult.Configuration.DEFAULT, monitor)

    // Exact pre-SA-00 instruction inputs: no references, primary status, or callfixups.
    private fun legacyInstructions(p: ProgramDB) =
        p.listing
            .getInstructions(true)
            .iterator()
            .asSequence()
            .map {
                listOf(it.address.toString(), it.length, it.flowOverride, it.isFallThroughOverridden, it.fallThrough?.toString())
            }.toList()

    @Test
    fun `reference-only mutations reproduce omitted dependency and invalidate apply and discovery`() {
        for (mutation in listOf("target", "type", "primary", "addition", "removal")) {
            program { p ->
                val ins = p.listing.getInstructionAt(address(0x153))
                val r = preview(p)
                val before = ProgramFingerprint.components(p, TaskMonitor.DUMMY)
                val oldInputs = legacyInstructions(p)
                val oldFlows = ins.flows.toSet()
                val ref = p.referenceManager.getReferencesFrom(ins.address).single { it.referenceType.isCall }
                p.withTransaction {
                    when (mutation) {
                        "target" -> {
                            p.referenceManager.delete(ref)
                            p.referenceManager.addMemoryReference(
                                ins.address,
                                address(0x2100),
                                RefType.UNCONDITIONAL_CALL,
                                SourceType.USER_DEFINED,
                                0,
                            )
                        }
                        "type" -> p.referenceManager.updateRefType(ref, RefType.DATA)
                        "primary" -> p.referenceManager.setPrimary(ref, !ref.isPrimary)
                        "addition" ->
                            p.referenceManager.addMemoryReference(
                                ins.address,
                                address(0x2100),
                                RefType.UNCONDITIONAL_CALL,
                                SourceType.USER_DEFINED,
                                -1,
                            )
                        "removal" -> p.referenceManager.delete(ref)
                    }
                }
                val after = ProgramFingerprint.components(p, TaskMonitor.DUMMY)
                assertEquals(oldInputs, legacyInstructions(p), mutation)
                for (key in listOf("memory", "mapping", "data", "instructions")) assertEquals(before[key], after[key], "$mutation $key")
                if (mutation ==
                    "primary"
                ) {
                    assertEquals(oldFlows, ins.flows.toSet())
                } else {
                    assertNotEquals(oldFlows, ins.flows.toSet(), mutation)
                }
                assertNotEquals(before["flowReferences"], after["flowReferences"], mutation)
                assertThrows(IllegalStateException::class.java) { BankAnalysis.apply(p, r, TaskMonitor.DUMMY) }
                assertThrows(IllegalStateException::class.java) { FunctionDiscovery.discover(p, listOf(), r, TaskMonitor.DUMMY) }
                val rerun = preview(p)
                assertEquals(rerun, preview(p), mutation)
                assertFalse(rerun.findings().any { "2100" in it.targets() }, rerun.toString())
                if (mutation in listOf("target", "addition")) {
                    assertTrue(rerun.findings().any { it.reason().startsWith("Unsupported instruction interpretation") })
                } else {
                    // Missing/changed-to-data annotations do not erase decoded machine-code proof.
                    assertTrue(rerun.findings().any { it.access() == "call" && it.targets() == listOf("2000") })
                }
            }
        }
    }

    @Test
    fun `reference change during preview reports input changed with no proven candidates`() =
        program { p ->
            val monitor =
                object : TaskMonitorAdapter() {
                    var changed = false

                    override fun setMessage(message: String?) {
                        if (message == "Exploring bank states" && !changed) {
                            changed = true
                            p.withTransaction {
                                p.referenceManager.addMemoryReference(
                                    address(0x153),
                                    address(0x2100),
                                    RefType.UNCONDITIONAL_CALL,
                                    SourceType.USER_DEFINED,
                                    -1,
                                )
                            }
                        }
                    }
                }
            val r = preview(p, monitor)
            assertEquals(AnalysisResult.Completion.INPUT_CHANGED, r.completion())
            assertFalse(r.findings().any { it.confidence() == AnalysisResult.Confidence.PROVEN })
            assertThrows(IllegalStateException::class.java) { BankAnalysis.apply(p, r, TaskMonitor.DUMMY) }
        }

    @Test
    fun `transient reference mutation restored during preview still invalidates snapshot`() =
        program { p ->
            val fingerprint = ProgramFingerprint.capture(p, TaskMonitor.DUMMY)
            val monitor =
                object : TaskMonitorAdapter() {
                    override fun setMessage(message: String?) {
                        if (message == "Exploring bank states") {
                            p.withTransaction {
                                val added =
                                    p.referenceManager.addMemoryReference(
                                        address(0x153),
                                        address(0x2100),
                                        RefType.UNCONDITIONAL_CALL,
                                        SourceType.USER_DEFINED,
                                        -1,
                                    )
                                p.referenceManager.delete(added)
                            }
                        }
                    }
                }
            val r = preview(p, monitor)
            assertEquals(fingerprint, ProgramFingerprint.capture(p, TaskMonitor.DUMMY))
            assertEquals(AnalysisResult.Completion.INPUT_CHANGED, r.completion())
            assertFalse(r.findings().any { it.confidence() == AnalysisResult.Confidence.PROVEN })
            assertThrows(IllegalStateException::class.java) { BankAnalysis.apply(p, r, TaskMonitor.DUMMY) }
            assertThrows(IllegalStateException::class.java) { FunctionDiscovery.discover(p, listOf(), r, TaskMonitor.DUMMY) }
            assertEquals(AnalysisResult.Completion.COMPLETE, preview(p).completion())
        }

    @Test
    fun `supplemental generated data never supplies flow proof or invalidates reapplication`() =
        program { p ->
            val r = preview(p)
            p.withTransaction {
                p.referenceManager.addMemoryReference(address(0x153), address(0x2100), RefType.DATA, SourceType.ANALYSIS, -1)
            }
            assertEquals(r, preview(p))
            BankAnalysis.apply(p, r, TaskMonitor.DUMMY)
            assertEquals(r, preview(p))
            BankAnalysis.apply(p, r, TaskMonitor.DUMMY)
            AnalysisOwnership.removeAll(p, TaskMonitor.DUMMY)
            assertEquals(r, preview(p))
            BankAnalysis.apply(p, r, TaskMonitor.DUMMY)
            val data = p.referenceManager.getReferencesFrom(address(0x153)).single { it.toAddress == address(0x2100) }
            p.withTransaction { p.referenceManager.updateRefType(data, RefType.UNCONDITIONAL_CALL) }
            assertThrows(IllegalStateException::class.java) { BankAnalysis.apply(p, r, TaskMonitor.DUMMY) }
            assertTrue(preview(p).findings().any { it.reason().contains("stored flow annotation") })
        }
}
