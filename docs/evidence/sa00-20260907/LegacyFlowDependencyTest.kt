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
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class LegacyFlowDependencyTest : IntegrationTest() {
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
                for (range in listOf(AddressSet(address(0x150), address(0x156)), AddressSet(address(0x2000)), AddressSet(address(0x2100)))) {
                    d.disassemble(range.minAddress, range)
                }
            }
            test(p)
        } finally {
            p.release(consumer)
        }
    }

    private fun preview(p: ProgramDB, monitor: TaskMonitor = TaskMonitor.DUMMY) =
        BankAnalysis.preview(p, address(0x150), MapperState.reset(), AnalysisResult.Configuration.DEFAULT, monitor)

    // Exact pre-SA-00 instruction inputs: no references, primary status, or callfixups.
    private fun legacyInstructions(p: ProgramDB) =
        p.listing.getInstructions(true).iterator().asSequence().map {
            listOf(it.address.toString(), it.length, it.flowOverride, it.isFallThroughOverridden, it.fallThrough?.toString())
        }.toList()

    @Test
    fun `old engine accepts stale reference-only mutations`() {
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
                            p.referenceManager.addMemoryReference(ins.address, address(0x2100), RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0)
                        }
                        "type" -> p.referenceManager.updateRefType(ref, RefType.DATA)
                        "primary" -> p.referenceManager.setPrimary(ref, !ref.isPrimary)
                        "addition" -> p.referenceManager.addMemoryReference(ins.address, address(0x2100), RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, -1)
                        "removal" -> p.referenceManager.delete(ref)
                    }
                }
                val after = ProgramFingerprint.components(p, TaskMonitor.DUMMY)
                assertEquals(oldInputs, legacyInstructions(p), mutation)
                for (key in listOf("memory", "mapping", "data", "instructions")) assertEquals(before[key], after[key], "$mutation $key")
                if (mutation == "primary") assertEquals(oldFlows, ins.flows.toSet()) else assertNotEquals(oldFlows, ins.flows.toSet(), mutation)
                assertEquals(before, after, mutation)
                assertEquals(r.fingerprint(), ProgramFingerprint.capture(p, TaskMonitor.DUMMY), mutation)
                BankAnalysis.apply(p, r, TaskMonitor.DUMMY)
                FunctionDiscovery.discover(p, listOf(), r, TaskMonitor.DUMMY)
                val rerun = preview(p)
                println("LEGACY $mutation oldFlows=$oldFlows newFlows=${ins.flows.toSet()} staleApply=ACCEPTED staleDiscovery=ACCEPTED oldCalls=${r.findings().filter { it.access() == "call" }} newCalls=${rerun.findings().filter { it.access() == "call" }}")
                if (mutation == "primary") assertEquals(r.findings(), rerun.findings()) else assertNotEquals(r.findings(), rerun.findings(), mutation)

            }
        }
    }

}
