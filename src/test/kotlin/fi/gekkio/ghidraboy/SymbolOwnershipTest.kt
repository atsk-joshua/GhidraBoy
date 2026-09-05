package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.model.address.AddressSet
import ghidra.program.model.symbol.SourceType
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SymbolOwnershipTest : IntegrationTest() {
    private fun program(test: (ProgramDB) -> Unit) {
        val consumer = Any()
        val p = ProgramDB("symbol lifecycle", language, language.defaultCompilerSpec, consumer)
        try {
            val bytes =
                ByteArray(0x10000).also {
                    it[0x147] = 0x19
                    it[0x148] = 1
                }
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, false, false, TaskMonitor.DUMMY, MessageLog())
            }
            test(p)
        } finally {
            p.release(consumer)
        }
    }

    private fun put(
        p: ProgramDB,
        source: String,
        text: String = "2:4010 Shared\n",
    ) = SymbolService.importSymbols(p, SymbolFile.parse(text.toByteArray()), source, TaskMonitor.DUMMY)

    @Test
    fun `both source removal orders and changed reloads retain shared membership`() {
        for (first in listOf("a", "b")) {
            program { p ->
                put(p, "a")
                put(p, "b")
                assertEquals(2, SymbolService.sources(p).size)
                SymbolService.removeOwned(p, first, TaskMonitor.DUMMY)
                assertTrue(p.symbolTable.getSymbols("Shared").hasNext())
                val remaining = if (first == "a") "b" else "a"
                put(p, remaining, "2:4011 Replacement\n")
                assertFalse(p.symbolTable.getSymbols("Shared").hasNext())
                assertTrue(p.symbolTable.getSymbols("Replacement").hasNext())
                SymbolService.removeOwned(p, remaining, TaskMonitor.DUMMY)
                assertFalse(p.symbolTable.getSymbols("Replacement").hasNext())
            }
        }
    }

    @Test
    fun `preexisting edited moved and promoted labels survive last source removal`() {
        for (change in listOf("preexisting", "rename", "namespace", "promotion")) {
            program { p ->
                val target = ProgramMapping.fileToStatic(p, 0x8010).single()
                if (change == "preexisting") {
                    p.withTransaction {
                        p.symbolTable.createLabel(target, "Shared", SourceType.USER_DEFINED)
                    }
                }
                put(p, "a")
                put(p, "b")
                val symbol = p.symbolTable.getSymbols("Shared").next()
                val id = symbol.id
                p.withTransaction {
                    when (change) {
                        "rename" -> symbol.setName("Edited", SourceType.USER_DEFINED)
                        "namespace" ->
                            symbol.setNamespace(
                                p.symbolTable.createNameSpace(p.globalNamespace, "Moved", SourceType.USER_DEFINED),
                            )
                        "promotion" -> p.functionManager.createFunction("Shared", target, AddressSet(target), SourceType.USER_DEFINED)
                    }
                }
                SymbolService.removeOwned(p, "a", TaskMonitor.DUMMY)
                SymbolService.removeOwned(p, "b", TaskMonitor.DUMMY)
                assertTrue(p.symbolTable.getSymbol(id) != null || p.functionManager.getFunctionAt(target) != null, change)
            }
        }
    }

    @Test
    fun `cancelled import rolls back claims and newly created labels`() =
        program { p ->
            put(p, "a")
            val monitor =
                object : TaskMonitorAdapter(true) {
                    var checks = 0

                    override fun checkCancelled() {
                        if (++checks == 3) throw CancelledException()
                    }
                }
            assertThrows(CancelledException::class.java) {
                SymbolService.importSymbols(p, SymbolFile.parse("2:4011 NewOne\n2:4012 NewTwo\n".toByteArray()), "cancelled", monitor)
            }
            assertEquals(listOf("a"), SymbolService.sources(p).map { it.name() })
            assertFalse(p.symbolTable.getSymbols("NewOne").hasNext())
            assertFalse(p.symbolTable.getSymbols("NewTwo").hasNext())
            assertTrue(p.symbolTable.getSymbols("Shared").hasNext())
        }
}
