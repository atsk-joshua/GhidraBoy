package fi.gekkio.ghidraboy

import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.WordDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.LocalVariableImpl
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.VariableStorage
import ghidra.program.model.symbol.SourceType
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class FunctionOwnershipTest : IntegrationTest() {
    private fun program(test: (ProgramDB, Function) -> Unit) {
        val consumer = Any()
        val p = ProgramDB("function-ownership", language, language.defaultCompilerSpec, consumer)
        try {
            p.withTransaction {
                p.memory.createInitializedBlock("code", address(0x300), 0x100, 0.toByte(), TaskMonitor.DUMMY, false)
                for (at in listOf(0x300L, 0x310L)) {
                    p.memory.setByte(address(at), 0xc9.toByte())
                    Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(address(at), AddressSet(address(at)))
                }
            }
            discover(p)
            test(p, p.functionManager.getFunctionAt(address(0x300)))
        } finally {
            p.release(consumer)
        }
    }

    private fun discover(p: ProgramDB) =
        FunctionDiscovery.discover(p, listOf(address(0x300)), emptyList<BankAnalysis.Finding>(), TaskMonitor.DUMMY)

    private fun receipt(p: ProgramDB, f: Function) = p.withTransaction {
        val group = AnalysisOwnership.Group()
        group.function(f)
        AnalysisOwnership.save(p, "functions", group)
    }

    @ParameterizedTest
    @ValueSource(strings = ["local", "inline", "noreturn", "varargs", "cleanup", "namespace", "body", "comment", "repeatable", "tag", "fixup", "return", "storage", "signature", "parameter", "local-label", "thunk"])
    fun `edited discovered functions survive every removal route`(edit: String) = program { p, f ->
        val id = f.id
        p.withTransaction {
            when (edit) {
                "local" -> f.addLocalVariable(LocalVariableImpl("saved", WordDataType.dataType, -2, p), SourceType.USER_DEFINED)
                "inline" -> f.isInline = true
                "noreturn" -> f.setNoReturn(true)
                "varargs" -> f.setVarArgs(true)
                "cleanup" -> f.stackPurgeSize = 4
                "namespace" -> f.parentNamespace = p.symbolTable.createNameSpace(null, "UserSpace", SourceType.USER_DEFINED)
                "body" -> f.body = AddressSet(address(0x300), address(0x301))
                "comment" -> f.comment = "user comment"
                "repeatable" -> f.repeatableComment = "user repeatable"
                "tag" -> f.addTag("user tag")
                "fixup" -> f.callFixup = "user_fixup"
                "return" -> f.setReturnType(ByteDataType.dataType, SourceType.USER_DEFINED)
                "storage" -> f.setCustomVariableStorage(true)
                "signature" -> f.signatureSource = SourceType.USER_DEFINED
                "parameter" -> f.addParameter(ParameterImpl("input", WordDataType.dataType, 2, p), SourceType.USER_DEFINED)
                "local-label" -> p.symbolTable.createLabel(address(0x301), "user_local", f, SourceType.USER_DEFINED)
                "thunk" -> f.setThunkedFunction(p.functionManager.createFunction("target", address(0x310), AddressSet(address(0x310)), SourceType.USER_DEFINED))
            }
        }
        val messages = discover(p)
        assertEquals(id, p.functionManager.getFunctionAt(address(0x300))?.id, edit)
        assertTrue(messages.any { it.contains("Preserved") }, messages.toString())
        AnalysisOwnership.remove(p, "functions", TaskMonitor.DUMMY)
        AnalysisOwnership.removeAll(p, TaskMonitor.DUMMY)
        discover(p)
        assertEquals(id, p.functionManager.getFunctionAt(address(0x300))?.id, edit)
    }

    @ParameterizedTest
    @ValueSource(strings = ["local", "parameter", "return"])
    fun `variable detail edits survive explicit removal`(kind: String) = program { p, f ->
        for (edit in if (kind == "return") listOf("type", "storage") else listOf("name", "comment", "type", "storage")) {
            val v = p.withTransaction {
                when (kind) {
                    "local" -> {
                        f.localVariables.forEach { f.removeVariable(it) }
                        f.addLocalVariable(LocalVariableImpl("local_2", WordDataType.dataType, -2, p), SourceType.ANALYSIS)
                    }
                    "parameter" -> {
                        if (f.parameterCount > 0) f.removeParameter(0)
                        f.addParameter(ParameterImpl("param_1", WordDataType.dataType, 2, p), SourceType.ANALYSIS)
                    }
                    else -> { f.setReturnType(WordDataType.dataType, SourceType.ANALYSIS); f.getReturn() }
                }
            }
            receipt(p, f)
            p.withTransaction {
                when (edit) {
                    "name" -> if (kind != "return") v.setName("renamed", SourceType.USER_DEFINED) else f.setReturnType(ByteDataType.dataType, SourceType.USER_DEFINED)
                    "comment" -> v.comment = "preserve variable comment"
                    "type" -> v.setDataType(ByteDataType.dataType, SourceType.USER_DEFINED)
                    "storage" -> {
                        f.setCustomVariableStorage(true)
                        v.setDataType(WordDataType.dataType, VariableStorage(p, p.getRegister("BC")), true, SourceType.USER_DEFINED)
                    }
                }
            }
            assertTrue(AnalysisOwnership.remove(p, "functions", TaskMonitor.DUMMY).any { it.contains("Preserved") }, "$kind $edit")
            assertEquals(f.id, p.functionManager.getFunctionAt(address(0x300))?.id, "$kind $edit")
        }
    }

    @Test
    fun `in place referenced type mutation never certifies unchanged ownership`() = program { p, f ->
        val type = p.withTransaction {
            val structure = StructureDataType("Mutable", 0)
            structure.add(ByteDataType.dataType, "field", null)
            val resolved = p.dataTypeManager.resolve(structure, DataTypeConflictHandler.DEFAULT_HANDLER) as Structure
            f.setReturnType(resolved, SourceType.ANALYSIS)
            resolved
        }
        receipt(p, f)
        p.withTransaction { type.getComponent(0).comment = "edited without changing path or size" }
        assertTrue(AnalysisOwnership.removeAll(p, TaskMonitor.DUMMY).any { it.contains("Preserved") })
        assertNotNull(p.functionManager.getFunctionAt(address(0x300)))
    }

    @Test
    fun `legacy receipts retain even apparently unchanged functions and never rebaseline`() = program { p, f ->
        p.withTransaction {
            val json = ProgramMapping.JSON.toJsonTree(AnalysisOwnership.Group().apply { function(f) }).asJsonObject
            json.getAsJsonArray("functions").forEach { it.asJsonObject.remove("version") }
            p.getOptions(ProgramMapping.OPTIONS).setString("analysis.ownership.v1", "{\"version\":1,\"groups\":{\"functions\":$json}}")
        }
        val messages = discover(p)
        assertTrue(messages.any { it.contains("legacy") }, messages.toString())
        AnalysisOwnership.removeAll(p, TaskMonitor.DUMMY)
        assertEquals(f.id, p.functionManager.getFunctionAt(address(0x300))?.id)
    }

    @Test
    fun `unchanged functions remove but preexisting user functions survive`() = program { p, _ ->
        AnalysisOwnership.remove(p, "functions", TaskMonitor.DUMMY)
        assertNull(p.functionManager.getFunctionAt(address(0x300)))
        p.withTransaction { p.functionManager.createFunction("user", address(0x300), AddressSet(address(0x300)), SourceType.USER_DEFINED) }
        discover(p)
        AnalysisOwnership.removeAll(p, TaskMonitor.DUMMY)
        assertEquals("user", p.functionManager.getFunctionAt(address(0x300)).name)
    }

    @Test
    fun `cancelled removal restores function and receipts including relinquished edits`() = program { p, f ->
        p.withTransaction { f.isInline = true }
        val before = p.getOptions(ProgramMapping.OPTIONS).getString("analysis.ownership.v1", "")
        val monitor = object : TaskMonitorAdapter() {
            override fun checkCancelled() {
                if (p.getOptions(ProgramMapping.OPTIONS).getString("analysis.ownership.v1", "") != before) throw CancelledException()
            }
        }
        assertThrows(CancelledException::class.java) { AnalysisOwnership.removeAll(p, monitor) }
        assertEquals(before, p.getOptions(ProgramMapping.OPTIONS).getString("analysis.ownership.v1", ""))
        assertTrue(p.functionManager.getFunctionAt(address(0x300)).isInline)
        assertTrue(AnalysisOwnership.removeAll(p, TaskMonitor.DUMMY).any { it.contains("Preserved") })
    }
}
