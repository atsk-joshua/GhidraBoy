package fi.gekkio.ghidraboy

import ghidra.app.decompiler.DecompInterface
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CompilerAbiTest : IntegrationTest() {
    @Test
    fun `per function profiles cover emitted ordinary variadic banked and explicit aggregate storage`() {
        val consumer = Any()
        val p = ProgramDB("ABI", language, language.defaultCompilerSpec, consumer)
        try {
            val parameters =
                listOf(
                    CompilerAbi.Parameter("a", "u8", null),
                    CompilerAbi.Parameter("b", "u16", null),
                    CompilerAbi.Parameter("c", "u8", null),
                )
            val legacy = CompilerAbi.preview(p, CompilerAbi.Request("sdcc416", "u16", null, parameters, null, null))
            assertEquals(listOf("Stack[0x2]", "Stack[0x3]", "Stack[0x5]"), legacy.parameters().map { it.storage().substringBefore(":") })
            assertTrue(legacy.returns().storage().startsWith("DE"))
            val current = CompilerAbi.Request("sdcc451-call1", "u16", null, parameters, null, null)
            val plan = CompilerAbi.preview(p, current)
            assertEquals(listOf("A", "DE", "Stack[0x2]"), plan.parameters().map { it.storage().substringBefore(":") })
            assertEquals(1, plan.stackPurgeBytes())
            val f =
                p.withTransaction {
                    p.functionManager.createFunction("owned_name", address(0x100), AddressSet(address(0x100)), SourceType.USER_DEFINED)
                }
            CompilerAbi.apply(p, f, current)
            assertEquals("default", p.compilerSpec.compilerSpecID.toString())
            assertEquals("owned_name", f.name)
            assertEquals(1, f.body.numAddresses)
            assertEquals("BC", f.getReturn().register.name)
            val variadic = CompilerAbi.preview(p, CompilerAbi.Request("sdcc451-variadic", "u16", null, listOf(parameters[0]), null, null))
            assertTrue(variadic.variadic())
            assertTrue(variadic.parameters()[0].storage().startsWith("Stack[0x2]"))
            assertEquals(0, variadic.stackPurgeBytes())
            val banked = CompilerAbi.preview(p, CompilerAbi.Request("sdcc451-banked-callee", "u8", null, parameters.take(2), null, null))
            assertTrue(banked.parameters()[0].storage().startsWith("Stack[0x6]"), banked.toString())
            assertTrue(banked.parameters()[1].storage().startsWith("Stack[0x7]"), banked.toString())
            val aggregate =
                CompilerAbi.Request(
                    "explicit",
                    "void",
                    null,
                    listOf(CompilerAbi.Parameter("result", "ptr", "stack:2"), CompilerAbi.Parameter("value", "bytes:3", "stack:4")),
                    5,
                    "__sdcc451_call1_first16",
                )
            CompilerAbi.apply(p, f, aggregate)
            assertEquals(5, f.stackPurgeSize)
            assertEquals(3, f.parameters[1].dataType.length)
            assertFalse(f.hasVarArgs())
            assertThrows(IllegalArgumentException::class.java) {
                CompilerAbi.preview(p, CompilerAbi.Request("sdcc451-call1", "bytes:3", null, parameters, null, null))
            }
        } finally {
            p.release(consumer)
        }
    }

    @Test
    fun `decompiler honors per function preserved BC across a call`() {
        val consumer = Any()
        val p = ProgramDB("ABI decompiler", language, language.defaultCompilerSpec, consumer)
        val decompiler = DecompInterface()
        try {
            p.withTransaction {
                p.memory.createInitializedBlock("rom", address(0), 0x8000, 0, TaskMonitor.DUMMY, false)
                p.memory.setBytes(address(0x100), byteArrayOf(0x3e, 1, 0x0e, 9, 0xcd.toByte(), 0, 2, 0x81.toByte(), 0xc9.toByte()))
                p.memory.setBytes(address(0x200), byteArrayOf(0x3c, 0xc9.toByte()))
                Disassembler
                    .getDisassembler(
                        p,
                        TaskMonitor.DUMMY,
                        null,
                    ).disassemble(address(0x100), AddressSet(address(0x100), address(0x201)))
            }
            val caller =
                p.withTransaction {
                    p.functionManager.createFunction(
                        "caller",
                        address(0x100),
                        AddressSet(address(0x100), address(0x108)),
                        SourceType.USER_DEFINED,
                    )
                }
            val callee =
                p.withTransaction {
                    p.functionManager.createFunction(
                        "preserved",
                        address(0x200),
                        AddressSet(address(0x200), address(0x201)),
                        SourceType.USER_DEFINED,
                    )
                }
            CompilerAbi.apply(p, caller, CompilerAbi.Request("sdcc451-call1", "u8", null, listOf(), null, null))
            CompilerAbi.apply(
                p,
                callee,
                CompilerAbi.Request("sdcc451-preserves-bc", "u8", null, listOf(CompilerAbi.Parameter("a", "u8", null)), null, null),
            )
            assertTrue(decompiler.openProgram(p))
            val result = decompiler.decompileFunction(caller, 30, TaskMonitor.DUMMY)
            assertTrue(result.decompileCompleted(), result.errorMessage)
            val c = result.decompiledFunction.c
            assertTrue(c.contains("preserved(1)"), c)
            assertTrue(c.contains("+ 9"), c)
            assertEquals(0, result.highFunction.function.parameterCount)
        } finally {
            decompiler.dispose()
            p.release(consumer)
        }
    }

    @Test
    fun `native manual index resolves the bundled local reference`() {
        assertTrue(language.hasManual())
        val entry = language.getManualEntry("ADC")
        assertTrue(java.io.File(entry.manualPath).isFile)
        assertTrue(entry.manualPath.endsWith("SM83.html"))
        assertTrue(language.manualInstructionMnemonicKeys.containsAll(listOf("ADC", "SBC", "DAA", "POP")))
    }
}
