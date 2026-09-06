package fi.gekkio.ghidraboy

import com.google.gson.JsonParser
import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.assembler.Assemblers
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.Enum
import ghidra.program.model.data.EnumDataType
import ghidra.program.model.listing.Instruction
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HardwareReferenceTest : IntegrationTest() {
    private fun fixture(action: (ProgramDB) -> Unit) {
        val consumer = Any()
        val program = ProgramDB("hardware enum", language, language.defaultCompilerSpec, consumer)
        try {
            program.withTransaction {
                program.memory.createInitializedBlock("rom", address(0), 0x100, 0.toByte(), TaskMonitor.DUMMY, false)
                GameBoyUtils.addHardwareBlocks(program, GameBoyKind.CGB, MessageLog())
                GameBoyUtils.populateHardwareBlocks(program, GameBoyKind.CGB)
            }
            action(program)
        } finally {
            program.release(consumer)
        }
    }

    @Test
    fun `all numeric masks and source aliases remain documented uniquely`() {
        fixture { program ->
            program.withTransaction { HardwareReference.apply(program, GameBoyKind.CGB, true) }
            HardwareReference::class.java.getResourceAsStream("/hardware-registers.json")!!.reader().use { reader ->
                val definitions = JsonParser.parseReader(reader).asJsonObject
                for (entry in definitions["registers"].asJsonArray) {
                    val register = entry.asJsonObject
                    val masks = register["masks"].asJsonObject
                    if (masks.size() == 0) continue
                    val type = program.dataTypeManager.getDataType("/GhidraBoy/Hardware/${register["name"].asString}Bits") as Enum
                    assertEquals(type.count, type.values.size)
                    val expected = masks.entrySet().map { it.value.asJsonObject["value"].asLong }.toSet()
                    assertEquals(expected, type.values.toSet())
                    for ((name, definition) in masks.entrySet()) {
                        val mask = definition.asJsonObject
                        val canonical = type.getName(mask["value"].asLong)
                        assertTrue(type.getComment(canonical).contains("$name: ${mask["description"].asString}"))
                    }
                }
            }
        }
    }

    @Test
    fun `hardware register stores decompile without duplicate enum diagnostics`() {
        fixture { program ->
            val function =
                program.withTransaction {
                    HardwareReference.apply(program, GameBoyKind.CGB, true)
                    val instructions: Iterable<Instruction> =
                        Assemblers.getAssembler(program).assemble(
                            address(0),
                            "LD A, 0x43",
                            "LD (0xff40), A",
                            "LD A, 0x40",
                            "LD (0xff41), A",
                            "LD A, 0x05",
                            "LD (0xff07), A",
                            "LD A, 0x30",
                            "LD (0xff00), A",
                            "RET",
                        )
                    val body = AddressSet()
                    for (instruction in instructions) body.add(instruction.minAddress, instruction.maxAddress)
                    program.functionManager.createFunction("configure", address(0), body, SourceType.USER_DEFINED)
                }
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(program))
                val result = decompiler.decompileFunction(function, 10, TaskMonitor.DUMMY)
                assertTrue(result.decompileCompleted(), result.errorMessage)
                val c = result.decompiledFunction.c
                assertFalse(c.contains("WARNING"), c)
                for (name in listOf("LCDC", "STAT", "TAC", "P1")) assertTrue(c.contains("$name ="), c)
            } finally {
                decompiler.dispose()
            }
        }
    }

    @Test
    fun `existing aliases and student comments are preserved on reapplication`() {
        fixture { program ->
            program.withTransaction {
                val legacy = EnumDataType(CategoryPath("/GhidraBoy/Hardware"), "JOYPBits", 1)
                legacy.add("STUDENT_BUTTONS", 0x10, "student interpretation")
                legacy.add("LEGACY_SGB_ONE", 0x10, "retained alias")
                program.dataTypeManager.addDataType(legacy, DataTypeConflictHandler.KEEP_HANDLER)
                HardwareReference.apply(program, GameBoyKind.CGB)
            }
            val preserved = program.dataTypeManager.getDataType("/GhidraBoy/Hardware/JOYPBits") as Enum
            assertEquals(setOf("STUDENT_BUTTONS", "LEGACY_SGB_ONE"), preserved.names.toSet())
            assertEquals("student interpretation", preserved.getComment("STUDENT_BUTTONS"))
            assertEquals("retained alias", preserved.getComment("LEGACY_SGB_ONE"))
        }
    }
}
