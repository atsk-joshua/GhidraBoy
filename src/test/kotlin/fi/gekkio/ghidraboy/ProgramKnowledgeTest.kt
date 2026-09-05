package fi.gekkio.ghidraboy

import com.google.gson.JsonParser
import ghidra.program.database.ProgramDB
import ghidra.program.model.listing.CodeUnit
import ghidra.program.model.symbol.SourceType
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class ProgramKnowledgeTest : IntegrationTest() {
    @TempDir
    lateinit var directory: Path

    @Test
    fun `export preserves legacy schema annotations and create-new semantics`() {
        val consumer = Any()
        val program = ProgramDB("knowledge fixture", language, language.defaultCompilerSpec, consumer)
        try {
            program.withTransaction {
                program.memory.createInitializedBlock("student code", address(0x100), 16, 0.toByte(), TaskMonitor.DUMMY, false)
                program.symbolTable.createLabel(address(0x100), "StudentLabel", SourceType.USER_DEFINED)
                program.listing.setComment(address(0x100), CodeUnit.EOL_COMMENT, "Student note")
            }
            val output = directory.resolve("new knowledge.json")
            ProgramKnowledge.export(program, output, TaskMonitor.DUMMY)
            val text = Files.readString(output)
            val json = JsonParser.parseString(text).asJsonObject
            assertEquals("ghigbc-knowledge-v1", json["schema"].asString)
            assertEquals("SM83:LE:16:default", json["language"].asString)
            assertTrue(text.contains("StudentLabel") && text.contains("Student note"))
            assertThrows(
                java.nio.file.FileAlreadyExistsException::class.java,
            ) { ProgramKnowledge.export(program, output, TaskMonitor.DUMMY) }
            assertEquals(text, Files.readString(output))
            assertEquals("Student note", program.listing.getComment(CodeUnit.EOL_COMMENT, address(0x100)))
        } finally {
            program.release(consumer)
        }
    }

    @Test
    fun `cancelled export creates no file and leaves program unchanged`() {
        val consumer = Any()
        val program = ProgramDB("cancel fixture", language, language.defaultCompilerSpec, consumer)
        try {
            val monitor = TaskMonitorAdapter(true).apply { cancel() }
            val output = directory.resolve("cancelled.json")
            assertThrows(CancelledException::class.java) { ProgramKnowledge.export(program, output, monitor) }
            assertFalse(Files.exists(output))
            assertEquals(0, program.memory.blocks.size)
        } finally {
            program.release(consumer)
        }
    }
}
