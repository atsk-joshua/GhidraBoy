package fi.gekkio.ghidraboy

import ghidra.framework.data.OpenMode
import ghidra.framework.store.db.PackedDatabase
import ghidra.program.database.ProgramDB
import ghidra.program.model.symbol.RefType
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
import java.nio.file.Path

class UserReferencePrimacyTest : IntegrationTest() {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `restore preserves every user primary boolean and changes no reference tuple`() {
        fixture().useProgram { program ->
            val snapshot = snapshot(program)
            val tupleCount = allReferences(program).size
            displace(program)
            val result = UserReferencePrimacy.restore(program, snapshot, TaskMonitor.DUMMY)
            assertEquals(2, result.changedPrimaryStates())
            assertEquals(tupleCount + 2, allReferences(program).size)
            assertStates(program, true)
            assertFalse(program.referenceManager.getReference(address(0x100), address(0x300), 0).isPrimary)
            assertFalse(program.referenceManager.getReference(address(0x110), address(0x310), 0).isPrimary)
            assertTrue(program.referenceManager.getReference(address(0x120), address(0x320), 0).isPrimary)
            assertEquals(0, UserReferencePrimacy.restore(program, snapshot, TaskMonitor.DUMMY).changedPrimaryStates())
        }
    }

    @Test
    fun `wrong Program and missing expected reference refuse before mutation`() {
        fixture().useProgram { source ->
            val snapshot = snapshot(source)
            fixture().useProgram { wrong ->
                assertThrows(IllegalArgumentException::class.java) {
                    UserReferencePrimacy.restore(wrong, snapshot, TaskMonitor.DUMMY)
                }
                assertStates(wrong, true)
            }

            val missing = source.referenceManager.getReference(address(0x100), address(0x200), 0)
            source.withTransaction { source.referenceManager.delete(missing) }
            val revision = source.modificationNumber
            assertThrows(IllegalArgumentException::class.java) {
                UserReferencePrimacy.restore(source, snapshot, TaskMonitor.DUMMY)
            }
            assertEquals(revision, source.modificationNumber)
        }
    }

    @Test
    fun `cancellation rolls back a partially attempted restoration`() {
        fixture().useProgram { program ->
            val snapshot = snapshot(program)
            displace(program)
            val monitor =
                object : TaskMonitorAdapter(true) {
                    private var checks = 0

                    override fun checkCancelled() {
                        checks++
                        if (checks == 18) throw CancelledException()
                        super.checkCancelled()
                    }
                }
            assertThrows(CancelledException::class.java) {
                UserReferencePrimacy.restore(program, snapshot, monitor)
            }
            assertStates(program, false)
        }
    }

    @Test
    fun `restored primacy and preservation marker survive packed reopen`() {
        fixture().useProgram { program ->
            val snapshot = snapshot(program)
            displace(program)
            UserReferencePrimacy.restore(program, snapshot, TaskMonitor.DUMMY)
            val packed = temporary.resolve("primacy.gzf").toFile()
            program.saveToPackedFile(packed, TaskMonitor.DUMMY)
            val database = PackedDatabase.getPackedDatabase(packed, true, TaskMonitor.DUMMY)
            val consumer = Any()
            var reopened: ProgramDB? = null
            try {
                reopened =
                    ProgramDB(
                        database.open(TaskMonitor.DUMMY),
                        OpenMode.IMMUTABLE,
                        TaskMonitor.DUMMY,
                        consumer,
                    )
                UserReferencePrimacy.verify(reopened, snapshot, TaskMonitor.DUMMY)
                assertEquals(
                    "PRESERVED",
                    reopened.getOptions(ProgramMapping.OPTIONS).getString("migration.referencePrimacy", null),
                )
                assertStates(reopened, true)
            } finally {
                reopened?.release(consumer)
                database.dispose()
            }
        }
    }

    private fun snapshot(program: ProgramDB): UserReferencePrimacy.Snapshot {
        val captured = UserReferencePrimacy.capture(program, 3, TaskMonitor.DUMMY)
        val binding = captured.binding()
        return UserReferencePrimacy.Snapshot(
            captured.schema(),
            captured.schemaVersion(),
            UserReferencePrimacy.Binding(
                binding.originalSha256(),
                binding.executableSha256(),
                binding.executableMd5(),
                binding.programName(),
                binding.uniqueProgramId(),
                binding.domainFileId(),
                binding.domainPath(),
                binding.languageId(),
                1,
                2,
                binding.compilerSpecId(),
            ),
            captured.referenceCount(),
            captured.primaryReferenceCount(),
            captured.tupleSha256(),
            captured.stateSha256(),
            captured.references(),
        )
    }

    private fun displace(program: ProgramDB) {
        program.withTransaction {
            for ((from, to) in listOf(0x100L to 0x300L, 0x110L to 0x310L)) {
                val competitor =
                    program.referenceManager.addMemoryReference(
                        address(from),
                        address(to),
                        RefType.DATA,
                        SourceType.DEFAULT,
                        0,
                    )
                program.referenceManager.setPrimary(competitor, true)
            }
        }
        assertStates(program, false)
    }

    private fun assertStates(
        program: ProgramDB,
        restored: Boolean,
    ) {
        val first = program.referenceManager.getReference(address(0x100), address(0x200), 0)
        val second = program.referenceManager.getReference(address(0x110), address(0x210), 0)
        val intentional = program.referenceManager.getReference(address(0x120), address(0x220), 0)
        assertEquals(restored, first.isPrimary)
        assertEquals(restored, second.isPrimary)
        assertFalse(intentional.isPrimary)
    }

    private fun allReferences(program: ProgramDB) =
        buildList {
            for (from in listOf(0x100L, 0x110L, 0x120L)) {
                addAll(program.referenceManager.getReferencesFrom(address(from)).toList())
            }
        }

    private fun fixture(): Fixture {
        val consumer = Any()
        val program = ProgramDB("primacy", language, language.defaultCompilerSpec, consumer)
        program.withTransaction<Unit> {
            val bytes = ByteArray(0x8000).also { it[0x147] = 0 }
            ghidra.app.util.bin.ByteArrayProvider(bytes).use { provider ->
                val file =
                    ghidra.app.util.MemoryBlockUtils
                        .createFileBytes(program, provider, TaskMonitor.DUMMY)
                program.memory.createInitializedBlock("rom", address(0), file, 0, bytes.size.toLong(), false)
            }
            val first =
                program.referenceManager.addMemoryReference(
                    address(0x100),
                    address(0x200),
                    RefType.DATA,
                    SourceType.USER_DEFINED,
                    0,
                )
            val second =
                program.referenceManager.addMemoryReference(
                    address(0x110),
                    address(0x210),
                    RefType.DATA,
                    SourceType.USER_DEFINED,
                    0,
                )
            program.referenceManager.addMemoryReference(
                address(0x120),
                address(0x220),
                RefType.DATA,
                SourceType.USER_DEFINED,
                0,
            )
            val intentionalPrimary =
                program.referenceManager.addMemoryReference(
                    address(0x120),
                    address(0x320),
                    RefType.DATA,
                    SourceType.DEFAULT,
                    0,
                )
            program.referenceManager.setPrimary(first, true)
            program.referenceManager.setPrimary(second, true)
            program.referenceManager.setPrimary(intentionalPrimary, true)
        }
        assertStates(program, true)
        return Fixture(program, consumer)
    }

    private class Fixture(
        val program: ProgramDB,
        private val consumer: Any,
    ) {
        fun <T> useProgram(block: (ProgramDB) -> T): T =
            try {
                block(program)
            } finally {
                program.release(consumer)
            }
    }
}
