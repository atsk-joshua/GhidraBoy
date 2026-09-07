package fi.gekkio.ghidraboy

import ghidra.program.database.ProgramDB
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ReferenceOwnershipTest : IntegrationTest() {
    private fun program(test: (ProgramDB) -> Unit) {
        val consumer = Any()
        val p = ProgramDB("reference-ownership", language, language.defaultCompilerSpec, consumer)
        try {
            test(p)
        } finally {
            p.release(consumer)
        }
    }

    private fun own(p: ProgramDB) =
        p.withTransaction {
            val reference = p.referenceManager.addMemoryReference(address(0x150), address(0x200), RefType.DATA, SourceType.ANALYSIS, -1)
            p.referenceManager.setPrimary(reference, true)
            AnalysisOwnership.Group().also {
                it.reference(p.referenceManager.getReferencesFrom(address(0x150)).single())
                AnalysisOwnership.save(p, "test", it)
            }
        }

    @Test
    fun `unchanged receipt removes reference but primary edit relinquishes ownership`() =
        program { p ->
            own(p)
            AnalysisOwnership.remove(p, "test", TaskMonitor.DUMMY)
            assertEquals(0, p.referenceManager.getReferencesFrom(address(0x150)).size)
            own(p)
            p.withTransaction {
                p.referenceManager.setPrimary(p.referenceManager.getReferencesFrom(address(0x150)).single(), false)
            }
            AnalysisOwnership.remove(p, "test", TaskMonitor.DUMMY)
            assertEquals(1, p.referenceManager.getReferencesFrom(address(0x150)).size)
            assertTrue(
                !p.referenceManager
                    .getReferencesFrom(address(0x150))
                    .single()
                    .isPrimary,
            )
        }

    @Test
    fun `historical receipt lacking primary evidence is retained even after another group is saved`() {
        for (version in listOf(2, 3, 4)) {
            program { p ->
                own(p)
                p.withTransaction {
                    val options = p.getOptions(ProgramMapping.OPTIONS)
                    val root =
                        com.google.gson.JsonParser
                            .parseString(options.getString("analysis.ownership.v1", ""))
                            .asJsonObject
                    assertEquals(5, root.get("version").asInt)
                    root.addProperty("version", version)
                    for (key in listOf(
                        "views",
                        "siteReferences",
                        "primaries",
                        "payloads",
                        "repairs",
                        "helpers",
                        "bodies",
                        "stateEntries",
                    )) {
                        root.getAsJsonObject("groups").getAsJsonObject("test").remove(key)
                    }
                    root
                        .getAsJsonObject("groups")
                        .getAsJsonObject("test")
                        .getAsJsonArray("references")
                        .single()
                        .asJsonObject
                        .remove("primary")
                    options.setString("analysis.ownership.v1", root.toString())
                    AnalysisOwnership.save(p, "another", AnalysisOwnership.Group())
                    val upgraded =
                        com.google.gson.JsonParser
                            .parseString(options.getString("analysis.ownership.v1", ""))
                            .asJsonObject
                    assertEquals(5, upgraded.get("version").asInt)
                }
                val diagnostics = AnalysisOwnership.remove(p, "test", TaskMonitor.DUMMY)
                assertEquals(1, p.referenceManager.getReferencesFrom(address(0x150)).size)
                assertTrue(diagnostics.any { it.contains("lacks primary-status edit evidence") })
            }
        }
    }
}
