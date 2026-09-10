package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.DBObjectCache
import ghidra.program.database.ProgramDB
import ghidra.program.database.symbol.SymbolDB
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressMapImpl
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FarCallEvidenceTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY

    private fun fixture(action: (ProgramDB) -> Unit) {
        val owner = Any()
        val p = ProgramDB("dependency identity", language, language.defaultCompilerSpec, owner)
        try {
            val bytes = ByteArray(0x10000)
            bytes[0x147] = 0x13
            bytes[0x148] = 1
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, monitor, MessageLog())
            }
            action(p)
        } finally {
            p.release(owner)
        }
    }

    private fun fingerprints(p: ProgramDB): List<String> =
        listOf(FarCallEvidence.capture(p, monitor), FarCallEvidence.captureWithoutOwnership(p, monitor))

    private fun symbolDescriptions(p: ProgramDB): List<String> =
        p.symbolTable
            .getAllSymbols(true)
            .iterator()
            .asSequence()
            .map { "${it.address}:${it.getName(true)}:${it.source}:${it.isPinned}:${it.isDynamic}" }
            .sorted()
            .toList()

    private fun <T> withFreshDynamicMap(
        p: ProgramDB,
        order: List<Address>,
        action: (List<Long>) -> T,
    ): T {
        val symbols = p.symbolTable
        // Pinned Ghidra SymbolManager constructs these two process-local objects afresh.
        // AddressMapImpl assigns base indices on first observation, not from Program records.
        // Reset both objects so cached dynamic symbols cannot alias the replacement map's keys.
        val mapField = symbols.javaClass.getDeclaredField("dynamicSymbolAddressMap").apply { isAccessible = true }
        val cacheField = symbols.javaClass.getDeclaredField("cache").apply { isAccessible = true }
        val originalMap = mapField.get(symbols)
        val originalCache = cacheField.get(symbols)
        try {
            mapField.set(symbols, AddressMapImpl(0x40.toByte(), p.addressFactory))
            cacheField.set(symbols, DBObjectCache<SymbolDB>(100))
            order.forEach { symbols.getDynamicSymbolID(it) }
            return action(order.sorted().map { symbols.getDynamicSymbolID(it) })
        } finally {
            mapField.set(symbols, originalMap)
            cacheField.set(symbols, originalCache)
        }
    }

    @Test
    fun `opposite dynamic address allocation order preserves both dependency variants`() =
        fixture { p ->
            val targets = listOf(address(0x350), ProgramMapping.fileToStatic(p, 0x8100).single())
            p.withTransaction {
                targets.forEachIndexed { index, target ->
                    p.referenceManager.addMemoryReference(
                        address(0x300 + index.toLong()),
                        target,
                        RefType.DATA,
                        SourceType.USER_DEFINED,
                        -1,
                    )
                }
            }
            val revision = p.modificationNumber
            val base = ProgramFingerprint.capture(p, monitor)
            val first =
                withFreshDynamicMap(p, targets) { ids ->
                    targets.forEach { assertTrue(p.symbolTable.getPrimarySymbol(it).isDynamic) }
                    Triple(ids, symbolDescriptions(p), fingerprints(p))
                }
            val reversed =
                withFreshDynamicMap(p, targets.reversed()) { ids ->
                    targets.forEach { assertTrue(p.symbolTable.getPrimarySymbol(it).isDynamic) }
                    Triple(ids, symbolDescriptions(p), fingerprints(p))
                }
            assertNotEquals(first.first, reversed.first, "The control must actually reverse ephemeral numeric identities")
            assertEquals(first.second, reversed.second, "Every symbol still denotes the same address, name, source and ownership")
            assertEquals(base, ProgramFingerprint.capture(p, monitor))
            assertEquals(revision, p.modificationNumber, "Allocation order is observation, not a Program edit")
            assertEquals(first.third, reversed.third, "Both production dependency variants must survive fresh dynamic allocation order")
        }

    @Test
    fun `replacing a stored label retains distinct ownership identity`() =
        fixture { p ->
            val original =
                p.withTransaction {
                    val label = p.symbolTable.createLabel(address(0x350), "owned_label", SourceType.USER_DEFINED)
                    // Keep a later record so deleting the label cannot recycle the highest ID.
                    p.symbolTable.createLabel(address(0x360), "later_label", SourceType.USER_DEFINED)
                    label
                }
            assertFalse(original.isDynamic)
            val id = original.id
            val descriptions = symbolDescriptions(p)
            val before = fingerprints(p)
            val replacement =
                p.withTransaction {
                    assertTrue(original.delete())
                    p.symbolTable.createLabel(address(0x350), "owned_label", SourceType.USER_DEFINED)
                }
            assertNotEquals(id, replacement.id)
            assertEquals(descriptions, symbolDescriptions(p), "Only the stored ownership identity was replaced")
            fingerprints(p).zip(before).forEach { (after, prior) -> assertNotEquals(prior, after) }
        }

    @Test
    fun `rebinding a reference between stored labels at the same address remains visible`() =
        fixture { p ->
            val target = address(0x350)
            val source = address(0x300)
            val labels =
                p.withTransaction {
                    val a = p.symbolTable.createLabel(target, "binding_A", SourceType.USER_DEFINED)
                    val b = p.symbolTable.createLabel(target, "binding_B", SourceType.USER_DEFINED)
                    val reference = p.referenceManager.addMemoryReference(source, target, RefType.DATA, SourceType.USER_DEFINED, -1)
                    p.referenceManager.setAssociation(a, reference)
                    a to b
                }
            assertEquals(
                labels.first.id,
                p.referenceManager
                    .getReferencesFrom(source)
                    .single()
                    .symbolID,
            )
            val descriptions = symbolDescriptions(p)
            val base = ProgramFingerprint.capture(p, monitor)
            val before = fingerprints(p)
            p.withTransaction {
                p.referenceManager.setAssociation(labels.second, p.referenceManager.getReferencesFrom(source).single())
            }
            assertEquals(
                labels.second.id,
                p.referenceManager
                    .getReferencesFrom(source)
                    .single()
                    .symbolID,
            )
            assertEquals(descriptions, symbolDescriptions(p), "Both stored labels are unchanged")
            assertEquals(base, ProgramFingerprint.capture(p, monitor), "The additional review guard owns this binding dependency")
            fingerprints(p).zip(before).forEach { (after, prior) -> assertNotEquals(prior, after) }
        }

    @Test
    fun `ownership exclusion leaves convention and other dependencies intact`() =
        fixture { p ->
            val before = fingerprints(p)
            p.withTransaction { p.getOptions(ProgramMapping.OPTIONS).setString("analysis.ownership.v1", "reviewed ownership change") }
            val ownership = fingerprints(p)
            assertNotEquals(before[0], ownership[0])
            assertEquals(before[1], ownership[1])
            p.withTransaction { p.getOptions(ProgramMapping.OPTIONS).setString("farCallConvention", "reviewed convention change") }
            fingerprints(p).zip(ownership).forEach { (after, prior) -> assertNotEquals(prior, after) }
        }
}
