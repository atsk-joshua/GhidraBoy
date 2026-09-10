package fi.gekkio.ghidraboy

import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

class W4MemoryImageTest : IntegrationTest() {
    private val monitor = TaskMonitor.DUMMY
    private val primary = "fa60c0ea70c03cea60e0fa60c0ea71c0c9"

    private fun fixture(
        code: String = primary,
        action: (ProgramDB, Function) -> Unit,
    ) {
        val bytes = requireNotNull(javaClass.getResourceAsStream("/ordinary/PREDICATED_CALLS.gb")).use { it.readBytes() }
        val instructions = HexFormat.of().parseHex(code)
        instructions.copyInto(bytes, 0x150)
        HexFormat.of().parseHex("3e31ea74c0c9").copyInto(bytes, 0x300)
        HexFormat.of().parseHex("3ea7ea74c0c9").copyInto(bytes, 0x320)
        val owner = Any()
        val p = ProgramDB("w4-memory-image", language, language.defaultCompilerSpec, owner)
        try {
            ByteArrayProvider(
                bytes,
            ).use { CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, monitor, MessageLog()) }
            p.withTransaction {
                val block = p.memory.getBlock(address(0xc000))
                if (!block.isInitialized) p.memory.convertToInitialized(block, 0)
                val body = AddressSet(address(0x150), address(0x150L + instructions.size - 1))
                Disassembler.getDisassembler(p, monitor, null).disassemble(address(0x150), body)
                p.functionManager.createFunction("memory_root", address(0x150), body, SourceType.USER_DEFINED)
            }
            action(p, p.functionManager.getFunctionAt(address(0x150)))
        } finally {
            p.release(owner)
        }
    }

    private fun proof(
        p: ProgramDB,
        f: Function,
        writes: List<SymbolicMemory.MayWrite> = emptyList(),
    ) = PredicatedCallGraph.preview(
        p,
        f,
        PredicatedCallGraph.Limits.PRIMARY,
        SymbolicMemory.declare(p, listOf(0xc060), writes, null),
        monitor,
    )

    @Test
    fun `unknown physical memory remains symbolic across echo read after write and poison fills`() =
        fixture { p, f ->
            for (fill in listOf(0, 0x53, 0xff)) {
                p.withTransaction { p.memory.setByte(address(0xc060), fill.toByte()) }
                val result = proof(p, f)
                assertTrue(result.complete(), result.frontier().toString())
                val effects = result.nodes().flatMap { it.memoryAccesses() }
                val first = effects.single { it.kind() == "WRITE" && it.cpu() == 0xc070 }.value()
                val second = effects.single { it.kind() == "WRITE" && it.cpu() == 0xc071 }.value()
                val echo = effects.single { it.kind() == "WRITE" && it.cpu() == 0xe060 }
                assertEquals(MapperState.Physical("WRAM", 0, 0x60), echo.physical())
                assertEquals(AbstractValues.OriginKind.INPUT, first.kind())
                assertEquals(second, echo.value())
                val relation = AbstractValues.relation(listOf(first, second))
                assertTrue(relation.complete())
                assertEquals((0L..255).map { listOf(it, (it + 1) and 255) }.toSet(), relation.reachable().map { it.values() }.toSet())
            }
            val alias = PredicatedCalls.install(p, proof(p, f), monitor)
            val emitted = PredicatedCalls.emit(p, alias, 0x200000, monitor)
            assertTrue(emitted.any { it.inputs.any { n -> n.isAddress && n.offset == 0xc060L && n.address.addressSpace.name == "ram" } })
        }

    @Test
    fun `may write weakens current alias fact while earlier observation and disjoint store survive`() =
        fixture("3e42ea62c0" + primary.dropLast(2) + "fa62c0c9") { p, f ->
            val result = proof(p, f, listOf(SymbolicMemory.MayWrite(0x15f, 0xe060, "possible external byte write")))
            assertTrue(result.complete(), result.frontier().toString())
            val effects = result.nodes().flatMap { it.memoryAccesses() }
            val first = effects.single { it.kind() == "WRITE" && it.cpu() == 0xc070 }.value()
            val second = effects.single { it.kind() == "WRITE" && it.cpu() == 0xc071 }.value()
            assertNotEquals(first, second)
            assertEquals(AbstractValues.OriginKind.INPUT, second.kind())
            assertEquals(0x42L, effects.single { it.kind() == "READ" && it.cpu() == 0xc062 }.value().constant())
            assertEquals(1, effects.count { it.kind() == "MAY_WRITE" })
        }

    @Test
    fun `established image replacement and same bytes require explicit current generation`() =
        fixture { p, _ ->
            val bytes1 = HexFormat.of().parseHex("3e31ea74c0c9")
            val bytes2 = HexFormat.of().parseHex("3ea7ea74c0c9")
            val first = ExecutableImages.establish(p, address(0x300), 0xc200, bytes1, "explicit bounded copy I1", monitor)

            fun preview(
                image: ExecutableImages.Image,
                writes: List<SymbolicMemory.MayWrite> = emptyList(),
            ): PredicatedCallGraph.Proof {
                val f = p.functionManager.getFunctionAt(p.addressFactory.getAddress(image.entry()))
                return PredicatedCallGraph.preview(
                    p,
                    f,
                    PredicatedCallGraph.Limits.PRIMARY,
                    SymbolicMemory.declare(p, emptyList(), writes, image.generation()),
                    monitor,
                )
            }
            val initial = preview(first)
            assertTrue(initial.complete(), initial.frontier().toString())
            val alias = PredicatedCalls.install(p, initial, monitor)
            assertTrue(PredicatedCalls.emit(p, alias, 0x200000, monitor).isNotEmpty())
            val authority = ExecutableImages.serialized(p)
            val overlap = preview(first, listOf(SymbolicMemory.MayWrite(0xc200, 0xe201, "possible executable operand replacement")))
            assertFalse(overlap.complete())
            assertTrue(overlap.frontier().any { it.reason().contains("executable-byte knowledge") }, overlap.frontier().toString())
            val disjoint = preview(first, listOf(SymbolicMemory.MayWrite(0xc200, 0xc062, "disjoint possible write")))
            assertTrue(disjoint.complete(), disjoint.frontier().toString())
            assertEquals(authority, ExecutableImages.serialized(p))
            assertEquals(first, ExecutableImages.resolve(p, first.generation()))
            p.withTransaction { p.memory.setBytes(address(0xc200), bytes2) }
            assertThrows(IllegalArgumentException::class.java) { PredicatedCalls.emit(p, alias, 0x200000, monitor) }
            val second = ExecutableImages.establish(p, address(0x320), 0xc200, bytes2, "explicit bounded copy I2", monitor)
            assertNotEquals(first.generation(), second.generation())
            assertTrue(
                assertThrows(IllegalArgumentException::class.java) {
                    ExecutableImages.resolve(p, first.generation())
                }.message!!.contains("Noncurrent"),
            )
            val proof2 = preview(second)
            assertTrue(proof2.complete(), proof2.frontier().toString())
            val secondAlias = PredicatedCalls.install(p, proof2, monitor)
            assertTrue(PredicatedCalls.emit(p, secondAlias, 0x200000, monitor).isNotEmpty())
            val third = ExecutableImages.establish(p, address(0x320), 0xc200, bytes2, "explicit same bytes new lifetime", monitor)
            assertTrue(
                assertThrows(IllegalArgumentException::class.java) {
                    ExecutableImages.resolve(p, second.generation())
                }.message!!.contains("Noncurrent"),
            )
            assertTrue(preview(third).complete())
            assertThrows(IllegalArgumentException::class.java) { ExecutableImages.resolve(p, null) }
        }

    @Test
    fun `source history survives ROM edit and owned snapshots survive new lifetimes`() =
        fixture { p, _ ->
            val bytes = HexFormat.of().parseHex("3e31ea74c0c9")
            val first = ExecutableImages.establish(p, address(0x300), 0xc200, bytes, "explicit snapshot", monitor)
            val saved = ExecutableImages.serialized(p)
            p.withTransaction { p.memory.setByte(address(0x301), 0x5a) }
            assertEquals(first, ExecutableImages.resolve(p, first.generation()))
            assertEquals(saved, ExecutableImages.serialized(p))
            val oldFunction = p.functionManager.getFunctionAt(p.addressFactory.getAddress(first.entry()))
            p.withTransaction { oldFunction.comment = "later user annotation" }
            p.withTransaction { p.memory.setByte(address(0x301), 0x31) }
            ExecutableImages.establish(p, address(0x300), 0xc200, bytes, "new lifetime", monitor)
            assertEquals("later user annotation", oldFunction.comment)
            assertEquals(first.initializer(), ExecutableImages.history(p).first().initializer())
        }

    @Test
    fun `establishment rejects canonical annotation conflicts and rolls back cancelled copy`() =
        fixture { p, _ ->
            val bytes = HexFormat.of().parseHex("3e31ea74c0c9")
            p.withTransaction { p.symbolTable.createLabel(address(0xc200), "user_data", SourceType.USER_DEFINED) }
            assertThrows(
                IllegalArgumentException::class.java,
            ) { ExecutableImages.establish(p, address(0x300), 0xc200, bytes, "conflicting", monitor) }
            assertTrue(ExecutableImages.history(p).isEmpty())
            p.withTransaction { p.symbolTable.getPrimarySymbol(address(0xc200)).delete() }
            val cancellation =
                object : ghidra.util.task.TaskMonitorAdapter() {
                    override fun checkCancelled() {
                        if (p.memory.getByte(address(0xc200)) == 0x3e.toByte()) throw ghidra.util.exception.CancelledException()
                    }
                }
            assertThrows(ghidra.util.exception.CancelledException::class.java) {
                ExecutableImages.establish(p, address(0x300), 0xc200, bytes, "cancel after physical copy", cancellation)
            }
            assertEquals(0, p.memory.getByte(address(0xc200)).toInt())
            assertTrue(ExecutableImages.history(p).isEmpty())
            assertFalse(p.memory.blocks.any { it.name.contains("image_") })
        }

    @Test
    fun `distinct may writes with the same reason cannot correlate independent observations`() =
        fixture("fa60c0ea70c0fa60c0ea71c0c9") { p, f ->
            val result =
                proof(
                    p,
                    f,
                    listOf(
                        SymbolicMemory.MayWrite(0x150, 0xe060, "external write"),
                        SymbolicMemory.MayWrite(0x156, 0xe060, "external write"),
                    ),
                )
            assertTrue(result.complete(), result.frontier().toString())
            val reads = result.nodes().flatMap { it.memoryAccesses() }.filter { it.kind() == "READ" }
            assertEquals(2, reads.size)
            assertNotEquals(reads[0].value(), reads[1].value())
            for (value in reads) assertEquals(AbstractValues.OriginKind.INPUT, value.value().kind())
        }
}
