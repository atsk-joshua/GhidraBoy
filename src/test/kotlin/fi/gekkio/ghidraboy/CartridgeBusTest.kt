package fi.gekkio.ghidraboy

import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileOptions
import ghidra.app.emulator.EmulatorHelper
import ghidra.app.plugin.assembler.Assemblers
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CartridgeBusTest : IntegrationTest() {
    private fun fixture(
        cartridge: Boolean,
        mapperOverride: String = "AUTO",
        cartridgeType: Int = 0x19,
        action: (ProgramDB) -> Unit,
    ) {
        val consumer = Any()
        val program = ProgramDB("direct bus fixture", language, language.defaultCompilerSpec, consumer)
        try {
            if (cartridge) {
                val bytes = ByteArray(0x10000)
                bytes[0x143] = 0x80.toByte()
                bytes[0x147] = cartridgeType.toByte()
                bytes[0x148] = 1
                bytes[0x2000] = 0x5a
                bytes[0x3000] = 0x66
                var headerChecksum = 0
                for (index in 0x134..0x14c) headerChecksum = (headerChecksum - (bytes[index].toInt() and 255) - 1) and 255
                bytes[0x14d] = headerChecksum.toByte()
                val globalChecksum = bytes.indices.filter { it != 0x14e && it != 0x14f }.sumOf { bytes[it].toInt() and 255 } and 0xffff
                bytes[0x14e] = (globalChecksum ushr 8).toByte()
                bytes[0x14f] = globalChecksum.toByte()
                ByteArrayProvider(bytes).use {
                    CartridgeLayout.load(
                        program,
                        it,
                        "CARTRIDGE",
                        mapperOverride,
                        GameBoyKind.CGB,
                        true,
                        false,
                        TaskMonitor.DUMMY,
                        MessageLog(),
                    )
                }
            } else {
                program.withTransaction {
                    program.memory.createInitializedBlock("flat", address(0), 0x10000, 0, TaskMonitor.DUMMY, false).isWrite = true
                    program.memory.setByte(address(0x2000), 0x5a)
                }
            }
            action(program)
        } finally {
            program.release(consumer)
        }
    }

    private fun function(
        program: ProgramDB,
        vararg code: String,
    ): Function =
        program.withTransaction {
            val body = AddressSet()
            val instructions: Iterable<Instruction> = Assemblers.getAssembler(program).assemble(address(0x150), *code)
            for (instruction in instructions) body.add(instruction.minAddress, instruction.maxAddress)
            program.functionManager.createFunction("bus_fixture", address(0x150), body, SourceType.USER_DEFINED)
        }

    private fun nativeWrite(
        program: ProgramDB,
        function: Function,
        cpu: Long,
        value: Long,
        control: Boolean,
    ) {
        val decompiler = DecompInterface()
        try {
            decompiler.setOptions(DecompileOptions())
            assertTrue(decompiler.openProgram(program))
            val result = decompiler.decompileFunction(function, 10, TaskMonitor.DUMMY)
            assertTrue(result.decompileCompleted(), result.errorMessage)
            val c = result.decompiledFunction.c
            println(c)
            assertFalse(c.contains("WARNING"), c)
            assertEquals(control, c.contains("gb_cartridge_write8("), c)
            assertTrue(
                result.highFunction.pcodeOps.asSequence().any {
                    it.opcode == PcodeOp.COPY && it.output?.address == address(cpu) && it.getInput(0).isConstant &&
                        it.getInput(0).offset == value
                },
                c,
            )
        } finally {
            decompiler.dispose()
        }
    }

    @Test
    fun `verified MBC5 direct control write preserves immutable fixed ROM read`() =
        fixture(true) { program ->
            val function = function(program, "LD A, 2", "LD (0x2000), A", "LD A, (0x2000)", "LD (0xc000), A", "RET")
            val before = ProgramMapping.exportBytes(program, true, false, TaskMonitor.DUMMY)
            nativeWrite(program, function, 0xc000, 0x5a, true)
            val emulator = EmulatorHelper(program)
            try {
                val initial = MapperState(0x44, 1, 0, 0, false, 0, 1, 0)
                CartridgeBusEmulation.attach(emulator, initial).use { bus ->
                    emulator.writeRegister("PC", 0x150)
                    emulator.writeRegister("F", 0xb0)
                    repeat(4) { assertTrue(emulator.step(TaskMonitor.DUMMY), emulator.lastError) }
                    assertEquals(2, bus.state().romLow())
                    assertEquals(1, bus.state().romHigh())
                    assertEquals(0x5a, emulator.readMemoryByte(address(0x2000)).toInt())
                    assertEquals(0x5a, emulator.readMemoryByte(address(0xc000)).toInt())
                    assertEquals(0xb0, emulator.readRegister("F").toInt())
                    assertEquals(listOf(CartridgeBusEmulation.Write(0x2000, 2), CartridgeBusEmulation.Write(0xc000, 0x5a)), bus.writes())
                }
            } finally {
                emulator.dispose()
            }
            assertArrayEquals(before, ProgramMapping.exportBytes(program, true, false, TaskMonitor.DUMMY))
            assertFalse(program.memory.getBlock(address(0x2000)).isWrite)
        }

    @Test
    fun `unadorned flat CPU direct writes retain ordinary memory semantics`() =
        fixture(false) { program ->
            val function = function(program, "LD A, 2", "LD (0x2000), A", "LD A, (0x2000)", "LD (0xc000), A", "RET")
            nativeWrite(program, function, 0xc000, 2, false)
            val emulator = EmulatorHelper(program)
            try {
                emulator.writeRegister("PC", 0x150)
                repeat(4) { assertTrue(emulator.step(TaskMonitor.DUMMY), emulator.lastError) }
                assertEquals(2, emulator.readMemoryByte(address(0x2000)).toInt())
                assertEquals(2, emulator.readMemoryByte(address(0xc000)).toInt())
            } finally {
                emulator.dispose()
            }
        }

    @Test
    fun `cartridge ordinary RAM stores stay native stores`() =
        fixture(true) { program ->
            val function = function(program, "LD A, 2", "LD (0xc001), A", "LD A, (0xc001)", "LD (0xc000), A", "RET")
            nativeWrite(program, function, 0xc000, 2, false)
        }

    @Test
    fun `bank analysis consumes the same direct control write hook`() =
        fixture(true) { program ->
            function(program, "LD SP, 0xc100", "LD A, 2", "LD (0x2000), A", "CALL 0x4000", "RET")
            program.withTransaction {
                Assemblers.getAssembler(program).assemble(ProgramMapping.fileToStatic(program, 0x8000).single(), "RET")
            }
            val result =
                BankAnalysis.preview(
                    program,
                    address(0x150),
                    MapperState.reset(),
                    AnalysisResult.Configuration.DEFAULT,
                    TaskMonitor.DUMMY,
                )
            assertTrue(
                result.findings().any {
                    it.access() == "write" && it.source() == "0155" && it.reason().startsWith("device:")
                },
                result.toString(),
            )
            assertTrue(result.findings().any { it.access() == "call" && it.targets() == listOf("rom2::4000") }, result.toString())
        }

    @Test
    fun `encoded SP stores perform ordered mapper and wrapping bus byte writes`() {
        for (target in listOf(0x2fff, 0x7fff, 0xffff)) {
            fixture(true) { program ->
                function(program, "LD (0x${target.toString(16)}), SP", "RET")
                val emulator = EmulatorHelper(program)
                try {
                    val initial = MapperState(0x44, 1, 0, 0, true, 0, 1, 0)
                    CartridgeBusEmulation.attach(emulator, initial).use { bus ->
                        emulator.writeRegister("PC", 0x150)
                        emulator.writeRegister("SP", 0x1234)
                        emulator.writeRegister("F", 0xb0)
                        assertTrue(emulator.step(TaskMonitor.DUMMY), emulator.lastError)
                        assertEquals(
                            listOf(CartridgeBusEmulation.Write(target, 0x34), CartridgeBusEmulation.Write((target + 1) and 0xffff, 0x12)),
                            bus.writes(),
                        )
                        assertEquals(0x1234, emulator.readRegister("SP").toInt())
                        assertEquals(0xb0, emulator.readRegister("F").toInt())
                        when (target) {
                            0x2fff -> {
                                assertEquals(0x34, bus.state().romLow())
                                assertEquals(0, bus.state().romHigh())
                                assertEquals(0x66, emulator.readMemoryByte(address(0x3000)).toInt())
                            }
                            0x7fff -> {
                                assertEquals(initial, bus.state())
                                assertEquals(0x12, emulator.readMemoryByte(address(0x8000)).toInt())
                                assertEquals(0, emulator.readMemoryByte(address(0x7fff)).toInt())
                            }
                            0xffff -> {
                                assertFalse(bus.state().ramEnabled())
                                assertEquals(0x34, emulator.readMemoryByte(address(0xffff)).toInt())
                                assertEquals(0, emulator.readMemoryByte(address(0)).toInt())
                            }
                        }
                    }
                } finally {
                    emulator.dispose()
                }
            }
        }
    }

    @Test
    fun `flat CPU SP store wraps across FFFF and zero`() =
        fixture(false) { program ->
            function(program, "LD (0xffff), SP", "RET")
            val emulator = EmulatorHelper(program)
            try {
                emulator.writeRegister("PC", 0x150)
                emulator.writeRegister("SP", 0x1234)
                assertTrue(emulator.step(TaskMonitor.DUMMY), emulator.lastError)
                assertEquals(0x34, emulator.readMemoryByte(address(0xffff)).toInt())
                assertEquals(0x12, emulator.readMemoryByte(address(0)).toInt())
                assertEquals(0x1234, emulator.readRegister("SP").toInt())
            } finally {
                emulator.dispose()
            }
        }

    @Test
    fun `native SP control stores expose ordered low and high effects`() =
        fixture(true) { program ->
            val function = function(program, "LD (0x2fff), SP", "RET")
            val decompiler = DecompInterface()
            try {
                decompiler.setOptions(DecompileOptions())
                assertTrue(decompiler.openProgram(program))
                val result = decompiler.decompileFunction(function, 10, TaskMonitor.DUMMY)
                assertTrue(result.decompileCompleted(), result.errorMessage)
                val c = result.decompiledFunction.c
                println(c)
                assertFalse(c.contains("WARNING"), c)
                assertEquals(2, Regex("gb_cartridge_write8\\(").findAll(c).count(), c)
                assertTrue(c.indexOf("0x2fff") < c.indexOf("0x3000"), c)
            } finally {
                decompiler.dispose()
            }
        }

    @Test
    fun `legacy write reference cannot forward mapper value into ROM read`() =
        fixture(true) { program ->
            val function = function(program, "LD A, 2", "LD (0x2000), A", "LD A, (0x2000)", "LD (0xc000), A", "RET")
            val reference =
                program.withTransaction {
                    program.referenceManager.addMemoryReference(
                        address(0x152),
                        address(0x2000),
                        ghidra.program.model.symbol.RefType.WRITE,
                        SourceType.USER_DEFINED,
                        0,
                    )
                }
            val before = reference.toString()
            val decompiler = DecompInterface()
            try {
                decompiler.setOptions(DecompileOptions())
                assertTrue(decompiler.openProgram(program))
                val result = decompiler.decompileFunction(function, 10, TaskMonitor.DUMMY)
                assertTrue(result.decompileCompleted(), result.errorMessage)
                val c = result.decompiledFunction.c
                println(c)
                assertTrue(c.contains("gb_cartridge_write8(0x2000,2)"), c)
                assertFalse(
                    result.highFunction.pcodeOps.asSequence().any {
                        it.opcode == PcodeOp.COPY && it.output?.address == address(0xc000) && it.getInput(0).isConstant &&
                            it.getInput(0).offset == 2L
                    },
                    c,
                )
                assertEquals(before, reference.toString())
                assertEquals(SourceType.USER_DEFINED, reference.source)
            } finally {
                decompiler.dispose()
            }
        }

    @Test
    fun `flat overlay stores retain their original address space`() =
        fixture(false) { program ->
            val function =
                program.withTransaction {
                    val block = program.memory.createInitializedBlock("view", address(0x4000), 0x100, 0, TaskMonitor.DUMMY, true)
                    block.isWrite = true
                    val entry = block.start
                    val body = AddressSet()
                    val instructions: Iterable<Instruction> =
                        Assemblers
                            .getAssembler(
                                program,
                            ).assemble(entry, "LD A, 2", "LD (0x4020), A", "LD A, (0x4020)", "LD (0xc000), A", "RET")
                    for (instruction in instructions) body.add(instruction.minAddress, instruction.maxAddress)
                    program.functionManager.createFunction("overlay_bus", entry, body, SourceType.USER_DEFINED)
                }
            nativeWrite(program, function, 0xc000, 2, false)
        }

    @Test
    fun `cartridge overlay caller writes CPU control port and reads fixed ROM`() =
        fixture(true) { program ->
            val function =
                program.withTransaction {
                    val entry = ProgramMapping.fileToStatic(program, 0x8000).single()
                    val body = AddressSet()
                    val instructions: Iterable<Instruction> =
                        Assemblers
                            .getAssembler(
                                program,
                            ).assemble(entry, "LD A, 2", "LD (0x2000), A", "LD A, (0x2000)", "LD (0xc000), A", "RET")
                    for (instruction in instructions) body.add(instruction.minAddress, instruction.maxAddress)
                    program.functionManager.createFunction("overlay_bus", entry, body, SourceType.USER_DEFINED)
                }
            nativeWrite(program, function, 0xc000, 0x5a, true)
        }

    @Test
    fun `explicit RAW selection overrides a valid MBC5 header without invented controls`() =
        fixture(true, "RAW") { program ->
            verifyRawStores(program)
        }

    @Test
    fun `unsupported mapper descriptor remains raw without invented controls`() =
        fixture(true, "AUTO", 0xfc) { program ->
            verifyRawStores(program)
        }

    private fun verifyRawStores(program: ProgramDB) {
        val cartridge = ProgramMapping.cartridge(program)
        assertEquals(Cartridge.Mapper.RAW, cartridge.mapper())
        assertEquals(Cartridge.HeaderStatus.COMPLETE, cartridge.headerStatus())
        assertEquals(cartridge.headerChecksum(), cartridge.computedHeaderChecksum())
        assertEquals(cartridge.globalChecksum(), cartridge.computedGlobalChecksum())
        assertFalse(CartridgeBus.supportsControls(cartridge))
        val function = function(program, "LD A, 2", "LD (0x2000), A", "RET")
        val decompiler = DecompInterface()
        try {
            decompiler.setOptions(DecompileOptions())
            assertTrue(decompiler.openProgram(program))
            val result = decompiler.decompileFunction(function, 10, TaskMonitor.DUMMY)
            assertTrue(result.decompileCompleted(), result.errorMessage)
            val c = result.decompiledFunction.c
            println(c)
            assertFalse(c.contains("gb_cartridge_write8"), c)
            assertTrue(
                result.highFunction.pcodeOps.asSequence().any {
                    it.opcode == PcodeOp.COPY && it.output?.address == address(0x2000) &&
                        it.getInput(0).isConstant && it.getInput(0).offset == 2L
                },
                c,
            )
        } finally {
            decompiler.dispose()
        }
        val emulator = EmulatorHelper(program)
        try {
            assertThrows(IllegalArgumentException::class.java) { CartridgeBusEmulation.attach(emulator, MapperState.reset()) }
            emulator.writeRegister("PC", 0x150)
            repeat(2) { assertTrue(emulator.step(TaskMonitor.DUMMY), emulator.lastError) }
            assertEquals(2, emulator.readMemoryByte(address(0x2000)).toInt())
        } finally {
            emulator.dispose()
        }
    }

    @Test
    fun `diagnostic overflow drops only old records and preserves every write effect`() =
        fixture(true) { program ->
            function(
                program,
                "LD A, 1",
                "LD (0xc000), A",
                "LD A, 2",
                "LD (0x2000), A",
                "LD A, 3",
                "LD (0xc001), A",
                "LD A, 4",
                "LD (0x3000), A",
                "RET",
            )
            val emulator = EmulatorHelper(program)
            try {
                assertThrows(IllegalArgumentException::class.java) { CartridgeBusEmulation.attach(emulator, MapperState.reset(), 0) }
                CartridgeBusEmulation.attach(emulator, MapperState.reset(), 2).use { bus ->
                    emulator.writeRegister("PC", 0x150)
                    repeat(8) { assertTrue(emulator.step(TaskMonitor.DUMMY), emulator.lastError) }
                    assertEquals(2L, bus.droppedWrites())
                    assertEquals(listOf(CartridgeBusEmulation.Write(0xc001, 3), CartridgeBusEmulation.Write(0x3000, 4)), bus.writes())
                    assertEquals(1, emulator.readMemoryByte(address(0xc000)).toInt())
                    assertEquals(3, emulator.readMemoryByte(address(0xc001)).toInt())
                    assertEquals(2, bus.state().romLow())
                    assertEquals(0, bus.state().romHigh())
                    assertEquals(0x5a, emulator.readMemoryByte(address(0x2000)).toInt())
                    assertEquals(0x66, emulator.readMemoryByte(address(0x3000)).toInt())
                }
            } finally {
                emulator.dispose()
            }
        }

    @Test
    fun `bounded context rejects unsupported indirect control store before ROM mutation`() =
        fixture(true) { program ->
            function(program, "LD HL, 0x2000", "LD A, 3", "LD (HL), A", "RET")
            val emulator = EmulatorHelper(program)
            try {
                CartridgeBusEmulation.attach(emulator, MapperState.reset()).use { bus ->
                    emulator.writeRegister("PC", 0x150)
                    repeat(2) { assertTrue(emulator.step(TaskMonitor.DUMMY), emulator.lastError) }
                    assertFalse(emulator.step(TaskMonitor.DUMMY))
                    assertTrue(emulator.lastError.contains("Unsupported cartridge-control STORE"), emulator.lastError)
                    assertEquals(0x5a, emulator.readMemoryByte(address(0x2000)).toInt())
                    assertEquals(1, bus.state().romLow())
                    assertEquals(1L, bus.rejectedControlWrites())
                    assertTrue(bus.writes().isEmpty())
                }
                emulator.writeMemory(address(0x2000), byteArrayOf(4))
                assertEquals(4, emulator.readMemoryByte(address(0x2000)).toInt())
            } finally {
                emulator.dispose()
            }
        }

    @Test
    fun `older and unknown userops are not mistaken for direct writes`() {
        val legacy =
            java.lang.reflect.Proxy.newProxyInstance(
                ghidra.program.model.lang.Language::class.java.classLoader,
                arrayOf(ghidra.program.model.lang.Language::class.java),
            ) { _, method, arguments ->
                when (method.name) {
                    "getNumberOfUserDefinedOpNames" -> 4
                    "getUserDefinedOpName" -> listOf("IME", "daaOperand", "halt", "stop")[arguments[0] as Int]
                    else -> throw AssertionError("Unexpected language query: ${method.name}")
                }
            } as ghidra.program.model.lang.Language
        val constantSpace = language.addressFactory.constantSpace
        for (index in listOf(1L, 99L)) {
            val inputs =
                arrayOf(
                    ghidra.program.model.pcode
                        .Varnode(constantSpace.getAddress(index), 4),
                    ghidra.program.model.pcode
                        .Varnode(constantSpace.getAddress(0x2000), 2),
                    ghidra.program.model.pcode
                        .Varnode(constantSpace.getAddress(2), 1),
                )
            assertFalse(CartridgeBus.isDirectWrite(legacy, PcodeOp(address(0), 0, PcodeOp.CALLOTHER, inputs)))
        }
    }
}
