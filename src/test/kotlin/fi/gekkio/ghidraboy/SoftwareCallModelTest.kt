package fi.gekkio.ghidraboy

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.util.HexFormat

class SoftwareCallModelTest {
    private val cartridge =
        Cartridge.parse(
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
            },
            "MBC3",
        )
    private val incoming = SoftwareCallModel.Registers(2, 0xb0, 0x7703, 0x5566, 0x4567)
    private val mapper = MapperState.reset().write(cartridge, 0x2000, 2)

    private fun enter(
        family: SoftwareCallModel.Family,
        payload: ByteArray = byteArrayOf(),
        constant: Int? = null,
        transfer: SoftwareCallModel.EntryTransfer = SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
    ): SoftwareCallModel.Frame {
        val template = SoftwareCallModel.Template(family, 0x200, payload.size, constant)
        return SoftwareCallModel.enter(
            cartridge,
            template,
            HexFormat.of().parseHex(template.bodyHex()),
            SoftwareCallModel.Entry(transfer, 0xc100, 0x103, incoming, mapper, payload),
        )
    }

    @Test
    fun `inline RET models caller push pop payload adjustment and target push pop`() {
        for (length in listOf(3, 4, 7, 16)) {
            val payload =
                ByteArray(length).apply {
                    this[0] = 0x80.toByte()
                    this[1] = 0x67
                    this[2] = 0x45
                }
            val f = enter(SoftwareCallModel.Family.INLINE_RET, payload)
            assertEquals(0xc0fe, f.targetSp())
            assertEquals(0x103 + length, f.continuationCpu())
            assertEquals(MapperState.Physical("ROM", 1, 0x567), f.target())
            assertEquals(SoftwareCallModel.Selector(128, 1), f.targetSelector())
            assertEquals(0, f.targetMapper().romLow())
            assertEquals(0x103 + length, f.targetRegisters().hl())
            assertEquals(0x4567, f.targetRegisters().de())
            assertEquals(0xb0, f.targetRegisters().f())
            assertEquals(listOf(0xc0ff, 0xc0fe, 0x2000, 0xc0ff, 0xc0fe, 0xc0fd, 0xc0fc), f.writes().map { it.cpuAddress() })
            assertEquals(listOf(1, 3, 128, 1, 3 + length, 0x45, 0x67), f.writes().map { it.value() })
            assertEquals(listOf(0x103, 0x4567), f.pops().map { it.value() })
        }
    }

    @Test
    fun `return policies preserve callee flags and expose real wrapper register clobbers`() {
        val result = SoftwareCallModel.Registers(0x55, 0x90, 0x1234, 0x9876, 0x8765)
        for (family in listOf(
            SoftwareCallModel.Family.REGISTER_JP,
            SoftwareCallModel.Family.RESTORING_REGISTER_JP,
            SoftwareCallModel.Family.CONSTANT_REGISTER_JP,
        )) {
            val frame = enter(family, constant = if (family == SoftwareCallModel.Family.CONSTANT_REGISTER_JP) 0x80 else null)
            val calleeMapper = mapper.write(cartridge, 0x2000, 1)
            val returned =
                SoftwareCallModel.returnFrom(
                    cartridge,
                    frame,
                    SoftwareCallModel.Exit.MAY_RETURN,
                    frame.targetSp(),
                    result,
                    calleeMapper,
                    frame.stackBytes(),
                )
            assertEquals(0xc100, returned.sp())
            assertEquals(0x103, returned.cpu())
            assertEquals(0x90, returned.registers().f())
            assertEquals(0x9876, returned.registers().de())
            assertEquals(0x8765, returned.registers().hl())
            when (family) {
                SoftwareCallModel.Family.REGISTER_JP -> {
                    assertEquals(0x55, returned.registers().a())
                    assertEquals(0x1234, returned.registers().bc())
                    assertEquals(1, returned.mapper().romLow())
                    assertEquals(0xc0fe, frame.targetSp())
                }
                SoftwareCallModel.Family.RESTORING_REGISTER_JP -> {
                    assertEquals(2, returned.registers().a())
                    assertEquals(0x02b0, returned.registers().bc())
                    assertEquals(2, returned.mapper().romLow())
                    assertEquals(0xc0fa, frame.targetSp())
                }
                else -> {
                    assertEquals(0x80, returned.registers().a())
                    assertEquals(0x1234, returned.registers().bc())
                    assertEquals(0, returned.mapper().romLow())
                    assertEquals(0xc0fc, frame.targetSp())
                }
            }
        }
    }

    @Test
    fun `nonlocal unknown and nonreturning exits never synthesize a return`() {
        val frame = enter(SoftwareCallModel.Family.REGISTER_JP, transfer = SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION)
        for (exit in listOf(SoftwareCallModel.Exit.NONLOCAL, SoftwareCallModel.Exit.NONRETURNING, SoftwareCallModel.Exit.UNKNOWN)) {
            val returned = SoftwareCallModel.returnFrom(cartridge, frame, exit, null, null, null, null)
            assertNull(returned.cpu())
            assertNull(returned.sp())
            assertEquals(emptyList<SoftwareCallModel.Write>(), returned.writes())
        }
    }

    @Test
    fun `return requires balanced SP and live frame contents`() {
        val frame = enter(SoftwareCallModel.Family.RESTORING_REGISTER_JP)
        assertThrows(IllegalArgumentException::class.java) {
            SoftwareCallModel.returnFrom(
                cartridge,
                frame,
                SoftwareCallModel.Exit.MAY_RETURN,
                frame.targetSp() + 2,
                incoming,
                mapper,
                frame.stackBytes(),
            )
        }
        val corrupt = frame.stackBytes().toMutableMap().apply { this[0xc0fe] = 0x44 }
        assertThrows(IllegalArgumentException::class.java) {
            SoftwareCallModel.returnFrom(cartridge, frame, SoftwareCallModel.Exit.MAY_RETURN, frame.targetSp(), incoming, mapper, corrupt)
        }
    }

    @Test
    fun `nested software frames balance independently without consuming outer bytes`() {
        val outer = enter(SoftwareCallModel.Family.RESTORING_REGISTER_JP)
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.CONSTANT_REGISTER_JP, 0x240, 0, 2)
        val inner =
            SoftwareCallModel.enter(
                cartridge,
                template,
                HexFormat.of().parseHex(template.bodyHex()),
                SoftwareCallModel.Entry(
                    SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION,
                    outer.targetSp(),
                    0x280,
                    incoming,
                    mapper,
                    byteArrayOf(),
                ),
            )
        assertEquals(0xc0f6, inner.targetSp())
        val innerReturn =
            SoftwareCallModel.returnFrom(
                cartridge,
                inner,
                SoftwareCallModel.Exit.MAY_RETURN,
                inner.targetSp(),
                incoming,
                mapper,
                inner.stackBytes(),
            )
        assertEquals(outer.targetSp(), innerReturn.sp())
        val outerReturn =
            SoftwareCallModel.returnFrom(
                cartridge,
                outer,
                SoftwareCallModel.Exit.MAY_RETURN,
                innerReturn.sp(),
                innerReturn.registers(),
                innerReturn.mapper(),
                outer.stackBytes(),
            )
        assertEquals(0xc100, outerReturn.sp())
        assertEquals(0x103, outerReturn.cpu())
    }

    @Test
    fun `payload and frame boundaries cannot be guessed`() {
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x200, 3, null)
        val bytes = HexFormat.of().parseHex(template.bodyHex())
        for ((sp, continuation, payload) in listOf(
            Triple(0xc100, 0x3ffe, byteArrayOf(2, 0, 0x40)),
            Triple(0xc002, 0x103, byteArrayOf(2, 0, 0x40)),
            Triple(0xc100, 0x103, byteArrayOf(2, 0)),
            Triple(0xc100, 0x103, byteArrayOf(2, 0, 0x80.toByte())),
        )) {
            assertThrows(IllegalArgumentException::class.java) {
                SoftwareCallModel.enter(
                    cartridge,
                    template,
                    bytes,
                    SoftwareCallModel.Entry(SoftwareCallModel.EntryTransfer.HARDWARE_CALL, sp, continuation, incoming, mapper, payload),
                )
            }
        }
    }

    @Test
    fun `modified implementation unknown mapper and unproven selector fail validation`() {
        val template = SoftwareCallModel.Template(SoftwareCallModel.Family.RESTORING_REGISTER_JP, 0x200, 0, null)
        val bytes = HexFormat.of().parseHex(template.bodyHex())
        assertThrows(IllegalArgumentException::class.java) { template.validateBytes(bytes.clone().apply { this[0] = 0 }) }
        for (state in listOf(null, MapperState.reset())) {
            assertThrows(IllegalArgumentException::class.java) {
                SoftwareCallModel.enter(
                    cartridge,
                    template,
                    bytes,
                    SoftwareCallModel.Entry(SoftwareCallModel.EntryTransfer.HARDWARE_RST, 0xc100, 0x103, incoming, state, byteArrayOf()),
                )
            }
        }
    }

    @Test
    fun `effect stream orders payload reads selector write and actual stack traffic`() {
        val frame = enter(SoftwareCallModel.Family.INLINE_RET, byteArrayOf(2, 0x67, 0x45))
        assertEquals(
            listOf(
                "Write",
                "Write",
                "Transfer",
                "Pop",
                "Read",
                "Write",
                "Read",
                "Read",
                "Write",
                "Write",
                "Write",
                "Write",
                "Pop",
                "Transfer",
            ),
            frame.events().map { it.javaClass.simpleName },
        )
        assertEquals(SoftwareCallModel.Read(0x103, 2, "inline raw selector", MapperState.Physical("ROM", 0, 0x103)), frame.events()[4])
        assertEquals(SoftwareCallModel.Write(0x2000, 2, "target ROM selector"), frame.events()[5])
        assertEquals(SoftwareCallModel.Read(0x104, 0x67, "inline target low", MapperState.Physical("ROM", 0, 0x104)), frame.events()[6])
        val restoring = enter(SoftwareCallModel.Family.RESTORING_REGISTER_JP)
        val returned =
            SoftwareCallModel.returnFrom(
                cartridge,
                restoring,
                SoftwareCallModel.Exit.MAY_RETURN,
                restoring.targetSp(),
                incoming,
                mapper,
                restoring.stackBytes(),
            )
        assertEquals(listOf("Pop", "Transfer", "Pop", "Write", "Pop", "Transfer"), returned.events().map { it.javaClass.simpleName })
        assertEquals(SoftwareCallModel.Write(0x2000, 2, "return ROM selector"), returned.events()[3])
    }
}
