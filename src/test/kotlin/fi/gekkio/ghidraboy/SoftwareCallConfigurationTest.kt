package fi.gekkio.ghidraboy

import com.google.gson.JsonParser
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class SoftwareCallConfigurationTest {
    private fun input() =
        ProgramMapping.JSON.toJson(
            listOf(
                SoftwareCallValidation.Configuration(
                    0x150,
                    SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x200, 0, null),
                    SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, 0, 0, 0x4000),
                    MapperState.reset(),
                ),
            ),
        )

    @Test
    fun `explicit zero flag remains zero but absent flag is not a premise`() {
        assertEquals(
            0,
            SoftwareCallConfiguration
                .read(input())
                .single()
                .registers()
                .f(),
        )
        val root = JsonParser.parseString(input()).asJsonArray
        root[0].asJsonObject.getAsJsonObject("registers").remove("f")
        assertThrows(IllegalArgumentException::class.java) { SoftwareCallConfiguration.read(root.toString()) }
    }

    @Test
    fun `missing mapper latch and null register are unknown rather than zero`() {
        for (member in listOf("mapper" to "latch", "registers" to "a")) {
            val root = JsonParser.parseString(input()).asJsonArray
            root[0].asJsonObject.getAsJsonObject(member.first).add(member.second, null)
            assertThrows(IllegalArgumentException::class.java) { SoftwareCallConfiguration.read(root.toString()) }
        }
    }
}
