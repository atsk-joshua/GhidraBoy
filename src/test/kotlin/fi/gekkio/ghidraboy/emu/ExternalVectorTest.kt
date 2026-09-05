package fi.gekkio.ghidraboy.emu

import com.google.gson.JsonParser
import ghidra.app.emulator.EmulatorHelper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class ExternalVectorTest : EmuTest() {
    private fun vectorText(name: String): String {
        val root = System.getProperty("ghidraboy.vector.dir")
        return if (root == null) {
            javaClass.getResource("/vectors/$name")!!.readText()
        } else {
            java.nio.file.Path
                .of(root, name)
                .toFile()
                .readText()
        }
    }

    @Test
    fun `pinned MIT SingleStepTests samples compare registers and memory`() {
        val manifest = JsonParser.parseString(vectorText("manifest.json")).asJsonObject
        for (file in manifest.getAsJsonObject("files").keySet()) {
            val vectors = JsonParser.parseString(vectorText(file)).asJsonArray
            for (vector in vectors) {
                // Fresh decode cache and memory per vector; shared Program/application.
                emulator.dispose()
                emulator = EmulatorHelper(program)
                emulator.memoryFaultHandler = FailOnMemoryFault(emulator)
                val v = vector.asJsonObject
                val initial = v.getAsJsonObject("initial")
                val final = v.getAsJsonObject("final")
                val registers = listOf("a", "f", "b", "c", "d", "e", "h", "l", "sp", "pc")
                for (r in registers) {
                    var value = initial.get(r).asInt
                    if (r == "f") value = value and 0xf0
                    emulator.writeRegister(r.uppercase(), value.toLong())
                }
                for (pair in initial.getAsJsonArray("ram")) {
                    emulator.write(pair.asJsonArray[0].asInt.toUShort(), pair.asJsonArray[1].asInt.toUByte())
                }
                emulator.step()
                for (r in registers) {
                    var expected = final.get(r).asInt
                    if (r == "f") expected = expected and 0xf0
                    assertEquals(expected, emulator.readRegister(r.uppercase()).toInt(), "${v.get("name")} register=$r")
                }
                for (pair in final.getAsJsonArray("ram")) {
                    val address = pair.asJsonArray[0].asInt
                    assertEquals(pair.asJsonArray[1].asInt, emulator.read(address.toUShort()).toInt(), "${v.get("name")} memory=$address")
                }
            }
        }
    }
}
