package fi.gekkio.ghidraboy

import ghidra.program.model.data.ByteDataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.WordDataType
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test

class SoftwareCallTypeDependencyTest {
    @Test
    fun `same name and size mutation behind native pointer changes dependency`() {
        val structure = StructureDataType("result", 0)
        structure.add(WordDataType.dataType, "pair", null)
        val pointer = PointerDataType(structure, 2)
        val before = SoftwareCallRegistry.nativeTypeIdentity(pointer)
        structure.replaceAtOffset(0, ByteDataType.dataType, 1, "first", null)
        structure.replaceAtOffset(1, ByteDataType.dataType, 1, "second", null)
        assertNotEquals(before, SoftwareCallRegistry.nativeTypeIdentity(pointer))
    }
}
