package fi.gekkio.ghidraboy

import ghidra.app.cmd.function.CreateFunctionCmd
import ghidra.app.cmd.function.CreateThunkFunctionCmd
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.FlowOverride
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

/** Independent stock-command and architectural boundary checks; no analyzer options are changed. */
class SoftwareCallBoundedListingTest : IntegrationTest() {
    private fun fixture(
        manual: Boolean = false,
        action: (ProgramDB, Address, Address, Address, List<String>) -> Unit,
    ) {
        val helper = SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null)
        val next = if (manual) 0x4507 else 0x4501
        // Manual entry: LD BC,4507; PUSH BC; JP 0028. The configuration starts at LD BC.
        val source = if (manual) "010745c5c32800" else "ef"
        val regions =
            mapOf(
                0x28 to helper.bodyHex(),
                0x240 to "3e5a37c9",
                0x4500 to source,
                0x8000 to "c9",
                0x8000 + next - 0x4000 to "cd40023c38023e00ea00c2c9",
            )
        val bytes =
            ByteArray(0x10000).apply {
                this[0x147] = 0x13
                this[0x148] = 1
                for ((offset, hex) in regions) HexFormat.of().parseHex(hex).copyInto(this, offset)
            }
        val consumer = Any()
        val p = ProgramDB("bounded software-call listing", language, language.defaultCompilerSpec, consumer)
        try {
            ByteArrayProvider(bytes).use {
                CartridgeLayout.load(p, it, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false, TaskMonitor.DUMMY, MessageLog())
            }
            val root = SoftwareCallValidation.executionAddress(p, MapperState.reset(), 0x4500)
            val site = root.add(if (manual) 4 else 0)
            p.withTransaction {
                p.symbolTable.createLabel(root, "bounded_source", SourceType.USER_DEFINED)
                Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(root, AddressSet(root, root.add(source.length / 2L - 1)))
            }
            val instructions = p.listing.getInstructions(AddressSet(root, site.add(if (manual) 2 else 0)), true).iterator().asSequence().toList()
            val originalPcode = instructions.flatMap { it.getPcode(false).toList() }
            val raw = originalPcode.map { it.toString() }
            // Both architectures push exactly one word, high byte then low byte, via two
            // one-byte stores and two 16-bit SP decrements. JP itself adds no second push.
            assertEquals(2, originalPcode.count { it.opcode == PcodeOp.STORE && it.getInput(2).size == 1 })
            assertEquals(
                2,
                originalPcode.count {
                    it.opcode == PcodeOp.INT_SUB && it.output.address == p.getRegister("SP").address &&
                        it.output.size == 2 && it.getInput(1).isConstant && it.getInput(1).offset == 1L
                },
            )
            if (manual) assertFalse(p.listing.getInstructionAt(site).getPcode(false).any { it.opcode == PcodeOp.STORE })
            val config =
                SoftwareCallValidation.Configuration(
                    0x4500,
                    helper,
                    if (manual) SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION else SoftwareCallModel.EntryTransfer.HARDWARE_RST,
                    0xc100,
                    SoftwareCallModel.Registers(2, 0, if (manual) next else 0, 0, 0x4000),
                    MapperState.reset(),
                )
            val review = SoftwareCallApplication.preview(p, listOf(config), TaskMonitor.DUMMY)
            assertTrue(review.stateContinuations().containsKey(site.toString()))
            SoftwareCallApplication.apply(p, review, TaskMonitor.DUMMY)
            val view = p.addressFactory.getAddressSpace(review.executionViews().getValue(site.toString()).name())
            action(p, root, site, view.getAddress(site.offset), raw)
        } finally {
            p.release(consumer)
        }
    }

    private fun assertBounded(
        p: ProgramDB,
        root: Address,
        site: Address,
        alias: Address,
        raw: List<String>,
    ) {
        val manual = root != site
        val instructions = p.listing.getInstructions(AddressSet(root, site.add(if (manual) 2 else 0)), true).iterator().asSequence().toList()
        assertEquals(raw, instructions.flatMap { it.getPcode(false).map { op -> op.toString() } })
        for (entry in listOf(site, alias)) {
            val instruction = p.listing.getInstructionAt(entry)
            assertEquals(entry, instruction.fallThrough)
            assertTrue(instruction.flowType.isCall)
            assertFalse(instruction.flowType.isTerminal)
            assertNull(CreateThunkFunctionCmd.getThunkedAddr(p, entry), "Real stack effects must prevent a helper thunk at $entry")
            assertNotNull(SoftwareCallRegistry.resolve(p, entry))
        }
        val canonical = p.functionManager.getFunctionAt(root)
        val derived = p.functionManager.getFunctionContaining(alias)
        assertEquals(SourceType.DEFAULT, canonical.signatureSource)
        assertEquals(SourceType.DEFAULT, derived.signatureSource)
        assertEquals(0, derived.parameterCount)
        assertFalse(derived.hasCustomVariableStorage())
        assertFalse(derived.isThunk)
        assertNull(derived.callFixup)
        assertNull(canonical.callFixup)
        val canonicalId = canonical.id
        val derivedId = derived.id
        p.withTransaction {
            // This is the stock operation invoked by EntryPointAnalyzer's placeholder repair.
            CreateFunctionCmd.fixupFunctionBody(p, derived, TaskMonitor.DUMMY)
            CreateFunctionCmd.fixupFunctionBody(p, canonical, TaskMonitor.DUMMY)
        }
        assertEquals(canonicalId, p.functionManager.getFunctionAt(root).id)
        assertEquals(derivedId, p.functionManager.getFunctionContaining(alias).id)
        assertFalse(derived.isThunk)
        assertNull(canonical.callFixup)
        assertTrue(AnalysisOwnership.sourceRedirectCurrent(p, canonical))
        assertNotNull(SoftwareCallRegistry.resolve(p, site))
        assertNotNull(SoftwareCallRegistry.resolve(p, alias))
    }

    @Test
    fun `bounded RST preserves raw push and default contract through stock function repair`() =
        fixture { p, root, site, alias, raw -> assertBounded(p, root, site, alias, raw) }

    @Test
    fun `bounded manual JP preserves its prelude push without creating another frame`() =
        fixture(true) { p, root, site, alias, raw -> assertBounded(p, root, site, alias, raw) }

    private fun transitionInventory(
        p: ProgramDB,
        phase: String,
        root: Address,
        alias: Address,
    ) {
        fun functionInventory(function: ghidra.program.model.listing.Function): Map<String, Any?> =
            linkedMapOf(
                "id" to function.id,
                "entry" to function.entryPoint.toString(),
                "name" to function.getName(true),
                "symbolSource" to function.symbol.source.toString(),
                "symbolPinned" to function.symbol.isPinned,
                "body" to function.body.addressRanges.iterator().asSequence().map { it.toString() }.toList(),
                "thunk" to function.isThunk,
                "thunkTarget" to function.getThunkedFunction(false)?.entryPoint?.toString(),
                "recursiveThunkTarget" to function.getThunkedFunction(true)?.entryPoint?.toString(),
                "thunkCallers" to function.functionThunkAddresses?.map { it.toString() },
                "fixup" to function.callFixup,
                "signatureSource" to function.signatureSource.toString(),
                "prototype" to function.getPrototypeString(true, true),
                "convention" to function.callingConventionName,
                "parameters" to function.parameters.map { it.toString() },
                "returnType" to function.returnType.pathName,
                "returnStorage" to function.getReturn().variableStorage.toString(),
                "locals" to function.localVariables.map { it.toString() },
                "customStorage" to function.hasCustomVariableStorage(),
                "stackPurge" to function.stackPurgeSize,
                "noReturn" to function.hasNoReturn(),
                "inline" to function.isInline,
                "varArgs" to function.hasVarArgs(),
                "comment" to function.comment,
                "repeatableComment" to function.repeatableComment,
                "ownershipStamp" to AnalysisOwnership.functionStamp(function, true),
            )
        val options = p.getOptions(ProgramMapping.OPTIONS)
        val functions = p.functionManager.getFunctions(true).iterator().asSequence().map { functionInventory(it) }.toList()
        val instructions =
            p.listing.getInstructions(true).iterator().asSequence().map { instruction ->
                linkedMapOf(
                    "address" to instruction.address.toString(),
                    "bytes" to HexFormat.of().formatHex(instruction.bytes),
                    "flowOverride" to instruction.flowOverride.toString(),
                    "flowType" to instruction.flowType.toString(),
                    "fallthroughOverridden" to instruction.isFallThroughOverridden,
                    "fallthrough" to instruction.fallThrough?.toString(),
                    "flows" to instruction.flows.map { it.toString() }.sorted(),
                    "rawPcode" to instruction.getPcode(false).map { it.toString() },
                    "references" to instruction.referencesFrom.map { reference ->
                        linkedMapOf(
                            "from" to reference.fromAddress.toString(),
                            "to" to reference.toAddress.toString(),
                            "type" to reference.referenceType.toString(),
                            "source" to reference.source.toString(),
                            "operand" to reference.operandIndex,
                            "primary" to reference.isPrimary,
                            "symbolId" to reference.symbolID,
                        )
                    },
                )
            }.toList()
        val inventory =
            linkedMapOf(
                "phase" to phase,
                "scenario" to "rollback-only old terminal RST counterfactual",
                "canonical" to root.toString(),
                "alias" to alias.toString(),
                "modification" to p.modificationNumber,
                "sourceRedirectCurrent" to AnalysisOwnership.sourceRedirectCurrent(p, p.functionManager.getFunctionAt(root)),
                "functions" to functions,
                "instructions" to instructions,
                "rawRegistry" to options.getString(SoftwareCallRegistry.KEY, null),
                "rawOwnership" to options.getString("analysis.ownership.v1", null),
                "completeKnowledgeFingerprint" to FarCallEvidence.capture(p, TaskMonitor.DUMMY),
            )
        println("SA01_STOCK_TRANSITION_JSON " + com.google.gson.GsonBuilder().serializeNulls().create().toJson(inventory))
    }

    @Test
    fun `old terminal RST boundary demonstrably inherits helper contract during stock repair`() =
        fixture { p, root, _, alias, _ ->
            val canonical = p.functionManager.getFunctionAt(root)
            val derived = p.functionManager.getFunctionAt(alias)
            val id = derived.id
            assertFalse(derived.isThunk)
            assertNull(canonical.callFixup)
            val options = p.getOptions(ProgramMapping.OPTIONS)
            val registryBefore = options.getString(SoftwareCallRegistry.KEY, null)
            val ownershipBefore = options.getString("analysis.ownership.v1", null)
            transitionInventory(p, "BOUNDED_BEFORE", root, alias)
            val transaction = p.startTransaction("Reproduce old terminal listing in disposable transaction")
            try {
                val instruction = p.listing.getInstructionAt(alias)
                instruction.flowOverride = FlowOverride.CALL_RETURN
                instruction.setFallThrough(null)
                assertEquals(address(0x28), CreateThunkFunctionCmd.getThunkedAddr(p, alias))
                transitionInventory(p, "LEGACY_TERMINAL_BEFORE_STOCK_REPAIR", root, alias)
                CreateFunctionCmd.fixupFunctionBody(p, derived, TaskMonitor.DUMMY)
                transitionInventory(p, "LEGACY_TERMINAL_AFTER_STOCK_REPAIR", root, alias)
                assertEquals(registryBefore, options.getString(SoftwareCallRegistry.KEY, null), "Stock repair must not refresh semantic dependencies")
                assertEquals(ownershipBefore, options.getString("analysis.ownership.v1", null), "Stock repair must not refresh ownership receipts")
                assertEquals(id, derived.id)
                assertTrue(derived.isThunk)
                assertEquals(address(0x28), derived.getThunkedFunction(false).entryPoint)
                assertEquals(SoftwareCallInjection.NAME, derived.callFixup)
                assertEquals(SoftwareCallInjection.NAME, canonical.callFixup)
                assertFalse(AnalysisOwnership.sourceRedirectCurrent(p, canonical))
                assertThrows(IllegalArgumentException::class.java) { SoftwareCallRegistry.resolve(p, root) }
            } finally {
                p.endTransaction(transaction, false)
            }
            transitionInventory(p, "BOUNDED_AFTER_ROLLBACK", root, alias)
            assertEquals(registryBefore, options.getString(SoftwareCallRegistry.KEY, null))
            assertEquals(ownershipBefore, options.getString("analysis.ownership.v1", null))
            assertNotNull(SoftwareCallRegistry.resolve(p, root))
            assertNotNull(SoftwareCallRegistry.resolve(p, alias))
        }

    @Test
    fun `harmful boundary and helper endpoint edits still reject both entry paths`() {
        for (change in listOf("fallthrough", "flow", "endpoint")) {
            fixture { p, root, site, alias, _ ->
                p.withTransaction {
                    val instruction = p.listing.getInstructionAt(alias)
                    when (change) {
                        "fallthrough" -> instruction.setFallThrough(alias.add(1))
                        "flow" -> instruction.flowOverride = FlowOverride.CALL_RETURN
                        "endpoint" -> {
                            val reference =
                                p.referenceManager.getReferencesFrom(alias).single {
                                    it.referenceType == RefType.CALL_OVERRIDE_UNCONDITIONAL
                                }
                            p.referenceManager.delete(reference)
                            p.referenceManager.setPrimary(
                                p.referenceManager.addMemoryReference(alias, address(0x240), RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, -1),
                                true,
                            )
                        }
                    }
                }
                assertThrows(IllegalArgumentException::class.java, { SoftwareCallRegistry.resolve(p, site) }, change)
                assertThrows(IllegalArgumentException::class.java, { SoftwareCallRegistry.resolve(p, alias) }, change)
                assertTrue(p.functionManager.getFunctionAt(root).isThunk)
            }
        }
    }
}
