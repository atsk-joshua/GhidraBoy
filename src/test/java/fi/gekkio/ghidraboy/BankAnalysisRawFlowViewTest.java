package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.plugin.core.function.SharedReturnAnalyzer;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import org.junit.jupiter.api.Test;

/** Self-authored raw SM83 hardware oracles independent of saved Ghidra presentation. */
class BankAnalysisRawFlowViewTest extends IntegrationTest {
  private static final String SP = "3100d0";
  private static final String STOP = "18fe";

  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("Raw flow and presentation", getLanguage(),
        getLanguage().getDefaultCompilerSpec(), owner);

    Fixture(String caller, String callee) throws Exception {
      this(Map.of("0150", caller, "0300", callee));
    }

    Fixture(Map<String, String> code) throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      for (var entry : code.entrySet()) {
        var split = entry.getKey().split("::");
        int cpu = Integer.parseInt(split[split.length - 1], 16);
        int bank = split.length == 1 ? 0 : Integer.parseInt(split[0].substring(3));
        int file = bank == 0 ? cpu : bank * 0x4000 + cpu - 0x4000;
        byte[] body = HexFormat.of().parseHex(entry.getValue());
        System.arraycopy(body, 0, bytes, file, body.length);
      }
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.GB,
            true, true, TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("Define self-authored raw-flow fixture");
      try {
        for (var entry : code.entrySet()) if (!entry.getValue().isEmpty()) {
          var first = at(entry.getKey());
          Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first,
              new AddressSet(first, first.add(entry.getValue().length() / 2 - 1)));
        }
      } finally { p.endTransaction(tx, true); }
    }

    Address at(String address) throws Exception { return ProgramMapping.staticAddress(p, address); }
    Instruction ins(String address) throws Exception { return p.getListing().getInstructionAt(at(address)); }

    void override(String address, FlowOverride override) throws Exception {
      int tx = p.startTransaction("Authored presentation state");
      try { ins(address).setFlowOverride(override); }
      finally { p.endTransaction(tx, true); }
    }

    BankAnalysis.FetchPreview preview() throws Exception { return preview(MapperState.reset()); }
    BankAnalysis.FetchPreview preview(MapperState mapper) throws Exception {
      return BankAnalysis.previewFetch(p, at("0150"), mapper,
          AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
    }

    @Override public void close() { p.release(owner); }
  }

  private static BankAnalysis.FetchStep step(BankAnalysis.FetchPreview preview, String source) {
    return preview.steps().stream().filter(s -> s.source().equals(source)).findFirst().orElseThrow();
  }

  private static List<BankAnalysis.WriteTransition> writes(BankAnalysis.FetchPreview preview, String source) {
    return step(preview, source).writes();
  }

  private static List<Integer> values(BankAnalysis.FetchPreview preview, String source) {
    return writes(preview, source).stream().map(BankAnalysis.WriteTransition::value).toList();
  }

  private static void hardwareEqual(BankAnalysis.FetchPreview baseline, BankAnalysis.FetchPreview overridden) {
    assertEquals(baseline.steps(), overridden.steps());
    assertEquals(baseline.result().findings(), overridden.result().findings());
    assertEquals(baseline.result().completion(), overridden.result().completion());
    assertEquals(baseline.result().exploredStates(), overridden.result().exploredStates());
  }

  @Test void jpAllEnumsFollowRawTargetWithoutPushOrInventedContinuation() throws Exception {
    try (var f = new Fixture(SP + "c30003" + "3e99ea00c1" + STOP, "08f0cfea00c1" + STOP)) {
      var baseline = f.preview();
      assertEquals(List.of("0300"), step(baseline, "0153").successors());
      assertTrue(writes(baseline, "0153").isEmpty());
      assertEquals(List.of(0, 0xd0), values(baseline, "0300"));
      assertTrue(baseline.steps().stream().noneMatch(s -> s.source().equals("0156")));
      for (var override : FlowOverride.values()) {
        f.override("0153", override);
        long modification = f.p.getModificationNumber();
        var actual = f.preview();
        hardwareEqual(baseline, actual);
        assertEquals(override, f.ins("0153").getFlowOverride());
        assertEquals(modification, f.p.getModificationNumber());
        if (override != FlowOverride.NONE && override != FlowOverride.BRANCH)
          assertTrue(actual.result().diagnostics().stream().anyMatch(d -> d.contains("0153")
              && d.contains(override.name())), actual.result().diagnostics().toString());
        else assertTrue(actual.result().diagnostics().stream().noneMatch(d -> d.contains("0153")
            && d.contains("presentation differs")), "An identical JP presentation needs no discrepancy warning");
      }
    }
  }

  @Test void callAllEnumsRetainRealPushMatchedRetAndRestoredSp() throws Exception {
    try (var f = new Fixture(SP + "cd0003" + "08f0cfea00c1" + STOP, "3e2ac9")) {
      var baseline = f.preview();
      assertEquals(List.of(0xcfff, 0xcffe), writes(baseline, "0153").stream()
          .map(BankAnalysis.WriteTransition::cpu).toList());
      assertEquals(List.of(1, 0x56), values(baseline, "0153"));
      assertNotNull(step(baseline, "0302"));
      assertEquals(List.of(0, 0xd0), values(baseline, "0156"));
      assertEquals(List.of(0x2a), values(baseline, "0159"));
      for (var override : FlowOverride.values()) {
        f.override("0153", override);
        var actual = f.preview();
        hardwareEqual(baseline, actual);
        assertEquals(override, f.ins("0153").getFlowOverride());
        if (override == FlowOverride.NONE || override == FlowOverride.CALL)
          assertTrue(actual.result().diagnostics().stream().noneMatch(d -> d.contains("0153")
              && d.contains("presentation differs")), "An identical CALL presentation needs no discrepancy warning");
      }
    }
  }

  @Test void retAllEnumsKeepRealPopAndComputedReturnInsideMatchedFrame() throws Exception {
    try (var f = new Fixture(SP + "cd0003" + "08f0cfea00c1" + STOP, "3e2ac9")) {
      var baseline = f.preview();
      var raw = Arrays.asList(f.ins("0302").getPcode(false));
      assertEquals(2, raw.stream().filter(op -> op.getOpcode() == PcodeOp.LOAD).count());
      assertEquals(1, raw.stream().filter(op -> op.getOpcode() == PcodeOp.RETURN).count());
      for (var override : FlowOverride.values()) {
        f.override("0302", override);
        var actual = f.preview();
        hardwareEqual(baseline, actual);
        assertEquals(override, f.ins("0302").getFlowOverride());
        assertEquals(List.of(0, 0xd0), values(actual, "0156"));
        if (override == FlowOverride.NONE || override == FlowOverride.RETURN)
          assertTrue(actual.result().diagnostics().stream().noneMatch(d -> d.contains("0302")
              && d.contains("presentation differs")), "An identical RET presentation needs no discrepancy warning");
      }
    }
  }

  @Test void rstCallReturnRetainsRealPushAndArchitecturalFallbackContinuation() throws Exception {
    try (var f = new Fixture(Map.of("0150", SP + "ef" + STOP, "0028", "c9"))) {
      var baseline = f.preview();
      assertEquals(List.of(0xcfff, 0xcffe), writes(baseline, "0153").stream()
          .map(BankAnalysis.WriteTransition::cpu).toList());
      assertEquals(List.of(1, 0x54), values(baseline, "0153"));
      assertTrue(step(baseline, "0153").successors().contains("0154"));
      assertTrue(baseline.result().ordinaryCallProofs().isEmpty(), "RST composition is outside current CD scope");
      f.override("0153", FlowOverride.CALL_RETURN);
      hardwareEqual(baseline, f.preview());
      assertEquals(FlowOverride.CALL_RETURN, f.ins("0153").getFlowOverride());
    }
  }

  @Test void conditionalJrKnownTrueKnownFalseAndUnknownArePresentationInvariant() throws Exception {
    // CP establishes Z in the first two cases; the third leaves entry flags unknown.
    for (String prefix : List.of("3e00fe00", "3e01fe00", "")) {
      String source = String.format("%04x", 0x150 + prefix.length() / 2);
      try (var f = new Fixture(prefix + "2807" + "3e11ea00c1" + STOP + "3e22ea00c1" + STOP, "")) {
        var baseline = f.preview();
        var rawSuccessors = step(baseline, source).successors();
        int fall = Integer.parseInt(source, 16) + 2;
        String fallthrough = String.format("%04x", fall);
        String target = String.format("%04x", fall + 7);
        assertEquals(prefix.equals("3e00fe00") ? List.of(target)
            : prefix.equals("3e01fe00") ? List.of(fallthrough) : List.of(target, fallthrough), rawSuccessors);
        for (var override : List.of(FlowOverride.BRANCH, FlowOverride.CALL, FlowOverride.CALL_RETURN, FlowOverride.RETURN)) {
          f.override(source, override);
          hardwareEqual(baseline, f.preview());
        }
      }
    }
  }

  @Test void conditionalCallAndConditionalRetMicroflowsUseRawTypeAndFallthrough() throws Exception {
    for (String flags : List.of("00", "80")) {
      String prefix = SP + "01" + flags + "01c5f1";
      try (var f = new Fixture(prefix + "cc0003" + "ea00c1" + STOP, "3e2ac8c9")) {
        String source = String.format("%04x", 0x150 + prefix.length() / 2);
        var baseline = f.preview();
        f.override(source, FlowOverride.CALL_RETURN);
        f.override("0302", FlowOverride.CALL);
        hardwareEqual(baseline, f.preview());
      }
    }
  }

  @Test void fourAndEightIterationPredicatesRemainExactUnderReturnPresentation() throws Exception {
    var bodies = Map.of("0e000c79fe0420fa79ea00c1c9", List.of(0x302, 0x306, 4),
        "16082100c10100c22a02031520fac9", List.of(0x308, 0x30c, 8));
    for (var entry : bodies.entrySet()) try (var f = new Fixture(SP + "cd0003" + STOP, entry.getKey())) {
      var baseline = f.preview();
      var controls = entry.getValue();
      assertEquals(controls.get(2).longValue(), baseline.steps().stream()
          .filter(s -> s.cpu() == controls.get(0)).count());
      String branch = String.format("%04x", controls.get(1));
      f.override(branch, FlowOverride.RETURN);
      hardwareEqual(baseline, f.preview());
    }
  }

  @Test void bankedCallWithMapperChangingCalleeReturnsToPhysicalContinuation() throws Exception {
    try (var f = new Fixture(Map.of("0150", SP + "3e01ea0020cd0040ea00c1" + STOP,
        "rom1::4000", "3e02ea0020", "rom2::4005", "3e2ac9"))) {
      var baseline = f.preview();
      assertNotNull(step(baseline, "rom1::4000"));
      assertNotNull(step(baseline, "rom2::4005"));
      assertEquals(2, step(baseline, "015b").incoming().low());
      assertEquals(List.of(0x2a), values(baseline, "015b"));
      for (var override : FlowOverride.values()) {
        f.override("0158", override);
        f.override("rom2::4007", FlowOverride.CALL_RETURN);
        hardwareEqual(baseline, f.preview());
      }
    }
  }

  @Test void unresolvedPhysicalTargetCannotBeResolvedByPresentationOverride() throws Exception {
    try (var f = new Fixture(Map.of("0150", SP + "cd0040" + STOP,
        "rom1::4000", "3e11c9", "rom2::4000", "3e22c9"))) {
      var baseline = f.preview(null);
      assertTrue(baseline.result().ordinaryCallProofs().isEmpty());
      assertTrue(baseline.result().findings().stream().anyMatch(x -> x.access().equals("call") && x.targets().isEmpty()));
      for (var override : FlowOverride.values()) {
        f.override("0153", override);
        hardwareEqual(baseline, f.preview(null));
      }
    }
  }

  @Test void indirectHlJumpAndSixteenBitWrapUseArchitecturalSuccessor() throws Exception {
    for (String prefix : List.of("210003", "21ffff23")) {
      String destination = prefix.equals("210003") ? "0300" : "0000";
      String source = String.format("%04x", 0x150 + prefix.length() / 2);
      try (var f = new Fixture(Map.of("0150", prefix + "e9", destination, STOP))) {
        var baseline = f.preview();
        assertEquals(List.of(destination), step(baseline, source).successors());
        for (var override : FlowOverride.values()) {
          f.override(source, override);
          hardwareEqual(baseline, f.preview());
        }
      }
    }
  }

  @Test void foreignExplicitReferenceOverrideFallthroughLengthAndFixupRemainRefused() throws Exception {
    for (String unsafe : List.of("foreign", "referenceOverride", "incompatibleType", "fallthrough", "length", "callfixup")) {
      try (var f = new Fixture(SP + (unsafe.equals("callfixup") ? "cd0003" : "c30003") + STOP, "c9")) {
        f.override("0153", FlowOverride.CALL_RETURN);
        int tx = f.p.startTransaction("Unsafe annotation counterexample");
        try {
          var ins = f.ins("0153");
          switch (unsafe) {
            case "foreign" -> f.p.getReferenceManager().addMemoryReference(ins.getAddress(), f.at("0320"),
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            case "referenceOverride" -> f.p.getReferenceManager().addMemoryReference(ins.getAddress(), f.at("0300"),
                RefType.JUMP_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0);
            case "incompatibleType" -> f.p.getReferenceManager().addMemoryReference(ins.getAddress(), f.at("0300"),
                RefType.CONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            case "fallthrough" -> ins.setFallThrough(f.at("0320"));
            case "length" -> ins.setLengthOverride(1);
            case "callfixup" -> f.p.getFunctionManager().createFunction("unsafe_fixup", f.at("0300"),
                new AddressSet(f.at("0300")), SourceType.USER_DEFINED).setCallFixup("unsupported_raw_fixture_fixup");
            default -> throw new AssertionError(unsafe);
          }
        } finally { f.p.endTransaction(tx, true); }
        long modification = f.p.getModificationNumber();
        var actual = f.preview();
        assertTrue(actual.steps().stream().noneMatch(s -> s.source().equals("0300")), unsafe);
        assertTrue(actual.result().ordinaryCallProofs().isEmpty(), unsafe);
        assertTrue(actual.result().findings().stream().anyMatch(x -> x.source().equals("0153")
            && x.confidence() == AnalysisResult.Confidence.UNKNOWN), unsafe + actual.result().findings());
        assertEquals(modification, f.p.getModificationNumber(), unsafe);
      }
    }
  }

  @Test void sameTargetReferenceRetypingIsAllowedWithoutSourceTypeOwnershipInference() throws Exception {
    for (var source : List.of(SourceType.DEFAULT, SourceType.ANALYSIS, SourceType.USER_DEFINED)) {
      try (var f = new Fixture("c30003", STOP)) {
        var baseline = f.preview();
        int tx = f.p.startTransaction("Existing same-target reference source");
        try {
          f.p.getReferenceManager().removeAllReferencesFrom(f.at("0150"));
          f.p.getReferenceManager().addMemoryReference(f.at("0150"), f.at("0300"),
              RefType.UNCONDITIONAL_JUMP, source, 0);
        } finally { f.p.endTransaction(tx, true); }
        f.override("0150", FlowOverride.CALL_RETURN);
        hardwareEqual(baseline, f.preview());
        assertEquals(source, f.ins("0150").getReferencesFrom()[0].getSource());
      }
    }
  }

  @Test void analysisPreservesUserPresentationObjectsAndProgramModificationNumber() throws Exception {
    try (var f = new Fixture(SP + "c30003", STOP)) {
      f.override("0153", FlowOverride.CALL_RETURN);
      int tx = f.p.startTransaction("User work independent of raw traversal");
      try {
        f.p.getListing().setComment(f.at("0153"), CodeUnit.EOL_COMMENT, "Authored JP presentation");
        f.p.getBookmarkManager().setBookmark(f.at("0153"), "Note", "Raw flow fixture", "Preserve this bookmark");
        f.p.getSymbolTable().createLabel(f.at("0300"), "user_target", SourceType.USER_DEFINED);
        var function = f.p.getFunctionManager().createFunction("user_function", f.at("0300"),
            new AddressSet(f.at("0300"), f.at("0301")), SourceType.USER_DEFINED);
        function.setReturnType(ByteDataType.dataType, SourceType.USER_DEFINED);
        function.setComment("User function contract");
        f.p.getReferenceManager().addMemoryReference(f.at("0153"), f.at("c100"),
            RefType.READ, SourceType.USER_DEFINED, 1);
      } finally { f.p.endTransaction(tx, true); }
      String before = presentation(f);
      var fingerprint = ProgramFingerprint.capture(f.p, TaskMonitor.DUMMY);
      long modification = f.p.getModificationNumber();
      var actual = f.preview();
      assertNotNull(step(actual, "0300"));
      assertEquals(before, presentation(f));
      assertEquals(fingerprint, ProgramFingerprint.capture(f.p, TaskMonitor.DUMMY));
      assertEquals(modification, f.p.getModificationNumber());
    }
  }

  private static String presentation(Fixture f) throws Exception {
    var ins = f.ins("0153");
    var function = f.p.getFunctionManager().getFunctionAt(f.at("0300"));
    var refs = Arrays.stream(ins.getReferencesFrom()).map(r -> r.getFromAddress() + ":" + r.getToAddress()
        + ":" + r.getReferenceType() + ":" + r.getSource() + ":" + r.getOperandIndex() + ":" + r.isPrimary()).sorted().toList();
    var bookmarks = new ArrayList<String>();
    f.p.getBookmarkManager().getBookmarksIterator().forEachRemaining(b -> bookmarks.add(b.getAddress()
        + ":" + b.getTypeString() + ":" + b.getCategory() + ":" + b.getComment()));
    var symbols = Arrays.stream(f.p.getSymbolTable().getSymbols(f.at("0300")))
        .map(s -> s.getName() + ":" + s.getSymbolType() + ":" + s.getSource() + ":" + s.isPrimary()).sorted().toList();
    return ins.getFlowOverride() + ":" + HexFormat.of().formatHex(ins.getBytes()) + ":" + ins.getFlowType()
        + ":" + ins.getFallThrough() + ":" + ins.getComment(CodeUnit.EOL_COMMENT) + ":" + refs
        + ":" + bookmarks + ":" + symbols + ":" + function.getBody() + ":" + function.getPrototypeString(true, true)
        + ":" + function.getSignatureSource() + ":" + function.getComment();
  }

  @Test void freshStockSharedReturnAnalyzerCreatesPreservedPresentationOnlyCallReturn() throws Exception {
    try (var f = new Fixture(SP + "c30003", "08f0cf" + STOP)) {
      int tx = f.p.startTransaction("Stock shared-return Function boundary");
      try {
        f.p.getFunctionManager().createFunction("stock_caller", f.at("0150"),
            new AddressSet(f.at("0150"), f.at("0155")), SourceType.ANALYSIS);
        f.p.getFunctionManager().createFunction("stock_target", f.at("0300"),
            new AddressSet(f.at("0300"), f.at("0304")), SourceType.ANALYSIS);
      } finally { f.p.endTransaction(tx, true); }
      assertEquals(FlowOverride.NONE, f.ins("0153").getFlowOverride());
      var baseline = f.preview();
      tx = f.p.startTransaction("Run stock Shared Return Calls analyzer");
      try {
        var analyzer = new SharedReturnAnalyzer();
        assertTrue(analyzer.added(f.p, new AddressSet(f.at("0300")), TaskMonitor.DUMMY, new MessageLog()));
      } finally { f.p.endTransaction(tx, true); }
      assertEquals(FlowOverride.CALL_RETURN, f.ins("0153").getFlowOverride());
      var stockPcode = Arrays.asList(f.ins("0153").getPcode(true));
      assertTrue(stockPcode.stream().anyMatch(op -> op.getOpcode() == PcodeOp.CALL));
      assertTrue(stockPcode.stream().anyMatch(op -> op.getOpcode() == PcodeOp.RETURN));
      var caller = f.p.getFunctionManager().getFunctionAt(f.at("0150"));
      var callerBody = new AddressSet(caller.getBody());
      String callerPrototype = caller.getPrototypeString(true, true);
      String before = presentation(f);
      long modification = f.p.getModificationNumber();
      var actual = f.preview();
      hardwareEqual(baseline, actual);
      assertTrue(writes(actual, "0153").isEmpty());
      assertEquals(List.of("0300"), step(actual, "0153").successors());
      assertEquals(List.of(0, 0xd0), values(actual, "0300"));
      assertTrue(actual.result().diagnostics().stream().anyMatch(d -> d.contains("0153")
          && d.contains("CALL_RETURN") && d.contains("raw=")), actual.result().diagnostics().toString());
      assertEquals(FlowOverride.CALL_RETURN, f.ins("0153").getFlowOverride());
      assertEquals(before, presentation(f));
      assertEquals(callerBody, caller.getBody());
      assertEquals(callerPrototype, caller.getPrototypeString(true, true));
      assertEquals(modification, f.p.getModificationNumber());
    }
  }

  @Test void consumedPresentationChangesInvalidateEvenWhenRawHardwareIsIdentical() throws Exception {
    for (String mutation : List.of("enum", "source", "operand", "primary", "fallthrough")) try (var f = new Fixture("c30003", STOP)) {
      var baseline = f.preview();
      ProgramFingerprint.requireCurrent(f.p, baseline.result(), TaskMonitor.DUMMY);
      int tx = f.p.startTransaction("Change consumed presentation dependency");
      try {
        switch (mutation) {
          case "enum" -> f.ins("0150").setFlowOverride(FlowOverride.CALL_RETURN);
          case "source", "operand" -> {
            var old = f.ins("0150").getReferencesFrom()[0];
            int operand = mutation.equals("operand") ? old.getOperandIndex() + 1 : old.getOperandIndex();
            var source = mutation.equals("source") ? SourceType.USER_DEFINED : old.getSource();
            boolean primary = old.isPrimary();
            f.p.getReferenceManager().removeAllReferencesFrom(f.at("0150"));
            var replacement = f.p.getReferenceManager().addMemoryReference(f.at("0150"), f.at("0300"),
                RefType.UNCONDITIONAL_JUMP, source, operand);
            f.p.getReferenceManager().setPrimary(replacement, primary);
          }
          case "primary" -> {
            var old = f.ins("0150").getReferencesFrom()[0];
            f.p.getReferenceManager().setPrimary(old, !old.isPrimary());
          }
          case "fallthrough" -> f.ins("0150").setFallThrough(f.at("0320"));
          default -> throw new AssertionError(mutation);
        }
      } finally { f.p.endTransaction(tx, true); }
      assertThrows(IllegalStateException.class,
          () -> ProgramFingerprint.requireCurrent(f.p, baseline.result(), TaskMonitor.DUMMY));
      assertThrows(IllegalStateException.class,
          () -> AnalysisApplication.apply(f.p, baseline.result(), TaskMonitor.DUMMY));
      assertThrows(IllegalStateException.class,
          () -> OrdinaryCallFlow.publish(f.p, baseline.result(), TaskMonitor.DUMMY));
      var fresh = f.preview();
      if (!mutation.equals("fallthrough")) hardwareEqual(baseline, fresh);
      assertNotEquals(baseline.result().fingerprint(), fresh.result().fingerprint());
      ProgramFingerprint.requireCurrent(f.p, fresh.result(), TaskMonitor.DUMMY);
    }
  }
}
