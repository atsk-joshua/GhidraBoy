package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Method;
import java.util.*;
import org.junit.jupiter.api.Test;

/** W2b parity against the W2a read recorder, plus independent expected findings. */
class BankAnalysisScalarReadTest extends IntegrationTest {
  private static final String EVIDENCE = "Explicit state, execution context, or constant p-code evidence";
  private static final String UNKNOWN = "unknown: Required mapper register is unknown";
  private static final String NO_STATIC = "Physical destination has no static mapping";
  private static final MapperKnowledge EXACT = MapperKnowledge.from(MapperState.reset());

  private final class Fixture implements AutoCloseable {
    final Object consumer = new Object();
    final ProgramDB p = new ProgramDB("W2b scalar read", getLanguage(), getLanguage().getDefaultCompilerSpec(), consumer);
    final Cartridge c;

    Fixture() throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, false,
            TaskMonitor.DUMMY, new MessageLog());
      }
      c = ProgramMapping.cartridge(p);
    }

    Address at(String value) {
      return Objects.requireNonNull(ProgramMapping.staticAddress(p, value));
    }

    MemoryBlock alias(String name, int cpu, Address source, boolean execute) throws Exception {
      int tx = p.startTransaction("Add self-authored mapping fixture");
      try {
        var block = p.getMemory().createByteMappedBlock(name, at(String.format("%04x", cpu)), source, 32, true);
        block.setExecute(execute);
        return block;
      } finally {
        p.endTransaction(tx, true);
      }
    }

    @Override
    public void close() {
      p.release(consumer);
    }
  }

  private static Method method(String name, Class<?>... args) throws Exception {
    var result = BankAnalysis.class.getDeclaredMethod(name, args);
    result.setAccessible(true);
    return result;
  }

  private static void read(Fixture f, MapperKnowledge state, int cpu, int width, Address source,
      int operation, int operand, boolean canonical, AnalysisCandidates out) throws Exception {
    method("readAccess", Program.class, Cartridge.class, MapperKnowledge.class, int.class,
        int.class, Address.class, int.class, int.class, Map.class, Map.class, boolean.class)
        .invoke(null, f.p, f.c, state, cpu, width, source, operation, operand, out.targets, out.reasons, canonical);
  }

  @SuppressWarnings("unchecked")
  private static List<Address> context(Fixture f, MapperKnowledge state, int cpu, Address source,
      boolean canonical) throws Exception {
    return (List<Address>) method("resolveWithContext", Program.class, Cartridge.class,
        MapperKnowledge.class, int.class, Address.class, boolean.class)
        .invoke(null, f.p, f.c, state, cpu, source, canonical);
  }

  // Frozen W2a readAccess/record policy. Do not update this oracle to match the adapter.
  private static AnalysisCandidates legacy(Fixture f, MapperKnowledge state, int address, int width,
      Address source, int operation, int operand, boolean canonical) throws Exception {
    var out = new AnalysisCandidates();
    for (int i = 0; i < width; i++) {
      int cpu = (address + i) & 65535;
      var key = new AnalysisCandidates.Site(source, AnalysisCandidates.Access.READ, operation, operand, i);
      var resolution = state.translate(f.c, cpu, false);
      if (resolution.physical() == null) {
        out.reasons.put(key, resolution.status() + ": " + resolution.reason());
        continue;
      }
      var addresses = new ArrayList<Address>();
      for (var candidate : ProgramMapping.physicalToStatic(f.p, resolution.physical())) {
        if (candidate.getOffset() != cpu) continue;
        var block = f.p.getMemory().getBlock(candidate);
        if (canonical && (block == null || block.getName().startsWith(SoftwareCallExecutionView.PREFIX)
            || block.getName().startsWith(OrdinaryEntryAccess.PREFIX))) continue;
        if (candidate.getAddressSpace().getName().startsWith(SoftwareCallExecutionView.PREFIX)
            && (block == null || !block.isExecute())) continue;
        addresses.add(candidate);
      }
      if (addresses.isEmpty()) out.reasons.put(key, NO_STATIC);
      for (var candidate : addresses) out.targets.computeIfAbsent(key, ignored -> new TreeSet<>()).add(candidate);
    }
    return out;
  }

  private static AnalysisCandidates parity(Fixture f, MapperKnowledge state, int cpu, int width,
      Address source, int operation, int operand, boolean canonical) throws Exception {
    var expected = legacy(f, state, cpu, width, source, operation, operand, canonical);
    var actual = new AnalysisCandidates();
    read(f, state, cpu, width, source, operation, operand, canonical, actual);
    assertEquals(expected.targets, actual.targets, "Every static target and access-site key");
    assertEquals(expected.reasons, actual.reasons, "Every unresolved reason and access-site key");
    assertEquals(expected.finish(AnalysisResult.Completion.COMPLETE), actual.finish(AnalysisResult.Completion.COMPLETE),
        "Complete findings, including confidence and provenance");
    return actual;
  }

  private static BankAnalysis.Finding finding(String source, List<String> targets, String reason,
      AnalysisResult.Confidence confidence, int operation, int operand, int index) {
    return new BankAnalysis.Finding(source, "read", targets, reason, confidence, operation, operand, index);
  }

  @Test
  void exactRomWindowsAndUninitializedRamRetainMappingFindings() throws Exception {
    try (var f = new Fixture()) {
      for (var row : Map.of(0x0200, "0200", 0x4010, "rom1::4010", 0xc100, "c100").entrySet()) {
        var actual = parity(f, EXACT, row.getKey(), 1, f.at("0150"), 7, 2, false);
        assertEquals(List.of(finding("0150", List.of(row.getValue()), EVIDENCE,
            AnalysisResult.Confidence.PROVEN, 7, 2, 0)), actual.finish(AnalysisResult.Completion.COMPLETE));
      }
      assertFalse(f.p.getMemory().getBlock(f.at("c100")).isInitialized(),
          "A proven READ target is a mapping finding, not proof of a known byte value");
    }
  }

  @Test
  void unknownReadStaysUnknownEvenWhenSameWindowContextResolvesControl() throws Exception {
    try (var f = new Fixture()) {
      var from = f.at("rom2::4000");
      var actual = parity(f, MapperKnowledge.unknown(), 0x4010, 1, from, 3, -1, false);
      assertEquals(List.of(finding(from.toString(), List.of(), UNKNOWN,
          AnalysisResult.Confidence.UNKNOWN, 3, -1, 0)), actual.finish(AnalysisResult.Completion.COMPLETE));
      assertEquals(List.of(f.at("rom2::4010")), context(f, MapperKnowledge.unknown(), 0x4010, from, false));
      assertEquals(List.of(f.at("rom1::4010")), context(f, EXACT, 0x4010, from, false),
          "Exact direct control mapping wins over context");
      assertEquals(List.of(), context(f, MapperKnowledge.unknown(), 0x4010, f.at("0150"), false),
          "Context must not infer a bank across ROM windows");
    }
  }

  @Test
  void physicalIdentityWithoutEligibleCpuTargetRetainsEmptyFindingAndContextFailure() throws Exception {
    try (var f = new Fixture()) {
      var from = f.at("rom1::4000");
      f.alias("wrong_cpu", 0x5010, f.at("rom1::4010"), true);
      int tx = f.p.startTransaction("Exclude only same-CPU mapping");
      try {
        f.p.getMemory().getBlock("rom1").setName(OrdinaryEntryAccess.PREFIX + "excluded");
      } finally {
        f.p.endTransaction(tx, true);
      }
      var actual = parity(f, EXACT, 0x4010, 1, from, 4, 1, true);
      assertEquals(List.of(finding(from.toString(), List.of(), NO_STATIC,
          AnalysisResult.Confidence.UNKNOWN, 4, 1, 0)), actual.finish(AnalysisResult.Completion.COMPLETE));
      assertEquals(List.of(), context(f, EXACT, 0x4010, from, true));
    }
  }

  @Test
  void generatedViewsKeepCanonicalAndRetiredFilteringDistinct() throws Exception {
    try (var f = new Fixture()) {
      var live = f.alias(SoftwareCallExecutionView.PREFIX + "live", 0x4010, f.at("rom1::4010"), true);
      f.alias(SoftwareCallExecutionView.PREFIX + "retired", 0x4010, f.at("rom1::4010"), false);
      var ordinary = f.alias(OrdinaryEntryAccess.PREFIX + "read", 0x4010, f.at("rom1::4010"), false);
      var all = parity(f, EXACT, 0x4010, 1, f.at("0150"), 5, 0, false);
      var expected = new TreeSet<>(List.of("rom1::4010", live.getStart().toString(), ordinary.getStart().toString()));
      assertEquals(expected, new TreeSet<>(all.finish(AnalysisResult.Completion.COMPLETE).get(0).targets()));
      assertEquals(AnalysisResult.Confidence.AMBIGUOUS, all.finish(AnalysisResult.Completion.COMPLETE).get(0).confidence());
      assertEquals("Finite alternative destinations", all.finish(AnalysisResult.Completion.COMPLETE).get(0).reason());
      var canonical = parity(f, EXACT, 0x4010, 1, f.at("0150"), 5, 0, true);
      assertEquals(List.of(finding("0150", List.of("rom1::4010"), EVIDENCE,
          AnalysisResult.Confidence.PROVEN, 5, 0, 0)), canonical.finish(AnalysisResult.Completion.COMPLETE));
    }
  }

  @Test
  void orderedBytesWrapAndAliasesPreserveFullProvenance() throws Exception {
    try (var f = new Fixture()) {
      var wrap = parity(f, EXACT, 0xffff, 2, f.at("rom2::4000"), 9, -1, false);
      assertEquals(List.of(
          finding("rom2::4000", List.of(), "device: Volatile hardware register", AnalysisResult.Confidence.UNKNOWN, 9, -1, 0),
          finding("rom2::4000", List.of("0000"), EVIDENCE, AnalysisResult.Confidence.PROVEN, 9, -1, 1)),
          wrap.finish(AnalysisResult.Completion.COMPLETE));
      for (var row : Map.of(0xc100, List.of("c100", "c101"),
          0xe100, List.of("e100", "e101"), 0x7fff, List.of("rom1::7fff", "8000")).entrySet()) {
        var result = parity(f, EXACT, row.getKey(), 2, f.at("0150"), 12, 1, false);
        assertEquals(List.of(
            finding("0150", List.of(row.getValue().get(0)), EVIDENCE, AnalysisResult.Confidence.PROVEN, 12, 1, 0),
            finding("0150", List.of(row.getValue().get(1)), EVIDENCE, AnalysisResult.Confidence.PROVEN, 12, 1, 1)),
            result.finish(AnalysisResult.Completion.COMPLETE));
      }
      assertEquals(ProgramMapping.staticToPhysical(f.p, f.at("c100")),
          ProgramMapping.staticToPhysical(f.p, f.at("e100")));
      var echo = parity(f, EXACT, 0xe100, 1, f.at("0150"), 12, 1, false);
      assertEquals(List.of("e100"), echo.finish(AnalysisResult.Completion.COMPLETE).get(0).targets(),
          "Equivalent physical identity must still retain the actual CPU alias");
    }
  }

  @Test
  void mergedKnownAndUnknownReadsRetainReasonAndCandidateConfidence() throws Exception {
    try (var f = new Fixture()) {
      var actual = new AnalysisCandidates();
      var source = f.at("0150");
      read(f, MapperKnowledge.unknown(), 0x4010, 1, source, 2, 0, false, actual);
      read(f, EXACT, 0x4010, 1, source, 2, 0, false, actual);
      assertEquals(List.of(finding("0150", List.of("rom1::4010"), UNKNOWN,
          AnalysisResult.Confidence.CANDIDATE, 2, 0, 0)), actual.finish(AnalysisResult.Completion.COMPLETE));
      assertEquals(AnalysisResult.Confidence.CANDIDATE,
          parity(f, EXACT, 0x4010, 1, source, 2, 0, false).finish(AnalysisResult.Completion.STATE_LIMIT).get(0).confidence());
    }
  }
}
