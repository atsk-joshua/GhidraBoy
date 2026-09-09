package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import org.junit.jupiter.api.Test;

/** W2c parity against frozen W2b write policy, with separate ordered-state expectations. */
class BankAnalysisScalarWriteTest extends IntegrationTest {
  private static final String EVIDENCE = "Explicit state, execution context, or constant p-code evidence";
  private static final String CONTROL = "device: ROM is read-only; mapper control write";
  private static final String DEVICE = "device: Volatile hardware register";
  private static final MapperKnowledge EXACT = MapperKnowledge.from(MapperState.reset());
  private static final MapperKnowledge SELECTED = new MapperKnowledge(0x44, 1, 0, 0, true, 0, 1, 0);

  private final class Fixture implements AutoCloseable {
    final Object consumer = new Object();
    final ProgramDB p = new ProgramDB("W2c scalar write", getLanguage(), getLanguage().getDefaultCompilerSpec(), consumer);
    final Cartridge c;

    Fixture(int type, boolean color) throws Exception {
      byte[] bytes = new byte[type == 0x00 ? 0x8000 : 0x10000];
      bytes[0x143] = (byte) (color ? 0x80 : 0);
      bytes[0x147] = (byte) type;
      bytes[0x148] = (byte) (type == 0x00 ? 0 : 1);
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", color ? GameBoyKind.CGB : GameBoyKind.GB,
            true, false, TaskMonitor.DUMMY, new MessageLog());
      }
      c = ProgramMapping.cartridge(p);
      assertEquals(color, c.color());
      assertEquals(switch (type) {
        case 0x00 -> Cartridge.Mapper.ROM_ONLY;
        case 0x05 -> Cartridge.Mapper.MBC2;
        case 0x19 -> Cartridge.Mapper.MBC5;
        default -> throw new IllegalArgumentException("Unexpected fixture mapper");
      }, c.mapper(), "Fixture must retain its intended controller");
    }

    Address at(String value) {
      return Objects.requireNonNull(ProgramMapping.staticAddress(p, value));
    }

    MemoryBlock alias(String name, int cpu, boolean execute) throws Exception {
      int tx = p.startTransaction("Add self-authored mapping fixture");
      try {
        var block = p.getMemory().createByteMappedBlock(name, at(String.format("%04x", cpu)), at("c100"), 32, true);
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

  private record Result(AnalysisCandidates candidates, MapperKnowledge state, List<BankAnalysis.WriteTransition> writes) {
    List<BankAnalysis.Finding> findings() {
      return candidates.finish(AnalysisResult.Completion.COMPLETE);
    }
  }

  private static Result actual(Fixture f, MapperKnowledge state, int address, int width, Long value,
      Address source, int operation, boolean diagnostic) throws Exception {
    var out = new AnalysisCandidates();
    var writes = diagnostic ? new ArrayList<BankAnalysis.WriteTransition>() : null;
    var method = BankAnalysis.class.getDeclaredMethod("writeAccess", Program.class, Cartridge.class,
        MapperKnowledge.class, int.class, int.class, Long.class, Address.class, int.class,
        Map.class, Map.class, List.class);
    method.setAccessible(true);
    var after = (MapperKnowledge) method.invoke(null, f.p, f.c, state, address, width, value,
        source, operation, out.targets, out.reasons, writes);
    return new Result(out, after, writes);
  }

  // Frozen W2b writeAccess + record + executionCandidate policies. This oracle deliberately
  // uses the concrete mapper authority, not ScalarAccess or BankAnalysis private helpers.
  // Do not update it to make a changed adapter result pass.
  private static Result legacy(Fixture f, MapperKnowledge state, int address, int width, Long value,
      Address source, int operation, boolean diagnostic) throws Exception {
    var out = new AnalysisCandidates();
    var writes = diagnostic ? new ArrayList<BankAnalysis.WriteTransition>() : null;
    for (int i = 0; i < width; i++) {
      int cpu = (address + i) & 65535;
      var key = new AnalysisCandidates.Site(source, AnalysisCandidates.Access.WRITE, operation, -1, i);
      var resolution = state.translate(f.c, cpu, true);
      if (resolution.physical() == null) {
        out.reasons.put(key, resolution.status() + ": " + resolution.reason());
      } else {
        var addresses = new ArrayList<Address>();
        for (var candidate : ProgramMapping.physicalToStatic(f.p, resolution.physical())) {
          if (candidate.getOffset() != cpu) continue;
          var block = f.p.getMemory().getBlock(candidate);
          if (diagnostic && (block == null || block.getName().startsWith(SoftwareCallExecutionView.PREFIX)
              || block.getName().startsWith(OrdinaryEntryAccess.PREFIX))) continue;
          if (candidate.getAddressSpace().getName().startsWith(SoftwareCallExecutionView.PREFIX)
              && (block == null || !block.isExecute())) continue;
          addresses.add(candidate);
        }
        if (addresses.isEmpty()) out.reasons.put(key, "Physical destination has no static mapping");
        for (var candidate : addresses) out.targets.computeIfAbsent(key, ignored -> new TreeSet<>()).add(candidate);
      }
      var before = state;
      Integer octet = value == null ? null : (int) (value >>> (i * 8)) & 255;
      boolean control = (cpu < 0x8000 && f.c.mapper() != Cartridge.Mapper.ROM_ONLY)
          || (f.c.color() && (cpu == 0xff4f || cpu == 0xff70));
      if (control) state = state.write(f.c, cpu, octet);
      if (diagnostic) writes.add(new BankAnalysis.WriteTransition(operation, i, cpu, octet, before, state, control));
    }
    return new Result(out, state, writes);
  }

  private static Result parity(Fixture f, MapperKnowledge state, int cpu, int width, Long value,
      Address source, int operation, boolean diagnostic) throws Exception {
    var expected = legacy(f, state, cpu, width, value, source, operation, diagnostic);
    var actual = actual(f, state, cpu, width, value, source, operation, diagnostic);
    assertEquals(expected.candidates.targets, actual.candidates.targets, "Every static target and complete site key");
    assertEquals(expected.candidates.reasons, actual.candidates.reasons, "Every reason and complete site key");
    assertEquals(expected.findings(), actual.findings(), "Findings including confidence and provenance");
    assertEquals(expected.state, actual.state, "All final known/unknown mapper registers");
    assertEquals(expected.writes, actual.writes, "Every ordered byte, control flag, value and intermediate mapper state");
    return actual;
  }

  private static BankAnalysis.Finding finding(String source, List<String> targets, String reason,
      AnalysisResult.Confidence confidence, int operation, int index) {
    return new BankAnalysis.Finding(source, "write", targets, reason, confidence, operation, -1, index);
  }

  private static BankAnalysis.Finding unresolved(String source, String reason, int operation, int index) {
    return finding(source, List.of(), reason, AnalysisResult.Confidence.UNKNOWN, operation, index);
  }

  @Test
  void ordinaryMappedWritesAndEchoAliasesPreserveStateAndFullByteProvenance() throws Exception {
    try (var f = new Fixture(0x19, false)) {
      for (int cpu : List.of(0xc100, 0xe100)) {
        for (boolean diagnostic : List.of(false, true)) {
          var result = parity(f, SELECTED, cpu, 2, 0x1234L, f.at("rom2::4000"), 17, diagnostic);
          assertEquals(SELECTED, result.state);
          assertEquals(List.of(
              finding("rom2::4000", List.of(String.format("%04x", cpu)), EVIDENCE, AnalysisResult.Confidence.PROVEN, 17, 0),
              finding("rom2::4000", List.of(String.format("%04x", cpu + 1)), EVIDENCE, AnalysisResult.Confidence.PROVEN, 17, 1)),
              result.findings());
          if (diagnostic) assertEquals(List.of(
              new BankAnalysis.WriteTransition(17, 0, cpu, 0x34, SELECTED, SELECTED, false),
              new BankAnalysis.WriteTransition(17, 1, cpu + 1, 0x12, SELECTED, SELECTED, false)), result.writes);
        }
      }
      assertEquals(ProgramMapping.staticToPhysical(f.p, f.at("c100")), ProgramMapping.staticToPhysical(f.p, f.at("e100")));
    }
  }

  @Test
  void mbc5LowHighAndUnknownControlValuesRetainEveryRegister() throws Exception {
    try (var f = new Fixture(0x19, false)) {
      for (int cpu : List.of(0x2000, 0x3000)) {
        for (Long value : Arrays.asList(0x122L, null)) {
          var result = parity(f, SELECTED, cpu, 1, value, f.at("0150"), 7, true);
          var expected = cpu == 0x2000
              ? new MapperKnowledge(value == null ? null : 0x22, 1, 0, 0, true, 0, 1, 0)
              : new MapperKnowledge(0x44, value == null ? null : 0, 0, 0, true, 0, 1, 0);
          assertEquals(expected, result.state);
          assertEquals(List.of(unresolved("0150", CONTROL, 7, 0)), result.findings());
          assertEquals(List.of(new BankAnalysis.WriteTransition(7, 0, cpu, value == null ? null : 0x22,
              SELECTED, expected, true)), result.writes);
        }
      }
      var unknownPair = parity(f, SELECTED, 0x2fff, 2, null, f.at("0150"), 8, true);
      assertNull(unknownPair.writes.get(0).after().low());
      assertEquals(1, unknownPair.writes.get(0).after().high());
      assertNull(unknownPair.state.low());
      assertNull(unknownPair.state.high());
    }
  }

  @Test
  void mbc2A8SeparatesRamEnableFromRomSelectorWithinBankAnalysisControlPolicy() throws Exception {
    try (var f = new Fixture(0x05, false)) {
      var initial = new MapperKnowledge(3, 0, 0, 0, false, 0, 1, 0);
      var enabled = parity(f, initial, 0x2000, 1, 0x0aL, f.at("0150"), 3, true);
      assertEquals(new MapperKnowledge(3, 0, 0, 0, true, 0, 1, 0), enabled.state);
      var selected = parity(f, initial, 0x2100, 1, 0x0aL, f.at("0150"), 4, true);
      assertEquals(new MapperKnowledge(10, 0, 0, 0, false, 0, 1, 0), selected.state);
      assertEquals(List.of(unresolved("0150", CONTROL, 3, 0)), enabled.findings());
      assertEquals(List.of(unresolved("0150", CONTROL, 4, 0)), selected.findings());
      assertTrue(enabled.writes.get(0).mapperControl());
      assertTrue(selected.writes.get(0).mapperControl());
    }
  }

  @Test
  void cgbPortsCommitButDmgPortsRetainIncomingStateEvenWhenAdapterProposesChange() throws Exception {
    for (boolean color : List.of(false, true)) {
      try (var f = new Fixture(0x19, color)) {
        for (int cpu : List.of(0xff4f, 0xff70)) {
          for (Long value : Arrays.asList(7L, null)) {
            var proposed = cpu == 0xff4f
                ? new MapperKnowledge(1, 0, 0, 0, false, value == null ? null : 1, 1, 0)
                : new MapperKnowledge(1, 0, 0, 0, false, 0, value == null ? null : 7, 0);
            var request = new ScalarAccess.Request(cpu, ScalarAccess.Kind.WRITE, 1, 0, "0150", 11, -1,
                value == null ? null : value.intValue());
            assertEquals(proposed, ScalarAccess.resolve(f.c, EXACT, request).after().orElseThrow());
            for (boolean diagnostic : List.of(false, true)) {
              var result = parity(f, EXACT, cpu, 1, value, f.at("0150"), 11, diagnostic);
              assertEquals(color ? proposed : EXACT, result.state);
              assertEquals(List.of(unresolved("0150", DEVICE, 11, 0)), result.findings());
              if (diagnostic) assertEquals(List.of(new BankAnalysis.WriteTransition(11, 0, cpu,
                  value == null ? null : value.intValue(), EXACT, color ? proposed : EXACT, color)), result.writes);
            }
          }
        }
      }
    }
  }

  @Test
  void boundaryStoreRetainsIntermediateOrderEvenWhenReversingBytesHasSameFinalState() throws Exception {
    try (var f = new Fixture(0x19, false)) {
      var result = parity(f, SELECTED, 0x2fff, 2, 0x1234L, f.at("0150"), 9, true);
      var lowFirst = new MapperKnowledge(0x34, 1, 0, 0, true, 0, 1, 0);
      var highFirst = new MapperKnowledge(0x44, 0, 0, 0, true, 0, 1, 0);
      var finalState = new MapperKnowledge(0x34, 0, 0, 0, true, 0, 1, 0);
      // Explicit states are independent of both oracle and ScalarAccess; final equality alone
      // would miss accidentally reversing these two independent selector effects.
      assertEquals(List.of(new BankAnalysis.WriteTransition(9, 0, 0x2fff, 0x34, SELECTED, lowFirst, true),
          new BankAnalysis.WriteTransition(9, 1, 0x3000, 0x12, lowFirst, finalState, true)), result.writes);
      assertEquals(List.of(unresolved("0150", CONTROL, 9, 0), unresolved("0150", CONTROL, 9, 1)), result.findings());
      var reversedFirst = actual(f, SELECTED, 0x3000, 1, 0x12L, f.at("0150"), 9, true);
      var reversedLast = actual(f, reversedFirst.state, 0x2fff, 1, 0x34L, f.at("0150"), 10, true);
      assertEquals(highFirst, reversedFirst.state);
      assertNotEquals(lowFirst, reversedFirst.state);
      assertEquals(finalState, result.state);
      assertEquals(result.state, reversedLast.state);
    }
  }

  @Test
  void wideStoreWrapsFfffToZeroAndCommitsOnlyTheSecondByteControl() throws Exception {
    try (var f = new Fixture(0x19, false)) {
      var result = parity(f, SELECTED, 0xffff, 2, 0x1234L, f.at("rom2::4000"), 14, true);
      var disabled = new MapperKnowledge(0x44, 1, 0, 0, false, 0, 1, 0);
      assertEquals(List.of(new BankAnalysis.WriteTransition(14, 0, 0xffff, 0x34, SELECTED, SELECTED, false),
          new BankAnalysis.WriteTransition(14, 1, 0, 0x12, SELECTED, disabled, true)), result.writes);
      assertEquals(List.of(unresolved("rom2::4000", DEVICE, 14, 0), unresolved("rom2::4000", CONTROL, 14, 1)), result.findings());
      assertEquals(disabled, result.state);
    }
  }

  @Test
  void deviceUnmappedAndUnknownWritesKeepEmptyTargetsAndExactReasons() throws Exception {
    try (var f = new Fixture(0x19, true)) {
      for (var row : Map.of(0xff00, DEVICE, 0xfea0, "unmapped: Unusable hardware interval",
          0xa000, "unmapped: RAM/RTC disabled").entrySet()) {
        var result = parity(f, EXACT, row.getKey(), 1, 0x55L, f.at("0150"), 6, true);
        assertEquals(EXACT, result.state);
        assertEquals(List.of(unresolved("0150", row.getValue(), 6, 0)), result.findings());
        assertFalse(result.writes.get(0).mapperControl());
      }
      var unknown = parity(f, MapperKnowledge.unknown(), 0x8000, 1, null, f.at("0150"), 6, true);
      assertEquals(MapperKnowledge.unknown(), unknown.state);
      assertEquals(List.of(unresolved("0150", "unknown: Required mapper register is unknown", 6, 0)), unknown.findings());
    }
    try (var f = new Fixture(0x00, false)) {
      var result = parity(f, SELECTED, 0x2000, 1, 2L, f.at("0150"), 6, true);
      assertEquals(SELECTED, result.state);
      assertEquals(List.of(unresolved("0150", "unmapped: ROM is read-only; mapper control write", 6, 0)), result.findings());
      assertFalse(result.writes.get(0).mapperControl());
    }
  }

  @Test
  void diagnosticModeRetainsCanonicalFilteringAndNoEligibleStaticTargetReason() throws Exception {
    try (var f = new Fixture(0x19, false)) {
      var live = f.alias(SoftwareCallExecutionView.PREFIX + "live_write", 0xc100, true);
      f.alias(SoftwareCallExecutionView.PREFIX + "retired_write", 0xc100, false);
      var ordinary = f.alias(OrdinaryEntryAccess.PREFIX + "write", 0xc100, false);
      f.alias("wrong_cpu_write", 0xc200, true);
      var all = parity(f, EXACT, 0xc100, 1, 1L, f.at("0150"), 5, false);
      assertEquals(new TreeSet<>(List.of("c100", live.getStart().toString(), ordinary.getStart().toString())),
          new TreeSet<>(all.findings().get(0).targets()));
      assertEquals(AnalysisResult.Confidence.AMBIGUOUS, all.findings().get(0).confidence());
      assertEquals("Finite alternative destinations", all.findings().get(0).reason());
      var canonical = parity(f, EXACT, 0xc100, 1, 1L, f.at("0150"), 5, true);
      assertEquals(List.of(finding("0150", List.of("c100"), EVIDENCE, AnalysisResult.Confidence.PROVEN, 5, 0)), canonical.findings());
      int tx = f.p.startTransaction("Exclude only eligible canonical mapping");
      try {
        f.p.getMemory().getBlock(f.at("c100")).setName(OrdinaryEntryAccess.PREFIX + "excluded_write");
      } finally {
        f.p.endTransaction(tx, true);
      }
      var absent = parity(f, EXACT, 0xc100, 1, 1L, f.at("0150"), 5, true);
      assertEquals(List.of(unresolved("0150", "Physical destination has no static mapping", 5, 0)), absent.findings());
      assertEquals(EXACT, absent.state);
    }
  }
}
