package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Self-authored 1C chains with independent CPU, physical slot and restored-SP witnesses. */
class BankAnalysisCallDepthTest extends IntegrationTest {
  @TempDir Path temporary;

  private static String hex(int cpu) { return String.format("%04x", cpu); }
  private static String word(int value) { return String.format("%02x%02x", value & 255, value >>> 8); }
  private static int target(int level) { return 0x300 + 0x20 * (level - 1); }
  private static MapperState.Physical rom(int cpu) { return new MapperState.Physical("ROM", 0, cpu); }

  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("Three active ordinary calls", getLanguage(),
        getLanguage().getDefaultCompilerSpec(), owner);

    Fixture(int depth, String leaf) throws Exception { this(depth, leaf, false); }
    Fixture(int depth, String leaf, boolean conditional) throws Exception { this(depth, leaf, conditional, 0xd000); }
    Fixture(int depth, String leaf, boolean conditional, int sp) throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      var code = new LinkedHashMap<Integer, String>();
      code.put(0x150, "31" + word(sp) + "3e02cd00030800c1ea0020c30040");
      for (int level = 1; level <= depth; level++) {
        String body = level == depth ? leaf : (conditional && level == 3 ? "cc" : "cd") + word(target(level + 1));
        code.put(target(level), body + "08" + word(0xc100 + 2 * level) + "c9");
      }
      code.put(0x8000, "18fe");
      for (var entry : code.entrySet()) {
        byte[] part = HexFormat.of().parseHex(entry.getValue());
        System.arraycopy(part, 0, bytes, entry.getKey(), part.length);
      }
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.CGB, true, true,
            TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("Define exact chain");
      try {
        for (var entry : code.entrySet()) {
          var first = ProgramMapping.staticAddress(p, entry.getKey() == 0x8000 ? "rom2::4000" : hex(entry.getKey()));
          Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first,
              new AddressSet(first, first.add(entry.getValue().length() / 2 - 1)));
        }
      } finally { p.endTransaction(tx, true); }
    }

    BankAnalysis.FetchPreview preview(boolean reverse, int limit) throws Exception {
      return BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
          new AnalysisResult.Configuration(limit, reverse), TaskMonitor.DUMMY);
    }
    @Override public void close() { p.release(owner); }
  }

  private static List<BankAnalysis.WriteTransition> writes(BankAnalysis.FetchPreview preview, int source) {
    return preview.steps().stream().filter(s -> s.cpu() == source).flatMap(s -> s.writes().stream()).toList();
  }

  private void positive(Fixture f, int depth) throws Exception {
    for (boolean reverse : List.of(false, true)) {
      var preview = f.preview(reverse, 4096);
      assertEquals(depth, preview.result().ordinaryCallProofs().size(), preview.result().findings().toString());
      var expected = new HashSet<AnalysisResult.OrdinaryCallProof>();
      var slots = new HashSet<MapperState.Physical>();
      for (int level = 1; level <= depth; level++) {
        int source = level == 1 ? 0x155 : target(level - 1);
        int continuation = source + 3;
        expected.add(new AnalysisResult.OrdinaryCallProof(hex(source), rom(source), hex(target(level)),
            rom(target(level)), hex(continuation), rom(continuation)));
        var ins = f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, hex(source)));
        var raw = Arrays.asList(ins.getPcode(false));
        assertEquals(2, raw.stream().filter(op -> op.getOpcode() == PcodeOp.STORE).count());
        assertEquals(PcodeOp.CALL, raw.get(raw.size() - 1).getOpcode());
        assertEquals(hex(continuation), ins.getFallThrough().toString());
        var stores = writes(preview, source);
        int low = 0xd000 - 2 * level;
        assertEquals(List.of(low + 1, low), stores.stream().map(BankAnalysis.WriteTransition::cpu).toList());
        assertEquals(List.of(continuation >>> 8, continuation & 255), stores.stream().map(BankAnalysis.WriteTransition::value).toList());
        for (int cpu : List.of(low, low + 1)) {
          var physical = new MapperState.Physical("WRAM", 0, cpu - 0xc000);
          assertEquals(physical, MapperState.translate(ProgramMapping.cartridge(f.p), MapperState.reset(), cpu, false).physical());
          assertTrue(slots.add(physical));
        }
        int witness = level < depth ? target(level) + 3 : target(level);
        var sp = writes(preview, witness);
        assertEquals(List.of(0xc100 + 2 * level, 0xc101 + 2 * level), sp.stream().map(BankAnalysis.WriteTransition::cpu).toList());
        assertEquals(List.of(low & 255, low >>> 8), sp.stream().map(BankAnalysis.WriteTransition::value).toList());
        var ret = preview.steps().stream().filter(s -> s.cpu() == witness + 3).findFirst().orElseThrow();
        assertEquals(MapperKnowledge.from(MapperState.reset()), ret.incoming());
        assertEquals(ret.incoming(), ret.outgoing());
        var retIns = f.p.getListing().getInstructionAt(ProgramMapping.staticAddress(f.p, hex(witness + 3)));
        assertEquals(2, Arrays.stream(retIns.getPcode(false)).filter(op -> op.getOpcode() == PcodeOp.LOAD).count());
        assertEquals(1, Arrays.stream(retIns.getPcode(false)).filter(op -> op.getOpcode() == PcodeOp.RETURN).count());
      }
      assertEquals(expected, new HashSet<>(preview.result().ordinaryCallProofs()));
      assertEquals(List.of(0, 0xd0), writes(preview, 0x158).stream().map(BankAnalysis.WriteTransition::value).toList());
      assertEquals(2, writes(preview, 0x15b).get(0).value());
      assertTrue(preview.steps().stream().anyMatch(s -> s.source().equals("rom2::4000") && Objects.equals(2, s.incoming().low())));
    }
  }

  @ParameterizedTest @ValueSource(ints = {1, 2, 3})
  void exactFramesAndMatchedReturns(int depth) throws Exception {
    try (var f = new Fixture(depth, "")) { positive(f, depth); }
  }

  private void refused(Fixture f, String absent) throws Exception {
    for (boolean reverse : List.of(false, true)) {
      var preview = f.preview(reverse, 4096);
      assertTrue(preview.result().ordinaryCallProofs().isEmpty(), preview.result().findings().toString());
      assertNull(writes(preview, 0x15b).get(0).value());
      if (absent != null) assertTrue(preview.steps().stream().noneMatch(s -> s.source().equals(absent)));
    }
  }

  @Test void fourthActiveCallStillRefuses() throws Exception {
    try (var f = new Fixture(4, "")) {
      refused(f, "0360");
      assertTrue(f.preview(false, 4096).result().findings().stream().anyMatch(x -> x.reason().contains("active depth 3")));
    }
  }
  @Test void directRecursionStillRefuses() throws Exception {
    try (var f = new Fixture(1, "cd0003")) { refused(f, null); }
  }
  @Test void mutualRecursionStillRefuses() throws Exception {
    try (var f = new Fixture(2, "cd0003")) { refused(f, null); }
  }
  @Test void conditionalFourthLevelInvalidatesContainingProof() throws Exception {
    try (var f = new Fixture(4, "", true)) { refused(f, "0360"); }
  }
  @Test void incompleteThirdCalleeStillRefuses() throws Exception {
    try (var f = new Fixture(3, "c30006")) { refused(f, null); }
  }
  @Test void thirdCalleeCycleStillRefuses() throws Exception {
    try (var f = new Fixture(3, "18fe")) { refused(f, null); }
  }
  @Test void sharedGlobalBudgetStillRefuses() throws Exception {
    try (var f = new Fixture(3, "")) {
      var preview = f.preview(false, 4);
      assertEquals(AnalysisResult.Completion.STATE_LIMIT, preview.result().completion());
      assertEquals(4, preview.result().exploredStates());
      assertTrue(preview.result().ordinaryCallProofs().isEmpty());
    }
  }
  @Test void thirdCalleeLocalBudgetStillRefuses() throws Exception {
    try (var f = new Fixture(3, "3e00".repeat(179))) {
      refused(f, null);
      assertTrue(f.preview(false, 4096).result().findings().stream().anyMatch(x -> x.reason().contains("callee state bound")));
    }
  }
  @Test void cancellationAtThirdInvocationStillRefuses() throws Exception {
    try (var f = new Fixture(3, "")) {
      var monitor = new ghidra.util.task.TaskMonitorAdapter(true) {
        int invocations;
        @Override public void setMessage(String message) {
          if (message.equals("Exploring bank states") && ++invocations == 4) cancel();
        }
      };
      var result = BankAnalysis.preview(f.p, ProgramMapping.staticAddress(f.p, "0150"), MapperState.reset(),
          AnalysisResult.Configuration.DEFAULT, monitor);
      assertEquals(AnalysisResult.Completion.CANCELLED, result.completion());
      assertTrue(result.ordinaryCallProofs().isEmpty());
    }
  }
  @Test void thirdLevelRetainsTwoATwoBRefusals() throws Exception {
    // DMA, unknown device, alias, changed bank, unknown address, unresolved LOAD, forged SP, incompatible mapper returns.
    for (String leaf : List.of("3ec0e046", "3e00e055", "3e00e041", "21facf3600",
        "12", "fa00a0", "31fecf", "28063e01ea0020c9" + "3e02ea0020c9")) {
      try (var f = new Fixture(3, leaf)) { refused(f, null); }
    }
  }
  @Test void thirdLevelChangedPhysicalBankStillRefuses() throws Exception {
    try (var f = new Fixture(3, "3e02e070", false, 0xd100)) { refused(f, null); }
  }
  @Test void thirdLevelSupportedUnknownLoadAndScxStillCompose() throws Exception {
    for (String read : List.of("f070", "2100c27e")) {
      try (var f = new Fixture(3, read + "e0433e02")) {
        var preview = f.preview(false, 4096);
        assertEquals(3, preview.result().ordinaryCallProofs().size(), preview.result().findings().toString());
        assertTrue(preview.steps().stream().flatMap(s -> s.writes().stream()).anyMatch(w -> w.cpu() == 0xff43 && w.value() == null));
        assertEquals(2, writes(preview, 0x15b).get(0).value());
      }
    }
  }
  @ParameterizedTest @ValueSource(ints = {1, 2, 3})
  void qualifiedUnknownDeviceWritesRetainExactDepthProofs(int depth) throws Exception {
    for (String device : List.of("40", "26")) try (var f = new Fixture(depth, "f070e0" + device + "3e02")) {
      for (boolean reverse : List.of(false, true)) {
        var preview = f.preview(reverse, 4096);
        var expected = new HashSet<AnalysisResult.OrdinaryCallProof>();
        for (int level = 1; level <= depth; level++) {
          int source = level == 1 ? 0x155 : target(level - 1);
          expected.add(new AnalysisResult.OrdinaryCallProof(hex(source), rom(source), hex(target(level)),
              rom(target(level)), hex(source + 3), rom(source + 3)));
        }
        assertEquals(depth, preview.result().ordinaryCallProofs().size(), preview.result().findings().toString());
        assertEquals(expected, new HashSet<>(preview.result().ordinaryCallProofs()));
        var deviceWrite = writes(preview, target(depth) + 2).get(0);
        assertEquals(0xff00 + Integer.parseInt(device, 16), deviceWrite.cpu());
        assertNull(deviceWrite.value());
        assertEquals(deviceWrite.before(), deviceWrite.after());
        assertEquals(List.of(0, 0xd0), writes(preview, 0x158).stream().map(BankAnalysis.WriteTransition::value).toList());
        assertEquals(2, writes(preview, 0x15b).get(0).value());
      }
    }
  }
  @Test void qualifiedDeviceWritesCannotBypassDepthStructuralCycleOrResourceRefusal() throws Exception {
    for (String device : List.of("40", "26")) {
      String prefix = "f070e0" + device + "3e02";
      // The qualified write executes in the third callee before the refused fourth invocation.
      try (var f = new Fixture(3, prefix + "cd6003")) {
        refused(f, "0360");
        var preview = f.preview(false, 4096);
        assertTrue(preview.result().findings().stream().anyMatch(x -> x.reason().contains("active depth 3")));
        assertNull(writes(preview, target(3) + 2).get(0).value());
      }
      for (String effect : List.of("18fe", "fa00a0", "cd0003"))
        try (var f = new Fixture(3, prefix + effect)) { refused(f, null); }
      try (var f = new Fixture(3, prefix + "3e00".repeat(179))) {
        refused(f, null);
        assertTrue(f.preview(false, 4096).result().findings().stream().anyMatch(x -> x.reason().contains("callee state bound")));
      }
    }
  }
  @Test void packedPriorEngineRequiresRecomputation() throws Exception {
    for (String priorEngine : List.of("20261001-call-stack-liveness-2a-1",
        "20261001-call-stack-liveness-2c-1",
        "20261001-call-stack-liveness-2d-1",
        "20261002-memory-storage-copy-1",
        "20261002-call-stack-liveness-2e-1",
        "20261002-local-loop-1")) try (var f = new Fixture(3, "")) {
      var result = f.preview(false, 4096).result();
      var oldJson = ProgramMapping.JSON.toJson(result).replace(AnalysisResult.ENGINE_VERSION, priorEngine);
      int tx = f.p.startTransaction("Store obsolete result");
      try { f.p.getOptions(ProgramMapping.OPTIONS).setString("analysis.latest", oldJson); }
      finally { f.p.endTransaction(tx, true); }
      var packed = temporary.resolve(priorEngine + ".gzf").toFile();
      f.p.saveToPackedFile(packed, TaskMonitor.DUMMY);
      var database = PackedDatabase.getPackedDatabase(packed, true, TaskMonitor.DUMMY);
      Object consumer = new Object();
      ProgramDB reopened = null;
      try {
        reopened = new ProgramDB(database.open(TaskMonitor.DUMMY), OpenMode.IMMUTABLE, TaskMonitor.DUMMY, consumer);
        var p = reopened;
        String stored = p.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", null);
        assertThrows(IllegalArgumentException.class, () -> AnalysisResult.read(stored));
        var old = ProgramMapping.JSON.fromJson(stored, AnalysisResult.class);
        assertTrue(old.ordinaryCallProofs().isEmpty());
        assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(p, old, TaskMonitor.DUMMY));
        assertThrows(IllegalStateException.class, () -> AnalysisApplication.apply(p, old, TaskMonitor.DUMMY));
        assertThrows(IllegalStateException.class, () -> OrdinaryCallFlow.publish(p, old, TaskMonitor.DUMMY));
        var fresh = BankAnalysis.preview(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
            AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
        assertEquals(result.ordinaryCallProofs(), fresh.ordinaryCallProofs());
        assertEquals(3, fresh.ordinaryCallProofs().size());
        assertEquals(4, fresh.schemaVersion());
        assertEquals(AnalysisResult.ENGINE_VERSION, fresh.engineVersion());
        ProgramFingerprint.requireCurrent(p, fresh, TaskMonitor.DUMMY);
      } finally { if (reopened != null) reopened.release(consumer); database.dispose(); }
    }
  }
}
