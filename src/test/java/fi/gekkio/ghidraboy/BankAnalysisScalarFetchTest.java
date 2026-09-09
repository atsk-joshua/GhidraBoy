package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.*;
import org.junit.jupiter.api.Test;

/** Frozen W2c fetch policy, supplemented by independent admission and source expectations. */
class BankAnalysisScalarFetchTest extends IntegrationTest {
  private static final MapperKnowledge EXACT = MapperKnowledge.from(MapperState.reset());
  private static final MapperKnowledge UNKNOWN = MapperKnowledge.unknown();

  private final class Fixture implements AutoCloseable {
    final Object consumer = new Object();
    final ProgramDB p = new ProgramDB("W2d scalar fetch", getLanguage(), getLanguage().getDefaultCompilerSpec(), consumer);
    final Cartridge c;

    Fixture() throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x143] = (byte) 0x80;
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      bytes[0x200] = 0x3e;
      bytes[0x201] = 0x27;
      bytes[0x4010] = 0x06;
      bytes[0x4011] = (byte) 0xa7;
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.CGB, true, true,
            TaskMonitor.DUMMY, new MessageLog());
      }
      c = ProgramMapping.cartridge(p);
      assertEquals(Cartridge.Mapper.MBC5, c.mapper());
    }

    Address at(String value) {
      return Objects.requireNonNull(ProgramMapping.staticAddress(p, value));
    }

    Instruction decode(Address start, int width) throws Exception {
      int tx = p.startTransaction("Decode self-authored instruction");
      try {
        Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
            .disassemble(start, new AddressSet(start, start.add(width - 1)));
        var instruction = p.getListing().getInstructionAt(start);
        assertNotNull(instruction);
        assertEquals(width, instruction.getLength());
        return instruction;
      } finally {
        p.endTransaction(tx, true);
      }
    }

    MemoryBlock alias(String name, int cpu, Address source, boolean execute) throws Exception {
      int tx = p.startTransaction("Add self-authored execution view");
      try {
        var block = p.getMemory().createByteMappedBlock(name, at(String.format("%04x", cpu)), source, 2, true);
        block.setExecute(execute);
        return block;
      } finally {
        p.endTransaction(tx, true);
      }
    }

    Instruction boundary(boolean validLastByte) throws Exception {
      var start = at("rom1::7fff");
      var vram = p.getMemory().getBlock("vram0");
      int tx = p.startTransaction("Build three-byte cross-window instruction");
      try {
        p.getMemory().convertToInitialized(vram, (byte) 0);
        p.getMemory().setByte(start, (byte) 0xc3);
        p.getMemory().createByteMappedBlock("first suffix", start.getAddressSpace().getAddressInThisSpaceOnly(0x8000), vram.getStart(), 1, false).setExecute(true);
        var lastSource = validLastByte ? vram.getStart().add(1) : at("rom2::4001");
        p.getMemory().createByteMappedBlock("last suffix", start.getAddressSpace().getAddressInThisSpaceOnly(0x8001), lastSource, 1, false).setExecute(true);
      } finally {
        p.endTransaction(tx, true);
      }
      return decode(start, 3);
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

  @SuppressWarnings("unchecked")
  private static List<Address> resolve(Fixture f, MapperKnowledge state, int cpu, Address context,
      boolean canonical) throws Exception {
    return (List<Address>) method("resolveWithContext", Program.class, Cartridge.class,
        MapperKnowledge.class, int.class, Address.class, boolean.class)
        .invoke(null, f.p, f.c, state, cpu, context, canonical);
  }

  private static boolean established(Fixture f, MapperKnowledge state, Instruction ins,
      boolean canonical) throws Exception {
    return (boolean) method("fetchEstablished", Program.class, Cartridge.class, MapperKnowledge.class,
        Instruction.class, boolean.class).invoke(null, f.p, f.c, state, ins, canonical);
  }

  @SuppressWarnings("unchecked")
  private static List<BankAnalysis.FetchByte> bytes(Fixture f, Instruction ins) throws Exception {
    return (List<BankAnalysis.FetchByte>) method("fetchBytes", Program.class, Instruction.class)
        .invoke(null, f.p, ins);
  }

  // Frozen W2c executionCandidate/resolve/resolveWithContext/fetchEstablished policy.
  // Deliberately uses MapperKnowledge directly; do not adapt this oracle to ScalarAccess.
  private static boolean legacyCandidate(Program p, Address address, boolean canonical) {
    var block = p.getMemory().getBlock(address);
    if (canonical && (block == null || block.getName().startsWith(SoftwareCallExecutionView.PREFIX)
        || block.getName().startsWith(OrdinaryEntryAccess.PREFIX))) return false;
    return !address.getAddressSpace().getName().startsWith(SoftwareCallExecutionView.PREFIX)
        || (block != null && block.isExecute());
  }

  private static List<Address> legacyResolve(Fixture f, MapperKnowledge state, int cpu,
      Address context, boolean canonical) throws Exception {
    var physical = state.translate(f.c, cpu, false).physical();
    var direct = physical == null ? List.<Address>of() : ProgramMapping.physicalToStatic(f.p, physical).stream()
        .filter(a -> a.getOffset() == cpu && legacyCandidate(f.p, a, canonical)).toList();
    if (!direct.isEmpty() || context == null || f.c.mapper() == Cartridge.Mapper.RAW
        || cpu >= 0x8000 || context.getOffset() >= 0x8000
        || cpu / 0x4000 != context.getOffset() / 0x4000) return direct;
    var identities = ProgramMapping.staticToPhysical(f.p, context);
    if (identities.size() != 1 || !identities.get(0).region().equals("ROM")
        || !state.allowsExecution(f.c, cpu, identities.get(0).bank())) return direct;
    var contextual = new MapperState.Physical("ROM", identities.get(0).bank(), cpu % 0x4000);
    return ProgramMapping.physicalToStatic(f.p, contextual).stream()
        .filter(a -> a.getOffset() == cpu && legacyCandidate(f.p, a, canonical)).toList();
  }

  private static int legacyWindow(int cpu) {
    int[] ends = {0x4000, 0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xf000, 0xfe00,
        0xfea0, 0xff00, 0xff80, 0xffff, 0x10000};
    for (int i = 0; i < ends.length; i++) if (cpu < ends[i]) return i;
    throw new IllegalArgumentException("CPU address out of range");
  }

  private static boolean legacyEstablished(Fixture f, MapperKnowledge state, Instruction ins,
      boolean canonical) throws Exception {
    if (!legacyCandidate(f.p, ins.getAddress(), canonical)) return false;
    long start = ins.getAddress().getOffset(), end = start + ins.getLength() - 1;
    var source = ProgramMapping.staticToPhysical(f.p, ins.getAddress());
    var expected = state.translate(f.c, (int) start, false).physical();
    if (expected != null && (source.size() != 1 || !source.get(0).equals(expected))) return false;
    if (legacyWindow((int) start) == legacyWindow((int) (end & 65535)) && end <= 65535) return true;
    byte[] bytes = ins.getBytes();
    for (int i = 0; i < bytes.length; i++) {
      int cpu = (int) ((start + i) & 65535);
      var views = legacyResolve(f, state, cpu, ins.getAddress(), canonical);
      if (views.isEmpty()) return false;
      var actual = ProgramMapping.staticToPhysical(f.p, ins.getAddress().addWrap(i));
      if (actual.size() != 1) return false;
      for (var view : views) {
        if (!ProgramMapping.staticToPhysical(f.p, view).equals(actual)
            || f.p.getMemory().getByte(view) != bytes[i]) return false;
      }
    }
    return true;
  }

  private static void admission(Fixture f, MapperKnowledge state, Instruction ins,
      boolean canonical, boolean expected) throws Exception {
    assertEquals(expected, legacyEstablished(f, state, ins, canonical), "Independent legacy admission expectation");
    assertEquals(expected, established(f, state, ins, canonical), "Migrated admission must agree");
  }

  private static void targets(Fixture f, MapperKnowledge state, int cpu, Address context,
      boolean canonical, List<Address> expected) throws Exception {
    var actual = resolve(f, state, cpu, context, canonical);
    assertEquals(legacyResolve(f, state, cpu, context, canonical), actual, "Exact ordered static sources");
    assertEquals(expected, actual, "Independent source expectation");
    for (int i = 0; i < expected.size(); i++) {
      assertEquals(ProgramMapping.staticToPhysical(f.p, expected.get(i)),
          ProgramMapping.staticToPhysical(f.p, actual.get(i)), "Physical backing of each source");
    }
  }

  @Test
  void exactRomWindowsPreserveAdmissionAndEveryByteSource() throws Exception {
    try (var f = new Fixture()) {
      var rom0 = f.decode(f.at("0200"), 2);
      var romx = f.decode(f.at("rom1::4010"), 2);
      admission(f, EXACT, rom0, true, true);
      admission(f, EXACT, romx, true, true);
      targets(f, EXACT, 0x200, null, true, List.of(f.at("0200")));
      targets(f, EXACT, 0x4010, null, true, List.of(f.at("rom1::4010")));
      assertEquals(List.of(
          new BankAnalysis.FetchByte(0x200, "0200", new MapperState.Physical("ROM", 0, 0x200), 0x3e),
          new BankAnalysis.FetchByte(0x201, "0201", new MapperState.Physical("ROM", 0, 0x201), 0x27)), bytes(f, rom0));
      assertEquals(List.of(
          new BankAnalysis.FetchByte(0x4010, "rom1::4010", new MapperState.Physical("ROM", 1, 0x10), 6),
          new BankAnalysis.FetchByte(0x4011, "rom1::4011", new MapperState.Physical("ROM", 1, 0x11), 0xa7)), bytes(f, romx));
    }
  }

  @Test
  void unknownRequiredSelectorNeedsSameWindowContextForResolutionButListingAdmissionIsUnchanged() throws Exception {
    try (var f = new Fixture()) {
      targets(f, UNKNOWN, 0x4010, null, true, List.of());
      targets(f, UNKNOWN, 0x4010, f.at("0200"), true, List.of());
      targets(f, UNKNOWN, 0x4010, f.at("rom2::4000"), true, List.of(f.at("rom2::4010")));
      // Retain the existing listing-based same-window admission, even with unknown knowledge.
      // A stronger refusal here would be a semantic expansion, not W2d adapter parity.
      admission(f, UNKNOWN, f.decode(f.at("rom2::4010"), 1), true, true);
      admission(f, UNKNOWN, f.boundary(true), true, false);
    }
  }

  @Test
  void wrongPhysicalBankIsRefusedAndExactMappingStillWinsOverContext() throws Exception {
    try (var f = new Fixture()) {
      admission(f, EXACT, f.decode(f.at("rom2::4010"), 1), true, false);
      targets(f, EXACT, 0x4010, f.at("rom2::4000"), true, List.of(f.at("rom1::4010")));
      int tx = f.p.startTransaction("Exclude known target from canonical candidates");
      try {
        f.p.getMemory().getBlock("rom1").setName(OrdinaryEntryAccess.PREFIX + "excluded");
      } finally {
        f.p.endTransaction(tx, true);
      }
      targets(f, EXACT, 0x4010, f.at("rom2::4000"), true, List.of());
    }
  }

  @Test
  void generatedViewsRetainLiveRetiredAndCanonicalExclusions() throws Exception {
    try (var f = new Fixture()) {
      var live = f.alias(SoftwareCallExecutionView.PREFIX + "live", 0x4010, f.at("rom1::4010"), true);
      var retired = f.alias(SoftwareCallExecutionView.PREFIX + "retired", 0x4010, f.at("rom1::4010"), true);
      var ordinary = f.alias(OrdinaryEntryAccess.PREFIX + "diagnostic", 0x4010, f.at("rom1::4010"), true);
      var liveIns = f.decode(live.getStart(), 2);
      var retiredIns = f.decode(retired.getStart(), 2);
      var ordinaryIns = f.decode(ordinary.getStart(), 2);
      int tx = f.p.startTransaction("Retire generated execution view");
      try {
        retired.setExecute(false);
      } finally {
        f.p.endTransaction(tx, true);
      }
      admission(f, EXACT, liveIns, false, true);
      admission(f, EXACT, liveIns, true, false);
      admission(f, EXACT, retiredIns, false, false);
      admission(f, EXACT, retiredIns, true, false);
      admission(f, EXACT, ordinaryIns, true, false);
      targets(f, EXACT, 0x4010, null, true, List.of(f.at("rom1::4010")));
      var eligible = resolve(f, EXACT, 0x4010, null, false);
      assertEquals(legacyResolve(f, EXACT, 0x4010, null, false), eligible);
      assertEquals(Set.of(f.at("rom1::4010"), live.getStart(), ordinary.getStart()), new HashSet<>(eligible));
      assertFalse(eligible.contains(retired.getStart()));
    }
  }

  @Test
  void crossWindowFetchChecksPhysicalBackingOfTheLastByteEvenWhenValuesMatch() throws Exception {
    for (boolean valid : List.of(false, true)) {
      try (var f = new Fixture()) {
        var ins = f.boundary(valid);
        assertArrayEquals(new byte[] {(byte) 0xc3, 0, 0}, ins.getBytes());
        admission(f, EXACT, ins, true, valid);
        var expectedViews = new TreeSet<>(List.of(f.at("vram0::8001")));
        if (valid) expectedViews.add(f.at("rom1::8001"));
        targets(f, EXACT, 0x8001, ins.getAddress(), true, List.copyOf(expectedViews));
        assertEquals(List.of(
            new BankAnalysis.FetchByte(0x7fff, "rom1::7fff", new MapperState.Physical("ROM", 1, 0x3fff), 0xc3),
            new BankAnalysis.FetchByte(0x8000, "rom1::8000", new MapperState.Physical("VRAM", 0, 0), 0),
            new BankAnalysis.FetchByte(0x8001, "rom1::8001",
                valid ? new MapperState.Physical("VRAM", 0, 1) : new MapperState.Physical("ROM", 2, 1), 0)), bytes(f, ins));
      }
    }
  }

  @Test
  void boundaryListingByteMismatchIsRefusedDespiteIdenticalPhysicalIdentity() throws Exception {
    try (var f = new Fixture()) {
      var actual = f.boundary(true);
      admission(f, EXACT, actual, true, true);
      // Synthetic inconsistent listing snapshot: delegate every Instruction method except getBytes.
      // This isolates the existing equality guard without changing Ghidra's shared backing memory.
      var mismatch = (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
          new Class<?>[] {Instruction.class}, (proxy, called, args) -> {
            if (called.getName().equals("getBytes") && called.getParameterCount() == 0)
              return new byte[] {(byte) 0xc3, 0, 1};
            return called.invoke(actual, args);
          });
      assertEquals(ProgramMapping.staticToPhysical(f.p, actual.getAddress().add(2)),
          ProgramMapping.staticToPhysical(f.p, f.at("vram0::8001")));
      admission(f, EXACT, mismatch, true, false);
    }
  }

  @Test
  void supportedPcWrapKeepsDeviceResolutionDistinctFromListingStorage() throws Exception {
    try (var f = new Fixture()) {
      int tx = f.p.startTransaction("Initialize one-byte PC wrap fixture");
      try {
        f.p.getMemory().convertToInitialized(f.p.getMemory().getBlock("ie"), (byte) 0);
        f.p.getListing().clearCodeUnits(f.at("ffff"), f.at("ffff"), false);
        f.p.getMemory().setByte(f.at("0000"), (byte) 0xc9);
      } finally {
        f.p.endTransaction(tx, true);
      }
      var last = f.decode(f.at("ffff"), 1);
      var wrapped = f.decode(f.at("0000"), 1);
      admission(f, EXACT, last, true, true);
      admission(f, EXACT, wrapped, true, true);
      targets(f, EXACT, (0xffff + last.getLength()) & 65535, last.getAddress(), true, List.of(f.at("0000")));
      assertEquals(List.of(new MapperState.Physical("IE", 0, 0)),
          ProgramMapping.staticToPhysical(f.p, last.getAddress()), "Listing storage identity remains available");
      targets(f, EXACT, 0xffff, null, true, List.of());
      assertNull(EXACT.translate(f.c, 0xffff, false).physical(),
          "Static IE storage identity does not turn device resolution into a mapped fetch");
      assertEquals(List.of(new BankAnalysis.FetchByte(0xffff, "ffff", new MapperState.Physical("IE", 0, 0), 0)),
          bytes(f, last), "Diagnostic byte comes from separately initialized listing memory");
      var result = BankAnalysis.preview(f.p, last.getAddress(), MapperState.reset(),
          AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
      assertEquals(2, result.exploredStates());
      assertFalse(result.findings().stream().anyMatch(finding -> finding.reason().contains("No defined instruction")));
      assertEquals(List.of(new BankAnalysis.FetchByte(0, "0000", new MapperState.Physical("ROM", 0, 0), 0xc9)),
          bytes(f, wrapped));
    }
  }
}
