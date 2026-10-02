package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** CPU-byte oracles for actual one-byte storage COPY forms; no private ROM fixtures. */
class BankAnalysisMemoryStorageCopyTest extends IntegrationTest {
  @TempDir Path temporary;
  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("Memory-storage COPY", getLanguage(),
        getLanguage().getDefaultCompilerSpec(), owner);

    Fixture(String prefix, String callee) throws Exception {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      byte[] caller = HexFormat.of().parseHex(prefix + "31feffcd0003ea00c276");
      byte[] body = HexFormat.of().parseHex(callee);
      System.arraycopy(caller, 0, bytes, 0x150, caller.length);
      System.arraycopy(body, 0, bytes, 0x300, body.length);
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.CGB, true, true,
            TaskMonitor.DUMMY, new MessageLog());
      }
      int tx = p.startTransaction("Define self-authored storage COPY fixture");
      try {
        for (var row : Map.of(0x150L, caller.length, 0x300L, body.length).entrySet()) {
          var first = p.getAddressFactory().getDefaultAddressSpace().getAddress(row.getKey());
          Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(first,
              new AddressSet(first, first.add(row.getValue() - 1)));
        }
      } finally { p.endTransaction(tx, true); }
    }

    BankAnalysis.FetchPreview preview(boolean reverse) throws Exception {
      return BankAnalysis.previewFetch(p, ProgramMapping.staticAddress(p, "0150"), MapperState.reset(),
          new AnalysisResult.Configuration(4096, reverse), TaskMonitor.DUMMY);
    }

    PcodeOp[] raw() { return p.getListing().getInstructionAt(ProgramMapping.staticAddress(p, "0300")).getPcode(false); }

    @Override public void close() { p.release(owner); }
  }

  private static void storageCopy(Fixture f, int cpu) {
    var raw = f.raw();
    assertEquals(1, raw.length, Arrays.toString(raw));
    assertEquals(PcodeOp.COPY, raw[0].getOpcode());
    assertEquals(1, raw[0].getNumInputs());
    assertEquals(new Varnode(f.p.getRegister("A").getAddress(), 1), raw[0].getOutput());
    assertTrue(raw[0].getInput(0).isAddress());
    assertFalse(raw[0].getInput(0).isConstant());
    assertEquals(f.p.getAddressFactory().getDefaultAddressSpace(), raw[0].getInput(0).getAddress().getAddressSpace());
    assertEquals(cpu, raw[0].getInput(0).getOffset());
    assertEquals(1, raw[0].getInput(0).getSize());
  }

  private static void returnedValue(BankAnalysis.FetchPreview preview, Integer expected) {
    assertEquals(1, preview.result().ordinaryCallProofs().size(), preview.result().findings().toString());
    var writes = preview.steps().stream().flatMap(s -> s.writes().stream()).filter(w -> w.cpu() == 0xc200).toList();
    assertFalse(writes.isEmpty(), "Matched continuation must execute its observable write");
    assertTrue(writes.stream().allMatch(w -> Objects.equals(expected, w.value())), writes.toString());
  }

  @Test void exactC100ValuesOneAndSevenPropagateIndependentOfSvbk() throws Exception {
    for (int value : List.of(1, 7)) for (int bank : List.of(1, 7)) {
      try (var f = new Fixture(String.format("2100c136%02x3e%02xe070", value, bank), "fa00c1c9")) {
        storageCopy(f, 0xc100);
        assertEquals(List.of(new MapperState.Physical("WRAM", 0, 0x100)),
            ProgramMapping.staticToPhysical(f.p, ProgramMapping.staticAddress(f.p, "c100")));
        for (boolean reverse : List.of(false, true)) returnedValue(f.preview(reverse), value);
      }
    }
  }

  @Test void absentAndKilledC100FactsStayUnknownButPermitMatchedReturn() throws Exception {
    for (String prefix : List.of("", "2100c136073e07e070f070ea00c1")) {
      try (var f = new Fixture(prefix, "fa00c1c9")) {
        storageCopy(f, 0xc100);
        for (boolean reverse : List.of(false, true)) returnedValue(f.preview(reverse), null);
      }
    }
  }

  @Test void hramKnownAndAbsentValuesUseExactPhysicalIdentity() throws Exception {
    for (String prefix : List.of("2190ff365a", "")) {
      try (var f = new Fixture(prefix, "fa90ffc9")) {
        storageCopy(f, 0xff90);
        assertEquals(List.of(new MapperState.Physical("HRAM", 0, 0x10)),
            ProgramMapping.staticToPhysical(f.p, ProgramMapping.staticAddress(f.p, "ff90")));
        for (boolean reverse : List.of(false, true)) returnedValue(f.preview(reverse), prefix.isEmpty() ? null : 0x5a);
      }
    }
  }

  @Test void emittedD100StorageCopySelectsCurrentSvbkPhysicalFact() throws Exception {
    String writes = "3e01e0702100d136113e02e0702100d13622";
    for (int bank : List.of(1, 2)) {
      try (var f = new Fixture(writes + String.format("3e%02xe070", bank), "fa00d1c9")) {
        storageCopy(f, 0xd100);
        var physical = MapperKnowledge.from(MapperState.reset()).write(ProgramMapping.cartridge(f.p), 0xff70, bank)
            .translate(ProgramMapping.cartridge(f.p), 0xd100, false).physical();
        assertEquals(new MapperState.Physical("WRAM", bank, 0x100), physical);
        for (boolean reverse : List.of(false, true)) returnedValue(f.preview(reverse), bank == 1 ? 0x11 : 0x22);
      }
    }
  }

  @Test void unknownBankUnsupportedDeviceAndUnusableStorageStillRefuse() throws Exception {
    for (String callee : List.of("f070e070fa00d1c9", "faa0fec9", "fa00ffc9")) {
      try (var f = new Fixture("", callee)) {
        for (boolean reverse : List.of(false, true)) assertTrue(f.preview(reverse).result().ordinaryCallProofs().isEmpty(), callee);
      }
    }
    try (var f = new Fixture("", "fa00c1c9")) {
      int tx = f.p.startTransaction("Remove supported mutable backing");
      try { f.p.getMemory().getBlock(ProgramMapping.staticAddress(f.p, "c100")).setVolatile(true); }
      finally { f.p.endTransaction(tx, true); }
      for (boolean reverse : List.of(false, true)) assertTrue(f.preview(reverse).result().ordinaryCallProofs().isEmpty());
    }
  }

  @Test void rawImmediateAndIndirectFormsRetainTheirDistinctSemantics() throws Exception {
    for (String callee : List.of("fa00c1c9", "fa90ffc9", "fa00d1c9", "fa00ffc9")) {
      try (var f = new Fixture("", callee)) {
        int cpu = Integer.parseInt(callee.substring(4, 6) + callee.substring(2, 4), 16);
        storageCopy(f, cpu);
      }
    }
    for (String callee : List.of("0ac9", "1ac9", "7ec9", "f090c9")) {
      try (var f = new Fixture("", callee)) {
        assertTrue(Arrays.stream(f.raw()).anyMatch(op -> op.getOpcode() == PcodeOp.LOAD), callee);
      }
    }
  }

  @Test void knownAndUnknownStorageCopyProofsPublishAndSurvivePackedReopen() throws Exception {
    for (String prefix : List.of("2100c13607", "")) {
      Integer expected = prefix.isEmpty() ? null : 7;
      try (var f = new Fixture(prefix, "fa00c1c9")) {
        var original = f.preview(false);
        returnedValue(original, expected);
        ProgramFingerprint.requireCurrent(f.p, original.result(), TaskMonitor.DUMMY);
        BankAnalysis.apply(f.p, original.result(), TaskMonitor.DUMMY);
        var stored = AnalysisResult.read(f.p.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", null));
        assertEquals(original.result(), stored);
        var packed = temporary.resolve(prefix.isEmpty() ? "unknown-copy.gzf" : "known-copy.gzf").toFile();
        f.p.saveToPackedFile(packed, TaskMonitor.DUMMY);
        var database = PackedDatabase.getPackedDatabase(packed, true, TaskMonitor.DUMMY);
        Object owner = new Object();
        ProgramDB reopened = null;
        try {
          reopened = new ProgramDB(database.open(TaskMonitor.DUMMY), OpenMode.IMMUTABLE,
              TaskMonitor.DUMMY, owner);
          var restored = AnalysisResult.read(reopened.getOptions(ProgramMapping.OPTIONS)
              .getString("analysis.latest", null));
          assertEquals(original.result(), restored);
          ProgramFingerprint.requireCurrent(reopened, restored, TaskMonitor.DUMMY);
          var fresh = BankAnalysis.previewFetch(reopened, ProgramMapping.staticAddress(reopened, "0150"),
              MapperState.reset(), new AnalysisResult.Configuration(4096, false), TaskMonitor.DUMMY);
          assertEquals(restored, fresh.result());
          assertEquals(original.result().ordinaryCallProofs(), fresh.result().ordinaryCallProofs());
          returnedValue(fresh, expected);
        } finally {
          if (reopened != null) reopened.release(owner);
          database.dispose();
        }
      }
    }
  }

  @Test void productionImmediateAndRegisterCopiesDoNotReadMemoryAtTheirValues() throws Exception {
    // C100 contains 07. Loading literal C100 into HL and copying L into A must yield 00.
    // The scalar register's numeric pointer does not authorize reading that byte.
    for (var row : Map.of("2100c17dc9", 0, "3e01c9", 1, "3e074778c9", 7).entrySet()) {
      try (var f = new Fixture("2100c13607", row.getKey())) {
        assertFalse(Arrays.stream(f.raw()).anyMatch(op -> Arrays.stream(op.getInputs()).anyMatch(Varnode::isAddress)));
        for (boolean reverse : List.of(false, true)) returnedValue(f.preview(reverse), row.getValue());
      }
    }
  }

  @Test void widerStorageAndNonCpuAddressSpacesAreNotNewlyQualified() throws Exception {
    var dispatch = BankAnalysis.class.getDeclaredMethod("memoryStorageCopy", Program.class, PcodeOp.class);
    dispatch.setAccessible(true);
    try (var f = new Fixture("", "c9")) {
      var cpu = f.p.getAddressFactory().getDefaultAddressSpace();
      var rom = ProgramMapping.staticAddress(f.p, "rom1::4000");
      for (var input : List.of(new Varnode(cpu.getAddress(0xc100), 2), new Varnode(rom, 1))) {
        var output = new Varnode(f.p.getRegister("HL").getAddress(), input.getSize());
        var op = new PcodeOp(cpu.getAddress(0x300), 0, PcodeOp.COPY, new Varnode[] {input}, output);
        assertFalse((boolean) dispatch.invoke(null, f.p, op), input.toString());
      }
    }
  }

  @Test void constantsRegistersAndUniqueValuesRemainScalarEvenWhenEqualToC100() throws Exception {
    var dispatch = BankAnalysis.class.getDeclaredMethod("memoryStorageCopy", Program.class, PcodeOp.class);
    dispatch.setAccessible(true);
    try (var f = new Fixture("", "c9")) {
      var regs = new HashMap<Long, Integer>();
      var unique = new HashMap<Long, Integer>();
      for (int width : List.of(1, 2)) {
        var output = new Varnode(f.p.getRegister("DE").getAddress(), width);
        var register = new Varnode(f.p.getRegister("HL").getAddress(), width);
        var temporary = new Varnode(f.p.getAddressFactory().getUniqueSpace().getAddress(0x1000), width);
        for (long value : List.of(7L, 0xc100L)) {
          PcodeConstants.put(register, value, regs, unique);
          PcodeConstants.put(temporary, value, regs, unique);
          var constant = new Varnode(f.p.getAddressFactory().getConstantSpace().getAddress(value), width);
          for (var input : List.of(constant, register, temporary)) {
            var op = new PcodeOp(ProgramMapping.staticAddress(f.p, "0300"),
                0, PcodeOp.COPY, new Varnode[] {input}, output);
            assertFalse((boolean) dispatch.invoke(null, f.p, op), input.toString());
            assertEquals(value & (width == 1 ? 0xffL : 0xffffL), PcodeConstants.evaluate(op, regs, unique));
          }
        }
      }
    }
  }
}
