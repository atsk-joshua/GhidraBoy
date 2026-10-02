package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Self-authored singleton architectural-pointer and independent physical-bank oracles. */
class BankAnalysisFinitePointerSuccessorTest extends IntegrationTest {
  @TempDir Path temporary;

  private final class Fixture implements AutoCloseable {
    final Object owner = new Object();
    final ProgramDB p = new ProgramDB("N8 singleton pointer", getLanguage(), getLanguage().getDefaultCompilerSpec(), owner);
    final byte[] bytes = new byte[0x10000];
    final Cartridge cartridge;
    final int entryLength;

    Fixture(String entry, String target) throws Exception {
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      bytes[0x200] = 0;
      bytes[0x201] = 0x41;
      byte[] code = HexFormat.of().parseHex(entry);
      byte[] body = HexFormat.of().parseHex(target);
      entryLength = code.length;
      System.arraycopy(code, 0, bytes, 0x150, code.length);
      // File-bank oracle: bank 1 CPU 4100 is file 4100, bank 2 CPU 4100 is file 8100.
      System.arraycopy(body, 0, bytes, 0x4100, body.length);
      System.arraycopy(body, 0, bytes, 0x8100, body.length);
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(p, provider, "CARTRIDGE", "AUTO", GameBoyKind.GB, true, true,
            TaskMonitor.DUMMY, new MessageLog());
      }
      cartridge = ProgramMapping.cartridge(p);
      edit(() -> {
        define("0150", code.length);
        if (body.length > 0) {
          define("rom1::4100", body.length);
          define("rom2::4100", body.length);
        }
      });
    }

    Address at(String address) { return Objects.requireNonNull(ProgramMapping.staticAddress(p, address)); }
    void define(String address, int length) throws Exception {
      var start = at(address);
      Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null)
          .disassemble(start, new AddressSet(start, start.add(length - 1)));
    }
    void edit(Checked action) throws Exception {
      int tx = p.startTransaction("N8 fixture");
      try { action.run(); } finally { p.endTransaction(tx, true); }
    }
    BankAnalysis.FetchPreview preview(MapperState mapper) throws Exception {
      return BankAnalysis.previewFetch(p, at("0150"), mapper,
          AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY);
    }
    @Override public void close() { p.release(owner); }
  }
  @FunctionalInterface private interface Checked { void run() throws Exception; }

  @Test void compiledE9IsOneArchitecturalHlBranch() throws Exception {
    try (var f = new Fixture("210041e9", "c9")) {
      var instruction = f.p.getListing().getInstructionAt(f.at("0153"));
      var raw = instruction.getPcode(false);
      System.out.println("N8 compiled E9 raw p-code: " + Arrays.toString(raw));
      assertEquals(1, raw.length, Arrays.toString(raw));
      assertEquals(PcodeOp.BRANCHIND, raw[0].getOpcode(), Arrays.toString(raw));
      assertEquals(1, raw[0].getNumInputs());
      assertNull(raw[0].getOutput());
      assertEquals(f.p.getRegister("HL").getAddress(), raw[0].getInput(0).getAddress());
      assertEquals(2, raw[0].getInput(0).getSize());
      assertNull(instruction.getFallThrough());
      assertEquals(FlowOverride.NONE, instruction.getFlowOverride());
    }
  }

  private static BankAnalysis.FetchStep jump(BankAnalysis.FetchPreview preview, int cpu) {
    return preview.steps().stream().filter(step -> step.cpu() == cpu).findFirst().orElseThrow();
  }

  private void proves(Fixture f, BankAnalysis.FetchPreview preview, int cpu, int bank) throws Exception {
    var expected = new MapperState.Physical("ROM", bank, 0x100);
    var target = f.at("rom" + bank + "::4100");
    assertEquals(List.of(expected), ProgramMapping.staticToPhysical(f.p, target));
    var step = jump(preview, cpu);
    var scalar = ScalarAccess.resolve(f.cartridge, step.outgoing(),
        new ScalarAccess.Request(0x4100, ScalarAccess.Kind.FETCH, 1, 0, step.source(), 0, 0, null));
    assertEquals(expected, scalar.resolution().orElseThrow().physical());
    assertEquals(List.of(target.toString()), step.successors());
    assertTrue(preview.result().findings().stream().anyMatch(finding -> finding.source().equals(step.source())
        && finding.targets().equals(List.of(target.toString()))
        && finding.confidence() == AnalysisResult.Confidence.PROVEN));
    assertTrue(preview.steps().stream().anyMatch(visited -> visited.source().equals(target.toString())));
    assertNull(f.p.getFunctionManager().getFunctionAt(target), "Successor proof does not discover Functions");
  }

  private static void refuses(BankAnalysis.FetchPreview preview, int cpu) {
    var step = jump(preview, cpu);
    assertTrue(step.successors().isEmpty());
    assertTrue(preview.result().findings().stream().anyMatch(finding -> finding.source().equals(step.source())
        && finding.targets().isEmpty() && !finding.reason().isBlank()));
    assertFalse(preview.steps().stream().anyMatch(visited -> visited.source().contains("::4100")));
  }

  @Test void exactHlEstablishesPhysicalSuccessorWithoutFallthroughOrFunction() throws Exception {
    try (var f = new Fixture("210041e9", "c9")) {
      proves(f, f.preview(MapperState.reset()), 0x153, 1);
      assertNull(f.p.getListing().getInstructionAt(f.at("0154")));
    }
  }

  @Test void immutableRomByteLoadsComposeIntoHlAndBankQualifiedSuccessor() throws Exception {
    // LD DE,0200; LD A,(DE); LD L,A; INC DE; LD A,(DE); LD H,A; JP HL.
    // The current evaluator's actual LOAD operations consume file bytes 00,41.
    try (var f = new Fixture("1100021a6f131a67e9", "c9")) {
      assertEquals(0, Byte.toUnsignedInt(f.bytes[0x200]));
      assertEquals(0x41, Byte.toUnsignedInt(f.bytes[0x201]));
      var first = f.p.getListing().getInstructionAt(f.at("0153")).getPcode(false);
      assertTrue(Arrays.stream(first).anyMatch(op -> op.getOpcode() == PcodeOp.LOAD));
      var preview = f.preview(MapperState.reset());
      proves(f, preview, 0x158, 1);
      assertTrue(preview.result().findings().stream().anyMatch(finding -> finding.access().equals("read")
          && finding.targets().equals(List.of("0200"))));
      assertTrue(preview.result().findings().stream().anyMatch(finding -> finding.access().equals("read")
          && finding.targets().equals(List.of("0201"))));
    }
  }

  @Test void sameCpuPointerWithDifferentMapperBanksHasDifferentPhysicalIdentity() throws Exception {
    try (var one = new Fixture("3e01ea0020210041e9", "c9");
        var two = new Fixture("3e02ea0020210041e9", "c9")) {
      proves(one, one.preview(MapperState.reset()), 0x158, 1);
      proves(two, two.preview(MapperState.reset()), 0x158, 2);
    }
  }

  @Test void unknownPartialAndBankDependentUnknownPointersRefuseSuccessor() throws Exception {
    try (var unknown = new Fixture("e9", "c9");
        var partial = new Fixture("2600e9", "c9");
        var mapper = new Fixture("210041e9", "c9")) {
      refuses(unknown.preview(MapperState.reset()), 0x150);
      refuses(partial.preview(MapperState.reset()), 0x152);
      refuses(mapper.preview(null), 0x153);
    }
  }

  @Test void ramDeviceAndOutsideRomExecutionWindowCannotAuthorizeTarget() throws Exception {
    for (String pointer : List.of("00c1", "00ff", "0080", "ffff")) {
      try (var f = new Fixture("21" + pointer + "e9", "c9")) {
        refuses(f.preview(MapperState.reset()), 0x153);
      }
    }
  }

  @Test void writableVolatileUnreadableAndNonexecutingRomCannotAuthorizeTarget() throws Exception {
    for (String permission : List.of("write", "volatile", "read", "execute")) {
      try (var f = new Fixture("210041e9", "c9")) {
        f.edit(() -> {
          var block = f.p.getMemory().getBlock(f.at("rom1::4100"));
          switch (permission) {
            case "write" -> block.setWrite(true);
            case "volatile" -> block.setVolatile(true);
            case "read" -> block.setRead(false);
            case "execute" -> block.setExecute(false);
            default -> throw new AssertionError(permission);
          }
        });
        refuses(f.preview(MapperState.reset()), 0x153);
      }
    }
  }

  @Test void undefinedTargetRemainsUndefinedAndHasNoSuccessor() throws Exception {
    try (var f = new Fixture("210041e9", "")) {
      assertNull(f.p.getListing().getInstructionAt(f.at("rom1::4100")));
      refuses(f.preview(MapperState.reset()), 0x153);
      assertNull(f.p.getListing().getInstructionAt(f.at("rom1::4100")));
    }
  }

  @Test void generatedCanonicalTargetCannotSupplyPhysicalAuthority() throws Exception {
    for (String prefix : List.of(SoftwareCallExecutionView.PREFIX, OrdinaryEntryAccess.PREFIX)) {
      try (var f = new Fixture("210041e9", "c9")) {
        f.edit(() -> f.p.getMemory().getBlock(f.at("rom1::4100")).setName(prefix + "snapshot"));
        refuses(f.preview(MapperState.reset()), 0x153);
      }
    }
  }

  @Test void flowOverridePreservesRawJumpWithoutSyntheticCallProof() throws Exception {
    for (var override : List.of(FlowOverride.CALL, FlowOverride.CALL_RETURN, FlowOverride.RETURN)) {
      try (var f = new Fixture("210041e9", "c9")) {
        f.edit(() -> f.p.getListing().getInstructionAt(f.at("0153")).setFlowOverride(override));
        var result = f.preview(MapperState.reset());
        assertTrue(result.steps().stream().anyMatch(step -> step.source().equals("rom1::4100")));
        assertTrue(result.result().findings().stream().anyMatch(finding -> finding.source().equals("0153")
            && finding.access().equals("jump") && finding.targets().contains("rom1::4100")));
        assertTrue(result.result().ordinaryCallProofs().isEmpty());
      }
    }
  }

  @Test void nonarchitecturalBranchindAndCallindRawFormsRemainUnsupported() throws Exception {
    try (var f = new Fixture("210041e9", "c9")) {
      var instruction = f.p.getListing().getInstructionAt(f.at("0153"));
      var hl = new Varnode(f.p.getRegister("HL").getAddress(), 2);
      var de = new Varnode(f.p.getRegister("DE").getAddress(), 2);
      assertTrue(BankAnalysis.exactHlJump(f.p, instruction, instruction.getPcode(false)));
      for (int opcode : List.of(PcodeOp.CALLIND, PcodeOp.RETURN)) {
        var op = new PcodeOp(instruction.getAddress(), 0, opcode, new Varnode[] {hl}, null);
        assertFalse(BankAnalysis.exactHlJump(f.p, instruction, new PcodeOp[] {op}));
      }
      var other = new PcodeOp(instruction.getAddress(), 0, PcodeOp.BRANCHIND, new Varnode[] {de}, null);
      assertFalse(BankAnalysis.exactHlJump(f.p, instruction, new PcodeOp[] {other}));
      var wrongWidth = new PcodeOp(instruction.getAddress(), 0, PcodeOp.BRANCHIND,
          new Varnode[] {new Varnode(hl.getAddress(), 1)}, null);
      assertFalse(BankAnalysis.exactHlJump(f.p, instruction, new PcodeOp[] {wrongWidth}));
      for (int width : List.of(4, 9)) {
        var oversized = new PcodeOp(instruction.getAddress(), 0, PcodeOp.BRANCHIND,
            new Varnode[] {new Varnode(hl.getAddress(), width)}, null);
        assertFalse(BankAnalysis.exactHlJump(f.p, instruction, new PcodeOp[] {oversized}));
      }
      var branch = instruction.getPcode(false)[0];
      assertFalse(BankAnalysis.exactHlJump(f.p, instruction, new PcodeOp[] {other, branch}));
      assertFalse(BankAnalysis.exactHlJump(f.p,
          f.p.getListing().getInstructionAt(f.at("0150")), new PcodeOp[] {branch}));
    }
  }

  private MemoryBlock independentSource(Fixture f, int targetByte) throws Exception {
    return independentSource(f, 0x4000, 0x100, targetByte);
  }

  private MemoryBlock independentSource(Fixture f, int base, int byteOffset, int value) throws Exception {
    MemoryBlock[] block = new MemoryBlock[1];
    f.edit(() -> {
      byte[] bank = Arrays.copyOfRange(f.bytes, 0x4000, 0x8000);
      bank[byteOffset] = (byte) value;
      block[0] = f.p.getMemory().createInitializedBlock("second_rom_source", f.at(String.format("%04x", base)),
          new java.io.ByteArrayInputStream(bank), bank.length, TaskMonitor.DUMMY, true);
      ProgramMapping.anchor(f.p, block[0], "ROM", 1);
      block[0].setRead(true);
      block[0].setWrite(false);
      block[0].setExecute(true);
    });
    return block[0];
  }

  @Test void conflictingEligiblePhysicalSourcesRefuseWithoutChoosingAnAlias() throws Exception {
    try (var f = new Fixture("210041e9", "c9")) {
      var original = f.preview(MapperState.reset()).result();
      var second = independentSource(f, 0x5000, 0x100, 0x00);
      var physical = new MapperState.Physical("ROM", 1, 0x100);
      assertEquals(List.of(physical), ProgramMapping.staticToPhysical(f.p, f.at("rom1::4100")));
      assertEquals(List.of(physical), ProgramMapping.staticToPhysical(f.p, second.getStart().add(0x100)));
      assertEquals(0xc9, Byte.toUnsignedInt(f.p.getMemory().getByte(f.at("rom1::4100"))));
      assertEquals(0, Byte.toUnsignedInt(f.p.getMemory().getByte(second.getStart().add(0x100))));
      assertEquals(List.of(f.at("rom1::4100")), ProgramMapping.physicalToStatic(f.p, physical).stream()
          .filter(address -> address.getOffset() == 0x4100).toList(), "Only one CPU-qualified execution view");
      assertThrows(IllegalStateException.class,
          () -> ProgramFingerprint.requireCurrent(f.p, original, TaskMonitor.DUMMY));
      refuses(f.preview(MapperState.reset()), 0x153);
    }
  }

  @Test void anExecutionAliasDoesNotMaskIneligibleCanonicalStorage() throws Exception {
    try (var f = new Fixture("210041e9", "c9")) {
      f.edit(() -> {
        var alias = f.p.getMemory().createByteMappedBlock("execution_alias", f.at("4100"),
            f.at("rom1::4100"), 1, true);
        alias.setExecute(true);
        alias.setRead(true);
        alias.setWrite(false);
        f.p.getMemory().getBlock(f.at("rom1::4100")).setWrite(true);
      });
      refuses(f.preview(MapperState.reset()), 0x153);
    }
  }

  @Test void boundaryInstructionWithNonRomAndWrongPhysicalSuffixIsRefused() throws Exception {
    try (var f = new Fixture("21ff7fe9", "c9")) {
      f.edit(() -> {
        var start = f.at("rom1::7fff");
        var vram = f.p.getMemory().getBlock(f.at("8000"));
        f.p.getMemory().convertToInitialized(vram, (byte) 0);
        f.p.getMemory().setByte(start, (byte) 0xc3);
        f.p.getMemory().createByteMappedBlock("suffix0", start.getAddressSpace().getAddressInThisSpaceOnly(0x8000),
            vram.getStart(), 1, false).setExecute(true);
        f.p.getMemory().createByteMappedBlock("suffix1", start.getAddressSpace().getAddressInThisSpaceOnly(0x8001),
            f.at("rom2::4001"), 1, false).setExecute(true);
        f.define("rom1::7fff", 3);
      });
      var instruction = f.p.getListing().getInstructionAt(f.at("rom1::7fff"));
      assertArrayEquals(new byte[] {(byte) 0xc3, 0, 0}, instruction.getBytes());
      assertEquals(List.of(new MapperState.Physical("ROM", 2, 1)),
          ProgramMapping.staticToPhysical(f.p, instruction.getAddress().add(2)));
      var preview = f.preview(MapperState.reset());
      refuses(preview, 0x153);
      assertTrue(preview.steps().stream().noneMatch(step -> step.source().equals("rom1::7fff")));
    }
  }

  private static List<Integer> stored(BankAnalysis.FetchPreview preview, int cpu) {
    return preview.steps().stream().flatMap(step -> step.writes().stream())
        .filter(write -> write.cpu() == cpu).map(BankAnalysis.WriteTransition::value).toList();
  }

  @Test void pointerTransitionPreservesMapperRegistersFlagsSpAndPhysicalRamFacts() throws Exception {
    // SP=D000; BC=0220; PUSH BC/POP AF -> A=02,F=20; write RAM C100=03;
    // HL=4100 and A=02 before JP. Target observes A, RAM, F and SP independently.
    try (var f = new Fixture("3100d0012002c5f11100c13e03122100413e02e9",
        "ea10c11aea11c1f5c179ea12c10820c1c9")) {
      var preview = f.preview(MapperState.reset());
      var transition = jump(preview, 0x163);
      var target = preview.steps().stream().filter(step -> step.source().equals("rom1::4100"))
          .findFirst().orElseThrow();
      assertEquals(transition.incoming(), transition.outgoing());
      assertEquals(transition.outgoing(), target.incoming());
      assertTrue(transition.writes().isEmpty(), "JP has no stack or memory writes");
      assertEquals(List.of(2), stored(preview, 0xc110));
      assertEquals(List.of(3), stored(preview, 0xc111));
      assertEquals(List.of(0x20), stored(preview, 0xc112));
      assertEquals(List.of(0), stored(preview, 0xc120));
      assertEquals(List.of(0xd0), stored(preview, 0xc121));
      assertEquals(List.of("rom1::4100"), transition.successors());
    }
  }

  @Test void activeCallFrameSurvivesJumpAndRetWithoutNewFrame() throws Exception {
    try (var f = new Fixture("3100d0cd0003ea0020c30040", "3e02c9")) {
      f.edit(() -> {
        f.p.getMemory().setBytes(f.at("0300"), HexFormat.of().parseHex("210041e9"));
        f.define("0300", 4);
      });
      var preview = f.preview(MapperState.reset());
      proves(f, preview, 0x303, 1);
      assertTrue(jump(preview, 0x303).writes().isEmpty());
      assertEquals(List.of(2), stored(preview, 0x2000));
      assertEquals(List.of(1), stored(preview, 0xcfff));
      assertEquals(List.of(0x56), stored(preview, 0xcffe));
      assertTrue(preview.steps().stream().anyMatch(step -> step.source().equals("0156")));
      assertTrue(preview.result().findings().stream().anyMatch(finding -> finding.source().equals("0159")
          && finding.targets().equals(List.of("rom2::4000"))));
    }
  }

  @Test void existingWorklistHandlesSingletonPointerCycleWithoutNewGraphOrBudget() throws Exception {
    try (var f = new Fixture("210041e9", "e9")) {
      var preview = f.preview(MapperState.reset());
      proves(f, preview, 0x153, 1);
      assertEquals(List.of("rom1::4100"), jump(preview, 0x4100).successors());
      assertTrue(preview.result().exploredStates() < 10);
      assertNotEquals(AnalysisResult.Completion.STATE_LIMIT, preview.result().completion());
    }
  }

  @Test void outOfDomainPointerIsRefusedRatherThanTruncated() throws Exception {
    try (var f = new Fixture("210041e9", "c9")) {
      var mapper = MapperKnowledge.from(MapperState.reset());
      assertNull(BankAnalysis.exactPointerTarget(f.p, f.cartridge, mapper, -1));
      assertNull(BankAnalysis.exactPointerTarget(f.p, f.cartridge, mapper, 0x14100));
      assertEquals(f.at("rom1::4100"), BankAnalysis.exactPointerTarget(f.p, f.cartridge, mapper, 0x4100));
    }
  }

  @Test void savedReopenedSingletonResultIsCurrentAndRejectsN7Engine() throws Exception {
    try (var f = new Fixture("1100021a6f131a67e9", "c9")) {
      var original = f.preview(MapperState.reset()).result();
      assertEquals(4, original.schemaVersion());
      BankAnalysis.apply(f.p, original, TaskMonitor.DUMMY);
      var packed = temporary.resolve("n8.gzf").toFile();
      f.p.saveToPackedFile(packed, TaskMonitor.DUMMY);
      var database = PackedDatabase.getPackedDatabase(packed, true, TaskMonitor.DUMMY);
      Object owner = new Object();
      ProgramDB reopened = null;
      try {
        reopened = new ProgramDB(database.open(TaskMonitor.DUMMY), OpenMode.IMMUTABLE, TaskMonitor.DUMMY, owner);
        var stored = AnalysisResult.read(reopened.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", null));
        assertEquals(original, stored);
        ProgramFingerprint.requireCurrent(reopened, stored, TaskMonitor.DUMMY);
        var recomputed = BankAnalysis.previewFetch(reopened, ProgramMapping.staticAddress(reopened, "0150"),
            MapperState.reset(), AnalysisResult.Configuration.DEFAULT, TaskMonitor.DUMMY).result();
        assertEquals(stored, recomputed);
        var staleJson = ProgramMapping.JSON.toJson(stored)
            .replace(AnalysisResult.ENGINE_VERSION, "20260930-n7-sequential-returning-call-1");
        assertThrows(IllegalArgumentException.class, () -> AnalysisResult.read(staleJson));
        var old = ProgramMapping.JSON.fromJson(staleJson, AnalysisResult.class);
        var program = reopened;
        assertThrows(IllegalStateException.class, () -> ProgramFingerprint.requireCurrent(program, old, TaskMonitor.DUMMY));
      } finally {
        if (reopened != null) reopened.release(owner);
        database.dispose();
      }
    }
  }

  @Test void agreeingIndependentExecutableViewsRemainAmbiguous() throws Exception {
    try (var f = new Fixture("210041e9", "c9")) {
      var second = independentSource(f, 0xc9);
      f.edit(() -> {
        var entry = second.getStart().add(0x100);
        Disassembler.getDisassembler(f.p, TaskMonitor.DUMMY, null)
            .disassemble(entry, new AddressSet(entry));
      });
      assertEquals(List.of(new MapperState.Physical("ROM", 1, 0x100)),
          ProgramMapping.staticToPhysical(f.p, second.getStart().add(0x100)));
      refuses(f.preview(MapperState.reset()), 0x153);
    }
  }

  @Test void unresolvedActiveCalleeAlternativeCannotBecomeACompleteReturn() throws Exception {
    // Unknown Z: RET path and unknown-HL JP path must both be accounted for.
    try (var f = new Fixture("3100d0cd0003ea0020c30040", "c9")) {
      f.edit(() -> {
        f.p.getMemory().setBytes(f.at("0300"), HexFormat.of().parseHex("28033e02c9e9"));
        f.define("0300", 6);
      });
      var preview = f.preview(MapperState.reset());
      assertFalse(stored(preview, 0x2000).isEmpty());
      assertTrue(stored(preview, 0x2000).stream().allMatch(Objects::isNull));
      refuses(preview, 0x305);
    }
  }

  @Test void activeCalleeSingletonCycleCannotAuthorizeCallerContinuation() throws Exception {
    try (var f = new Fixture("3100d0cd0003ea0020c30040", "e9")) {
      f.edit(() -> {
        f.p.getMemory().setBytes(f.at("0300"), HexFormat.of().parseHex("210041e9"));
        f.define("0300", 4);
      });
      var preview = f.preview(MapperState.reset());
      assertFalse(stored(preview, 0x2000).isEmpty());
      assertTrue(stored(preview, 0x2000).stream().allMatch(Objects::isNull));
      assertTrue(preview.result().exploredStates() < 20);
      assertNotEquals(AnalysisResult.Completion.STATE_LIMIT, preview.result().completion());
    }
  }

  @Test void laterRomInstructionByteRequiresAgreementEvenWhenFirstBytesAgree() throws Exception {
    try (var f = new Fixture("210041e9", "c30003")) {
      // The second ROM source starts at CPU 5000 but is anchored at physical bank-1 offset 0.
      // It supplies agreement evidence at 5100 without becoming a second CPU-4100 execution view.
      var second = independentSource(f, 0x5000, 0x102, 0x03);
      var instruction = f.p.getListing().getInstructionAt(f.at("rom1::4100"));
      assertArrayEquals(new byte[] {(byte) 0xc3, 0, 3}, instruction.getBytes());
      for (int byteIndex = 0; byteIndex < 3; byteIndex++) {
        var expected = new MapperState.Physical("ROM", 1, 0x100 + byteIndex);
        var canonical = instruction.getAddress().add(byteIndex);
        var alternate = second.getStart().add(0x100 + byteIndex);
        var scalar = ScalarAccess.resolve(f.cartridge, MapperKnowledge.from(MapperState.reset()),
            new ScalarAccess.Request(0x4100 + byteIndex, ScalarAccess.Kind.FETCH, 3, byteIndex,
                "rom1::4100", 0, 0, null));
        assertEquals(expected, scalar.resolution().orElseThrow().physical());
        assertEquals(List.of(expected), ProgramMapping.staticToPhysical(f.p, canonical));
        assertEquals(List.of(expected), ProgramMapping.staticToPhysical(f.p, alternate));
        assertEquals(f.p.getMemory().getByte(canonical), f.p.getMemory().getByte(alternate));
      }
      var control = f.preview(MapperState.reset());
      proves(f, control, 0x153, 1);
      f.edit(() -> f.p.getMemory().setByte(second.getStart().add(0x102), (byte) 4));
      assertEquals(f.p.getMemory().getByte(instruction.getAddress()), f.p.getMemory().getByte(second.getStart().add(0x100)));
      assertEquals(f.p.getMemory().getByte(instruction.getAddress().add(1)), f.p.getMemory().getByte(second.getStart().add(0x101)));
      assertNotEquals(f.p.getMemory().getByte(instruction.getAddress().add(2)), f.p.getMemory().getByte(second.getStart().add(0x102)));
      assertThrows(IllegalStateException.class,
          () -> ProgramFingerprint.requireCurrent(f.p, control.result(), TaskMonitor.DUMMY));
      refuses(f.preview(MapperState.reset()), 0x153);
    }
  }

  @Test void consumedTargetDependenciesInvalidateSavedPointerProofs() throws Exception {
    for (String dependency : List.of("execute", "volatile", "byte", "generated-name")) {
      try (var f = new Fixture("210041e9", "c9")) {
        var original = f.preview(MapperState.reset()).result();
        ProgramFingerprint.requireCurrent(f.p, original, TaskMonitor.DUMMY);
        f.edit(() -> {
          var block = f.p.getMemory().getBlock(f.at("rom1::4100"));
          switch (dependency) {
            case "execute" -> block.setExecute(false);
            case "volatile" -> block.setVolatile(true);
            case "byte" -> {
              var address = f.at("rom1::4100");
              f.p.getListing().clearCodeUnits(address, address, false);
              f.p.getMemory().setByte(address, (byte) 0);
              f.define("rom1::4100", 1);
            }
            case "generated-name" -> block.setName(SoftwareCallExecutionView.PREFIX + "snapshot");
            default -> throw new AssertionError(dependency);
          }
        });
        assertThrows(IllegalStateException.class,
            () -> ProgramFingerprint.requireCurrent(f.p, original, TaskMonitor.DUMMY));
      }
    }
  }
}
