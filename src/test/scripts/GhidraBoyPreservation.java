// Installed-extension smoke and persisted annotation preservation fixture.
// @category Game Boy Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;

public class GhidraBoyPreservation extends GhidraScript {
  @Override
  public void run() throws Exception {
    if (getScriptArgs()[0].equals("create")) {
      var lang = getLanguage(new LanguageID("SM83:LE:16:default"));
      var p = new ProgramDB("preserved", lang, lang.getDefaultCompilerSpec(), this);
      int tx = p.startTransaction("Legacy annotations");
      try {
        byte[] rom = new byte[0x10000];
        rom[0x147] = (byte) (getScriptArgs().length > 1 && getScriptArgs()[1].equals("mbc5") ? 0x19 : 3);
        rom[0x148] = 1;
        rom[0x149] = 3;
        rom[0x150] = 0x3e;
        rom[0x151] = 0x12;
        rom[0x152] = (byte) 0xc9;
        var as = p.getAddressFactory().getDefaultAddressSpace();
        try (var provider = new ByteArrayProvider(rom)) {
          var file = MemoryBlockUtils.createFileBytes(p, provider, monitor);
          p.getMemory().createInitializedBlock("rom0", as.getAddress(0), file, 0, 0x4000, false);
          for (int bank = 1; bank < 4; bank++)
            p.getMemory()
                .createInitializedBlock(
                    "rom" + bank, as.getAddress(0x4000), file, bank * 0x4000, 0x4000, true);
        }
        GameBoyUtils.addHardwareBlocks(p, GameBoyKind.CGB, new MessageLog());
        var a = as.getAddress(0x150);
        p.getSymbolTable().createLabel(a, "user_label", SourceType.USER_DEFINED);
        p.getListing().setComment(a, CodeUnit.EOL_COMMENT, "keep comment");
        p.getBookmarkManager().setBookmark(a, "Note", "student", "keep bookmark");
        Disassembler.getDisassembler(p, monitor, null).disassemble(a, new AddressSet(a, a.add(2)));
        var f =
            p.getFunctionManager()
                .createFunction(
                    "user_function", a, new AddressSet(a, a.add(2)), SourceType.USER_DEFINED);
        f.setCustomVariableStorage(true);
        f.setReturn(
            ByteDataType.dataType,
            new VariableStorage(p, p.getRegister("A")),
            SourceType.USER_DEFINED);
        p.getListing().getInstructionAt(a).setFallThrough(a.add(3));
        var type = new StructureDataType("UserType", 0);
        type.add(ByteDataType.dataType, "owned", null);
        p.getDataTypeManager().addDataType(type, DataTypeConflictHandler.KEEP_HANDLER);
        var bank = p.getMemory().getBlock("rom2");
        bank.setName("student bank");
        p.getMemory().setByte(bank.getStart().add(0x12), (byte) 0x5a);
        p.endTransaction(tx, true);
        tx = -1;
        state.getProject().getProjectData().getRootFolder().createFile("preserved", p, monitor);
        println("PRESERVATION_CREATED old language annotations");
      } finally {
        if (tx != -1) p.endTransaction(tx, false);
        p.release(this);
      }
    } else {
      var p = currentProgram;
      var a = toAddr(0x150);
      require(
          p.getFunctionManager().getFunctionAt(a).getName().equals("user_function"), "function");
      require(p.getFunctionManager().getFunctionAt(a).hasCustomVariableStorage(), "custom storage");
      require(
          p.getFunctionManager().getFunctionAt(a).getReturn().getRegister().getName().equals("A"),
          "return storage");
      require(p.getListing().getComment(CodeUnit.EOL_COMMENT, a).equals("keep comment"), "comment");
      require(p.getBookmarkManager().getBookmark(a, "Note", "student") != null, "bookmark");
      require(p.getDataTypeManager().getDataType("/UserType") != null, "type");
      require(p.getListing().getInstructionAt(a).isFallThroughOverridden(), "flow override");
      require(p.getSymbolTable().getSymbols("user_label").hasNext(), "label");
      LegacyEnhancement.enhance(p, "AUTO", monitor);
      LegacyEnhancement.enhance(p, "AUTO", monitor);
      var target = ProgramMapping.fileToStatic(p, 0x8012).get(0);
      require(p.getMemory().getByte(target) == 0x5a, "patch");
      require(p.getMemory().getBlock(target).getName().equals("student bank"), "rename");
      require(ProgramMapping.exportBytes(p, true, false, monitor)[0x8012] == 0x5a, "export");
      // Selective disassembly leaves defined code, marked data, and user function intact.
      Disassembler.getDisassembler(p, monitor, null).disassemble(a, new AddressSet(a, a.add(2)));
      require(p.getFunctionManager().getFunctionAt(a).getBody().getNumAddresses() == 3, "body");
      println("PRESERVATION_VERIFIED reopen enhance reanalysis annotations");
    }
  }

  private void require(boolean value, String what) {
    if (!value) throw new AssertionError(what);
  }
}
