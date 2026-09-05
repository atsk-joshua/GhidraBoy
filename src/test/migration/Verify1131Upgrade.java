// Verify a COPY of the actual 11.3.1 database under maintained Ghidra 12.1.3.
// @category Game Boy Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;

public class Verify1131Upgrade extends GhidraScript {
  private void check(boolean ok, String what) {
    if (!ok) throw new AssertionError(what);
  }

  private void annotations() {
    var p = currentProgram;
    var a = toAddr(0x150);
    var f = p.getFunctionManager().getFunctionAt(a);
    check(
        f != null && f.getName().equals("user_function") && f.getBody().getNumAddresses() == 3,
        "function/body");
    check(
        f.hasCustomVariableStorage() && f.getReturn().getRegister().getName().equals("A"),
        "custom storage");
    check(
        "keep comment 1131".equals(p.getListing().getComment(CodeUnit.EOL_COMMENT, a)), "comment");
    check(p.getBookmarkManager().getBookmark(a, "Note", "student") != null, "bookmark");
    check(p.getDataTypeManager().getDataType("/UserType1131") != null, "type");
    check(p.getListing().getInstructionAt(a).isFallThroughOverridden(), "fallthrough override");
    var labels = p.getSymbolTable().getSymbols("user_label");
    boolean namespace = false;
    while (labels.hasNext())
      if (labels.next().getName(true).equals("UserNamespace::user_label")) namespace = true;
    check(namespace, "namespaced label");
    var block = p.getMemory().getBlock("student bank 1131");
    try {
      check(
          block != null && p.getMemory().getByte(block.getStart().add(0x12)) == 0x5a,
          "patch/renamed overlay");
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public void run() throws Exception {
    check(ghidra.framework.Application.getApplicationVersion().equals("12.1.3"), "12.1.3 required");
    annotations();
    LegacyEnhancement.enhance(currentProgram, "AUTO", monitor);
    check(
        ProgramMapping.cartridge(currentProgram).hardware().equals("GB"),
        "historical GB override must survive CGB header");
    LegacyEnhancement.enhance(currentProgram, "AUTO", monitor);
    annotations();
    var manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
    manager.reAnalyzeAll(new AddressSet(toAddr(0x150), toAddr(0x152)));
    manager.startAnalysis(monitor);
    annotations();
    var emu = new EmulatorHelper(currentProgram);
    try {
      emu.writeRegister("PC", 0x150);
      emu.writeRegister("A", 255);
      emu.writeRegister("F", 16);
      check(emu.step(monitor), emu.getLastError());
      check(
          emu.readRegister("A").intValue() == 0 && (emu.readRegister("F").intValue() & 16) != 0,
          "updated ADC p-code");
    } finally {
      emu.dispose();
    }
    check(
        ProgramMapping.exportBytes(currentProgram, true, false, monitor)[0x8012] == 0x5a,
        "export patch");
    println("ACTUAL_1131_UPGRADE_REANALYSIS_AND_NEW_ADC_PASS");
  }
}
