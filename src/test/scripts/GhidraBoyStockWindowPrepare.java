// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.OrdinaryEntryAccess;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.symbol.SourceType;

/** Setup only: no native request; the measured consumer is the normal tool. */
public class GhidraBoyStockWindowPrepare extends GhidraScript {
  @Override public void run() throws Exception {
    if (!currentProgram.getLanguageID().toString().equals("SM83:LE:16:default") ||
        currentProgram.getLanguage().getVersion() != 2) throw new IllegalStateException("Requires language 2");
    var body = new AddressSet(toAddr(0x150), toAddr(0x161));
    Disassembler.getDisassembler(currentProgram, monitor, null).disassemble(toAddr(0x150), body);
    var f = getFunctionAt(toAddr(0x150));
    if (f == null) f = currentProgram.getFunctionManager().createFunction("w2e_f1234", toAddr(0x150), body, SourceType.ANALYSIS);
    if (!f.getBody().equals(body)) throw new IllegalStateException("Unexpected body");
    OrdinaryEntryAccess.install(currentProgram, OrdinaryEntryAccess.preview(currentProgram, f, monitor), monitor);
    // Suppress the normal first-open analysis prompt for this explicitly prepared fixture.
    ghidra.program.util.GhidraProgramUtilities.markProgramAnalyzed(currentProgram);
    println("G1_READINESS_FIXTURE_PREPARED_NOT_GUI_ACCEPTANCE");
  }
}
