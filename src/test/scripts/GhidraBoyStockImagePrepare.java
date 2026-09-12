// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import java.util.*;

/** Only constructs the existing tiny I1 fixture; no decompiler requests. */
public class GhidraBoyStockImagePrepare extends GhidraBoyMemoryImages {
  @Override public void run() throws Exception {
    if(currentProgram.getLanguage().getVersion()!=2)throw new IllegalStateException("Requires current language");
    var block=currentProgram.getMemory().getBlock(toAddr(0xc000));
    if(!block.isInitialized())currentProgram.getMemory().convertToInitialized(block,(byte)0);
    var distinct=currentProgram.getMemory().createInitializedBlock("w4_distinct",toAddr(0xc060),1,(byte)0x9a,monitor,true);
    distinct.setRead(true);distinct.setWrite(true);distinct.setExecute(false);
    var image=ExecutableImages.establish(currentProgram,toAddr(0x300),0xc200,HexFormat.of().parseHex("3e31ea74c0c9"),"explicit G1 I1 fixture setup",monitor);
    var source=getFunctionAt(currentProgram.getAddressFactory().getAddress(image.entry()));
    PredicatedCalls.install(currentProgram,preview(source,image.generation()),monitor);
    ghidra.program.util.GhidraProgramUtilities.markProgramAnalyzed(currentProgram);
    println("G1_IMAGE_FIXTURE_PREPARED_NOT_GUI_ACCEPTANCE");
  }
}
