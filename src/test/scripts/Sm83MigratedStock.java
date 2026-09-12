// Separate disposable post-preservation variant: ordinary native use and NEW public authority.
// @category Game Boy Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;

public class Sm83MigratedStock extends GhidraScript {
  @Override public void run() throws Exception {
    var p=currentProgram;var results=new ArrayList<Object>();var d=new DecompInterface();
    try {
      if(!d.openProgram(p))throw new AssertionError(d.getLastMessage());
      var canonical=d.decompileFunction(getFunctionAt(toAddr(0x150)),30,monitor);
      if(!canonical.decompileCompleted()||canonical.getHighFunction()==null)throw new AssertionError(canonical.getErrorMessage());
      results.add(Map.of("ordinaryMigratedC",canonical.getDecompiledFunction().getC()));
      LegacyEnhancement.enhance(p,"AUTO",monitor);
      byte[] bytes={(byte)0xe6,1,0x28,3,0x3e,0x22,(byte)0xc9,0x3e,0x11,(byte)0xc9};
      p.getMemory().setBytes(toAddr(0x500),bytes);disassemble(toAddr(0x500));
      var f=p.getFunctionManager().createFunction("new_requested_conditional",toAddr(0x500),new AddressSet(toAddr(0x500),toAddr(0x509)),SourceType.USER_DEFINED);
      var proof=PredicatedCalls.preview(p,f,PredicatedCallGraph.Limits.PRIMARY,monitor);
      if(!proof.complete())throw new AssertionError(proof.frontier().toString());
      var root=PredicatedCalls.install(p,proof,monitor);
      var record=p.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(root.toString(),null);
      var result=d.decompileFunction(getFunctionAt(root),30,monitor);
      if(!result.decompileCompleted()||result.getHighFunction()==null)throw new AssertionError(result.getErrorMessage());
      results.add(Map.of("newAuthority",record,"entry",root.toString(),"c",result.getDecompiledFunction().getC()));
      p.getListing().clearCodeUnits(toAddr(0x504),toAddr(0x505),false);
      p.getMemory().setByte(toAddr(0x505),(byte)0x33);
      disassemble(toAddr(0x504));
      var stale=d.decompileFunction(getFunctionAt(root),30,monitor);
      if(stale.decompileCompleted()||stale.getHighFunction()!=null||stale.getDecompiledFunction()!=null)throw new AssertionError("Stale request did not refuse");
      if(!record.equals(p.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(root.toString(),null)))throw new AssertionError("Passive request refreshed authority");
      results.add(Map.of("staleRefusal",stale.getErrorMessage(),"recordUnchanged",true));
    }finally{d.dispose();}
    Files.writeString(Path.of(getScriptArgs()[0]),new GsonBuilder().setPrettyPrinting().create().toJson(results));println("SM83_MIGRATED_NEW_STOCK_PASS");
  }
}
