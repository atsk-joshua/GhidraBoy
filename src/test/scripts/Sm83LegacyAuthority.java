// Genuine historical record inspection and public refusal; never converts or refreshes proofs.
// @category Game Boy Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Program;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;

public class Sm83LegacyAuthority extends GhidraScript {
  interface Attempt {void run() throws Exception;}
  void reject(List<Object> results,String name,Attempt action) throws Exception {
    var before=Sm83PreservationInventory.inventory(currentProgram);String reason=null;
    try {action.run();}catch(IllegalArgumentException expected){reason=expected.toString();}
    var after=Sm83PreservationInventory.inventory(currentProgram);
    if(reason==null||!before.equals(after))throw new AssertionError(name+" failed read-only refusal");
    results.add(Sm83PreservationInventory.row("operation",name,"refused",true,"reason",reason,"unchanged",true));
  }
  @Override public void run() throws Exception {
    var file=state.getProject().getProjectData().getRootFolder().getFile(getScriptArgs()[1]);
    currentProgram=(Program)file.getImmutableDomainObject(this,-1,monitor);
    try { inspect(); } finally {currentProgram.release(this);}
  }
  private void inspect() throws Exception {
    var result=new ArrayList<Object>();var p=currentProgram;
    var before=Sm83PreservationInventory.inventory(p);
    reject(result,"registry resolve",()->SoftwareCallRegistry.resolve(p,toAddr(0x200)));
    reject(result,"registry install",()->SoftwareCallRegistry.install(p,List.of()));
    reject(result,"ownership save",()->AnalysisOwnership.save(p,"unrelated",new AnalysisOwnership.Group()));
    reject(result,"registry remove",()->SoftwareCallRegistry.remove(p));
    reject(result,"ownership remove",()->AnalysisOwnership.remove(p,"software-call",monitor));
    reject(result,"ownership removeAll",()->AnalysisOwnership.removeAll(p,monitor));
    reject(result,"public stock preview",()->SoftwareCallApplication.preview(p,List.of(),monitor));
    var d=new DecompInterface();
    try {
      if(!d.openProgram(p))throw new AssertionError(d.getLastMessage());
      var f=p.getFunctionManager().getFunctionAt(toAddr(0x150));
      var nativeResult=d.decompileFunction(f,30,monitor);
      if(nativeResult.decompileCompleted()||nativeResult.getHighFunction()!=null||nativeResult.getDecompiledFunction()!=null||!nativeResult.getErrorMessage().contains("Incompatible software-call registry"))throw new AssertionError("Old authority did not fail closed in native use");
      result.add(Sm83PreservationInventory.row("operation","native old caller 0150","completed",nativeResult.decompileCompleted(),"highFunction",nativeResult.getHighFunction()!=null,"c",nativeResult.getDecompiledFunction()==null?null:nativeResult.getDecompiledFunction().getC(),"error",nativeResult.getErrorMessage()));
    }finally{d.dispose();}
    var after=Sm83PreservationInventory.inventory(p);
    Files.writeString(Path.of(getScriptArgs()[0]),new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(Sm83PreservationInventory.row("before",before,"after",after,"results",result,"pid",ProcessHandle.current().pid())));
    if(!before.equals(after))throw new AssertionError("Record consumption mutated Program");
    println("SM83_LEGACY_RECORD_REFUSAL_PASS");
  }
}
