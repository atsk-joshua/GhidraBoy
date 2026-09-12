// Additional clean canonical witness; does not repair the intentionally retained override.
// @category Game Boy Tests
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.util.Map;
import com.google.gson.GsonBuilder;

public class Sm83CanonicalNative extends GhidraScript {
  @Override public void run() throws Exception {
    var args=getScriptArgs();
    if(args[0].equals("create-old")) {
      var p=currentProgram;
      if(p.getLanguage().getVersion()!=1)throw new AssertionError("Actual old provider required");
      var a=p.getAddressFactory().getAddress("rom1::4000");
      var f=p.getFunctionManager().createFunction("migrated_canonical_return",a,new AddressSet(a,a.add(2)),SourceType.USER_DEFINED);
      f.setCallingConvention("__asm");
      f.setCustomVariableStorage(true);
      f.setReturn(ByteDataType.dataType,new VariableStorage(p,p.getRegister("A")),SourceType.USER_DEFINED);
      println("SM83_CLEAN_CANONICAL_OLD_SAVED");
      return;
    }
    var file=state.getProject().getProjectData().getRootFolder().getFile("preserved");
    var p=(Program)file.getImmutableDomainObject(this,-1,monitor);
    var d=new DecompInterface();
    try {
      if(p.isChangeable()||p.getLanguage().getVersion()!=2)throw new AssertionError("Current immutable Program required");
      var before=Sm83PreservationInventory.inventory(p);
      if(!d.openProgram(p))throw new AssertionError(d.getLastMessage());
      var f=p.getFunctionManager().getFunctionAt(p.getAddressFactory().getAddress("rom1::4000"));
      var result=d.decompileFunction(f,30,monitor);
      if(!result.decompileCompleted()||result.getHighFunction()==null||result.getDecompiledFunction()==null)throw new AssertionError(result.getErrorMessage());
      var c=result.getDecompiledFunction().getC();
      if(!c.contains("return 0x22;")||c.contains("WARNING"))throw new AssertionError(c);
      var after=Sm83PreservationInventory.inventory(p);
      if(!before.equals(after))throw new AssertionError("Native query changed inventory");
      Files.writeString(Path.of(args[1]),new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(Map.of("before",before,"after",after,"c",c,"error",result.getErrorMessage(),"pid",ProcessHandle.current().pid(),"changeable",p.isChangeable())));
      println("SM83_CLEAN_MIGRATED_CANONICAL_NATIVE_PASS");
    }finally{d.dispose();p.release(this);}
  }
}
