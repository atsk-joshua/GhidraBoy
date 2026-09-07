import ghidra.app.script.GhidraScript;
import fi.gekkio.ghidraboy.*;
import java.util.*;
import java.nio.file.*;
public class Sa01OwnershipInspect extends GhidraScript {
 private ghidra.program.model.address.Address at(AnalysisOwnership.Point p) {return p==null?null:currentProgram.getAddressFactory().getAddressSpace(p.space()).getAddress(p.offset());}
 @Override public void run() throws Exception {
  String json=currentProgram.getOptions(ProgramMapping.OPTIONS).getString("analysis.ownership.v1", "");
  Files.writeString(Path.of(getScriptArgs()[0],"saved-ownership.json"),json);
  var group=ProgramMapping.JSON.fromJson(com.google.gson.JsonParser.parseString(json).getAsJsonObject().getAsJsonObject("groups").get("software-call"),AnalysisOwnership.Group.class);
  for(var r:group.repairs){var a=at(r.address());var ins=currentProgram.getListing().getInstructionAt(a);println("REPAIR "+a+" expected="+r+" actual="+(ins==null?"null":HexFormat.of().formatHex(ins.getBytes())+":"+ins.getFlowOverride()+":"+ins.isFallThroughOverridden()+":"+ins.getFallThrough())+" current="+AnalysisOwnership.softwareCallCurrent(currentProgram,a));
   for(var ref:currentProgram.getReferenceManager().getReferencesFrom(a))println("REF "+a+" "+ref.getToAddress()+":"+ref.getOperandIndex()+":"+ref.getReferenceType()+":"+ref.getSource()+":"+ref.isPrimary()+":"+ref.getSymbolID());
  }
  for(var h:group.helpers){var f=currentProgram.getFunctionManager().getFunctionAt(at(h.address()));println("HELPER expected="+h+" actual="+(f==null?"null":f.getID()+":"+f.isThunk()+":"+f.hasNoReturn()+":"+f.getCallFixup()));}
  for(var v:group.views) {
   println("VIEW "+v);
   for(var f:currentProgram.getFunctionManager().getFunctions(true)) if(f.getEntryPoint().getAddressSpace().getName().equals(v.name())) {
    println("FUNCTION "+f.getEntryPoint()+" name="+f.getName()+" body="+f.getBody()+" locals="+Arrays.toString(f.getLocalVariables())+" params="+Arrays.toString(f.getParameters())+" return="+f.getReturnType()+" signatureSource="+f.getSignatureSource()+" stackLocal="+f.getStackFrame().getLocalSize()+" returnOffset="+f.getStackFrame().getReturnAddressOffset()+" purge="+f.getStackPurgeSize()+" noReturn="+f.hasNoReturn());
    for(var variable:f.getLocalVariables()) println("LOCAL "+variable.getName()+":"+variable.getSource()+":"+variable.getDataType()+":"+variable.getVariableStorage());
   }
   var bookmarks=currentProgram.getBookmarkManager().getBookmarksIterator();while(bookmarks.hasNext()){var b=bookmarks.next();if(b.getAddress().getAddressSpace().getName().equals(v.name()))println("BOOKMARK "+b.getAddress()+":"+b.getTypeString()+":"+b.getCategory()+":"+b.getComment());}
   for(var sym:currentProgram.getSymbolTable().getAllSymbols(true))if(sym.getAddress().getAddressSpace().getName().equals(v.name())&&!sym.isDynamic())println("SYMBOL "+sym.getAddress()+":"+sym.getName(true)+":"+sym.getSource());
  }
  println("DIAGNOSTIC_PASS");
 }
}
