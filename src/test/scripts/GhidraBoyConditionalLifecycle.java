// @category Game Boy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import java.nio.file.*;
import java.util.*;

/** Existing saved conditional record only; no import or implicit proof refresh. */
public class GhidraBoyConditionalLifecycle extends GhidraBoyPredicatedCalls {
 public void run()throws Exception {
  end(true); // Close only this capture wrapper before standalone public actions/native receipts.
  if(currentProgram.getCurrentTransactionInfo()!=null)throw new IllegalStateException("Capture requires its outer owner to finish before committed qualification");
  out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);String mode=getScriptArgs()[1];
  var originalProgram=currentProgram;boolean immutable=mode.equals("reopen");
  if(immutable){currentProgram=(ghidra.program.model.listing.Program)currentProgram.getDomainFile().getImmutableDomainObject(this,-1,monitor);state.setCurrentProgram(currentProgram);if(currentProgram.isChangeable())throw new IllegalStateException("Immutable reopen required");}
  var entries=currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames();if(entries.size()!=1)throw new IllegalStateException("Expected one owned conditional record");
  var entry=ProgramMapping.staticAddress(currentProgram,entries.getFirst());var proof=PredicatedCalls.registeredProof(currentProgram,entry);
  var owner=owner();try {
   if(mode.equals("reopen")) {
    long revision=currentProgram.getModificationNumber();stage("reopen",entry,owner);
    save("read-only.json",Map.of("pid",ProcessHandle.current().pid(),"programId",currentProgram.getUniqueProgramID(),"unchanged",currentProgram.getModificationNumber()==revision,"changeable",currentProgram.isChangeable()));
   } else if(mode.equals("stale-refresh")) {
    var target=proof.boundaries().stream().filter(b->b.kind().equals("RET_DISPATCH")).findFirst().orElseThrow();var at=ProgramMapping.staticAddress(currentProgram,target.physical()).add(2);
    int tx=currentProgram.startTransaction("Self-authored callee INC to DEC fault variant");try {
     var ins=currentProgram.getListing().getInstructionAt(at);if(ins!=null)currentProgram.getListing().clearCodeUnits(at,ins.getMaxAddress(),false);
     currentProgram.getMemory().setByte(at,(byte)0x3d);Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(at,new AddressSet(at),false);
    }finally{currentProgram.endTransaction(tx,true);}
    owner.flushCache();request(getFunctionAt(entry),owner,"stale");
    var stale=com.google.gson.JsonParser.parseString(Files.readString(out.resolve("stale-request.json"))).getAsJsonObject();
    if(stale.get("completed").getAsBoolean()||stale.get("highfunction_available").getAsBoolean()||!stale.get("error").getAsString().contains("Stale"))throw new IllegalStateException("Native stale use was not refused");
    save("request.json",proof.callSite());publicPredicateAction(new String[]{"conditional-call-preview",out.resolve("request.json").toString(),out.resolve("fresh.json").toString()});
    publicPredicateAction(new String[]{"stock-predicate-refresh",out.resolve("fresh.json").toString(),entry.toString()});
    owner.flushCache();stage("refreshed",entry,owner);
   } else if(mode.equals("mapper-stale")) {
    var node=proof.nodes().stream().filter(n->n.bytes().equals("ea0020")).findFirst().orElseThrow();
    var at=ProgramMapping.staticAddress(currentProgram,node.source());
    save("mapper-before.json",Map.of("source",node.source(),"bytes",node.bytes(),"low",proof.callSite().mapper().low(),"high",proof.callSite().mapper().high()));
    int tx=currentProgram.startTransaction("Self-authored low to high mapper port negative");boolean success=false;
    try{currentProgram.getListing().clearCodeUnits(at,at.add(2),false);currentProgram.getMemory().setByte(at.add(2),(byte)0x30);Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(at,new AddressSet(at),false);success=true;}finally{currentProgram.endTransaction(tx,success);}
    owner.flushCache();request(getFunctionAt(entry),owner,"mapper-stale");
    var stale=com.google.gson.JsonParser.parseString(Files.readString(out.resolve("mapper-stale-request.json"))).getAsJsonObject();
    if(stale.get("completed").getAsBoolean()||stale.get("highfunction_available").getAsBoolean()||!stale.get("error").getAsString().contains("Stale"))throw new IllegalStateException("Changed mapper port native use was not refused");
   } else if(mode.equals("remove")) {
    save("before.json",Sm83PreservationInventory.inventory(currentProgram));publicPredicateAction(new String[]{"stock-predicate-remove",entry.toString()});if(PredicatedCalls.registered(currentProgram,entry))throw new IllegalStateException("Public removal retained authority");save("after.json",Sm83PreservationInventory.inventory(currentProgram));
   } else throw new IllegalArgumentException("Unknown lifecycle mode");
   Files.write(out.resolve("fixture.gb"),ProgramMapping.exportBytes(currentProgram,true,false,monitor));
  }finally{owner.dispose();if(immutable){currentProgram.release(this);currentProgram=originalProgram;state.setCurrentProgram(currentProgram);}}
  println("CONDITIONAL_LIFECYCLE_COMPLETE "+mode);
 }
}
