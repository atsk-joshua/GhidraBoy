// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.disassemble.Disassembler;
import java.nio.file.*;
import java.util.*;

/** Unknown-B cyclic Program, real state-entry callbacks, mutation/refreshed capture and one saved format. */
public class GhidraBoyW3bLoops extends GhidraBoyPredicatedCalls {
  void mutate(Address root,int value)throws Exception {
    var source=toAddr(0x159);var alias=root.getAddressSpace().getAddress(0x159);
    currentProgram.getListing().clearCodeUnits(alias,alias,false);currentProgram.getListing().clearCodeUnits(source,source,false);
    currentProgram.getMemory().setByte(source,(byte)value);
    for(var at:List.of(source,alias))Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(at,new AddressSet(at,at),false);
  }
  @Override public void run()throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);String mode=getScriptArgs()[1];
    if(mode.equals("reopened")) {
      var root=currentProgram.getAddressFactory().getAddress(currentProgram.getOptions(PredicatedCalls.OPTIONS).getOptionNames().stream().filter(n->n.contains("_root::")).findFirst().orElseThrow());
      var owner=owner();try{stage("reopened",root,owner);}finally{owner.dispose();}
      println("W3B_CAPTURE_COMPLETE reopened");return;
    }
    var body=new AddressSet(toAddr(0x150),toAddr(0x174));Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(toAddr(0x150),body);
    var function=currentProgram.getFunctionManager().createFunction("cyclic_root",toAddr(0x150),body,ghidra.program.model.symbol.SourceType.USER_DEFINED);
    save("canonical-before.json",canonical(function));var proof=PredicatedCalls.preview(currentProgram,function,PredicatedCallGraph.Limits.PRIMARY,monitor);save("producer-preview.json",proof);
    if(!proof.complete())throw new IllegalStateException("Incomplete cyclic graph: "+proof.frontier());
    var root=PredicatedCalls.install(currentProgram,proof,monitor);var owner=owner();
    try {
      stage("original",root,owner);Files.write(out.resolve("original-image.gb"),ProgramMapping.exportBytes(currentProgram,true,false,monitor));
      var firstpass=owner();try{firstpass.setSimplificationStyle("firstpass");request(getFunctionAt(root),firstpass,"original-root-firstpass");}finally{firstpass.dispose();}
      var stored=currentProgram.getOptions(PredicatedCalls.OPTIONS).getString(root.toString(),null);mutate(root,0x15);
      boolean refused=false;String reason="";try{PredicatedCalls.emit(currentProgram,root,0x200000,monitor);}catch(IllegalArgumentException failure){refused=true;reason=failure.getMessage();}
      if(!refused||!reason.contains("Stale"))throw new IllegalStateException("Stale loop-body proof was consumed");
      request(getFunctionAt(root),owner,"stale-root");save("mutation.json",Map.of("physical","0159","old",0x14,"new",0x15,"proofRetained",stored.equals(currentProgram.getOptions(PredicatedCalls.OPTIONS).getString(root.toString(),null)),"directRefusal",reason));
      var fresh=PredicatedCalls.preview(currentProgram,function,PredicatedCallGraph.Limits.PRIMARY,monitor);PredicatedCalls.refresh(currentProgram,root,fresh,monitor);owner.flushCache();stage("refreshed",root,owner);
      Files.write(out.resolve("refreshed-image.gb"),ProgramMapping.exportBytes(currentProgram,true,false,monitor));
      // Save the primary relation in final format after exercising mutation and explicit refresh.
      mutate(root,0x14);fresh=PredicatedCalls.preview(currentProgram,function,PredicatedCallGraph.Limits.PRIMARY,monitor);PredicatedCalls.refresh(currentProgram,root,fresh,monitor);
      Files.writeString(out.resolve("saved-registration.json"),currentProgram.getOptions(PredicatedCalls.OPTIONS).getString(root.toString(),null));identity("saved",root);save("saved-proof.json",PredicatedCalls.registeredProof(currentProgram,root));
    }finally{owner.dispose();}
    println("W3B_CAPTURE_COMPLETE setup");
  }
}
