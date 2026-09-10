// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.disassemble.Disassembler;
import java.nio.file.*;
import java.util.*;

/** Capture only: all memory/generation establishment, proof and lowering use production APIs. */
public class GhidraBoyMemoryImages extends GhidraBoyPredicatedCalls {
  ghidra.app.decompiler.DecompInterface persistentOwner;
  ghidra.app.decompiler.DecompInterface session()throws Exception {if(persistentOwner==null)persistentOwner=owner();return persistentOwner;}
  boolean stock(){return Arrays.asList(getScriptArgs()).contains("stock");}
  Address install(PredicatedCallGraph.Proof proof)throws Exception {
    return stock()?PredicatedCalls.installStock(currentProgram,proof,monitor):PredicatedCalls.install(currentProgram,proof,monitor);
  }
  void stageFresh(String label,Address root)throws Exception {
    var before=ExecutableImages.serialized(currentProgram);var owner=stock()?session():owner();
    try{stage(label,root,owner);}finally{if(!stock())owner.dispose();}
    if(!Objects.equals(before,ExecutableImages.serialized(currentProgram)))throw new IllegalStateException("Callback mutated image authority");
    save(label+"-images.json",ExecutableImages.history(currentProgram));
  }
  PredicatedCallGraph.Proof preview(Function f,String image)throws Exception {
    var declaration=SymbolicMemory.declare(currentProgram,image==null?List.of(0xc060):List.of(),List.of(),image);
    return PredicatedCallGraph.preview(currentProgram,f,PredicatedCallGraph.Limits.PRIMARY,declaration,monitor);
  }
  void bindings(String label)throws Exception {
    var spaces=new ArrayList<Object>();for(var s:currentProgram.getAddressFactory().getAddressSpaces())spaces.add(Map.of("name",s.getName(),"id",s.getSpaceID(),"addressable_unit",s.getAddressableUnitSize(),"pointer_size",s.getPointerSize()));
    var cells=new ArrayList<Object>();for(int cpu:List.of(0xc060,0xe060,0xc070,0xc071,0xc074,0xc200,0xe201))cells.add(Map.of("cpu",cpu,"space",toAddr(cpu).getAddressSpace().getName(),"physical",ProgramMapping.staticToPhysical(currentProgram,toAddr(cpu))));
    var distinct=currentProgram.getMemory().getBlock("w4_distinct");
    save(label+"-bindings.json",Map.of("spaces",spaces,"cells",cells,"negative_storage",Map.of("space",distinct.getStart().getAddressSpace().getName(),"id",distinct.getStart().getAddressSpace().getSpaceID(),"offset",distinct.getStart().getOffset(),"size",1,"value",currentProgram.getMemory().getByte(distinct.getStart())&255,"mapped",distinct.isMapped())));
  }
  @Override public void run()throws Exception {try{executeCapture();}finally{if(persistentOwner!=null)persistentOwner.dispose();}}
  void executeCapture()throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);String mode=getScriptArgs()[1];
    if(!mode.equals("reopen")) {var distinct=currentProgram.getMemory().createInitializedBlock("w4_distinct",toAddr(0xc060),1,(byte)0x9a,monitor,true);distinct.setRead(true);distinct.setWrite(true);distinct.setExecute(false);}
    bindings(mode);
    if(mode.equals("reopen")) {
      String before=ExecutableImages.serialized(currentProgram);
      var images=ExecutableImages.history(currentProgram);var image=images.get(images.size()-1);var root=currentProgram.getAddressFactory().getAddress(image.entry());
      try{ExecutableImages.resolve(currentProgram,images.get(0).generation());throw new IllegalStateException("Old generation admitted");}catch(IllegalArgumentException expected){save("reopen-old-generation.json",Map.of("refusal",expected.getMessage()));}
      if(stock()) {
        var generation=image.generation();
        var matches=currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames().stream().map(n->currentProgram.getAddressFactory().getAddress(n)).filter(a->PredicatedCalls.registeredProof(currentProgram,a).memory().image().equals(generation)).toList();
        if(matches.size()!=1)throw new IllegalStateException("Missing unique current image carrier");root=matches.getFirst();
      }
      stageFresh("reopen",root);if(!before.equals(ExecutableImages.serialized(currentProgram)))throw new IllegalStateException("Reopen mutated authority");
      Files.writeString(out.resolve("reopen-authority.json"),before);println("W4_MEMORY_IMAGE_CAPTURE_COMPLETE reopen");return;
    }
    var block=currentProgram.getMemory().getBlock(toAddr(0xc000));if(block==null)throw new IllegalStateException("Fixture needs actual canonical hardware RAM");
    if(!block.isInitialized())currentProgram.getMemory().convertToInitialized(block,(byte)0);
    if(mode.equals("memory")||mode.equals("interference")) {
      var body=new AddressSet(toAddr(0x150),toAddr(0x160));Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(toAddr(0x150),body,false);
      var f=getFunctionAt(toAddr(0x150));if(f==null)f=currentProgram.getFunctionManager().createFunction("memory_root",toAddr(0x150),body,ghidra.program.model.symbol.SourceType.USER_DEFINED);
      var proof=mode.equals("interference")?PredicatedCallGraph.preview(currentProgram,f,PredicatedCallGraph.Limits.PRIMARY,SymbolicMemory.declare(currentProgram,List.of(0xc060),List.of(new SymbolicMemory.MayWrite(0x15a,0xe060,"declared possible external byte write")),null),monitor):preview(f,null);save("preview.json",proof);if(!proof.complete())throw new IllegalStateException("Incomplete memory graph "+proof.frontier());
      var root=install(proof);
      if(mode.equals("interference")){request(getFunctionAt(root),session(),"interference");println("W4_MEMORY_IMAGE_CAPTURE_COMPLETE interference");return;}
      stageFresh("memory",root);
      for(int fill:List.of(0x53,0xff)) {
        currentProgram.getMemory().setByte(toAddr(0xc060),(byte)fill);var fresh=preview(f,null);PredicatedCalls.refresh(currentProgram,root,fresh,monitor);stageFresh("poison"+fill,root);
      }
    } else {
      byte[] i1=HexFormat.of().parseHex("3e31ea74c0c9"),i2=HexFormat.of().parseHex("3ea7ea74c0c9");
      var first=ExecutableImages.establish(currentProgram,toAddr(0x300),0xc200,i1,"explicit current-ROM I1 snapshot",monitor);
      var firstFunction=getFunctionAt(currentProgram.getAddressFactory().getAddress(first.entry()));var root=install(preview(firstFunction,first.generation()));stageFresh("image1",root);
      String pathAuthority=ExecutableImages.serialized(currentProgram);
      var overlap=PredicatedCallGraph.preview(currentProgram,firstFunction,PredicatedCallGraph.Limits.PRIMARY,SymbolicMemory.declare(currentProgram,List.of(),List.of(new SymbolicMemory.MayWrite(0xc200,0xe201,"possible executable operand replacement")),first.generation()),monitor);
      var disjoint=PredicatedCallGraph.preview(currentProgram,firstFunction,PredicatedCallGraph.Limits.PRIMARY,SymbolicMemory.declare(currentProgram,List.of(),List.of(new SymbolicMemory.MayWrite(0xc200,0xc062,"disjoint possible write")),first.generation()),monitor);
      if(overlap.complete()||!disjoint.complete()||!pathAuthority.equals(ExecutableImages.serialized(currentProgram)))throw new IllegalStateException("Path-local image footprint/generation control failed");
      save("path-controls.json",Map.of("overlap",overlap,"disjoint",disjoint,"authorityUnchanged",true,"generation",first.generation()));
      if(mode.equals("source")) {
        String before=ExecutableImages.serialized(currentProgram);currentProgram.getMemory().setByte(toAddr(0x301),(byte)0x5a);
        var fresh=preview(firstFunction,first.generation());save("source-readonly-reproof.json",fresh);
        if(!before.equals(ExecutableImages.serialized(currentProgram)))throw new IllegalStateException("Source edit or readonly reproof changed image history");
        PredicatedCalls.refresh(currentProgram,root,fresh,monitor);stageFresh("source",root);
        save("source-independence.json",Map.of("generation",first.generation(),"initializer",first.initializer(),"ram",HexFormat.of().formatHex(getBytes(toAddr(0xc200),6)),"proof_refresh_explicit",true,"image_records_unchanged",before.equals(ExecutableImages.serialized(currentProgram))));
      } else {
        currentProgram.getMemory().setBytes(toAddr(0xc200),i2);
        var owner=stock()?session():owner();try{request(getFunctionAt(root),owner,"stale-image1");}finally{if(!stock())owner.dispose();}
        try{if(stock())PredicatedCalls.emitStock(currentProgram,root,0x200000,monitor);else PredicatedCalls.emit(currentProgram,root,0x200000,monitor);throw new IllegalStateException("Replaced RAM accepted");}catch(IllegalArgumentException expected){save("replacement-refusal.json",Map.of("reason",expected.getMessage()));}
        var second=ExecutableImages.establish(currentProgram,toAddr(0x320),0xc200,i2,"explicit current-ROM I2 snapshot",monitor);
        var secondFunction=getFunctionAt(currentProgram.getAddressFactory().getAddress(second.entry()));var secondRoot=install(preview(secondFunction,second.generation()));if(stock())session().resetDecompiler();stageFresh("image2",secondRoot);
        try{ExecutableImages.resolve(currentProgram,first.generation());throw new IllegalStateException("Old generation accepted");}catch(IllegalArgumentException expected){save("old-generation.json",Map.of("reason",expected.getMessage()));}
        if(mode.equals("samebytes")) {
          var third=ExecutableImages.establish(currentProgram,toAddr(0x320),0xc200,i2,"explicit same-bytes new lifetime",monitor);
          try{ExecutableImages.resolve(currentProgram,second.generation());throw new IllegalStateException("Prior same-bytes generation accepted");}
          catch(IllegalArgumentException expected){save("same-bytes-old-generation.json",Map.of("reason",expected.getMessage(),"old",second.generation(),"current",third.generation()));}
          request(getFunctionAt(secondRoot),session(),"same-bytes-stale-image2");
          var thirdFunction=getFunctionAt(currentProgram.getAddressFactory().getAddress(third.entry()));var thirdRoot=install(preview(thirdFunction,third.generation()));session().resetDecompiler();stageFresh("image3",thirdRoot);
        }
        Files.writeString(out.resolve("saved-authority.json"),ExecutableImages.serialized(currentProgram));
      }
    }
    println("W4_MEMORY_IMAGE_CAPTURE_COMPLETE "+mode);
  }
}
