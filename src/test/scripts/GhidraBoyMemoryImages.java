// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.disassemble.Disassembler;
import java.nio.file.*;
import java.util.*;

/** Capture only: all memory/generation establishment, proof and lowering use production APIs. */
public class GhidraBoyMemoryImages extends GhidraBoyPredicatedCalls {
  void stageFresh(String label,Address root)throws Exception {
    var before=ExecutableImages.serialized(currentProgram);var owner=owner();
    try{stage(label,root,owner);}finally{owner.dispose();}
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
  @Override public void run()throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);String mode=getScriptArgs()[1];
    if(!mode.equals("reopen")) {var distinct=currentProgram.getMemory().createInitializedBlock("w4_distinct",toAddr(0xc060),1,(byte)0x9a,monitor,true);distinct.setRead(true);distinct.setWrite(true);distinct.setExecute(false);}
    bindings(mode);
    if(mode.equals("reopen")) {
      String before=ExecutableImages.serialized(currentProgram);
      var images=ExecutableImages.history(currentProgram);var image=images.get(images.size()-1);var root=currentProgram.getAddressFactory().getAddress(image.entry());
      try{ExecutableImages.resolve(currentProgram,images.get(0).generation());throw new IllegalStateException("Old generation admitted");}catch(IllegalArgumentException expected){save("reopen-old-generation.json",Map.of("refusal",expected.getMessage()));}
      stageFresh("reopen",root);if(!before.equals(ExecutableImages.serialized(currentProgram)))throw new IllegalStateException("Reopen mutated authority");
      Files.writeString(out.resolve("reopen-authority.json"),before);println("W4_MEMORY_IMAGE_CAPTURE_COMPLETE reopen");return;
    }
    var block=currentProgram.getMemory().getBlock(toAddr(0xc000));if(block==null)throw new IllegalStateException("Fixture needs actual canonical hardware RAM");
    if(!block.isInitialized())currentProgram.getMemory().convertToInitialized(block,(byte)0);
    if(mode.equals("memory")) {
      var body=new AddressSet(toAddr(0x150),toAddr(0x160));Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(toAddr(0x150),body,false);
      var f=getFunctionAt(toAddr(0x150));if(f==null)f=currentProgram.getFunctionManager().createFunction("memory_root",toAddr(0x150),body,ghidra.program.model.symbol.SourceType.USER_DEFINED);
      var proof=preview(f,null);save("preview.json",proof);if(!proof.complete())throw new IllegalStateException("Incomplete memory graph "+proof.frontier());
      var root=PredicatedCalls.install(currentProgram,proof,monitor);stageFresh("memory",root);
      for(int fill:List.of(0x53,0xff)) {
        currentProgram.getMemory().setByte(toAddr(0xc060),(byte)fill);var fresh=preview(f,null);PredicatedCalls.refresh(currentProgram,root,fresh,monitor);stageFresh("poison"+fill,root);
      }
    } else {
      byte[] i1=HexFormat.of().parseHex("3e31ea74c0c9"),i2=HexFormat.of().parseHex("3ea7ea74c0c9");
      var first=ExecutableImages.establish(currentProgram,toAddr(0x300),0xc200,i1,"explicit current-ROM I1 snapshot",monitor);
      var firstFunction=getFunctionAt(currentProgram.getAddressFactory().getAddress(first.entry()));var root=PredicatedCalls.install(currentProgram,preview(firstFunction,first.generation()),monitor);stageFresh("image1",root);
      if(mode.equals("source")) {
        String before=ExecutableImages.serialized(currentProgram);currentProgram.getMemory().setByte(toAddr(0x301),(byte)0x5a);
        var fresh=preview(firstFunction,first.generation());save("source-readonly-reproof.json",fresh);
        if(!before.equals(ExecutableImages.serialized(currentProgram)))throw new IllegalStateException("Source edit or readonly reproof changed image history");
        PredicatedCalls.refresh(currentProgram,root,fresh,monitor);stageFresh("source",root);
        save("source-independence.json",Map.of("generation",first.generation(),"initializer",first.initializer(),"ram",HexFormat.of().formatHex(getBytes(toAddr(0xc200),6)),"proof_refresh_explicit",true,"image_records_unchanged",before.equals(ExecutableImages.serialized(currentProgram))));
      } else {
        currentProgram.getMemory().setBytes(toAddr(0xc200),i2);
        var owner=owner();try{request(getFunctionAt(root),owner,"stale-image1");}finally{owner.dispose();}
        try{PredicatedCalls.emit(currentProgram,root,0x200000,monitor);throw new IllegalStateException("Replaced RAM accepted");}catch(IllegalArgumentException expected){save("replacement-refusal.json",Map.of("reason",expected.getMessage()));}
        var second=ExecutableImages.establish(currentProgram,toAddr(0x320),0xc200,i2,"explicit current-ROM I2 snapshot",monitor);
        var secondFunction=getFunctionAt(currentProgram.getAddressFactory().getAddress(second.entry()));var secondRoot=PredicatedCalls.install(currentProgram,preview(secondFunction,second.generation()),monitor);stageFresh("image2",secondRoot);
        try{ExecutableImages.resolve(currentProgram,first.generation());throw new IllegalStateException("Old generation accepted");}catch(IllegalArgumentException expected){save("old-generation.json",Map.of("reason",expected.getMessage()));}
        Files.writeString(out.resolve("saved-authority.json"),ExecutableImages.serialized(currentProgram));
      }
    }
    println("W4_MEMORY_IMAGE_CAPTURE_COMPLETE "+mode);
  }
}
