// @category Game Boy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.address.*;
import ghidra.program.disassemble.Disassembler;
import java.nio.file.*;
import java.util.*;

/** Early end-to-end self-authored conditional call through maintained actions. */
public class GhidraBoyConditionalCalls extends GhidraBoyPredicatedCalls {
 public void run()throws Exception {
  var args=getScriptArgs();out=Path.of(args[0]);Files.createDirectories(out);Path input=Path.of(args[1]);String name=args[2];
  var info=com.google.gson.JsonParser.parseString(Files.readString(input.getParent().resolve("fixtures.json"))).getAsJsonObject().getAsJsonObject(name);
  var language=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("SM83:LE:16:default"));Object consumer=new Object();var p=new ProgramDB(name,language,language.getDefaultCompilerSpec(),consumer);
  try {
   try(var provider=new ByteArrayProvider(Files.readAllBytes(input))){CartridgeLayout.load(p,provider,"CARTRIDGE","AUTO",GameBoyKind.GB,true,false,monitor,new MessageLog());}
   currentProgram=p;state.setCurrentProgram(p);
   int tx=p.startTransaction("Independently authored instruction boundaries");try {
    for(var row:info.getAsJsonArray("spans")) {var r=row.getAsJsonObject();int bank=r.get("bank").getAsInt(),cpu=r.get("cpu").getAsInt(),length=r.get("bytes").getAsString().length()/2;var at=bank==0?toAddr(cpu):p.getAddressFactory().getAddress("rom"+bank+"::"+Integer.toHexString(cpu));
     if(cpu==(int)ProgramMapping.staticAddress(p,info.get("site").getAsString()).getOffset())length=1;
     for(int offset=0;offset<length;){var start=at.add(offset);Disassembler.getDisassembler(p,monitor,null).disassemble(start,new AddressSet(start,at.add(length-1)),false);var ins=p.getListing().getInstructionAt(start);if(ins==null)throw new IllegalStateException("Fixture decoding failed");offset+=ins.getLength();}
    }
   }finally{p.endTransaction(tx,true);}
   var file=state.getProject().getProjectData().getRootFolder().createFile(name+".gb",p,monitor);
   var request=new ConditionalCallSites.Request(p.getUniqueProgramID(),ProgramMapping.inspect(p).originalSha256(),info.get("site").getAsString(),new MapperKnowledge(1,0,null,null,null,null,null,null),0xffa1,1,List.of(),new SymbolicMemory.Footprint(0xc110,0xc7f8,-16,1),List.of(0,1),0,true,true,"Self-authored synchronous fixture; boot inactive; no external interference; explicitly constrained affine frame");
   save("request.json",request);long start=System.nanoTime();
   runScript("GhidraBoyTools.java",new String[]{"conditional-call-preview",out.resolve("request.json").toString(),out.resolve("preview.json").toString()},state);
   var proof=ProgramMapping.JSON.fromJson(Files.readString(out.resolve("preview.json")),PredicatedCallGraph.Proof.class);save("cost-derive.json",Map.of("ns",System.nanoTime()-start,"usedHeap",Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory()));
   if(!proof.complete())throw new IllegalStateException("Incomplete conditional source: "+proof.frontier());
   runScript("GhidraBoyTools.java",new String[]{"stock-predicate-apply",out.resolve("preview.json").toString()},state);
   var roots=p.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames();if(roots.size()!=1)throw new IllegalStateException("Missing public owned result");var entry=ProgramMapping.staticAddress(p,roots.getFirst());
   var owner=owner();try{stage("original",entry,owner);}finally{owner.dispose();}
   runScript("GhidraBoyTools.java",new String[]{"conditional-call-explain",entry.toString()},state);
   Files.write(out.resolve("fixture.gb"),Files.readAllBytes(input));
   p.save("Current conditional call-site authority",monitor);
   file.packFile(out.resolve("current.gzf").toFile(),monitor);
   println("CONDITIONAL_NATIVE_CAPTURE_COMPLETE");
  }finally{state.setCurrentProgram(null);p.release(consumer);}
 }
}
