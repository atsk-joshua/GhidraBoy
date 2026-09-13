// @category Game Boy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.disassemble.Disassembler;
import java.nio.file.*;
import java.util.*;

/** Source fixture capture using the maintained public graph and stock native route. */
public class GhidraBoyFiniteDispatch extends GhidraBoyPredicatedCalls {
  @Override public void run() throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    String mode=getScriptArgs()[1];boolean nibble=mode.startsWith("nibble");boolean banks=mode.startsWith("physical-banks");
    var spaces=new TreeMap<String,Object>();
    for(var space:currentProgram.getAddressFactory().getAddressSpaces())spaces.put(space.getName(),Map.of("id",space.getSpaceID(),"bits",space.getSize()));
    save("spaces.json",spaces);
    Address entry;
    if(mode.equals("reopen")) {
      var roots=currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames().stream().filter(n->n.contains("_root::")).toList();
      if(roots.size()!=1)throw new IllegalStateException("Expected one current root");
      entry=currentProgram.getAddressFactory().getAddress(roots.get(0));
    } else {
      int h=getScriptArgs().length>2?Integer.decode(getScriptArgs()[2]):0xc060;
      int tx=currentProgram.startTransaction("Declare self-authored dispatch fixture");
      try {
        for(int cpu:List.of(0xc000,0xff80)) {
          var block=currentProgram.getMemory().getBlock(toAddr(cpu));
          if(block==null)throw new IllegalArgumentException("Production fixture requires loader hardware blocks");
          if(!block.isInitialized())currentProgram.getMemory().convertToInitialized(block,(byte)0);
        }
        if(banks)for(int bank:mode.endsWith("reverse")?List.of(2,1):List.of(1,2)) {
          var at=currentProgram.getAddressFactory().getAddress("rom"+bank+"::4000");
          Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(at,new AddressSet(at,at.add(2)),false);
        }
        var body=new AddressSet(toAddr(0x100),toAddr(nibble?0x116:banks?0x113:mode.equals("zero")?0x108:0x12f));
        for(int i=0;i<(nibble?16:mode.startsWith("normalized")?6:0);i++){int at=nibble?0x1000+8*i:0x300+3*i;body.add(toAddr(at),toAddr(at+(nibble?6:2)));}
        Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(toAddr(0x100),body);
        var function=currentProgram.getFunctionManager().createFunction("finite_dispatch_source",toAddr(0x100),body,SourceType.USER_DEFINED);
        function.updateFunction("default",new ReturnParameterImpl(nibble?UnsignedShortDataType.dataType:ByteDataType.dataType,currentProgram.getRegister(nibble?"HL":"A"),currentProgram),Function.FunctionUpdateType.CUSTOM_STORAGE,true,SourceType.USER_DEFINED);
      } finally {currentProgram.endTransaction(tx,true);}
      var declaration=SymbolicMemory.declare(currentProgram,List.of(nibble?h:0xff80),List.of(),null,nibble?h:null);
      save("premises.json",declaration);
      save("public-premises.json",new PredicatedCalls.Premises("0100",List.of(nibble?h:0xff80),nibble?h:null));
      long revision=currentProgram.getModificationNumber();
      var proof=PredicatedCallGraph.preview(currentProgram,getFunctionAt(toAddr(0x100)),PredicatedCallGraph.Limits.PRIMARY,declaration,monitor);
      save("preview.json",proof);
      if(revision!=currentProgram.getModificationNumber()||!proof.complete())throw new IllegalStateException("Incomplete/mutating preview: "+proof.frontier());
      runScript("GhidraBoyTools.java",new String[]{"stock-predicate-preview",out.resolve("public-premises.json").toString(),out.resolve("public-preview.json").toString()},state);
      runScript("GhidraBoyTools.java",new String[]{"stock-predicate-apply",out.resolve("public-preview.json").toString()},state);
      var roots=currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames().stream().filter(n->n.contains("_root::")).toList();
      if(roots.size()!=1)throw new IllegalStateException("Public application did not install one root");
      entry=currentProgram.getAddressFactory().getAddress(roots.get(0));
      Files.write(out.resolve("fixture.gb"),ProgramMapping.exportBytes(currentProgram,true,false,monitor));
    }
    var owner=owner();try{
      String label=mode.equals("reopen")?"reopen":"original";
      ids.clear();save("carrier-raw.json",Arrays.stream(currentProgram.getListing().getInstructionAt(entry).getPcode(false)).map(this::operation).toList());
      long revision=currentProgram.getModificationNumber();stage(label,entry,owner);
      save(label+"-placements.json",PredicatedCalls.inspectEmission(currentProgram,entry,0x200000,monitor));
      if(currentProgram.getModificationNumber()!=revision)throw new IllegalStateException("Native capture mutated Program");
      Files.write(out.resolve(label+"-fixture.gb"),ProgramMapping.exportBytes(currentProgram,true,false,monitor));
      if(banks)for(int bank:List.of(2,1)) {
        currentAddress=currentProgram.getAddressFactory().getAddress("rom"+bank+"::4000");state.setCurrentAddress(currentAddress);
        String selected="selection-bank"+bank;
        save(selected+".json",Map.of("scriptNavigationSelection",state.getCurrentAddress().toString(),"qualifiedEntry",entry.toString()));
        stage(selected,entry,owner);save(selected+"-placements.json",PredicatedCalls.inspectEmission(currentProgram,entry,0x200000,monitor));
        Files.write(out.resolve(selected+"-fixture.gb"),ProgramMapping.exportBytes(currentProgram,true,false,monitor));
      }
      if(mode.equals("normalized-lifecycle")) {
        String prior=currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(entry.toString(),null);
        int tx=currentProgram.startTransaction("Consumed pointer word mutation");
        try{currentProgram.getMemory().setShort(toAddr(0x203),(short)0x303);}finally{currentProgram.endTransaction(tx,true);}
        save("mutation.json",Map.of("cpu",0x203,"old",0x300,"new",0x303,"oldRegistrationRetained",prior.equals(currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(entry.toString(),null))));
        owner.flushCache();request(getFunctionAt(entry),owner,"stale-root");
        var stale=com.google.gson.JsonParser.parseString(Files.readString(out.resolve("stale-root-request.json"))).getAsJsonObject();
        if(stale.get("completed").getAsBoolean()||stale.get("highfunction_available").getAsBoolean()||!stale.get("error").getAsString().contains("Stale predicated graph"))throw new IllegalStateException("Actual stale use was not specifically refused");
        runScript("GhidraBoyTools.java",new String[]{"stock-predicate-preview",out.resolve("public-premises.json").toString(),out.resolve("refresh-preview.json").toString()},state);
        runScript("GhidraBoyTools.java",new String[]{"stock-predicate-refresh",out.resolve("refresh-preview.json").toString(),entry.toString()},state);
        owner.flushCache();stage("refreshed",entry,owner);
        save("refreshed-placements.json",PredicatedCalls.inspectEmission(currentProgram,entry,0x200000,monitor));
        Files.write(out.resolve("refreshed-fixture.gb"),ProgramMapping.exportBytes(currentProgram,true,false,monitor));
      }
    }finally{owner.dispose();}
    println("FINITE_DISPATCH_CAPTURE_COMPLETE "+mode);
  }
}
