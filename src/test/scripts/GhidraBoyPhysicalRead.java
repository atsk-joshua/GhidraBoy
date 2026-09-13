// @category Game Boy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.disassemble.Disassembler;
import java.nio.file.*;
import java.util.*;

/** Independently authored direct/indirect physical read discriminator; real source RET. */
public class GhidraBoyPhysicalRead extends GhidraBoyPredicatedCalls {
  public void run() throws Exception {
    Path home=Path.of(getScriptArgs()[0]);Files.createDirectories(home);
    var language=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("SM83:LE:16:default"));
    for(int bank:List.of(1,2))for(boolean direct:List.of(true,false)) {
      String label="bank"+bank+"-"+(direct?"direct":"indirect");out=home.resolve(label);Files.createDirectories(out);
      byte[] image=new byte[0x10000];image[0x147]=0x19;image[0x148]=1;image[0x149]=0;
      image[0x4123]=0x35;image[0x8123]=(byte)0xca;
      byte[] code=HexFormat.of().parseHex("3e0"+bank+"ea0020"+(direct?"fa2341":"2123417e")+"c9");System.arraycopy(code,0,image,0x180,code.length);
      Object consumer=new Object();var p=new ProgramDB(label,language,language.getDefaultCompilerSpec(),consumer);
      try {
        try(var bytes=new ByteArrayProvider(image)){CartridgeLayout.load(p,bytes,"CARTRIDGE","AUTO",GameBoyKind.GB,true,false,monitor,new MessageLog());}
        currentProgram=p;state.setCurrentProgram(p);currentAddress=p.getAddressFactory().getDefaultAddressSpace().getAddress(0x180);state.setCurrentAddress(currentAddress);
        int tx=p.startTransaction("Self-authored source fixture");try {
          var body=new AddressSet(currentAddress,currentAddress.add(code.length-1));Disassembler.getDisassembler(p,monitor,null).disassemble(currentAddress,body,false);
          var f=p.getFunctionManager().createFunction("physical_read",currentAddress,body,SourceType.USER_DEFINED);
          f.updateFunction("default",new ReturnParameterImpl(ByteDataType.dataType,p.getRegister("A"),p),Function.FunctionUpdateType.CUSTOM_STORAGE,true,SourceType.USER_DEFINED);
        }finally{p.endTransaction(tx,true);}
        var times=new LinkedHashMap<String,Object>();long start=System.nanoTime();
        var proof=PredicatedCalls.preview(p,new PredicatedCalls.Premises(currentAddress.toString(),List.of(),null),monitor);times.put("deriveNs",System.nanoTime()-start);save("preview.json",proof);
        if(!proof.complete())throw new IllegalStateException("Incomplete: "+proof.frontier());
        start=System.nanoTime();var entry=PredicatedCalls.install(p,proof,monitor);times.put("validateApplyNs",System.nanoTime()-start);
        start=System.nanoTime();var emitted=PredicatedCalls.emit(p,entry,0x200000,monitor);times.put("validateLowerNs",System.nanoTime()-start);
        ids.clear();save("emitted.json",Arrays.stream(emitted).map(this::operation).toList());
        start=System.nanoTime();var owner=owner();try{stage("original",entry,owner);}finally{owner.dispose();}times.put("nativeStageNs",System.nanoTime()-start);
        times.put("heapUsed",Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory());times.put("proofBytes",Files.size(out.resolve("original-proof.json")));save("cost.json",times);
      }finally{state.setCurrentProgram(null);p.release(consumer);}
    }
    println("PHYSICAL_READ_CAPTURE_COMPLETE");
  }
}
