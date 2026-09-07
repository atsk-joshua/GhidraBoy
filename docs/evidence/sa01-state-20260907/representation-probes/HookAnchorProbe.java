import java.io.*;
import java.util.*;
import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.disassemble.Disassembler;
import ghidra.app.decompiler.DecompInterface;
import ghidra.base.project.GhidraProject;
import ghidra.util.task.TaskMonitor;
public class HookAnchorProbe {
  static final String ROOT="/private/tmp/ghidraboy-sa01-representation";
  record Chunk(int bank,int cpu,String hex){}
  static void inspect(Program p,String name)throws Exception {
    System.out.println("PROGRAM "+name+" language="+p.getLanguageID()+" pointer="+p.getDefaultPointerSize()+" PC="+p.getRegister("PC").getMinimumByteSize()+" SP="+p.getRegister("SP").getMinimumByteSize());
    var it=p.getListing().getInstructions(true);
    while(it.hasNext()) {var i=it.next();System.out.println("INSTRUCTION "+i.getAddress()+" "+i+" flows="+Arrays.toString(i.getDefaultFlows()));for(var op:i.getPcode(true))System.out.println("PCODE "+op);}
    var di=new DecompInterface();try {if(!di.openProgram(p))throw new Exception(di.getLastMessage());var f=p.getFunctionManager().getFunctions(true).next();var result=di.decompileFunction(f,20,TaskMonitor.DUMMY);System.out.println("NATIVE complete="+result.decompileCompleted()+" message="+result.getErrorMessage()); if(result.decompileCompleted())System.out.println(result.getDecompiledFunction().getC());}finally{di.dispose();}
  }
  public static void main(String[] args)throws Exception {
    var layout=new GhidraApplicationLayout(new File("/private/tmp/ghidraboy-sa00/ghidra_12.1.3_PUBLIC")) {
      @Override protected Map<String,GModule> findGhidraModules()throws IOException {var result=new HashMap<String,GModule>(super.findGhidraModules());result.put("HookAnchorProbe",new GModule(getApplicationRootDirs(),new ResourceFile(ROOT+"/hook-module")));return result;}
    };
    Application.initializeApplication(layout,new HeadlessGhidraApplicationConfiguration());
    var project=args.length==0?GhidraProject.createProject(ROOT,"entry-hook-anchor-probe",false):GhidraProject.openProject(ROOT,"entry-hook-anchor-probe",false);
    try{
    if(args.length>0){for(var name:List.of("revisit","conditional","data","nested")){var p=project.openProgram("/",name,false);inspect(p,"reopen-"+name);project.close(p);}return;}
    var language=ghidra.program.util.DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("SM83WideExperiment:LE:32:default"));
    var cases=new LinkedHashMap<String,List<Chunk>>();
    cases.put("revisit",List.of(new Chunk(2,0x4100,"043e03ea0020"),new Chunk(3,0x4106,"c30041"),new Chunk(3,0x4100,"0cc30042"),new Chunk(3,0x4200,"c9")));
    cases.put("conditional",List.of(new Chunk(2,0x4100,"ca20413e03ea0020"),new Chunk(3,0x4108,"c30042"),new Chunk(2,0x4120,"3e02ea0020c30042"),new Chunk(2,0x4200,"3e22c9"),new Chunk(3,0x4200,"3e33c9")));
    cases.put("data",List.of(new Chunk(2,0x4100,"fa0050473e03ea0020"),new Chunk(3,0x4109,"fa00504fc9")));
    cases.put("nested",List.of(new Chunk(2,0x4100,"cd004247c9"),new Chunk(2,0x4200,"3e03ea0020"),new Chunk(3,0x4205,"cd00433e02ea0020"),new Chunk(3,0x4300,"0cc9"),new Chunk(2,0x420d,"c9")));
    for(var entry:cases.entrySet()){
      var consumer=new Object();var p=new ProgramDB(entry.getKey(),language,language.getDefaultCompilerSpec(),consumer);p.addConsumer(project);int tx=p.startTransaction("self-authored segmented candidate");
      var body=new AddressSet();var space=p.getAddressFactory().getDefaultAddressSpace();
      for(var chunk:entry.getValue()) {var at=space.getAddress(((long)chunk.bank<<16)|chunk.cpu);var bytes=HexFormat.of().parseHex(chunk.hex);var b=p.getMemory().createInitializedBlock("source_"+chunk.bank+"_"+chunk.cpu,at,new ByteArrayInputStream(bytes),bytes.length,TaskMonitor.DUMMY,false);b.setWrite(false);b.setExecute(true);body.add(at,at.add(bytes.length-1));}
      if(entry.getKey().equals("data")){for(int bank:new int[]{2,3}){var at=space.getAddress(((long)bank<<16)|0x5000);var b=p.getMemory().createInitializedBlock("data_"+bank,at,new ByteArrayInputStream(new byte[]{(byte)(bank==2?0x22:0x33)}),1,TaskMonitor.DUMMY,false);b.setWrite(false);b.setExecute(false);}}
      var d=Disassembler.getDisassembler(p,TaskMonitor.DUMMY,null);for(var chunk:entry.getValue()){var at=space.getAddress(((long)chunk.bank<<16)|chunk.cpu);d.disassemble(at,new AddressSet(at,at.add(chunk.hex.length()/2-1)));}
      p.getListing().getInstructionAt(space.getAddress(0x24100)).setFallThrough(space.getAddress(0x24100));
      if(p.getListing().getInstructionAt(space.getAddress(0x24100)).getFlowType().isJump())p.getListing().getInstructionAt(space.getAddress(0x24100)).setFlowOverride(FlowOverride.RETURN);
      p.getFunctionManager().createFunction(entry.getKey(),space.getAddress(0x24100),body,SourceType.USER_DEFINED);p.endTransaction(tx,true);
      inspect(p,entry.getKey());project.saveAs(p,"/",entry.getKey(),true);p.release(consumer);
    }
    }finally{project.close();}
  }
}
