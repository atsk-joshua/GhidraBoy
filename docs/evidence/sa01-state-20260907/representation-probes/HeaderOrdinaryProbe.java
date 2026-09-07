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
public class HeaderOrdinaryProbe {
  static final String ROOT="/private/tmp/ghidraboy-sa01-representation";
  record Chunk(int bank,int cpu,String hex){}
  static void inspect(Program p,String name)throws Exception {
    System.out.println("PROGRAM "+name+" language="+p.getLanguageID()+" pointer="+p.getDefaultPointerSize()+" PC="+p.getRegister("PC").getMinimumByteSize()+" SP="+p.getRegister("SP").getMinimumByteSize());
    var it=p.getListing().getInstructions(true);
    while(it.hasNext()) {var i=it.next();System.out.println("INSTRUCTION "+i.getAddress()+" "+i+" flows="+Arrays.toString(i.getDefaultFlows()));for(var op:i.getPcode(false))System.out.println("PCODE "+op);}
    var di=new DecompInterface();try {if(!di.openProgram(p))throw new Exception(di.getLastMessage());var f=p.getFunctionManager().getFunctions(true).next();var result=di.decompileFunction(f,20,TaskMonitor.DUMMY);System.out.println("NATIVE complete="+result.decompileCompleted()+" message="+result.getErrorMessage()); if(!result.decompileCompleted() || result.getDecompiledFunction().getC().contains("GhidraBoy conditional execution model:"))throw new Exception("Ordinary function acquired conditional native header");System.out.println(result.getDecompiledFunction().getC());}finally{di.dispose();}
  }
  public static void main(String[] args)throws Exception {
    var layout=new GhidraApplicationLayout(new File("/private/tmp/ghidraboy-sa00/ghidra_12.1.3_PUBLIC")) {
      @Override protected Map<String,GModule> findGhidraModules()throws IOException {var result=new HashMap<String,GModule>(super.findGhidraModules());result.put("HeaderOrdinaryProbe",new GModule(getApplicationRootDirs(),new ResourceFile(ROOT+"/entry-module")));result.put("Decompiler",new GModule(getApplicationRootDirs(),new ResourceFile(ROOT+"/tool-installed-native-context-header/distribution/Ghidra/Features/Decompiler")));return result;}
    };
    Application.initializeApplication(layout,new HeadlessGhidraApplicationConfiguration());
    var project=args.length==0?GhidraProject.createProject(ROOT,"ordinary-no-header-probe",false):GhidraProject.openProject(ROOT,"ordinary-no-header-probe",false);
    try{
    if(args.length>0){for(var name:List.of("ordinary")){var p=project.openProgram("/",name,false);inspect(p,"reopen-"+name);project.close(p);}return;}
    var language=ghidra.program.util.DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("SM83StateExperiment:LE:16:default"));
    var cases=new LinkedHashMap<String,List<Chunk>>();
    cases.put("revisit",List.of(new Chunk(2,0x4100,"043e03ea0020"),new Chunk(3,0x4106,"c30041"),new Chunk(3,0x4100,"0cc30042"),new Chunk(3,0x4200,"c9")));
    cases.put("conditional",List.of(new Chunk(2,0x4100,"ca20413e03ea0020"),new Chunk(3,0x4108,"c30042"),new Chunk(2,0x4120,"3e02ea0020c30042"),new Chunk(2,0x4200,"3e22c9"),new Chunk(3,0x4200,"3e33c9")));
    cases.put("data",List.of(new Chunk(2,0x4100,"fa0050473e03ea0020"),new Chunk(3,0x4109,"fa00504fc9")));
    cases.put("nested",List.of(new Chunk(2,0x4100,"cd004247c9"),new Chunk(2,0x4200,"3e03ea0020"),new Chunk(3,0x4205,"cd00433e02ea0020"),new Chunk(3,0x4300,"0cc9"),new Chunk(2,0x420d,"c9")));
    cases.clear();cases.put("ordinary",List.of(new Chunk(2,0x4100,"3e42c9")));
    for(var entry:cases.entrySet()){
      var consumer=new Object();var p=new ProgramDB(entry.getKey(),language,language.getDefaultCompilerSpec(),consumer);p.addConsumer(project);int tx=p.startTransaction("self-authored segmented candidate");
      var body=new AddressSet();var space=p.getAddressFactory().getDefaultAddressSpace();
      var banks=new HashMap<Integer,AddressSpace>();
      for(int bank:new int[]{2,3}){var b=p.getMemory().createInitializedBlock("rom"+bank,space.getAddress(0x4000),new ByteArrayInputStream(new byte[0x4000]),0x4000,TaskMonitor.DUMMY,true);b.setWrite(false);b.setExecute(true);banks.put(bank,b.getStart().getAddressSpace());}
      for(var chunk:entry.getValue()) {var at=banks.get(chunk.bank).getAddress(chunk.cpu);var bytes=HexFormat.of().parseHex(chunk.hex);p.getMemory().setBytes(at,bytes);if(chunk.bank==2)body.add(at,at.add(bytes.length-1));}
      if(entry.getKey().equals("data")){p.getMemory().setByte(banks.get(2).getAddress(0x5000),(byte)0x22);p.getMemory().setByte(banks.get(3).getAddress(0x5000),(byte)0x33);}
      var d=Disassembler.getDisassembler(p,TaskMonitor.DUMMY,null);for(var chunk:entry.getValue()){var at=banks.get(chunk.bank).getAddress(chunk.cpu);d.disassemble(at,new AddressSet(at,at.add(chunk.hex.length()/2-1)));}
      p.getFunctionManager().createFunction(entry.getKey(),banks.get(2).getAddress(0x4100),body,SourceType.USER_DEFINED);p.getFunctionManager().getFunctionAt(banks.get(2).getAddress(0x4100)).setCallingConvention("__asm");p.endTransaction(tx,true);
      inspect(p,entry.getKey());project.saveAs(p,"/",entry.getKey(),true);p.release(consumer);
    }
    }finally{project.close();}
  }
}
