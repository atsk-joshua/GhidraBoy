// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.services.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.util.ProgramLocation;
import javax.swing.SwingUtilities;
import java.nio.file.*;
import java.util.*;

/** Qualification of the actual normal CodeBrowser provider, never a substitute controller/interface. */
public class GhidraBoyStockWindow extends GhidraBoyW3bDomains {
  DecompilerProvider window;
  void drain()throws Exception {
    currentProgram.flushEvents();Thread.sleep(3000);
    for(int i=0;i<120;i++) {
      boolean[] busy={true};SwingUtilities.invokeAndWait(()->busy[0]=window.getController().isDecompiling());
      if(!busy[0])return;Thread.sleep(250);
    }
    throw new IllegalStateException("Normal window did not settle within bounded wait");
  }
  void navigate(Function f)throws Exception {
    var tool=state.getTool();
    SwingUtilities.invokeAndWait(()->{
      tool.getService(ProgramManager.class).setCurrentProgram(currentProgram);
      tool.getService(GoToService.class).goTo(new ProgramLocation(currentProgram,f.getEntryPoint()));
    });drain();
  }
  void observe(Function f,String label)throws Exception {
    var holder=new ghidra.app.decompiler.component.DecompileData[1];
    SwingUtilities.invokeAndWait(()->holder[0]=window.getController().getDecompileData());
    var data=holder[0];var result=data.getDecompileResults();
    var record=new LinkedHashMap<String,Object>();record.put("surface","normal-CodeBrowser-DecompilerProvider");
    record.put("program",currentProgram.getName());record.put("program_id",currentProgram.getUniqueProgramID());record.put("revision",currentProgram.getModificationNumber());record.put("entry",f.getEntryPoint().toString());
    record.put("controller_identity",System.identityHashCode(window.getController()));record.put("owner_java_pid",ProcessHandle.current().pid());record.put("processes_after",processes());
    record.put("display_program_matches",data.getProgram()==currentProgram);record.put("display_function_matches",data.getFunction()!=null&&data.getFunction().getID()==f.getID());
    record.put("completed",result!=null&&result.decompileCompleted());record.put("highfunction_available",data.getHighFunction()!=null);record.put("error",data.getErrorMessage());
    if(data.getHighFunction()!=null) {
      ids.clear();var blocks=new ArrayList<Object>();
      for(var b:data.getHighFunction().getBasicBlocks()) {
        var in=new ArrayList<Integer>();var out=new ArrayList<Integer>();for(int i=0;i<b.getInSize();i++)in.add(b.getIn(i).getIndex());for(int i=0;i<b.getOutSize();i++)out.add(b.getOut(i).getIndex());
        var ops=new ArrayList<Object>();var iterator=b.getIterator();while(iterator.hasNext())ops.add(operation(iterator.next()));blocks.add(Map.of("index",b.getIndex(),"in",in,"out",out,"ops",ops));
      }
      save(label+"-high.json",blocks);var proto=data.getHighFunction().getFunctionPrototype();var params=new ArrayList<Object>();
      for(int i=0;i<proto.getNumParams();i++){var parameter=proto.getParam(i);params.add(Map.of("name",parameter.getName(),"storage",Arrays.stream(parameter.getStorage().getVarnodes()).map(this::varnode).toList()));}record.put("parameters",params);
    }
    if(result!=null&&result.getDecompiledFunction()!=null)Files.writeString(out.resolve(label+".c"),result.getDecompiledFunction().getC());
    save(label+"-request.json",record);
    SwingUtilities.invokeAndWait(()->{
      try {var component=window.getComponent();var image=new java.awt.image.BufferedImage(component.getWidth(),component.getHeight(),java.awt.image.BufferedImage.TYPE_INT_RGB);var g=image.createGraphics();component.paint(g);g.dispose();javax.imageio.ImageIO.write(image,"png",out.resolve(label+".png").toFile());}catch(Exception e){throw new RuntimeException(e);}
    });
    if(data.getProgram()!=currentProgram||data.getFunction()==null||data.getFunction().getID()!=f.getID())throw new IllegalStateException("Normal window displayed a different Program/Function");
  }
  @Override void request(Function function,DecompInterface ignored,String label)throws Exception {navigate(function);observe(function,label);}
  Program open(String file)throws Exception {
    var domainFile=state.getProject().getProjectData().getFile("/"+file);if(domainFile==null)throw new IllegalStateException("Missing copied fixture "+file);
    Program[] opened=new Program[1];SwingUtilities.invokeAndWait(()->opened[0]=state.getTool().getService(ProgramManager.class).openProgram(domainFile));return opened[0];
  }
  @Override public void run()throws Exception {
    if(isRunningHeadless())throw new IllegalStateException("Requires an actual CodeBrowser tool");
    out=Path.of(askString("Stock window capture","Absolute external evidence directory"));Files.createDirectories(out);
    var provider=state.getTool().getComponentProvider("Decompiler");
    if(!(provider instanceof DecompilerProvider))throw new IllegalStateException("Normal Decompiler provider unavailable");window=(DecompilerProvider)provider;
    var image=open("W4_MEMORY_IMAGE.gb");var domains=open("W3B_DOMAINS.gb");
    currentProgram=domains;domainStage("window-forward",SoftwareCallDomains.views(domains),null);
    currentProgram=image;var entry=StockEntries.entries(image).stream().filter(e->e.generation()!=null&&e.generation().equals(ExecutableImages.history(image).getLast().generation())).findFirst().orElseThrow();
    var root=image.getAddressFactory().getAddress(entry.carrier());stage("window-image2",root,null);
    int tx=image.startTransaction("Disposable warm-window image replacement");
    try{image.getMemory().setBytes(image.getAddressFactory().getDefaultAddressSpace().getAddress(0xc200),HexFormat.of().parseHex("3e31ea74c0c9"));}finally{image.endTransaction(tx,true);}
    drain();observe(getFunctionAt(root),"window-stale-image2");
    tx=image.startTransaction("Explicit new image lifetime and stock presentation");Address next;
    try {
      var generation=ExecutableImages.establish(image,image.getAddressFactory().getDefaultAddressSpace().getAddress(0x300),0xc200,HexFormat.of().parseHex("3e31ea74c0c9"),"explicit GUI qualification lifetime",monitor);
      var source=getFunctionAt(image.getAddressFactory().getAddress(generation.entry()));var memory=SymbolicMemory.declare(image,List.of(),List.of(),generation.generation());
      next=PredicatedCalls.installStock(image,PredicatedCallGraph.preview(image,source,PredicatedCallGraph.Limits.PRIMARY,memory,monitor),monitor);
    }finally{image.endTransaction(tx,true);}
    stage("window-new-image",next,null);
    currentProgram=domains;var reversed=new ArrayList<>(SoftwareCallDomains.views(domains));Collections.reverse(reversed);domainStage("window-reverse",reversed,null);
    currentProgram=image;request(getFunctionAt(next),null,"window-image-back");
    tx=image.startTransaction("Disposable stock registration corruption");
    try{image.getOptions(PredicatedCalls.STOCK_OPTIONS).removeOption(next.toString());}finally{image.endTransaction(tx,true);}
    drain();observe(getFunctionAt(next),"window-missing-registration");
    println("STOCK_NORMAL_WINDOW_CAPTURE_COMPLETE");
  }
  @Override boolean stock(){return true;}
}
