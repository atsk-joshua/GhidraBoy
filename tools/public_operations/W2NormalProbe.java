import fi.gekkio.ghidraboy.*;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.base.project.GhidraProject;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.services.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.*;
import javax.swing.SwingUtilities;
import docking.widgets.fieldpanel.listener.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/** Bounded normal-provider observation. Display callbacks are NOT complete native request coverage. */
public class W2NormalProbe extends GhidraBoyPublicLifecycleWindow implements GhidraLaunchable {
  static volatile W2NormalProbe activeProbe;
  /** Called only by the external JVM observer at public native API boundaries. */
  public static void nativeBoundary(ghidra.program.model.listing.Function function,TaskMonitor requestMonitor,String boundary,String requestId,Object result,long codeIndex) {
    var probe=activeProbe;if(probe==null)return;
    try {
      var p=function.getProgram();var record=new LinkedHashMap<String,Object>();
      record.put("request_id",requestId);record.put("boundary",boundary);record.put("return_code_index",codeIndex);record.put("monitor_cancelled",requestMonitor==null?null:requestMonitor.isCancelled());record.put("program",probe.identity(p));record.put("entry",function.getEntryPoint().toString());record.put("function_id",function.getID());record.put("function",probe.function(function));record.put("entry_authority",probe.authority(p,function.getEntryPoint()));
      record.put("transaction",probe.transaction(p.getCurrentTransactionInfo()));record.put("revision",p.getModificationNumber());record.put("phase",probe.phase);record.put("operation_at_boundary",probe.observedOperation);
      record.put("registration",probe.stockRegistration(p,function.getEntryPoint()));record.put("thread",Thread.currentThread().getName());record.put("java_thread_id",Thread.currentThread().threadId());record.put("result_object",result==null?null:System.identityHashCode(result));
      if(result instanceof ghidra.app.decompiler.DecompileResults r){probe.nativeResults.put(result,requestId);record.put("completed",r.decompileCompleted());record.put("error",r.getErrorMessage());record.put("cancelled",r.isCancelled());record.put("timed_out",r.isTimedOut());record.put("failed_to_start",r.failedToStart());}
      probe.event("native-api-boundary",record);
    }catch(Throwable failure){probe.observerFailure=failure;failure.printStackTrace();}
  }
  final Map<Object,String> nativeResults=Collections.synchronizedMap(new IdentityHashMap<>());
  final Map<Object,String> displayPrefixes=Collections.synchronizedMap(new IdentityHashMap<>());
  final Set<Object> displayed=Collections.newSetFromMap(new IdentityHashMap<>());
  volatile String phase="baseline";
  volatile String observedOperation="UNKNOWN";
  volatile Throwable observerFailure;
  LayoutModelListener displayListener;
  static void widen(java.awt.Component component,java.awt.Component target) {
    if(component instanceof javax.swing.JSplitPane split && split.getOrientation()==javax.swing.JSplitPane.HORIZONTAL_SPLIT
        && split.getRightComponent()!=null && SwingUtilities.isDescendingFrom(target,split.getRightComponent()))split.setDividerLocation(0.4);
    if(component instanceof java.awt.Container container)for(var child:container.getComponents())widen(child,target);
  }
  void captureDesktop(String label,Map<String,Object> record)throws Exception {
    if(!Boolean.getBoolean("ghidraboy.desktopCapture"))return;
    var frame=SwingUtilities.getWindowAncestor(window.getComponent());
    require(frame!=null&&frame.isShowing()&&window.getComponent().isShowing(),"Desktop capture requires visible normal provider: "+label);
    if(frame instanceof java.awt.Frame f)f.setExtendedState(java.awt.Frame.MAXIMIZED_BOTH);
    frame.setAlwaysOnTop(true);frame.setVisible(true);frame.toFront();frame.requestFocus();
    if(java.awt.Desktop.isDesktopSupported()&&java.awt.Desktop.getDesktop().isSupported(java.awt.Desktop.Action.APP_REQUEST_FOREGROUND))java.awt.Desktop.getDesktop().requestForeground(true);
    java.awt.Toolkit.getDefaultToolkit().sync();var robot=new java.awt.Robot();robot.delay(500);
    var point=frame.getLocationOnScreen();var image=out.resolve(label+"-desktop.png");
    javax.imageio.ImageIO.write(robot.createScreenCapture(new java.awt.Rectangle(point.x,point.y,frame.getWidth(),frame.getHeight())),"png",image.toFile());
    record.put("desktop_window_active",frame.isActive());record.put("desktop_window_focused",frame.isFocused());
    record.put("desktop_window_bounds",Map.of("x",point.x,"y",point.y,"width",frame.getWidth(),"height",frame.getHeight()));
    record.put("desktop_sha256",hash(image));record.put("visual_inspection","CAPTURED_UNREVIEWED");
  }
  String stockRegistration(Program p,Address at) {
    return W2AuthorityProbe.predicatedStockRecord(p,at);
  }
  Map<String,Object> function(Function f) {
    if(f==null)return Map.of("present",false);
    var result=new LinkedHashMap<String,Object>();result.put("present",true);result.put("class",f.getClass().getName());result.put("object",System.identityHashCode(f));result.put("id",f.getID());result.put("name",f.getName());result.put("entry",f.getEntryPoint().toString());result.put("body",f.getBody().toString());result.put("calling_convention_name",f.getCallingConventionName());result.put("calling_convention_model",f.getCallingConvention()==null?"NONE":f.getCallingConvention().getName());result.put("call_fixup",Objects.toString(f.getCallFixup(),"NONE"));result.put("thunk",f.isThunk());result.put("thunk_target",f.getThunkedFunction(true)==null?"NONE":f.getThunkedFunction(true).getEntryPoint().toString());result.put("inline",f.isInline());result.put("no_return",f.hasNoReturn());result.put("custom_storage",f.hasCustomVariableStorage());result.put("varargs",f.hasVarArgs());result.put("stack_purge",f.getStackPurgeSize());return result;
  }
  Map<String,Object> authority(Program p,Address at) {
    var result=new LinkedHashMap<String,Object>();result.put("address",at.toString());var manager=p.getFunctionManager();result.put("function_at",function(manager.getFunctionAt(at)));result.put("function_containing",function(manager.getFunctionContaining(at)));
    var block=p.getMemory().getBlock(at);if(block==null)result.put("block",Map.of("present",false));else {var item=new LinkedHashMap<String,Object>();item.put("present",true);item.put("name",block.getName());item.put("space",block.getStart().getAddressSpace().getName());item.put("start",block.getStart().toString());item.put("end",block.getEnd().toString());item.put("overlay",block.isOverlay());item.put("mapped",block.isMapped());item.put("initialized",block.isInitialized());item.put("comment",Objects.toString(block.getComment(),"NONE"));item.put("read",block.isRead());item.put("write",block.isWrite());item.put("execute",block.isExecute());item.put("volatile",block.isVolatile());item.put("sources",block.getSourceInfos().stream().map(s->Map.of("description",s.getDescription(),"min",s.getMinAddress().toString(),"max",s.getMaxAddress().toString(),"mapped",s.getMappedRange().map(Object::toString).orElse("NONE"),"file_bytes",s.getFileBytes().map(f->f.getFilename()).orElse("NONE"))).toList());result.put("block",item);}
    var predicate=p.getOptionsNames().contains(PredicatedCalls.STOCK_OPTIONS)&&p.getOptions(PredicatedCalls.STOCK_OPTIONS).contains(at.toString());var ordinary=p.getOptionsNames().contains(OrdinaryEntryAccess.STOCK_OPTIONS)&&p.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS).contains(at.toString());var carrierComment=block!=null&&"GhidraBoy stock carrier storage v3".equals(block.getComment());result.put("stock_owned_by_block",carrierComment);result.put("stock_predicate_cache_present",predicate);result.put("stock_ordinary_cache_present",ordinary);result.put("production_membership",W2AuthorityProbe.observe(p,at));result.put("stock_entries",StockEntries.entries(p));var register=p.getRegister("gb_analysis_entry");result.put("gb_analysis_entry",register==null?null:String.valueOf(p.getProgramContext().getValue(register,at,false)));result.put("revision",p.getModificationNumber());return result;
  }
  synchronized void display(String callback) {
    try {
      var data=window.getController().getDecompileData();
      if(data==null||!displayed.add(data))return;
      var record=new LinkedHashMap<String,Object>();
      record.put("phase",phase);record.put("callback",callback);record.put("data_object",System.identityHashCode(data));
      record.put("native_request_id","UNOBSERVED");record.put("operation_at_callback",observedOperation);
      record.put("provider_object",System.identityHashCode(window));record.put("provider_class",window.getClass().getName());
      var p=data.getProgram();var f=data.getFunction();var result=data.getDecompileResults();
      record.put("program",p==null?null:identity(p));record.put("entry",f==null?null:f.getEntryPoint().toString());
      record.put("function_id",f==null?null:f.getID());record.put("function",function(f));record.put("code_viewer_location",state.getTool().getService(CodeViewerService.class).getCurrentLocation().getAddress().toString());record.put("entry_authority",p==null||f==null?null:authority(p,f.getEntryPoint()));record.put("transaction_at_callback",p==null?null:transaction(p.getCurrentTransactionInfo()));
      record.put("revision_at_callback",p==null?null:p.getModificationNumber());
      record.put("registration_at_callback",p==null||f==null?null:stockRegistration(p,f.getEntryPoint()));
      record.put("eligibility_at_native_request","UNOBSERVED");
      record.put("completed",result!=null&&result.decompileCompleted());record.put("high_available",data.getHighFunction()!=null);
      record.put("error",data.getErrorMessage());record.put("result_object",result==null?null:System.identityHashCode(result));
      String prefix="display-"+displayed.size();displayPrefixes.put(data,prefix);
      if(result!=null&&result.getDecompiledFunction()!=null){Files.writeString(out.resolve(prefix+".c"),result.getDecompiledFunction().getC());record.put("c_file",prefix+".c");record.put("c_sha256",hash(out.resolve(prefix+".c")));}
      if(data.getHighFunction()!=null){
        ids.clear();var blocks=new ArrayList<Object>();
        for(var b:data.getHighFunction().getBasicBlocks()){
          var ops=new ArrayList<Object>();var iterator=b.getIterator();while(iterator.hasNext())ops.add(operation(iterator.next()));
          var in=new ArrayList<Integer>();var edges=new ArrayList<Integer>();for(int i=0;i<b.getInSize();i++)in.add(b.getIn(i).getIndex());for(int i=0;i<b.getOutSize();i++)edges.add(b.getOut(i).getIndex());
          blocks.add(Map.of("index",b.getIndex(),"in",in,"out",edges,"ops",ops));
        }
        save(prefix+"-high.json",blocks);record.put("high_file",prefix+"-high.json");record.put("high_sha256",hash(out.resolve(prefix+"-high.json")));
      }
      save(prefix+".json",record);event("display-data",record);
    }catch(Throwable failure){observerFailure=failure;failure.printStackTrace();}
  }
  Map<String,Object> topology() {
    var p=currentProgram;var spaces=new ArrayList<Object>();var blocks=new ArrayList<Object>();
    for(var s:p.getAddressFactory().getAllAddressSpaces())spaces.add(Map.of("name",s.getName(),"id",s.getSpaceID(),"type",s.getType(),"size",s.getSize(),"overlay",s.isOverlaySpace(),"physical_space",s.getPhysicalSpace().getName()));
    for(var b:p.getMemory().getBlocks()){
      var item=new LinkedHashMap<String,Object>();item.put("name",b.getName());item.put("start",b.getStart().toString());item.put("end",b.getEnd().toString());item.put("space",b.getStart().getAddressSpace().getName());item.put("size",b.getSize());item.put("type",b.getType().toString());item.put("initialized",b.isInitialized());item.put("read",b.isRead());item.put("write",b.isWrite());item.put("execute",b.isExecute());item.put("overlay",b.isOverlay());
      item.put("sources",b.getSourceInfos().stream().map(s->Map.of("description",s.getDescription(),"min",s.getMinAddress().toString(),"max",s.getMaxAddress().toString(),"mapped",s.getMappedRange().map(Object::toString).orElse("NONE"),"file_bytes",s.getFileBytes().map(f->f.getFilename()).orElse("NONE"))).toList());blocks.add(item);
    }
    return Map.of("program",identity(p),"revision",p.getModificationNumber(),"transaction",transaction(p.getCurrentTransactionInfo()),"spaces",spaces,"blocks",blocks,"domains",p.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames());
  }
  @Override GhidraBoyTools action(String... args)throws Exception {
    var script=start(new java.io.PrintWriter(System.out,true),args);
    if(script.lastOperation!=null){observedOperation=script.lastOperation.id();var outcome=script.lastOperation.completion().get(60,TimeUnit.SECONDS);save("operation-"+observedOperation+".json",outcome);event("public-action-outcome",outcome);var disposition=script.lastPresentation.get(60,TimeUnit.SECONDS);script.lastOperation.released().get(60,TimeUnit.SECONDS);event("public-action-presentation",Map.of("operation",observedOperation,"disposition",disposition));require(outcome.current(),"Public action outcome not current");}
    return script;
  }
  @Override void diagnosticDisplay(String label)throws Exception {
    SwingUtilities.invokeAndWait(()->display(label));save(label+"-processes.json",processes());
  }
  @Override void observe(Function expected,String label)throws Exception {
    if(target!=expected)target=expected;
    while(true) {
    var record=new LinkedHashMap<String,Object>();
    boolean[] raced={false};
    SwingUtilities.invokeAndWait(()->{
      try {
        long revision=currentProgram.getModificationNumber();var data=window.getController().getDecompileData();
        if(currentProgram.getCurrentTransactionInfo()!=null || window.getController().isDecompiling() || state.getTool().getService(ProgramManager.class).getCurrentProgram()!=currentProgram || revision!=settledRevision || count(currentProgram)!=settledEvents || data!=settledData){raced[0]=true;return;}
        var result=data==null?null:data.getDecompileResults();var f=data==null?null:data.getFunction();
        record.put("surface","normal-CodeBrowser-DecompilerProvider");
        record.put("provider_origin",window.getClass().getProtectionDomain().getCodeSource().getLocation().toString());
        record.put("extension_origin",StockEntries.class.getProtectionDomain().getCodeSource().getLocation().toString());
        record.put("provider_class",window.getClass().getName());record.put("controller_class",window.getController().getClass().getName());
        var nativeFile=ghidra.framework.Application.getOSFile("Decompiler","decompile").toPath();record.put("resolved_native",nativeFile.toString());record.put("native_sha256",hash(nativeFile));record.put("phase",label);
        record.put("program",currentProgram.getName());record.put("program_id",currentProgram.getUniqueProgramID());
        record.put("program_object",System.identityHashCode(currentProgram));record.put("revision",revision);
        record.put("entry",expected.getEntryPoint().toString());record.put("function_id",expected.getID());
        record.put("function",function(f));record.put("entry_authority",authority(currentProgram,expected.getEntryPoint()));record.put("code_viewer_location",state.getTool().getService(CodeViewerService.class).getCurrentLocation().getAddress().toString());
        record.put("controller_identity",System.identityHashCode(window.getController()));record.put("owner_java_pid",ProcessHandle.current().pid());
        record.put("java_start",ProcessHandle.current().info().startInstant().orElseThrow().toString());
        record.put("display_program_id",data==null||data.getProgram()==null?null:data.getProgram().getUniqueProgramID());
        record.put("display_program_matches",data!=null&&data.getProgram()==currentProgram);
        record.put("display_entry",f==null?null:f.getEntryPoint().toString());record.put("display_function_matches",f!=null&&f.getID()==expected.getID());
        record.put("completed",result!=null&&result.decompileCompleted());record.put("highfunction_available",data!=null&&data.getHighFunction()!=null);
        record.put("error",data==null?"no displayed data":data.getErrorMessage());record.put("data_identity",System.identityHashCode(data));
        record.put("events",count(currentProgram));record.put("schema",2);record.put("transaction_free",true);record.put("read_only",currentProgram.isChangeable()==false);
        if(data!=null&&data.getHighFunction()!=null) {
          ids.clear();var blocks=new ArrayList<Object>();
          for(var b:data.getHighFunction().getBasicBlocks()) {
            var in=new ArrayList<Integer>();var outEdges=new ArrayList<Integer>();for(int i=0;i<b.getInSize();i++)in.add(b.getIn(i).getIndex());for(int i=0;i<b.getOutSize();i++)outEdges.add(b.getOut(i).getIndex());
            var ops=new ArrayList<Object>();var iterator=b.getIterator();while(iterator.hasNext())ops.add(operation(iterator.next()));blocks.add(Map.of("index",b.getIndex(),"in",in,"out",outEdges,"ops",ops));
          }
          save(label+"-high.json",blocks);record.put("high_sha256",hash(out.resolve(label+"-high.json")));
          var proto=data.getHighFunction().getFunctionPrototype();var params=new ArrayList<Object>();
          for(int i=0;i<proto.getNumParams();i++){var p=proto.getParam(i);params.add(Map.of("name",p.getName(),"storage",Arrays.stream(p.getStorage().getVarnodes()).map(this::varnode).toList()));}record.put("parameters",params);
        }
        if(result!=null&&result.getDecompiledFunction()!=null){Files.writeString(out.resolve(label+".c"),result.getDecompiledFunction().getC());record.put("c_sha256",hash(out.resolve(label+".c")));}
        var frame=SwingUtilities.getWindowAncestor(window.getComponent());record.put("visible",frame!=null&&frame.isShowing()&&window.getComponent().isShowing());
        record.put("visual_inspection","UNOBSERVED");captureDesktop(label,record);
        record.put("native_request_id",nativeResults.get(result));
        record.put("retained_display_prefix",displayPrefixes.get(data));
        if(currentProgram.getCurrentTransactionInfo()!=null || window.getController().isDecompiling() || state.getTool().getService(ProgramManager.class).getCurrentProgram()!=currentProgram || revision!=currentProgram.getModificationNumber()||count(currentProgram)!=settledEvents||data!=window.getController().getDecompileData()){raced[0]=true;return;}
        save(label+"-request.json",record);
      }catch(Exception e){throw new RuntimeException(e);}
    });
    if(raced[0]){String discarded=label+"-discarded-"+(++discardedSequence);
      for(String suffix:List.of("-high.json",".c","-desktop.png","-request.json")){
        Path file=out.resolve(label+suffix);if(Files.exists(file))Files.move(file,out.resolve(discarded+suffix));}
      event("snapshot-discarded",Map.of("phase",label,"artifact_prefix",discarded,"reason","transaction/revision/result race"));
      drainUntil(settlementDeadline);continue;}
    event("passive-capture",Map.of("phase",label,"record_sha256",hash(out.resolve(label+"-request.json"))));
    // Diagnostic process enumeration happens only after passive snapshot, and is not result attribution.
    save(label+"-processes.json",processes());break;
    }
      Program program=currentProgram;long revision=program.getModificationNumber();Address entry=expected.getEntryPoint();
    String registration=stockRegistration(program,entry);
    var proof=PredicatedCalls.registeredProof(program,entry);var views=PredicatedCalls.views(program,entry);
    require(views.size()==1&&views.getFirst().invocation().equals("root"),"Normal collector expects the bounded inline conditional root");
    identity(label+"-before",entry);save(label+"-proof.json",proof);var raw=new TreeMap<String,Object>();
    try(var discovery=SoftwareCallInstructionDiscovery.begin(program,monitor)) {
      for(var node:proof.nodes())if(!raw.containsKey(node.source())) {
        var instruction=SoftwareCallInstructionDiscovery.instructionAt(program,ProgramMapping.staticAddress(program,node.source()),"Validated conditional source root",monitor);ids.clear();
        raw.put(node.source(),Map.of("address",node.source(),"bytes",HexFormat.of().formatHex(instruction.getBytes()),"physical",ProgramMapping.staticToPhysical(program,instruction.getAddress()),"ops",Arrays.stream(instruction.getPcode(false)).map(this::operation).toList()));
      }
    }
    save(label+"-raw.json",raw);ids.clear();save(label+"-root-requested.json",Arrays.stream(PredicatedCalls.emitStock(program,entry,0x200000,monitor)).map(this::operation).toList());
    save(label+"-views.json",List.of(Map.of("tag","root","view",views.getFirst())));
    Files.copy(out.resolve(label+"-high.json"),out.resolve(label+"-root-high.json"));
    var record=com.google.gson.JsonParser.parseString(Files.readString(out.resolve(label+"-request.json"))).getAsJsonObject();
    record.addProperty("entry",entry.toString());record.add("processes_after",com.google.gson.JsonParser.parseString(Files.readString(out.resolve(label+"-processes.json"))));
    record.addProperty("normal_window_capture",true);save(label+"-root-request.json",record);
    Files.write(out.resolve(label+"-fixture.gb"),ProgramMapping.exportBytes(program,true,false,monitor));
    require(revision==program.getModificationNumber() && Objects.equals(registration,stockRegistration(program,entry)),"Source changed during passive evidence binding");
    save(label+"-source-binding.json",Map.of("revision",revision,"program",identity(program),"record_sha256",hash(out.resolve(label+"-request.json")),
        "high_sha256",hash(out.resolve(label+"-root-high.json")),"raw_sha256",hash(out.resolve(label+"-raw.json")),"proof_sha256",hash(out.resolve(label+"-proof.json")),
        "emitted_sha256",hash(out.resolve(label+"-root-requested.json")),"image_sha256",hash(out.resolve(label+"-fixture.gb"))));
  }
  /** Physical navigation can legitimately select an address without a Function. */
  void settlePhysical(String label)throws Exception {
    long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(60);Object previous=null;long revision=-1;int events=-1,stable=0;
    while(System.nanoTime()<deadline) {
      currentProgram.flushEvents();Object[] data={null};boolean[] idle={false};
      SwingUtilities.invokeAndWait(()->{data[0]=window.getController().getDecompileData();idle[0]=!window.getController().isDecompiling()&&state.getTool().getService(ProgramManager.class).getCurrentProgram()==currentProgram;});
      long now=currentProgram.getModificationNumber();int countNow=count(currentProgram);
      stable=idle[0]&&currentProgram.getCurrentTransactionInfo()==null&&data[0]==previous&&now==revision&&countNow==events?stable+1:0;
      previous=data[0];revision=now;events=countNow;
      if(stable>=24&&System.nanoTime()-last(currentProgram)>=TimeUnit.SECONDS.toNanos(6)) {
        var details=new LinkedHashMap<String,Object>();details.put("phase",label);details.put("program",identity(currentProgram));details.put("revision",revision);details.put("events",events);details.put("stable_samples",stable);details.put("location",state.getTool().getService(CodeViewerService.class).getCurrentLocation().getAddress().toString());
        var function=currentProgram.getFunctionManager().getFunctionContaining(state.getTool().getService(CodeViewerService.class).getCurrentLocation().getAddress());details.put("containing_function",function==null?"NONE":function.getEntryPoint().toString());
        event("physical-provider-settled",details);diagnosticDisplay(label);return;
      }
      Thread.sleep(250);
    }
    diagnosticDisplay(label+"-timeout");throw new IllegalStateException("Physical provider did not settle: "+label);
  }
  void navigatePhysical(Address address,String label)throws Exception {
    phase=label;
    sample(currentProgram,"before-navigation-"+label);event("navigate",Map.of("phase",label,"program",currentProgram.getName(),"entry",address.toString()));
    SwingUtilities.invokeAndWait(()->{state.getTool().getService(ProgramManager.class).setCurrentProgram(currentProgram);state.getTool().getService(GoToService.class).goTo(new ProgramLocation(currentProgram,address));});sample(currentProgram,"after-navigation-"+label);
  }
  void capturePhysical(String label,Address address)throws Exception {
    var record=new LinkedHashMap<String,Object>();
    SwingUtilities.invokeAndWait(()->{
      try {
        var data=window.getController().getDecompileData();var function=data==null?null:data.getFunction();var result=data==null?null:data.getDecompileResults();
        require(data!=null&&data.getProgram()==currentProgram&&function!=null&&function.getEntryPoint().equals(address),"Wrong physical normal-provider result: "+label);
        require(result!=null&&result.decompileCompleted()&&data.getHighFunction()!=null&&result.getDecompiledFunction()!=null&&!result.getDecompiledFunction().getC().isBlank(),"Unusable physical normal-provider result: "+label+" error="+data.getErrorMessage());
        record.put("label",label);record.put("program",identity(currentProgram));record.put("revision",currentProgram.getModificationNumber());record.put("entry",address.toString());record.put("code_viewer_location",state.getTool().getService(CodeViewerService.class).getCurrentLocation().getAddress().toString());record.put("function",function(function));record.put("authority",authority(currentProgram,address));record.put("result_object",System.identityHashCode(result));record.put("native_request_id",nativeResults.get(result));record.put("completed",true);record.put("error",data.getErrorMessage());record.put("high_available",true);record.put("provider_class",window.getClass().getName());record.put("provider_object",System.identityHashCode(window));record.put("controller_object",System.identityHashCode(window.getController()));
        Files.writeString(out.resolve(label+".c"),result.getDecompiledFunction().getC());record.put("c_sha256",hash(out.resolve(label+".c")));
        ids.clear();var high=new ArrayList<Object>();for(var block:data.getHighFunction().getBasicBlocks()){var ops=new ArrayList<Object>();var iterator=block.getIterator();while(iterator.hasNext())ops.add(operation(iterator.next()));high.add(Map.of("index",block.getIndex(),"ops",ops));}save(label+"-high.json",high);record.put("high_sha256",hash(out.resolve(label+"-high.json")));
        var instruction=currentProgram.getListing().getInstructionAt(address);ids.clear();save(label+"-raw.json",Map.of("address",address.toString(),"bytes",HexFormat.of().formatHex(instruction.getBytes()),"ops",Arrays.stream(instruction.getPcode(false)).map(this::operation).toList()));record.put("raw_sha256",hash(out.resolve(label+"-raw.json")));
        captureDesktop(label,record);save(label+"-request.json",record);
      }catch(Exception failure){throw new RuntimeException(failure);}
    });
    event("physical-capture",Map.of("phase",label,"entry",address.toString(),"record_sha256",hash(out.resolve(label+"-request.json"))));
  }
  void captureStale(String label,Address oldEntry,Address currentEntry)throws Exception {
    var record=new LinkedHashMap<String,Object>();
    SwingUtilities.invokeAndWait(()->{
      try {
        var data=window.getController().getDecompileData();var function=data==null?null:data.getFunction();var result=data==null?null:data.getDecompileResults();
        require(data!=null&&data.getProgram()==currentProgram&&function!=null&&function.getEntryPoint().equals(oldEntry),"Wrong old-domain stale result");
        require(data.getHighFunction()==null&&result!=null&&!result.decompileCompleted()&&String.valueOf(data.getErrorMessage()).contains("Stale predicated graph registration"),"Old-domain stale refusal missing");
        record.put("label",label);record.put("program",identity(currentProgram));record.put("revision",currentProgram.getModificationNumber());record.put("old_entry",oldEntry.toString());record.put("current_entry",currentEntry.toString());record.put("display_entry",function.getEntryPoint().toString());record.put("result_object",System.identityHashCode(result));record.put("native_request_id",nativeResults.get(result));record.put("error",data.getErrorMessage());record.put("completed",result.decompileCompleted());record.put("high_available",false);save(label+".json",record);
      }catch(Exception failure){throw new RuntimeException(failure);}
    });
    event("old-domain-stale-control",record);
  }
  Map<String,Object> savedAuthority(Program p,Address entry) {
    var observed=authority(p,entry);observed.remove("revision");
    for(String name:List.of("function_at","function_containing")) {
      var stable=new LinkedHashMap<String,Object>((Map<String,Object>)observed.get(name));stable.remove("object");observed.put(name,stable);
    }
    return Map.of("program_id",p.getUniqueProgramID(),"file_id",String.valueOf(p.getDomainFile().getFileID()),"entry",entry.toString(),"authority",observed,"stock_entries",StockEntries.entries(p));
  }
  void physicalDiagnostic(Program p,Address carrier)throws Exception {
    phase="physical-diagnostic";var proof=PredicatedCalls.registeredProof(p,carrier);var targetAddresses=proof.boundaries().stream().filter(b->b.kind().equals("RET_DISPATCH")).map(b->ProgramMapping.staticAddress(p,b.physical())).distinct().toList();var continuationAddresses=proof.boundaries().stream().filter(b->b.kind().equals("MATCHED_CALL_COMPLETION")).map(b->ProgramMapping.staticAddress(p,b.physical())).distinct().toList();require(targetAddresses.size()==1&&continuationAddresses.size()==1,"Diagnostic needs one physical target and continuation");var physicalTarget=targetAddresses.getFirst();var continuation=continuationAddresses.getFirst();
    var before=authority(p,physicalTarget);long revision=p.getModificationNumber();var options=p.getOptions(PredicatedCalls.STOCK_OPTIONS);require(!options.contains(physicalTarget.toString()),"Physical pollution control did not begin absent");
    String polluted=options.getString(physicalTarget.toString(),null);var after=authority(p,physicalTarget);var membership=(Map<?,?>)after.get("production_membership");
    require(polluted==null&&options.contains(physicalTarget.toString())&&revision==p.getModificationNumber(),"Labeled pollution control did not reproduce cache-only typed entry");
    require(Boolean.FALSE.equals(membership.get("stock_entry_owned"))&&Boolean.FALSE.equals(membership.get("predicated_registered"))&&Boolean.FALSE.equals(membership.get("ordinary_registered")),"Physical pollution manufactured executable authority");
    save("physical-pollution-control.json",Map.of("label","INTENTIONAL_NEGATIVE_CONTROL_ONLY","address",physicalTarget.toString(),"revision_before",revision,"revision_after",p.getModificationNumber(),"typed_read_result","NULL","before",before,"after",after));
    navigatePhysical(physicalTarget,"physical-target-after-pollution");settlePhysical("physical-target-after-pollution");capturePhysical("physical-target-after-pollution",physicalTarget);
    navigatePhysical(continuation,"physical-continuation-after-pollution");settlePhysical("physical-continuation-after-pollution");capturePhysical("physical-continuation-after-pollution",continuation);
    phase="genuine-carrier-positive";target=p.getFunctionManager().getFunctionAt(carrier);navigate(target,"genuine-carrier-positive");observe(target,"genuine-carrier-positive");
    navigatePhysical(physicalTarget,"physical-target-after-carrier");settlePhysical("physical-target-after-carrier");capturePhysical("physical-target-after-carrier",physicalTarget);
    navigatePhysical(continuation,"physical-continuation-after-carrier");settlePhysical("physical-continuation-after-carrier");capturePhysical("physical-continuation-after-carrier",continuation);
    save("physical-diagnostic.json",Map.of("carrier",authority(p,carrier),"target",authority(p,physicalTarget),"continuation",authority(p,continuation),"program",identity(p),"revision",p.getModificationNumber(),"observer_failure",String.valueOf(observerFailure)));
  }
  @Override public void run()throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    currentProgram=state.getTool().getService(ProgramManager.class).getCurrentProgram();var p=currentProgram;p.addConsumer(this);
    window=(DecompilerProvider)state.getTool().getComponentProvider("Decompiler");
    try {
      activeProbe=this;listen(p);var seed=StockEntries.entries(p).stream().filter(e->e.generation()==null).findFirst().orElseThrow();var seedAt=ProgramMapping.staticAddress(p,seed.carrier());target=p.getFunctionManager().getFunctionAt(seedAt);
      displayListener=new LayoutModelListener(){public void modelSizeChanged(IndexMapper m){display("modelSizeChanged");}public void dataChanged(BigInteger a,BigInteger b){display("dataChanged");}};
      SwingUtilities.invokeAndWait(()->{window.getDecompilerPanel().getLayoutController().addLayoutModelListener(displayListener);display("observer-baseline");});
      event("observer-installed",Map.of("mechanism","synchronous-layout-model-listener","coverage","DISPLAYED_DATA_ONLY","native_request_coverage","UNOBSERVED","provider_object",System.identityHashCode(window),"normal_provider_class",window.getClass().getName(),"showing",window.getComponent().isShowing(),"program",identity(p)));
      if(Boolean.getBoolean("ghidraboy.w2R3Immutable")) {
        require(!p.isChangeable(),"W2-R3 second JVM Program is not immutable");var expected=com.google.gson.JsonParser.parseString(Files.readString(Path.of(System.getProperty("ghidraboy.w2R3Baseline")))).getAsJsonObject();var immutableEntry=ProgramMapping.staticAddress(p,expected.get("entry").getAsString());target=p.getFunctionManager().getFunctionAt(immutableEntry);require(target!=null,"Saved immutable carrier missing");phase="immutable-first";event("immutable-first-request-navigation",Map.of("entry",immutableEntry.toString(),"prior_display","NO_FUNCTION_AT_0100","purpose","initiate first immutable stock-authority use; not recovery"));navigate(target,"immutable-first");observe(target,"immutable-first");require(window.getController().getDecompileData().getHighFunction()!=null,"First immutable normal stock-authority use failed");
        var actual=savedAuthority(p,immutableEntry);save("immutable-authority.json",actual);require(com.google.gson.JsonParser.parseString(ProgramMapping.JSON.toJson(actual)).equals(expected),"Immutable authority differs from saved first-JVM receipt");save("w2-r3-immutable-result.json",Map.of("status","PASS","unchanged",true,"program",identity(p),"revision",p.getModificationNumber()));return;
      }
      if(Boolean.getBoolean("ghidraboy.w2PhysicalDiagnostic")) {physicalDiagnostic(p,seedAt);require(observerFailure==null,"Passive observer failed: "+observerFailure);save("w2-support-result.json",Map.of("status","DIAGNOSTIC","scope","physical destination discriminator only"));return;}
      if(Boolean.getBoolean("ghidraboy.w2R3"))physicalDiagnostic(p,seedAt);
      navigate(target,"baseline-before-measurement");
      require(window.getController().getDecompileData().getHighFunction()!=null,"Baseline normal native result unavailable");
      save("baseline-native-usable.json",Map.of("normal_provider",true,"showing",window.getComponent().isShowing(),"program",identity(p),"entry",seedAt.toString(),"visual_inspection","UNOBSERVED"));
      var request=domain(PredicatedCalls.registeredProof(p,seedAt).callSite(),0xc200,0xc500);var proof=preview(request,"second-domain");
      save("topology-before.json",topology());phase="measured-apply";observedOperation="UNKNOWN-until-public-wrapper-return";
      event("measured-apply-begin",Map.of("proof",proof.toString(),"proof_sha256",hash(proof),"request",request,"program",identity(p)));
      var applied=action("stock-predicate-apply",proof.toString());var entry=applied.lastOperation.entry();target=p.getFunctionManager().getFunctionAt(entry);
      event("measured-apply-terminal",Map.of("operation",applied.lastOperation.id(),"entry",entry.toString(),"program",identity(p),"transaction",transaction(p.getCurrentTransactionInfo())));
      save("topology-after.json",topology());drain();
      SwingUtilities.invokeAndWait(()->display("pre-rescue-settled"));
      observe(target,"topology-first-use");
      if(Boolean.getBoolean("ghidraboy.w2R3")) {
        phase="old-domain-stale-control";target=p.getFunctionManager().getFunctionAt(seedAt);navigate(target,"old-domain-stale-control");drain();SwingUtilities.invokeAndWait(()->display("old-domain-stale-control"));captureStale("old-domain-stale-control",seedAt,entry);
        phase="saved-current-positive";target=p.getFunctionManager().getFunctionAt(entry);navigate(target,"saved-current-positive");observe(target,"saved-current-positive");
        var saved=savedAuthority(p,entry);p.save("W2-R3 bounded current candidate",monitor);phase="post-save-natural-settlement";drain();diagnosticDisplay("post-save-natural-settlement");save("saved-current-authority.json",saved);save("w2-r3-first-jvm-result.json",Map.of("status","PASS","program",identity(p),"revision",p.getModificationNumber(),"saved",true,"post_save_normal_provider_settled",true));
      }
      event("pre-rescue-observation-end",Map.of("operation",applied.lastOperation.id(),"entry",entry.toString(),"coverage","DISPLAYED_DATA_ONLY","native_request_coverage","UNOBSERVED"));
      require(observerFailure==null,"Passive observer failed: "+observerFailure);
      if(Boolean.getBoolean("ghidraboy.w2Comparison")) {
        phase="explicit-comparison";event("explicit-comparison-begin",Map.of("retained_pre_rescue",true));
        for(var registered:List.of(seedAt,entry)) {
          var registeredRequest=PredicatedCalls.registeredProof(p,registered).callSite();
          action("stock-predicate-refresh",preview(registeredRequest,"comparison-after-first-result-"+Integer.toHexString(registered.toString().hashCode())).toString(),registered.toString());
          drain();
        }
        int captureIndex=0;
        for(var address:List.of(entry,seedAt,seedAt,entry)) {navigate(p.getFunctionManager().getFunctionAt(address),"comparison-domain-reversal");observe(target,"domain-order-"+(captureIndex++));}
        action("conditional-call-target",entry.toString());
        var proofAfter=PredicatedCalls.registeredProof(p,entry);
        var physical=proofAfter.boundaries().stream().filter(b->b.kind().equals("RET_DISPATCH")).map(ConditionalCallSites.Boundary::physical).distinct().toList();
        require(physical.size()==1&&state.getTool().getService(CodeViewerService.class).getCurrentLocation().getAddress().toString().equals(physical.getFirst()),"Physical target navigation differs from proof boundary");
        event("physical-target-verified",Map.of("entry",entry.toString(),"target",physical.getFirst()));
        settlePhysical("physical-target-result");
        capturePhysical("physical-target-result",state.getTool().getService(CodeViewerService.class).getCurrentLocation().getAddress());
        action("conditional-call-continuation",entry.toString());
        var continuation=proofAfter.boundaries().stream().filter(b->b.kind().equals("MATCHED_CALL_COMPLETION")).map(ConditionalCallSites.Boundary::physical).distinct().toList();
        require(continuation.size()==1&&state.getTool().getService(CodeViewerService.class).getCurrentLocation().getAddress().toString().equals(continuation.getFirst()),"Physical continuation navigation differs from proof boundary");
        event("physical-continuation-verified",Map.of("entry",entry.toString(),"target",continuation.getFirst()));
        settlePhysical("physical-continuation-result");
        capturePhysical("physical-continuation-result",state.getTool().getService(CodeViewerService.class).getCurrentLocation().getAddress());
      }
      save("w2-support-result.json",Map.of("status","UNOBSERVED","normal_native_baseline","PASS","display_observer","PASS","complete_native_request_attribution","UNOBSERVED","classification","PENDING_INDEPENDENT_ATTRIBUTION","reason","Display coverage alone is incomplete; external native boundary and exception receipts, if present, require independent correlation","explicit_comparison_performed",Boolean.getBoolean("ghidraboy.w2Comparison")));
    }finally{
      if(displayListener!=null)SwingUtilities.invokeAndWait(()->window.getDecompilerPanel().getLayoutController().removeLayoutModelListener(displayListener));
      activeProbe=null;if(listeners.containsKey(p))unlisten(p);p.release(this);
    }
  }
  @Override public void launch(GhidraApplicationLayout layout,String[] args)throws Exception {
    var config=new GhidraApplicationConfiguration();config.setShowSplashScreen(false);Application.initializeApplication(layout,config);
    var project=GhidraProject.openProject(args[0],args[1],true);var file=project.getProjectData().getFile(args[5]);require(file!=null,"Missing copied fixture");
    ghidra.framework.plugintool.PluginTool[] tool={null};ghidra.framework.main.FrontEndTool[] front={null};javax.swing.Timer[] timer={null};java.awt.Window[] desktopFrame={null};
    Path output=Path.of(args[2]);Files.createDirectories(output);
    SwingUtilities.invokeAndWait(()->{
      timer[0]=new javax.swing.Timer(50,e->{for(var w:java.awt.Window.getWindows())if(w instanceof java.awt.Dialog d&&d.isShowing()&&d.getTitle().equals("Analyze?")){
        boolean fixture=components(d).stream().anyMatch(c->c instanceof javax.swing.JLabel l&&l.getText()!=null&&l.getText().contains(file.getName()+" has not been analyzed"));
        if(fixture){try{Files.writeString(output.resolve("startup-analysis-choice.json"),ProgramMapping.JSON.toJson(Map.of("choice","No","mechanism","actual dialog button","program_file",file.getPathname(),"analysis_settings_changed",false)));}catch(Exception ex){throw new RuntimeException(ex);}timer[0].stop();button(d,"No").doClick();}
      }});timer[0].start();
      front[0]=new ghidra.framework.main.FrontEndTool(project.getProjectManager());front[0].setActiveProject(project.getProject());front[0].setVisible(true);
      if(Boolean.getBoolean("ghidraboy.w2R3Immutable"))tool[0]=project.getProject().getToolServices().launchTool("CodeBrowser",List.of());else tool[0]=project.getProject().getToolServices().launchTool("CodeBrowser",List.of(file));
      var provider=(DecompilerProvider)tool[0].getComponentProvider("Decompiler");tool[0].showComponentProvider(provider,true);
      if(Boolean.getBoolean("ghidraboy.desktopCapture")) {
        var frame=SwingUtilities.getWindowAncestor(provider.getComponent());
        desktopFrame[0]=frame;
        if(frame instanceof java.awt.Frame f)f.setExtendedState(java.awt.Frame.MAXIMIZED_BOTH);
        frame.setAlwaysOnTop(true);frame.toFront();widen(frame,provider.getComponent());
        if(java.awt.Desktop.isDesktopSupported()&&java.awt.Desktop.getDesktop().isSupported(java.awt.Desktop.Action.APP_REQUEST_FOREGROUND))java.awt.Desktop.getDesktop().requestForeground(true);
      }
    });
    if(Boolean.getBoolean("ghidraboy.desktopCapture")) {
      boolean[] active={false};
      for(int attempt=0;attempt<240&&!active[0];attempt++) {
        Thread.sleep(250);
        SwingUtilities.invokeAndWait(()->active[0]=desktopFrame[0]!=null&&desktopFrame[0].isActive()&&desktopFrame[0].isFocused());
      }
      require(active[0],"Disposable W2 window did not become active/focused for desktop capture");
    }
    if(Boolean.getBoolean("ghidraboy.w2R3Immutable")) {
      Program immutable=(Program)file.getImmutableDomainObject(W2NormalProbe.class,-1,TaskMonitor.DUMMY);
      try{SwingUtilities.invokeAndWait(()->tool[0].getService(ProgramManager.class).openProgram(immutable));}finally{immutable.release(W2NormalProbe.class);}
    }
    Program p=tool[0].getService(ProgramManager.class).getCurrentProgram();int exit=0;
    try {
      require(p!=null,"Copied fixture not open");
      var script=new W2NormalProbe();script.setPropertiesFileLocation(args[3],"W2NormalProbe");script.setScriptArgs(new String[]{args[2],args[4]});
      script.execute(new ghidra.app.script.GhidraState(tool[0],project.getProject(),null,null,null,null),new TaskMonitorAdapter(true),new java.io.PrintWriter(System.out,true));
    }catch(Throwable failure){exit=1;failure.printStackTrace();Files.writeString(output.resolve("execution-failure.txt"),failure.toString());}
    finally {
      // Disposable copy only. Save evidence separately; discard Program changes during closure.
      SwingUtilities.invokeAndWait(()->{timer[0].stop();tool[0].getService(ProgramManager.class).closeAllPrograms(true);tool[0].close();front[0].setActiveProject(null);});
      project.close();Files.writeString(output.resolve("tool-closed.json"),ProgramMapping.JSON.toJson(Map.of("pid",ProcessHandle.current().pid(),"program_closed",p==null||p.isClosed(),"remaining_consumers",p==null?0:p.getConsumerList().size(),"normal_w6_claim",false)));
    }
    System.exit(exit);
  }
}
