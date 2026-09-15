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
      record.put("request_id",requestId);record.put("boundary",boundary);record.put("return_code_index",codeIndex);record.put("monitor_cancelled",requestMonitor==null?null:requestMonitor.isCancelled());record.put("program",probe.identity(p));record.put("entry",function.getEntryPoint().toString());record.put("function_id",function.getID());
      record.put("transaction",probe.transaction(p.getCurrentTransactionInfo()));record.put("revision",p.getModificationNumber());record.put("phase",probe.phase);record.put("operation_at_boundary",probe.observedOperation);
      record.put("registration",p.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(function.getEntryPoint().toString(),null));record.put("thread",Thread.currentThread().getName());record.put("java_thread_id",Thread.currentThread().threadId());record.put("result_object",result==null?null:System.identityHashCode(result));
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
      record.put("function_id",f==null?null:f.getID());record.put("transaction_at_callback",p==null?null:transaction(p.getCurrentTransactionInfo()));
      record.put("revision_at_callback",p==null?null:p.getModificationNumber());
      record.put("registration_at_callback",p==null||f==null?null:p.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(f.getEntryPoint().toString(),null));
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
        record.put("visual_inspection","UNOBSERVED");
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
    String registration=program.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(entry.toString(),null);
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
    require(revision==program.getModificationNumber() && registration.equals(program.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(entry.toString(),null)),"Source changed during passive evidence binding");
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
  @Override public void run()throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    currentProgram=state.getTool().getService(ProgramManager.class).getCurrentProgram();var p=currentProgram;p.addConsumer(this);
    window=(DecompilerProvider)state.getTool().getComponentProvider("Decompiler");
    try {
      activeProbe=this;listen(p);var seed=StockEntries.entries(p).stream().filter(e->e.generation()==null).findFirst().orElseThrow();var seedAt=ProgramMapping.staticAddress(p,seed.carrier());target=p.getFunctionManager().getFunctionAt(seedAt);
      displayListener=new LayoutModelListener(){public void modelSizeChanged(IndexMapper m){display("modelSizeChanged");}public void dataChanged(BigInteger a,BigInteger b){display("dataChanged");}};
      SwingUtilities.invokeAndWait(()->{window.getDecompilerPanel().getLayoutController().addLayoutModelListener(displayListener);display("observer-baseline");});
      event("observer-installed",Map.of("mechanism","synchronous-layout-model-listener","coverage","DISPLAYED_DATA_ONLY","native_request_coverage","UNOBSERVED","provider_object",System.identityHashCode(window),"normal_provider_class",window.getClass().getName(),"showing",window.getComponent().isShowing(),"program",identity(p)));
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
      event("pre-rescue-observation-end",Map.of("operation",applied.lastOperation.id(),"entry",entry.toString(),"coverage","DISPLAYED_DATA_ONLY","native_request_coverage","UNOBSERVED"));
      require(observerFailure==null,"Passive observer failed: "+observerFailure);
      if(Boolean.getBoolean("ghidraboy.w2Comparison")) {
        phase="explicit-comparison";event("explicit-comparison-begin",Map.of("retained_pre_rescue",true));
        refreshAll("comparison-after-first-result");
        int captureIndex=0;
        for(var address:List.of(entry,seedAt,seedAt,entry)) {navigate(p.getFunctionManager().getFunctionAt(address),"comparison-domain-reversal");observe(target,"domain-order-"+(captureIndex++));}
        action("conditional-call-target",entry.toString());
        var proofAfter=PredicatedCalls.registeredProof(p,entry);
        var physical=proofAfter.boundaries().stream().filter(b->b.kind().equals("RET_DISPATCH")).map(ConditionalCallSites.Boundary::physical).distinct().toList();
        require(physical.size()==1&&state.getTool().getService(CodeViewerService.class).getCurrentLocation().getAddress().toString().equals(physical.getFirst()),"Physical target navigation differs from proof boundary");
        event("physical-target-verified",Map.of("entry",entry.toString(),"target",physical.getFirst()));
        settlePhysical("physical-target-result");
        action("conditional-call-continuation",entry.toString());
        var continuation=proofAfter.boundaries().stream().filter(b->b.kind().equals("MATCHED_CALL_COMPLETION")).map(ConditionalCallSites.Boundary::physical).distinct().toList();
        require(continuation.size()==1&&state.getTool().getService(CodeViewerService.class).getCurrentLocation().getAddress().toString().equals(continuation.getFirst()),"Physical continuation navigation differs from proof boundary");
        event("physical-continuation-verified",Map.of("entry",entry.toString(),"target",continuation.getFirst()));
        settlePhysical("physical-continuation-result");
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
    ghidra.framework.plugintool.PluginTool[] tool={null};ghidra.framework.main.FrontEndTool[] front={null};javax.swing.Timer[] timer={null};
    Path output=Path.of(args[2]);Files.createDirectories(output);
    SwingUtilities.invokeAndWait(()->{
      timer[0]=new javax.swing.Timer(50,e->{for(var w:java.awt.Window.getWindows())if(w instanceof java.awt.Dialog d&&d.isShowing()&&d.getTitle().equals("Analyze?")){
        boolean fixture=components(d).stream().anyMatch(c->c instanceof javax.swing.JLabel l&&l.getText()!=null&&l.getText().contains(file.getName()+" has not been analyzed"));
        if(fixture){try{Files.writeString(output.resolve("startup-analysis-choice.json"),ProgramMapping.JSON.toJson(Map.of("choice","No","mechanism","actual dialog button","program_file",file.getPathname(),"analysis_settings_changed",false)));}catch(Exception ex){throw new RuntimeException(ex);}timer[0].stop();button(d,"No").doClick();}
      }});timer[0].start();
      front[0]=new ghidra.framework.main.FrontEndTool(project.getProjectManager());front[0].setActiveProject(project.getProject());front[0].setVisible(true);
      tool[0]=project.getProject().getToolServices().launchTool("CodeBrowser",List.of(file));
      tool[0].showComponentProvider(tool[0].getComponentProvider("Decompiler"),true);
    });
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
