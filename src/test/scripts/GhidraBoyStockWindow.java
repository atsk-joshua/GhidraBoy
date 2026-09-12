// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.services.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.framework.model.DomainObjectListener;
import javax.swing.SwingUtilities;
import java.nio.file.*;
import java.util.*;

/** Passive capture from the stored normal CodeBrowser. Acceptance is a separate checker. */
public class GhidraBoyStockWindow extends GhidraBoyMemoryImages {
  DecompilerProvider window;
  final List<Object> timeline = Collections.synchronizedList(new ArrayList<>());
  volatile long lastEvent;
  volatile int eventCount;
  void event(String kind, Object detail) throws Exception {
    timeline.add(Map.of("kind",kind,"detail",detail,"utc",java.time.Instant.now().toString(),"nano",System.nanoTime()));
    synchronized(timeline){save("timeline.json",timeline);}
  }
  void drain() throws Exception {
    if(currentProgram.getCurrentTransactionInfo()!=null)throw new IllegalStateException("Outer transaction conceals real event boundary");
    currentProgram.flushEvents(); // Deliver only actual queued events; never refresh the controller.
    long deadline=System.nanoTime()+60_000_000_000L;Object[] previous={null};int stable=0;
    while(System.nanoTime()<deadline) {
      boolean[] settled={false};
      SwingUtilities.invokeAndWait(()->{
        var data=window.getController().getDecompileData();
        settled[0]=!window.getController().isDecompiling() && data==previous[0];previous[0]=data;
      });
      stable=settled[0]?stable+1:0;
      if(stable>=24 && System.nanoTime()-lastEvent>=6_000_000_000L) {
        event("settled",Map.of("stable_samples",stable,"sample_ms",250,"events",eventCount,"revision",currentProgram.getModificationNumber(),"flush_events",true));return;
      }
      Thread.sleep(250);
    }
    event("settlement-timeout",currentProgram.getName());throw new IllegalStateException("Normal window settlement timed out");
  }
  void navigate(Function f,String label)throws Exception {
    event("navigate",Map.of("phase",label,"program",currentProgram.getName(),"entry",f.getEntryPoint().toString()));
    SwingUtilities.invokeAndWait(()->{
      state.getTool().getService(ProgramManager.class).setCurrentProgram(currentProgram);
      state.getTool().getService(GoToService.class).goTo(new ProgramLocation(currentProgram,f.getEntryPoint()));
    });drain();
  }
  void observe(Function expected,String label)throws Exception {
    var record=new LinkedHashMap<String,Object>();
    SwingUtilities.invokeAndWait(()->{
      try {
        long revision=currentProgram.getModificationNumber();var data=window.getController().getDecompileData();
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
        record.put("events",eventCount);record.put("read_only",currentProgram.isChangeable()==false);
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
        if(frame!=null&&frame.isShowing()) {
          var pos=frame.getLocationOnScreen();javax.imageio.ImageIO.write(new java.awt.Robot().createScreenCapture(new java.awt.Rectangle(pos.x,pos.y,frame.getWidth(),frame.getHeight())),"png",out.resolve(label+"-desktop.png").toFile());
          record.put("desktop_sha256",hash(out.resolve(label+"-desktop.png")));
        }
        if(revision!=currentProgram.getModificationNumber()||data!=window.getController().getDecompileData())throw new IllegalStateException("Capture changed during snapshot");
        save(label+"-request.json",record);
      }catch(Exception e){throw new RuntimeException(e);}
    });
    event("passive-capture",Map.of("phase",label,"record_sha256",hash(out.resolve(label+"-request.json"))));
    // Diagnostic process enumeration happens only after passive snapshot, and is not result attribution.
    save(label+"-processes.json",processes());
  }
  void toolAction(String action,Path file) throws Exception {
    event("explicit-provider-action",Map.of("action",action,"file",file.toString()));
    // Invoke the shipped user-facing action with its documented explicit arguments.
    var script=new GhidraBoyTools();
    script.setPropertiesFileLocation(getScriptArgs()[2],"GhidraBoyTools");
    script.setScriptArgs(new String[]{action,file.toString()});
    ghidra.program.util.ProgramLocation[] selected={null};
    SwingUtilities.invokeAndWait(()->selected[0]=state.getTool().getService(CodeViewerService.class).getCurrentLocation());
    if(selected[0]==null || selected[0].getProgram()!=currentProgram)throw new IllegalStateException("No actual Listing selection for provider action");
    event("provider-action-listing-context",Map.of("program_id",currentProgram.getUniqueProgramID(),"address",selected[0].getAddress().toString()));
    script.execute(new ghidra.app.script.GhidraState(state.getTool(),state.getProject(),currentProgram,selected[0],null,null),monitor,new java.io.PrintWriter(System.out,true));
    if(currentProgram.getCurrentTransactionInfo()!=null)throw new IllegalStateException("Provider action transaction not closed");
  }
  boolean ordinaryRefresh(String phase,boolean allowUnavailable) throws Exception {
    var receipt=new LinkedHashMap<String,Object>();
    receipt.put("phase",phase);receipt.put("requested",true);receipt.put("enabled",false);
    receipt.put("invoked",false);receipt.put("completed",false);
    receipt.put("program_id",currentProgram.getUniqueProgramID());receipt.put("revision",currentProgram.getModificationNumber());
    receipt.put("controller_identity",System.identityHashCode(window.getController()));
    event("ordinary-refresh-requested",new LinkedHashMap<>(receipt));
    SwingUtilities.invokeAndWait(()->{
      try {
        var action=state.getTool().getAllActions().stream().filter(a->a.getName().equals("Refresh")&&a.getOwner().equals("DecompilePlugin")).findFirst().orElseThrow();
        var context=window.getActionContext(null);
        receipt.put("action",action.getName());receipt.put("owner",action.getOwner());
        receipt.put("action_class",action.getClass().getName());receipt.put("provider_class",window.getClass().getName());
        receipt.put("context_class",context.getClass().getName());receipt.put("context_provider_matches",context.getComponentProvider()==window);
        boolean enabled=action.isEnabledForContext(context);receipt.put("enabled",enabled);
        event("ordinary-refresh-enablement",new LinkedHashMap<>(receipt));
        if(enabled) {
          receipt.put("invoked",true);event("ordinary-refresh-invoked",new LinkedHashMap<>(receipt));
          action.actionPerformed(context);receipt.put("completed",true);
          receipt.put("status","DISPATCH_COMPLETED");
        } else receipt.put("status",allowUnavailable?"NOT_AVAILABLE_ON_ERROR":"NOT_AVAILABLE");
        save(phase+"-refresh-action.json",receipt);event("ordinary-refresh-disposition",new LinkedHashMap<>(receipt));
      }catch(Exception e){throw new RuntimeException(e);}
    });
    if(!(boolean)receipt.get("enabled")) {
      if(!allowUnavailable)throw new IllegalStateException("Ordinary Refresh disabled after settled proof recovery");
      return false;
    }
    drain();return true;
  }
  void requireMissingRefusal() throws Exception {
    SwingUtilities.invokeAndWait(()->{
      var data=window.getController().getDecompileData();
      if(data==null||data.getHighFunction()!=null||data.hasDecompileResults()||
          data.getErrorMessage()==null||!data.getErrorMessage().contains("Missing or foreign ordinary-entry registration"))
        throw new IllegalStateException("Missing-registration passive refusal not established");
    });
  }
  String authority(Program p)throws Exception {
    var result=new TreeMap<String,Object>();
    result.put("program_id",p.getUniqueProgramID());result.put("file_id",p.getDomainFile().getFileID());
    result.put("original_sha",p.getExecutableSHA256());result.put("current_sha",bytesHash(ProgramMapping.exportBytes(p,true,false,monitor)));
    for(var name:List.of(OrdinaryEntryAccess.STOCK_OPTIONS,PredicatedCalls.STOCK_OPTIONS)) {
      if(!p.getOptionsNames().contains(name))continue;
      var options=p.getOptions(name);var entries=new TreeMap<String,String>();
      for(var key:options.getOptionNames())entries.put(key,options.getValueAsString(key));result.put(name,entries);
    }
    result.put("images",p.getOptionsNames().contains(ExecutableImages.OPTIONS)?ExecutableImages.serialized(p):null);
    if(p.getOptionsNames().contains(ExecutableImages.OPTIONS)) {
      byte[] bytes=new byte[6];var at=p.getAddressFactory().getDefaultAddressSpace().getAddress(0xc200);p.getMemory().getBytes(at,bytes);
      result.put("physical_image",Map.of("cpu",0xc200,"bytes",HexFormat.of().formatHex(bytes),"physical",ProgramMapping.staticToPhysical(p,at)));
    }var functions=new ArrayList<Object>();
    for(var f:p.getFunctionManager().getFunctions(true))functions.add(Arrays.asList(f.getEntryPoint().toString(),f.getID(),f.getName(),f.getComment(),f.getCallingConventionName()));
    result.put("functions",functions);return ProgramMapping.JSON.toJson(result);
  }
  Program openFixture(String name,boolean readonly)throws Exception {
    var file=state.getProject().getProjectData().getFile("/"+name);if(file==null)throw new IllegalStateException("Missing fixture "+name);
    Program[] p={null};
    if(readonly) {
      p[0]=(Program)file.getReadOnlyDomainObject(this,-1,monitor);
      if(p[0].isChangeable())throw new IllegalStateException("Reopen is writable");
      SwingUtilities.invokeAndWait(()->state.getTool().getService(ProgramManager.class).openProgram(p[0]));p[0].release(this);
    } else SwingUtilities.invokeAndWait(()->p[0]=state.getTool().getService(ProgramManager.class).openProgram(file));
    return p[0];
  }
  void visit(Program p,Address at,String label)throws Exception {
    currentProgram=p;var f=getFunctionAt(at);navigate(f,label);observe(f,label);
  }
  void closePrograms(Program... programs)throws Exception {
    SwingUtilities.invokeAndWait(()->{
      for(var p:programs)if(!state.getTool().getService(ProgramManager.class).closeProgram(p,true))throw new IllegalStateException("Close refused");
    });
    var receipt=new ArrayList<Object>();for(var p:programs)receipt.add(Map.of("name",p.getName(),"closed",p.isClosed(),"consumers",p.getConsumerList().size()));
    save("program-closures.json",receipt);for(var p:programs)if(!p.isClosed()||!p.getConsumerList().isEmpty())throw new IllegalStateException("Retained Program consumer");
  }
  void imageSource(String label,Address at)throws Exception {
    var proof=PredicatedCalls.registeredProof(currentProgram,at);save(label+"-proof.json",proof);
    var raw=new TreeMap<String,Object>();
    for(var node:proof.nodes())if(!raw.containsKey(node.source())) {
      var instruction=getInstructionAt(currentProgram.getAddressFactory().getAddress(node.source()));ids.clear();
      raw.put(node.source(),Map.of("address",node.source(),"bytes",HexFormat.of().formatHex(instruction.getBytes()),"ops",Arrays.stream(instruction.getPcode(false)).map(this::operation).toList()));
    }
    save(label+"-raw.json",raw);
  }
  void fullAfterPassive(Function pf)throws Exception {
    var p=currentProgram;var pa=pf.getEntryPoint();
    Files.writeString(out.resolve("P-pre-proof-authority.json"),authority(p));
    toolAction("stock-ordinary-preview",out.resolve("reviewed-P-proof.json"));
    int beforeProofEvents=eventCount;long beforeProofRevision=p.getModificationNumber();
    toolAction("stock-ordinary-refresh",out.resolve("reviewed-P-proof.json"));
    long proofRevision=p.getModificationNumber();
    Files.writeString(out.resolve("P-post-proof-authority.json"),authority(p));
    event("proof-write-completed",Map.of("program_id",p.getUniqueProgramID(),"before_revision",beforeProofRevision,"revision",proofRevision,"before_events",beforeProofEvents));
    try{drain();}catch(Exception e){observe(pf,"P-post-proof");throw e;}
    observe(pf,"P-post-proof");
    if(proofRevision<=beforeProofRevision||eventCount<=beforeProofEvents)
      throw new IllegalStateException("No committed proof-write/event delivery");
    ordinaryRefresh("P3",false);observe(pf,"P3");
    save("P-source-after.json",canonical(getFunctionAt(toAddr(0x150))));
    navigate(getFunctionAt(toAddr(0x150)),"canonical-control");observe(getFunctionAt(toAddr(0x150)),"canonical-control");
    var q=openFixture("W4_MEMORY_IMAGE.gb",false);currentProgram=q;
    DomainObjectListener qListener=ev->{eventCount++;lastEvent=System.nanoTime();timeline.add(Map.of("kind","program-event","nano",lastEvent,"utc",java.time.Instant.now().toString(),"revision",q.getModificationNumber(),"records",ev.numRecords()));};q.addListener(qListener);
    try {
      var first=StockEntries.entries(q).stream().filter(e->e.generation()!=null).findFirst().orElseThrow();
      var qa=q.getAddressFactory().getAddress(first.carrier());var qf=getFunctionAt(qa);
      bindings("Q");Files.writeString(out.resolve("Q-I1-authority.json"),authority(q));
      navigate(qf,"Q0");observe(qf,"Q0");imageSource("Q0",qa);
      String originalImage=ExecutableImages.serialized(q);
      String originalProof=q.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(qa.toString(),null);
      int tx=q.startTransaction("G1 explicit physical I2 replacement retaining I1 authority");
      try{q.getMemory().setBytes(toAddr(0xc200),HexFormat.of().parseHex("3ea7ea74c0c9"));}finally{q.endTransaction(tx,true);}
      event("Q-mutation-committed",Map.of("transaction",tx,"revision",q.getModificationNumber()));
      drain();observe(qf,"Q1");
      boolean imageRetained=Objects.equals(originalImage,ExecutableImages.serialized(q));
      boolean proofRetained=Objects.equals(originalProof,q.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(qa.toString(),null));
      save("Q-mutation.json",Map.of("old_image_retained",imageRetained,"old_proof_retained",proofRetained,"cpu",0xc200,"bytes",HexFormat.of().formatHex(getBytes(toAddr(0xc200),6)),"generation",first.generation()));
      if(!imageRetained||!proofRetained)throw new IllegalStateException("Physical replacement changed old image/proof authority");
      tx=q.startTransaction("G1 explicit new executable generation and stock proof");Address qb;
      try {
        var image=ExecutableImages.establish(q,toAddr(0x320),0xc200,HexFormat.of().parseHex("3ea7ea74c0c9"),"explicit G1 user generation G2",monitor);
        qb=PredicatedCalls.install(q,preview(getFunctionAt(q.getAddressFactory().getAddress(image.entry())),image.generation()),monitor);
      }finally{q.endTransaction(tx,true);}
      event("explicit-image-generation",Map.of("entry",qb.toString(),"history",ExecutableImages.history(q)));
      visit(q,qb,"Q2");imageSource("Q2",qb);visit(q,qa,"Q-old-generation");
      try{ExecutableImages.resolve(q,first.generation());throw new IllegalStateException("Old generation accepted");}
      catch(IllegalArgumentException expected){save("Q-old-generation-refusal.json",Map.of("requested",first.generation(),"error",expected.getMessage()));}
      visit(p,pa,"switch-P");visit(q,qb,"switch-Q");visit(p,pa,"switch-P-return");
      event("quick-alternating-start","P/Q/P twice through ProgramManager and GoTo");
      SwingUtilities.invokeAndWait(()->{
        var pm=state.getTool().getService(ProgramManager.class);var go=state.getTool().getService(GoToService.class);
        for(int i=0;i<2;i++){pm.setCurrentProgram(q);go.goTo(new ProgramLocation(q,qb));pm.setCurrentProgram(p);go.goTo(new ProgramLocation(p,pa));}
      });drain();observe(pf,"quick-P-settled");
      for(var program:List.of(p,q))program.getDomainFile().save(monitor);
      Files.writeString(out.resolve("P-saved-authority.json"),authority(p));Files.writeString(out.resolve("Q-saved-authority.json"),authority(q));
      save("saved-entries.json",Map.of("P",pa.toString(),"Q1",qa.toString(),"Q2",qb.toString(),"G1",first.generation()));
      // A distinct saved copy supplies the warm negative; positive P/Q remain saved and intact.
      var variantFile=p.getDomainFile().copyTo(state.getProject().getProjectData().getRootFolder(),monitor);
      save("variant-file.json",Map.of("name",variantFile.getName()));
      var variant=openFixture(variantFile.getName(),false);visit(variant,variant.getAddressFactory().getAddress(pa.toString()),"missing-warm");
      DomainObjectListener vl=ev->{eventCount++;lastEvent=System.nanoTime();timeline.add(Map.of("kind","program-event","nano",lastEvent,"utc",java.time.Instant.now().toString(),"revision",variant.getModificationNumber(),"records",ev.numRecords()));};variant.addListener(vl);
      int vtx=variant.startTransaction("Disposable variant missing stock registration");
      try{variant.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS).removeOption(pa.toString());}finally{variant.endTransaction(vtx,true);}
      event("registration-removed",Map.of("transaction",vtx,"program_id",variant.getUniqueProgramID()));
      drain();observe(getFunctionAt(variant.getAddressFactory().getAddress(pa.toString())),"missing-passive");
      requireMissingRefusal();
      var invalid=getFunctionAt(variant.getAddressFactory().getAddress(pa.toString()));
      if(!ordinaryRefresh("missing-active",true)) {
        event("ACTIVE_NAVIGATION_REFUSAL",Map.of("program_id",variant.getUniqueProgramID(),"controller_identity",System.identityHashCode(window.getController()),"toolbar_refresh",false));
        navigate(getFunctionAt(toAddr(0x150)),"missing-away");navigate(invalid,"missing-back");
      }
      observe(invalid,"missing-active");requireMissingRefusal();
      variant.removeListener(vl);closePrograms(variant,p,q);
    }finally{q.removeListener(qListener);}
  }
  void reopen()throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    window=(DecompilerProvider)state.getTool().getComponentProvider("Decompiler");
    var saved=ProgramMapping.JSON.fromJson(Files.readString(Path.of(getScriptArgs()[3]).resolve("saved-entries.json")),com.google.gson.JsonObject.class);
    var p=openFixture("F1234.gb",true);var q=openFixture("W4_MEMORY_IMAGE.gb",true);
    Files.writeString(out.resolve("P-before-authority.json"),authority(p));Files.writeString(out.resolve("Q-before-authority.json"),authority(q));
    visit(p,p.getAddressFactory().getAddress(saved.get("P").getAsString()),"reopen-P");
    visit(q,q.getAddressFactory().getAddress(saved.get("Q2").getAsString()),"reopen-Q");
    visit(q,q.getAddressFactory().getAddress(saved.get("Q1").getAsString()),"reopen-Q-old");
    Files.writeString(out.resolve("P-after-authority.json"),authority(p));Files.writeString(out.resolve("Q-after-authority.json"),authority(q));
    closePrograms(p,q);save("timeline.json",timeline);
  }
  @Override public void run()throws Exception {
    if(isRunningHeadless())throw new IllegalStateException("Requires normal CodeBrowser");
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    if(getScriptArgs().length>1 && getScriptArgs()[1].equals("reopen")){reopen();return;}
    currentProgram=state.getTool().getService(ProgramManager.class).getCurrentProgram();
    // Script Manager owns an initial transaction; end only that script-owned transaction.
    end(true);
    if(currentProgram.getCurrentTransactionInfo()!=null)throw new IllegalStateException("Foreign transaction active");
    window=(DecompilerProvider)state.getTool().getComponentProvider("Decompiler");
    var listened=currentProgram;
    DomainObjectListener listener=ev->{eventCount++;lastEvent=System.nanoTime();timeline.add(Map.of("kind","program-event","nano",lastEvent,"utc",java.time.Instant.now().toString(),"revision",listened.getModificationNumber(),"records",ev.numRecords()));};
    listened.addListener(listener);
    try {
      var entry=StockEntries.entries(currentProgram).stream().filter(e->e.generation()==null).findFirst().orElseThrow();
      var at=currentProgram.getAddressFactory().getAddress(entry.carrier());var f=getFunctionAt(at);
      save("P-source-before.json",canonical(getFunctionAt(toAddr(0x150))));
      var original=currentProgram.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS).getString(at.toString(),null);
      Files.writeString(out.resolve("P-original-registration.json"),original);
      navigate(f,"P0");observe(f,"P0");navigate(f,"P1");observe(f,"P1");
      var source=ProgramMapping.fileToStatic(currentProgram,0xe000).stream().filter(a->a.getAddressSpace().getName().equals("rom3")).findFirst().orElseThrow();
      if((currentProgram.getMemory().getByte(source)&255)!=0xd3)throw new IllegalStateException("Not fresh D3 fixture");
      var before=ProgramMapping.exportBytes(currentProgram,true,false,monitor);
      int tx=currentProgram.startTransaction("G1 disposable consumed E000 D3 to E4");
      try{currentProgram.getMemory().setByte(source,(byte)0xe4);}finally{currentProgram.endTransaction(tx,true);}
      event("P-mutation-committed",Map.of("transaction",tx,"revision",currentProgram.getModificationNumber(),"source",source.toString(),"file_offset",0xe000));
      // Nothing here can issue a request, validate currentness, navigate, or refresh proof/cache.
      drain();observe(f,"P2");
      var after=ProgramMapping.exportBytes(currentProgram,true,false,monitor);var changed=new ArrayList<Integer>();
      for(int i=0;i<before.length;i++)if(before[i]!=after[i])changed.add(i);
      var retained=currentProgram.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS).getString(at.toString(),null);
      save("P-mutation.json",Map.of("changed_file_offsets",changed,"old",0xd3,"new",0xe4,"old_registration_retained",original.equals(retained),"source",source.toString(),"read_only_ROM",!currentProgram.getMemory().getBlock(source).isWrite()));
      if(!changed.equals(List.of(0xe000))||!original.equals(retained))throw new IllegalStateException("Witness changed more than one consumed byte or authority");
      event("initial-witness-complete","No active intervention performed");
      if(getScriptArgs().length>1 && getScriptArgs()[1].equals("full")) fullAfterPassive(f);
      println("STOCK_NORMAL_WINDOW_CAPTURE_COMPLETE_NOT_ACCEPTANCE");
    }finally{listened.removeListener(listener);synchronized(timeline){save("timeline.json",timeline);}}
  }
}
