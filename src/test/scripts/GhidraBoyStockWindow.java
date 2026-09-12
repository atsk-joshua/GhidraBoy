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
  final List<Object> timeline = new ArrayList<>();
  final Map<Program,Integer> counts = new IdentityHashMap<>();
  final Map<Program,Long> lastEvents = new IdentityHashMap<>();
  final Map<Program,Set<Integer>> owned = new IdentityHashMap<>();
  final Map<Program,List<ghidra.framework.model.TransactionInfo>> transactions = new IdentityHashMap<>();
  final Map<Program,DomainObjectListener> listeners = new IdentityHashMap<>();
  final Map<Program,ghidra.framework.model.TransactionListener> txListeners = new IdentityHashMap<>();
  final Map<Program,Mutation> pending = new IdentityHashMap<>();
  Function target;
  long settlementDeadline;
  long settledRevision;
  int settledEvents;
  Object settledData;
  int operationSequence;
  int discardedSequence;
  Map<String,Object> identity(Program p) {
    return Map.of("program_id",p.getUniqueProgramID(),"program_object",System.identityHashCode(p),
      "program",p.getName(),"file_id",String.valueOf(p.getDomainFile().getFileID()),
      "owner_java_pid",ProcessHandle.current().pid());
  }
  Map<String,Object> transaction(ghidra.framework.model.TransactionInfo tx) {
    if(tx==null)return Map.of("active",false);
    return Map.of("active",tx.getStatus()==ghidra.framework.model.TransactionInfo.Status.NOT_DONE || tx.getStatus()==ghidra.framework.model.TransactionInfo.Status.NOT_DONE_BUT_ABORTED,
      "id",tx.getID(),"description",tx.getDescription(),"status",tx.getStatus().toString(),
      "open_subtransactions",new ArrayList<>(tx.getOpenSubTransactions()),"db_committed",tx.hasCommittedDBTransaction());
  }
  synchronized int count(Program p){return counts.getOrDefault(p,0);}
  synchronized long last(Program p){return lastEvents.getOrDefault(p,0L);}
  synchronized void event(String kind, Object detail) throws Exception {
    // Freeze the entire detail before publishing it; all callback/action records use this append.
    var frozen=ProgramMapping.JSON.toJsonTree(detail);
    timeline.add(Map.of("schema",2,"sequence",timeline.size()+1,"kind",kind,"detail",frozen,
      "utc",java.time.Instant.now().toString(),"nano",System.nanoTime()));
    save("timeline.json",timeline);
  }
  void sample(Program p,String operation)throws Exception {
    var tx=p.getCurrentTransactionInfo();
    if(tx!=null && !transactions.get(p).contains(tx))transactions.get(p).add(tx);
    event("transaction-sample",Map.of("target",identity(p),"operation",operation,
      "transaction",transaction(tx),"observed_transactions",transactions.get(p).stream().map(this::transaction).toList(),
      "owned_subtransactions",new ArrayList<>(owned.get(p)),"revision",p.getModificationNumber(),"owner","unknown unless explicitly owned ID"));
  }
  void listen(Program p)throws Exception {
    if(listeners.containsKey(p))return;
    counts.put(p,0);owned.put(p,new HashSet<>());transactions.put(p,new java.util.concurrent.CopyOnWriteArrayList<>());
    DomainObjectListener listener=ev->{
      try {
        if(ev.getSource()!=p)throw new IllegalStateException("Foreign listener source");
        var records=new ArrayList<Object>();
        for(var change:ev) {
          var detail=new LinkedHashMap<String,Object>();detail.put("type",change.getEventType().toString());
          detail.put("record_class",change.getClass().getName());
          if(change instanceof ghidra.program.util.ProgramChangeRecord changeAt) {
            detail.put("start",String.valueOf(changeAt.getStart()));detail.put("end",String.valueOf(changeAt.getEnd()));
          }
          detail.put("old",String.valueOf(change.getOldValue()));detail.put("new",String.valueOf(change.getNewValue()));records.add(detail);
        }
        long revision=p.getModificationNumber();var id=identity(p);
        synchronized(this){counts.put(p,count(p)+1);lastEvents.put(p,System.nanoTime());
          event("program-event",Map.of("target",id,"event_sequence",count(p),"revision",revision,"records",records));}
      }catch(Exception e){throw new RuntimeException(e);}
    };
    var txListener=new ghidra.framework.model.TransactionListener(){
      public void transactionStarted(ghidra.framework.data.DomainObjectAdapterDB object,ghidra.framework.model.TransactionInfo tx){
        if(!transactions.get(p).contains(tx))transactions.get(p).add(tx);record("started",tx);
      }
      void record(String kind,ghidra.framework.model.TransactionInfo tx){try{
        event("transaction-callback",Map.of("target",identity(p),"callback",kind,"transaction",transaction(tx),
          "callback_thread",Thread.currentThread().getName(),"writer_thread","UNKNOWN; callback is asynchronous"));
      }catch(Exception e){throw new RuntimeException(e);}}
      public void transactionEnded(ghidra.framework.data.DomainObjectAdapterDB object){record("ended-observation",p.getCurrentTransactionInfo());}
      public void undoStackChanged(ghidra.framework.data.DomainObjectAdapterDB object){}
      public void undoRedoOccurred(ghidra.framework.data.DomainObjectAdapterDB object){record("undo-redo",p.getCurrentTransactionInfo());}
    };
    listeners.put(p,listener);txListeners.put(p,txListener);p.addListener(listener);p.addTransactionListener(txListener);
    sample(p,"listener-registration");
  }
  void unlisten(Program p){p.removeListener(listeners.get(p));p.removeTransactionListener(txListeners.get(p));}
  class Mutation {
    final Program p;final String id;final int sub;final long before;final int beforeEvents;
    String affectedStart;
    final ghidra.framework.model.TransactionInfo encompassing;
    Mutation(Program program,String purpose)throws Exception {
      p=program;id=purpose+"#"+(++operationSequence);before=p.getModificationNumber();beforeEvents=count(p);
      sample(p,id+"-before");
      event("operation-begin",Map.of("operation",id,"purpose",purpose,"target",identity(p),"pre_revision",before,"pre_events",beforeEvents));
      sub=p.startTransaction("G1 owned "+id);owned.get(p).add(sub);encompassing=p.getCurrentTransactionInfo();
      event("operation-started",detail());pending.put(p,this);
    }
    Map<String,Object> detail(){return new LinkedHashMap<>(Map.of("operation",id,"target",identity(p),"subtransaction",sub,
      "encompassing",transaction(encompassing),"pre_revision",before,"revision",p.getModificationNumber(),"pre_events",beforeEvents));}
    void end(boolean commit)throws Exception {
      var entry=detail();if(affectedStart!=null)entry.put("affected_start",affectedStart);entry.put("commit_requested",commit);event("commit-call-enter",entry);
      boolean returned=p.endTransaction(sub,commit);owned.get(p).remove(sub);
      var receipt=detail();receipt.put("commit_requested",commit);receipt.put("returned_committed",returned);event("commit-call-return",receipt);
      sample(p,id+"-after-return");
    }
    void qualify()throws Exception {
      var d=detail();event("operation-settled",d);
      if(encompassing.getStatus()!=ghidra.framework.model.TransactionInfo.Status.COMMITTED || !encompassing.hasCommittedDBTransaction())
        throw new IllegalStateException("Measured operation uncommitted/aborted "+id);
    }
  }
  void drain() throws Exception {
    settlementDeadline=System.nanoTime()+60_000_000_000L;drainUntil(settlementDeadline);
  }
  void drainUntil(long deadline)throws Exception {
    if(SwingUtilities.isEventDispatchThread())throw new IllegalStateException("Settlement on EDT");
    var p=currentProgram;
    if(!owned.get(p).isEmpty()){sample(p,"owned-leak");throw new IllegalStateException("Owned transaction remains open");}
    Object[] previous={null};long previousRevision=-1;int previousEvents=-1;int stable=0;
    sample(p,"settlement-entry");
    while(System.nanoTime()<deadline) {
      sample(p,"settlement-poll");
      p.flushEvents(); // Only actual queued events; no controller or proof intervention.
      long revision=p.getModificationNumber();int events=count(p);boolean[] settled={false};
      SwingUtilities.invokeAndWait(()->{
        var data=window.getController().getDecompileData();
        var f=data==null?null:data.getFunction();
        settled[0]=p.getCurrentTransactionInfo()==null && !window.getController().isDecompiling() && data==previous[0]
          && data!=null && data.getProgram()==p && f!=null && target!=null && f.getID()==target.getID()
          && state.getTool().getService(ProgramManager.class).getCurrentProgram()==p;
        previous[0]=data;
      });
      stable=settled[0] && revision==previousRevision && events==previousEvents?stable+1:0;
      previousRevision=revision;previousEvents=events;
      if(stable>=24 && System.nanoTime()-last(p)>=6_000_000_000L && p.getCurrentTransactionInfo()==null && revision==p.getModificationNumber()) {
        var mutation=pending.remove(p);if(mutation!=null)mutation.qualify();
        settledRevision=revision;settledEvents=events;settledData=previous[0];
        event("settled",Map.of("target",identity(p),"entry",target.getEntryPoint().toString(),"stable_samples",stable,"sample_ms",250,
          "events",events,"revision",revision,"transaction_free",true,"data_identity",System.identityHashCode(previous[0]),"flush_events",true));return;
      }
      Thread.sleep(250);
    }
    sample(p,"settlement-timeout");diagnosticDisplay("settlement-timeout");event("settlement-timeout",identity(p));throw new IllegalStateException("Normal window settlement timed out");
  }
  void diagnosticDisplay(String label)throws Exception {
    SwingUtilities.invokeAndWait(()->{try{
      var data=window.getController().getDecompileData();
      save(label+"-display.json",Map.of("diagnostic_only",true,"program",identity(currentProgram),"revision",currentProgram.getModificationNumber(),
        "error",data==null?"NO DATA":String.valueOf(data.getErrorMessage()),"data_identity",System.identityHashCode(data),"decompiling",window.getController().isDecompiling()));
      var frame=SwingUtilities.getWindowAncestor(window.getComponent());
      if(frame!=null&&frame.isShowing()) {var pos=frame.getLocationOnScreen();javax.imageio.ImageIO.write(new java.awt.Robot().createScreenCapture(new java.awt.Rectangle(pos.x,pos.y,frame.getWidth(),frame.getHeight())),"png",out.resolve(label+"-desktop.png").toFile());}
    }catch(Exception e){throw new RuntimeException(e);}});
    save(label+"-processes.json",processes());
  }
  void navigate(Function f,String label)throws Exception {
    target=f;sample(currentProgram,"before-navigation-"+label);
    event("navigate",Map.of("phase",label,"program",currentProgram.getName(),"entry",f.getEntryPoint().toString()));
    SwingUtilities.invokeAndWait(()->{
      state.getTool().getService(ProgramManager.class).setCurrentProgram(currentProgram);
      state.getTool().getService(GoToService.class).goTo(new ProgramLocation(currentProgram,f.getEntryPoint()));
    });sample(currentProgram,"after-navigation-"+label);drain();
  }
  void observe(Function expected,String label)throws Exception {
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
        if(frame!=null&&frame.isShowing()) {
          var pos=frame.getLocationOnScreen();javax.imageio.ImageIO.write(new java.awt.Robot().createScreenCapture(new java.awt.Rectangle(pos.x,pos.y,frame.getWidth(),frame.getHeight())),"png",out.resolve(label+"-desktop.png").toFile());
          record.put("desktop_sha256",hash(out.resolve(label+"-desktop.png")));
        }
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
    save(label+"-processes.json",processes());return;
    }
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
    sample(currentProgram,"provider-action-return-"+action);
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
        receipt.put("context_available",context!=null);receipt.put("context_class",context==null?"NONE":context.getClass().getName());receipt.put("context_provider_matches",context!=null&&context.getComponentProvider()==window);
        receipt.put("provider_program_id",window.getProgram().getUniqueProgramID());
        boolean enabled=context!=null&&action.isEnabledForContext(context);receipt.put("enabled",enabled);
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
          data.getErrorMessage()==null||!data.getErrorMessage().contains("Unavailable stock analysis entry: Missing predicated graph registration or stock software carrier"))
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
      p[0]=(Program)file.getImmutableDomainObject(this,-1,monitor);
      try {
        if(p[0].isChangeable())throw new IllegalStateException("Reopen is writable");
        save("open-"+name+".json",Map.of("api","DomainFile.getImmutableDomainObject","source_file_id",file.getFileID(),"source_path",file.getPathname(),"program_id",p[0].getUniqueProgramID(),"changeable",p[0].isChangeable()));
        SwingUtilities.invokeAndWait(()->state.getTool().getService(ProgramManager.class).openProgram(p[0]));
      } finally {p[0].release(this);}
    } else SwingUtilities.invokeAndWait(()->p[0]=state.getTool().getService(ProgramManager.class).openProgram(file));
    return p[0];
  }
  void visit(Program p,Address at,String label)throws Exception {
    currentProgram=p;var f=getFunctionAt(at);navigate(f,label);observe(f,label);
  }
  void closePrograms(Program... programs)throws Exception {
    var identities=Arrays.stream(programs).map(this::identity).toList();
    SwingUtilities.invokeAndWait(()->{
      for(var p:programs)if(!state.getTool().getService(ProgramManager.class).closeProgram(p,true))throw new IllegalStateException("Close refused");
    });
    var receipt=new ArrayList<Object>();for(int i=0;i<programs.length;i++){var p=programs[i];receipt.add(Map.of("target",identities.get(i),"name",p.getName(),"closed",p.isClosed(),"consumers",p.getConsumerList().size()));}
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
    int beforeProofEvents=count(p);long beforeProofRevision=p.getModificationNumber();
    var proofWrite=new Mutation(p,"proof-write");boolean proofSuccess=false;
    try{toolAction("stock-ordinary-refresh",out.resolve("reviewed-P-proof.json"));proofSuccess=true;}
    finally{proofWrite.end(proofSuccess);}
    long proofRevision=p.getModificationNumber();
    Files.writeString(out.resolve("P-post-proof-authority.json"),authority(p));
    event("proof-write-completed",Map.of("program_id",p.getUniqueProgramID(),"before_revision",beforeProofRevision,"revision",proofRevision,"before_events",beforeProofEvents));
    drain();
    observe(pf,"P-post-proof");
    if(proofRevision<=beforeProofRevision||count(p)<=beforeProofEvents)
      throw new IllegalStateException("No committed proof-write/event delivery");
    ordinaryRefresh("P3",false);observe(pf,"P3");
    save("P-source-after.json",canonical(getFunctionAt(toAddr(0x150))));
    navigate(getFunctionAt(toAddr(0x150)),"canonical-control");observe(getFunctionAt(toAddr(0x150)),"canonical-control");
    var q=openFixture("W4_MEMORY_IMAGE.gb",false);currentProgram=q;
    listen(q);
    try {
      var first=StockEntries.entries(q).stream().filter(e->e.generation()!=null).findFirst().orElseThrow();
      var qa=q.getAddressFactory().getAddress(first.carrier());var qf=getFunctionAt(qa);
      bindings("Q");Files.writeString(out.resolve("Q-I1-authority.json"),authority(q));
      navigate(qf,"Q0");observe(qf,"Q0");imageSource("Q0",qa);
      String originalImage=ExecutableImages.serialized(q);
      String originalProof=q.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(qa.toString(),null);
      var replacement=new Mutation(q,"Q-mutation");replacement.affectedStart=toAddr(0xc200).toString();boolean replaced=false;
      try{q.getMemory().setBytes(toAddr(0xc200),HexFormat.of().parseHex("3ea7ea74c0c9"));replaced=true;}finally{replacement.end(replaced);}
      event("Q-mutation-committed",replacement.detail());
      drain();observe(qf,"Q1");
      boolean imageRetained=Objects.equals(originalImage,ExecutableImages.serialized(q));
      boolean proofRetained=Objects.equals(originalProof,q.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(qa.toString(),null));
      save("Q-mutation.json",Map.of("old_image_retained",imageRetained,"old_proof_retained",proofRetained,"cpu",0xc200,"bytes",HexFormat.of().formatHex(getBytes(toAddr(0xc200),6)),"generation",first.generation()));
      if(!imageRetained||!proofRetained)throw new IllegalStateException("Physical replacement changed old image/proof authority");
      var generation=new Mutation(q,"Q-generation");boolean established=false;Address qb;
      try {
        var image=ExecutableImages.establish(q,toAddr(0x320),0xc200,HexFormat.of().parseHex("3ea7ea74c0c9"),"explicit G1 user generation G2",monitor);
        qb=PredicatedCalls.install(q,preview(getFunctionAt(q.getAddressFactory().getAddress(image.entry())),image.generation()),monitor);
        established=true;
      }finally{generation.end(established);}
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
      for(var program:List.of(p,q)){sample(program,"before-save");program.getDomainFile().save(monitor);sample(program,"after-save");}
      Files.writeString(out.resolve("P-saved-authority.json"),authority(p));Files.writeString(out.resolve("Q-saved-authority.json"),authority(q));
      save("saved-entries.json",Map.of("P",pa.toString(),"Q1",qa.toString(),"Q2",qb.toString(),"G1",first.generation()));
      missingNegative(p,q,pa);
    }finally{unlisten(q);}
  }
  void missingNegative(Program p,Program q,Address pa)throws Exception {
      // A distinct saved copy supplies the warm negative; positive P/Q remain saved and intact.
      var variantFile=p.getDomainFile().copyTo(state.getProject().getProjectData().getRootFolder().createFolder("G1-negative-"+ProcessHandle.current().pid()),monitor);
      save("variant-file.json",Map.of("name",variantFile.getName()));
      var variant=openFixture(variantFile.getParent().getName()+"/"+variantFile.getName(),false);listen(variant);currentProgram=variant;
      var variantFunction=getFunctionAt(variant.getAddressFactory().getAddress(pa.toString()));
      event("variant-setup",Map.of("source",identity(p),"variant",identity(variant),"reason","copyTo assigns a new Program ID; explicitly derive authority for this disposable copy before warm measurement"));
      navigate(variantFunction,"variant-setup");
      toolAction("stock-ordinary-preview",out.resolve("reviewed-variant-proof.json"));
      var variantProof=new Mutation(variant,"variant-proof-write");boolean variantReady=false;
      try{toolAction("stock-ordinary-refresh",out.resolve("reviewed-variant-proof.json"));variantReady=true;}finally{variantProof.end(variantReady);}
      drain();variant.getDomainFile().save(monitor);
      Files.writeString(out.resolve("variant-warm-authority.json"),authority(variant));
      observe(variantFunction,"missing-warm");
      var removal=new Mutation(variant,"registration-removal");boolean removed=false;
      try{variant.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS).removeOption(pa.toString());removed=true;}finally{removal.end(removed);}
      event("registration-removed",removal.detail());
      drain();observe(getFunctionAt(variant.getAddressFactory().getAddress(pa.toString())),"missing-passive");
      requireMissingRefusal();
      var invalid=getFunctionAt(variant.getAddressFactory().getAddress(pa.toString()));
      if(!ordinaryRefresh("missing-active",true)) {
        event("ACTIVE_NAVIGATION_REFUSAL",Map.of("program_id",variant.getUniqueProgramID(),"controller_identity",System.identityHashCode(window.getController()),"toolbar_refresh",false));
        navigate(getFunctionAt(toAddr(0x150)),"missing-away");navigate(invalid,"missing-back");
      }
      observe(invalid,"missing-active");requireMissingRefusal();
      unlisten(variant);closePrograms(variant,p,q);
  }
  void reopen()throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    window=(DecompilerProvider)state.getTool().getComponentProvider("Decompiler");
    var saved=ProgramMapping.JSON.fromJson(Files.readString(Path.of(getScriptArgs()[3]).resolve("saved-entries.json")),com.google.gson.JsonObject.class);
    var p=openFixture("F1234.gb",true);listen(p);var q=openFixture("W4_MEMORY_IMAGE.gb",true);listen(q);
    Files.writeString(out.resolve("P-before-authority.json"),authority(p));Files.writeString(out.resolve("Q-before-authority.json"),authority(q));
    visit(p,p.getAddressFactory().getAddress(saved.get("P").getAsString()),"reopen-P");
    visit(q,q.getAddressFactory().getAddress(saved.get("Q2").getAsString()),"reopen-Q");
    visit(q,q.getAddressFactory().getAddress(saved.get("Q1").getAsString()),"reopen-Q-old");
    Files.writeString(out.resolve("P-after-authority.json"),authority(p));Files.writeString(out.resolve("Q-after-authority.json"),authority(q));
    unlisten(p);unlisten(q);closePrograms(p,q);save("timeline.json",timeline);
  }
  void calibration()throws Exception {
    event("rehearsal-calibration", "Controlled transaction tests only; excluded from final qualification");
    var p=currentProgram;
    int tx=p.startTransaction("G1 deliberately held owned calibration");owned.get(p).add(tx);
    try {
      try{drain();throw new IllegalStateException("Calibration accepted held owned transaction");}
      catch(IllegalStateException expected){if(!expected.getMessage().equals("Owned transaction remains open"))throw expected;
        event("rehearsal-owned-refusal",expected.getMessage());}
    }finally{p.endTransaction(tx,false);owned.get(p).remove(tx);}
    var started=new java.util.concurrent.CountDownLatch(1);
    var failure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
    var worker=new Thread(()->{
      int other=p.startTransaction("G1 controlled temporary independent operation");
      started.countDown();
      try{Thread.sleep(1000);}catch(Exception e){failure.set(e);}finally{p.endTransaction(other,true);}
    },"G1-calibration-transaction-owner");
    worker.start();started.await();drain();worker.join();
    if(failure.get()!=null)throw new RuntimeException(failure.get());
    event("rehearsal-temporary-settled",identity(p));
  }
  void suffixRehearsal()throws Exception {
    if(!System.getProperty("g1.rehearsal","false").equals("true"))throw new IllegalStateException("Suffix is rehearsal only");
    var source=Path.of(getScriptArgs()[3]);
    var saved=ProgramMapping.JSON.fromJson(Files.readString(source.resolve("saved-entries.json")),com.google.gson.JsonObject.class);
    var p=currentProgram;var q=openFixture("W4_MEMORY_IMAGE.gb",false);listen(q);
    event("suffix-rehearsal",Map.of("source_captures",source.toString(),"not_acceptance",true));
    Files.writeString(out.resolve("P-saved-authority.json"),authority(p));Files.writeString(out.resolve("Q-saved-authority.json"),authority(q));
    Files.copy(source.resolve("saved-entries.json"),out.resolve("saved-entries.json"));
    try{missingNegative(p,q,p.getAddressFactory().getAddress(saved.get("P").getAsString()));}finally{unlisten(q);}
  }
  @Override public void run()throws Exception {
    if(isRunningHeadless())throw new IllegalStateException("Requires normal CodeBrowser");
    if(currentProgram!=null)throw new IllegalStateException("Launcher must supply no script Program; no hidden Script Manager transaction");
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    if(getScriptArgs().length>1 && getScriptArgs()[1].equals("reopen")){reopen();return;}
    currentProgram=state.getTool().getService(ProgramManager.class).getCurrentProgram();
    // The launcher executes with null script Program; only explicit Mutation IDs are ours.

    window=(DecompilerProvider)state.getTool().getComponentProvider("Decompiler");
    var listened=currentProgram;
    listen(listened);
    try {
      if(getScriptArgs()[1].equals("suffix-rehearsal")){suffixRehearsal();return;}
      var entry=StockEntries.entries(currentProgram).stream().filter(e->e.generation()==null).findFirst().orElseThrow();
      var at=currentProgram.getAddressFactory().getAddress(entry.carrier());var f=getFunctionAt(at);
      save("P-source-before.json",canonical(getFunctionAt(toAddr(0x150))));
      var original=currentProgram.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS).getString(at.toString(),null);
      Files.writeString(out.resolve("P-original-registration.json"),original);
      navigate(f,"P0");if(System.getProperty("g1.rehearsal","false").equals("true")){calibration();drain();}observe(f,"P0");navigate(f,"P1");observe(f,"P1");
      var source=ProgramMapping.fileToStatic(currentProgram,0xe000).stream().filter(a->a.getAddressSpace().getName().equals("rom3")).findFirst().orElseThrow();
      if((currentProgram.getMemory().getByte(source)&255)!=0xd3)throw new IllegalStateException("Not fresh D3 fixture");
      var before=ProgramMapping.exportBytes(currentProgram,true,false,monitor);
      var mutation=new Mutation(currentProgram,"P-mutation");mutation.affectedStart=source.toString();boolean changedByte=false;
      try{currentProgram.getMemory().setByte(source,(byte)0xe4);changedByte=true;}finally{mutation.end(changedByte);}
      event("P-mutation-committed",mutation.detail());
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
    }finally{unlisten(listened);save("timeline.json",timeline);}
  }
}
