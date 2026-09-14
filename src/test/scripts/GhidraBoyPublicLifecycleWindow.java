// @category Game Boy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.services.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Swing;
import ghidra.util.task.*;
import java.io.PrintWriter;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/** Attended normal-provider workflow. No controller reset, fabricated event or replacement interface. */
public class GhidraBoyPublicLifecycleWindow extends GhidraBoyStockWindow {
  static void require(boolean ok,String message){if(!ok)throw new IllegalStateException(message);}
  static class GateWriter extends PrintWriter {
    final CountDownLatch reached=new CountDownLatch(1),release=new CountDownLatch(1);
    GateWriter(){super(System.out,true);}
    @Override public void println(String text){super.println(text);
      if(text.contains("\"mutation\": \"NO_DATABASE_CHANGE\"")) {
        require(!javax.swing.SwingUtilities.isEventDispatchThread(),"Never hold EDT on worker gate");reached.countDown();
        try{require(release.await(30,TimeUnit.SECONDS),"Worker gate timed out");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException(e);}
      }
    }
  }
  GhidraBoyTools start(PrintWriter writer,String... args)throws Exception {return startWithMonitor(writer,new TaskMonitorAdapter(true),args);}
  GhidraBoyTools startWithMonitor(PrintWriter writer,TaskMonitor operationMonitor,String... args)throws Exception {
    // Separate standalone calls must observe the preceding tool/analysis owner settle.
    // This does not retry a refused mutation or opt into a foreign transaction.
    long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(30);boolean waited=false;
    while(state.getTool().isExecutingCommand()||currentProgram.getCurrentTransactionInfo()!=null){
      require(System.nanoTime()<deadline,"Standalone boundary did not settle");operationMonitor.checkCancelled();waited=true;Thread.sleep(20);
    }
    event("standalone-boundary",Map.of("program",identity(currentProgram),"waited",waited,"toolBusy",state.getTool().isExecutingCommand(),"transactionPending",currentProgram.getCurrentTransactionInfo()!=null));
    event("public-action-invoke",Map.of("action",args[0],"program",identity(currentProgram)));
    var script=new GhidraBoyTools();script.setScriptArgs(args);
    script.setPropertiesFileLocation(getScriptArgs()[1],"GhidraBoyTools");
    script.execute(new ghidra.app.script.GhidraState(state.getTool(),state.getProject(),currentProgram,
        (target!=null && target.getProgram()==currentProgram?new ProgramLocation(currentProgram,target.getEntryPoint()):null),null,null),operationMonitor,writer);
    event("public-action-return",Map.of("action",args[0],"program",identity(currentProgram),"operation",script.lastOperation==null?"read-preview":script.lastOperation.id(),"arguments",List.of(args)));
    return script;
  }
  GhidraBoyTools action(String... args)throws Exception {
    var script=start(new PrintWriter(System.out,true),args);
    if(script.lastOperation!=null) {
      var result=script.lastOperation.completion().get(60,TimeUnit.SECONDS);
      save("operation-"+script.lastOperation.id()+".json",result);
      event("public-action-outcome",result);
      script.lastPresentation.get(60,TimeUnit.SECONDS);script.lastOperation.released().get(60,TimeUnit.SECONDS);
      require(result.current(),"Public action did not produce current outcome: "+result);
    }
    return script;
  }
  Path preview(ConditionalCallSites.Request request,String label)throws Exception {
    Path input=out.resolve(label+"-request.json"),proof=out.resolve(label+"-proof.json");save(label+"-request.json",request);
    action("conditional-call-preview",input.toString(),proof.toString());return proof;
  }
  ConditionalCallSites.Request domain(ConditionalCallSites.Request r,int min,int max) {
    return new ConditionalCallSites.Request(r.programId(),r.imageSha256(),r.site(),r.mapper(),r.shadowCpu(),r.shadowValue(),r.memoryInputs(),
        new SymbolicMemory.Footprint(min,max,-16,1),r.incomingStackBytes(),r.continuationSteps(),true,true,r.provenance());
  }
  void refreshAll(String label)throws Exception {
    for(String name:new ArrayList<>(currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames())) {
      var entry=ProgramMapping.staticAddress(currentProgram,name);var request=PredicatedCalls.registeredProof(currentProgram,entry).callSite();
      action("stock-predicate-refresh",preview(request,label+"-"+Integer.toHexString(name.hashCode())).toString(),name);
    }
  }
  void requestOrdering(Program p,Address at,Program q,Address other,boolean switchAway)throws Exception {
    currentProgram=p;navigate(p.getFunctionManager().getFunctionAt(at),"ordering-start-"+switchAway);
    var gate=new GateWriter();var a=start(gate,"conditional-call-explain",at.toString());
    try {
      require(gate.reached.await(30,TimeUnit.SECONDS),"A publication not reached");long revision=p.getModificationNumber();
      if(switchAway) {
        currentProgram=q;navigate(q.getFunctionManager().getFunctionAt(other),"ordering-Q");observe(target,"ordering-Q");
        currentProgram=p;navigate(p.getFunctionManager().getFunctionAt(at),"ordering-back-P");
      }
      var b=action("conditional-call-explain",at.toString());
      require("PUBLISHED".equals(b.lastPresentation.get(30,TimeUnit.SECONDS)),"B must publish first");
      require(p.getModificationNumber()==revision,"Ordering witness must leave P unchanged");
      event("request-B-published",Map.of("A",a.lastOperation.completion().get(30,TimeUnit.SECONDS),"B",b.lastOperation.completion().get(30,TimeUnit.SECONDS),"revision",revision,"switchAway",switchAway));
      gate.release.countDown();String disposition=a.lastPresentation.get(30,TimeUnit.SECONDS);
      require(disposition.equals(switchAway?"ACTIVATION_SUPERSEDED":"REQUEST_SUPERSEDED"),"A replaced B: "+disposition);
      event("request-A-disposition",Map.of("operation",a.lastOperation.id(),"disposition",disposition,"revision",p.getModificationNumber(),"switchAway",switchAway));
      save("ordering-"+switchAway+".json",Map.of("program",identity(p),"revision",revision,"A",disposition,"B","PUBLISHED","unchanged",true,"A_operation",a.lastOperation.id(),"B_operation",b.lastOperation.id()));
    }finally{gate.release.countDown();}
  }
  void activationOnly(Program p,Address entry,Program q)throws Exception {
    currentProgram=p;navigate(p.getFunctionManager().getFunctionAt(entry),"activation-only-start");
    p.save("Explicit clean baseline before activation-only request",monitor);require(!p.isTemporary()&&!p.isChanged(),"Activation-only baseline not clean");
    var gate=new GateWriter();var a=start(gate,"conditional-call-explain",entry.toString());
    try {
      require(gate.reached.await(30,TimeUnit.SECONDS),"Activation-only publication gate");long revision=p.getModificationNumber();
      event("activation-only-A-return",Map.of("operation",a.lastOperation.id(),"program",identity(p),"revision",revision));
      var manager=state.getTool().getService(ProgramManager.class);
      Swing.runNow(()->{manager.setCurrentProgram(q);require(manager.getCurrentProgram()==q,"Actual Q activation failed");});event("activation-only-Q",identity(q));
      Swing.runNow(()->{manager.setCurrentProgram(p);require(manager.getCurrentProgram()==p,"Actual P reactivation failed");});event("activation-only-P",identity(p));
      gate.release.countDown();String disposition=a.lastPresentation.get(30,TimeUnit.SECONDS);require(disposition.equals("ACTIVATION_SUPERSEDED"),"Activation-only A revived");
      require(revision==p.getModificationNumber(),"Activation-only source changed");
      var receipt=Map.of("operation",a.lastOperation.id(),"program",identity(p),"disposition",disposition,"new_public_request",false,"unchanged",true,"revision",revision);
      event("activation-only-A-disposition",receipt);save("activation-only.json",receipt);
    }finally{gate.release.countDown();}
  }
  void outstandingNativeSwitch(Program q,Address entry)throws Exception {
    Program p=currentProgram;var record=new LinkedHashMap<String,Object>();record.put("native_processes_before",processes());
    Swing.runNow(()->{
      var providers=docking.DockingWindowManager.getAllDockingWindowManagers().stream().flatMap(manager->manager.getComponentProviders(DecompilerProvider.class).stream()).toList();
      require(providers.size()==1&&providers.getFirst()==window,"Native stack attribution requires exactly this normal provider in the JVM");
      record.put("normal_provider_count",providers.size());record.put("source_revision_before",p.getModificationNumber());
      var refresh=state.getTool().getAllActions().stream().filter(a->a.getName().equals("Refresh")&&a.getOwner().equals("DecompilePlugin")).findFirst().orElseThrow();
      var context=window.getActionContext(null);boolean enabled=context!=null&&refresh.isEnabledForContext(context);
      record.put("enabled",enabled);require(enabled,"Normal native Refresh disabled before cancellation witness");
      refresh.actionPerformed(context);record.put("invoked",true);record.put("outstanding_after_request",window.getController().isDecompiling());
      record.put("controller",System.identityHashCode(window.getController()));
    });
    long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);var nativeStacks=new ArrayList<Object>();
    while(System.nanoTime()<deadline){
      for(var item:Thread.getAllStackTraces().entrySet())if(Arrays.stream(item.getValue()).anyMatch(frame->frame.getClassName().equals("ghidra.app.decompiler.component.DecompileRunnable"))&&Arrays.stream(item.getValue()).anyMatch(frame->frame.getClassName().equals("ghidra.app.decompiler.DecompileProcess")&&(frame.getMethodName().equals("readResponse")||frame.getMethodName().equals("sendCommandTimeout"))))
        nativeStacks.add(Map.of("thread",item.getKey().getName(),"id",item.getKey().threadId(),"stack",Arrays.stream(item.getValue()).map(Object::toString).toList()));
      if(!nativeStacks.isEmpty()||!window.getController().isDecompiling())break;Thread.sleep(1);
    }
    record.put("native_worker_stacks",nativeStacks);record.put("native_work_phase",nativeStacks.isEmpty()?"UNOBSERVED":"RUNNING_REQUEST_AT_SAMPLE");
    record.put("P",identity(p));record.put("Q",identity(q));
    if(!nativeStacks.isEmpty())Swing.runNow(()->{
      record.put("outstanding_at_switch",window.getController().isDecompiling());record.put("source_revision_at_switch",p.getModificationNumber());
      state.getTool().getService(ProgramManager.class).setCurrentProgram(q);
      state.getTool().getService(GoToService.class).goTo(new ProgramLocation(q,entry));
    });
    record.put("boundary","Normal ProgramManager activation; stock provider owns native cancellation");save("native-outstanding-switch.json",record);
    require(!nativeStacks.isEmpty()&&Boolean.TRUE.equals(record.get("outstanding_at_switch"))&&record.get("source_revision_before").equals(record.get("source_revision_at_switch")),"Running native request interleaving not observed; no cancellation credit");
    currentProgram=q;target=q.getFunctionManager().getFunctionAt(entry);drain();observe(target,"native-after-switch-Q");
  }
  void closeDuringComputation(Program program,Address entry)throws Exception {
    currentProgram=program;var manager=state.getTool().getService(ProgramManager.class);Swing.runNow(()->{manager.openProgram(program);manager.setCurrentProgram(program);});
    target=program.getFunctionManager().getFunctionAt(entry);var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var first=new java.util.concurrent.atomic.AtomicBoolean();
    String authorityBefore=program.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(entry.toString(),null);
    var control=new TaskMonitorAdapter(true){@Override public void checkCancelled()throws ghidra.util.exception.CancelledException {
      if(PredicatePublication.inventory().get("requests")>0 && PredicateOperations.inventory().get("observations")>0 && first.compareAndSet(false,true)) {
        entered.countDown();try{require(release.await(30,TimeUnit.SECONDS),"Computational close gate timeout");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException(e);}
      }super.checkCancelled();
    }};
    var executor=Executors.newSingleThreadExecutor();
    try {
      var work=executor.submit(()->startWithMonitor(new PrintWriter(System.out,true),control,"conditional-call-explain",entry.toString()));
      require(entered.await(30,TimeUnit.SECONDS),"Actual computation gate not observed");boolean[] closed={false};Swing.runNow(()->closed[0]=manager.closeProgram(program,true));
      boolean cancelledBeforeOwner=control.isCancelled();
      String closeRoute;
      if(closed[0]){
        require(cancelledBeforeOwner,"Accepted close did not cancel the live request before owner intervention");
        closeRoute="ACCEPTED_CLOSE_CANCELLED_REQUEST";
      }else{closeRoute="DEFERRED_CLOSE_THEN_OWNER_CANCEL";control.cancel();}
      event("computation-close-disposition",Map.of("accepted",closed[0],"cancelledBeforeOwner",cancelledBeforeOwner,"route",closeRoute));
      release.countDown();
      try{var script=work.get(30,TimeUnit.SECONDS);require(!"PUBLISHED".equals(script.lastPresentation.get(30,TimeUnit.SECONDS)),"Closed/cancelled computation published");}
      catch(ExecutionException expected){require(expected.getCause() instanceof ghidra.util.exception.CancelledException,"Unexpected computation failure: "+expected.getCause());}
      if(!closed[0])Swing.runNow(()->require(manager.closeProgram(program,true),"Normal close did not recover after cancellation"));
      require(authorityBefore.equals(program.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(entry.toString(),null)),"Closing computation changed committed authority");
      require(PredicateOperations.inventory().get("observations")==0&&PredicatePublication.inventory().get("requests")==0,"Running operation resources remain");
      save("close-during-computation.json",Map.of("initial_close_accepted",closed[0],"cancelled_by_owner",!closed[0],"route",closeRoute,"cancelled_before_owner",cancelledBeforeOwner,"committed_authority_unchanged",true,"operations",PredicateOperations.inventory(),"publication",PredicatePublication.inventory()));
    }finally{release.countDown();executor.shutdownNow();executor.awaitTermination(30,TimeUnit.SECONDS);}
  }
  static List<java.awt.Component> components(java.awt.Component root){
    var all=new ArrayList<java.awt.Component>();all.add(root);if(root instanceof java.awt.Container c)for(var child:c.getComponents())all.addAll(components(child));return all;
  }
  static javax.swing.AbstractButton button(java.awt.Dialog dialog,String text){
    return components(dialog).stream().filter(c->c instanceof javax.swing.AbstractButton b&&text.equals(b.getText())&&b.isShowing()&&b.isEnabled()).map(c->(javax.swing.AbstractButton)c).findFirst().orElseThrow();
  }
  void captureDialog(java.awt.Dialog dialog,String label)throws Exception {
    var at=dialog.getLocationOnScreen();javax.imageio.ImageIO.write(new java.awt.Robot().createScreenCapture(new java.awt.Rectangle(at.x,at.y,dialog.getWidth(),dialog.getHeight())),"png",out.resolve(label+"-desktop.png").toFile());
  }
  void chooserAction(String label,String choice,Path file,boolean cancelChooser,boolean cancelFile)throws Exception {
    Program p=currentProgram;var tool=state.getTool();var manager=tool.getService(ProgramManager.class);var console=tool.getService(ConsoleService.class);
    var source=ghidra.app.script.GhidraScriptUtil.findScriptByName("GhidraBoyTools.java");
    require(source!=null&&source.getFile(false).toPath().toRealPath().equals(Path.of(getScriptArgs()[1],"GhidraBoyTools.java").toRealPath()),"Script Manager selected wrong script origin");
    var selectedLocation=tool.getService(CodeViewerService.class).getCurrentLocation();String selectedEntry=selectedLocation==null?"":selectedLocation.getAddress().toString();
    String before=authority(p);save(label+"-before.json",Sm83PreservationInventory.inventory(p));int offset=console.getTextLength();
    var finished=new CompletableFuture<String>();var failure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
    var interactions=new ArrayList<Object>();boolean[] acted={false,false};var dialogSamples=new java.util.IdentityHashMap<java.awt.Dialog,Integer>();
    var timer=new javax.swing.Timer(50,event->{try{
      for(var w:java.awt.Window.getWindows())if(w instanceof java.awt.Dialog dialog&&dialog.isShowing()){
        if(dialogSamples.merge(dialog,1,Integer::sum)<4)continue; // Let ordinary repaint precede desktop capture.
        if(!acted[0]&&dialog.getTitle().equals("GhidraBoy")){
          require(manager.getCurrentProgram()==p,"Wrong selected Program at chooser");captureDialog(dialog,label+"-action");
          if(!cancelChooser){
            var combo=components(dialog).stream().filter(c->c instanceof javax.swing.JComboBox<?> box&&java.util.stream.IntStream.range(0,box.getItemCount()).anyMatch(n->choice.equals(box.getItemAt(n)))).map(c->(javax.swing.JComboBox<?>)c).findFirst().orElseThrow();
            combo.setSelectedItem(choice);require(choice.equals(combo.getSelectedItem()),"Chooser selection failed");
          }
          acted[0]=true;interactions.add(Map.of("dialog",dialog.getTitle(),"choice",cancelChooser?"CANCEL":choice,"program",identity(p),"modality",dialog.getModalityType().toString()));button(dialog,cancelChooser?"Cancel":"OK").doClick();
        }else if(acted[0]&&!acted[1]&&dialog.getTitle().equals("Reviewed predicate proof JSON")){
          captureDialog(dialog,label+"-file");
          if(!cancelFile){
            var field=components(dialog).stream().filter(c->c instanceof javax.swing.JTextField&&"filenameTextField".equals(c.getName())).map(c->(javax.swing.JTextField)c).findFirst().orElseThrow();field.setText(file.toString());
          }
          acted[1]=true;interactions.add(Map.of("dialog",dialog.getTitle(),"action",cancelFile?"CANCEL":"Apply","file",cancelFile?"":file.toString(),"program",identity(p)));button(dialog,cancelFile?"Cancel":"Apply").doClick();
        }
      }
    }catch(Throwable problem){failure.set(problem);}});
    Swing.runNow(()->{tool.showComponentProvider(tool.getComponentProvider("Script Manager"),true);timer.start();});
    try {
      tool.getService(GhidraScriptService.class).runScript("GhidraBoyTools.java",new TaskListener(){
        public void taskCompleted(Task task){finished.complete("COMPLETED");}
        public void taskCancelled(Task task){finished.complete("CANCELLED");}
      });
      finished.get(60,TimeUnit.SECONDS);require(failure.get()==null,"Actual dialog interaction failed: "+failure.get());
      long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(30);
      while(tool.isExecutingCommand()||p.getCurrentTransactionInfo()!=null||PredicatePublication.inventory().get("requests")!=0||PredicateOperations.inventory().get("observations")!=0||PredicateOperations.inventory().get("gateUsers")!=0||PredicateOperations.inventory().get("cancellationListeners")!=0){require(System.nanoTime()<deadline,"Chooser resources did not settle");Thread.sleep(20);}
      Swing.runNow(()->{});String text=console.getText(offset,console.getTextLength()-offset);
      while(!text.contains("Finished!")&&!text.contains("User cancelled script")&&!text.contains("Error running script")){require(System.nanoTime()<deadline,"Script Manager console completion not observed");Thread.sleep(20);text=console.getText(offset,console.getTextLength()-offset);}
      Files.writeString(out.resolve(label+"-console.txt"),text);
      save(label+"-after.json",Sm83PreservationInventory.inventory(p));
      require(acted[0]&&(!cancelFile||acted[1]),"Required genuine dialog was not observed");
      require(manager.getCurrentProgram()==p,"Chooser changed selected Program");
      if(cancelChooser||cancelFile){require(before.equals(authority(p)),"Cancelled chooser changed owned authority");
        var inventoryBefore=com.google.gson.JsonParser.parseString(Files.readString(out.resolve(label+"-before.json"))).getAsJsonObject();
        var inventoryAfter=com.google.gson.JsonParser.parseString(Files.readString(out.resolve(label+"-after.json"))).getAsJsonObject();
        for(var inventory:List.of(inventoryBefore,inventoryAfter))inventory.getAsJsonObject("options").getAsJsonObject("Program Information").remove("Analysis Times.Times");
        require(inventoryBefore.equals(inventoryAfter),"Cancelled chooser changed preserved Program state beyond host analysis timing");require(!text.contains("Error running script")&&!text.contains("PUBLISHED")&&!text.contains("\"operationId\""),"Cancelled chooser ran or published a public operation");}
      else{require(!text.contains("Error running script")&&!text.contains("User cancelled script"),"Script Manager failed");if(!choice.equals("inspect"))require(text.contains("PUBLISHED"),"No successful public presentation after genuine chooser");}
      save(label+".json",Map.of("script",source.toString(),"script_sha256",hash(source.getFile(false).toPath()),"script_arguments",List.of(),"selected_entry",selectedEntry,"entrypoint","GhidraScriptService / real Script Manager","program",identity(p),"interactions",interactions,"task",finished.get(),"resources",Map.of("operations",PredicateOperations.inventory(),"publication",PredicatePublication.inventory())));
    }finally{Swing.runNow(timer::stop);}
  }
  void chooserAudit(Address entry,ConditionalCallSites.Request request)throws Exception {
    navigate(getFunctionAt(entry),"chooser-selected-domain");chooserAction("chooser-cancel","",null,true,false);
    chooserAction("chooser-inspect-recovery","inspect",null,false,false);
    chooserAction("chooser-file-cancel","stock-predicate-refresh",null,false,true);
    Path proof=preview(request,"chooser-reviewed-proof");
    navigate(getFunctionAt(entry),"chooser-refresh-domain");chooserAction("chooser-refresh","stock-predicate-refresh",proof,false,false);
    chooserAction("chooser-explain","conditional-call-explain",null,false,false);
    chooserAction("chooser-target","conditional-call-target",null,false,false);
    var expected=PredicatedCalls.registeredProof(currentProgram,entry).boundaries().stream().filter(b->b.kind().equals("RET_DISPATCH")).map(ConditionalCallSites.Boundary::physical).distinct().toList();
    require(expected.size()==1&&state.getTool().getService(CodeViewerService.class).getCurrentLocation().getAddress().toString().equals(expected.getFirst()),"No-argument navigation used wrong physical boundary");
    navigate(getFunctionAt(entry),"chooser-return-domain");
  }
  @Override void observe(ghidra.program.model.listing.Function expected,String label)throws Exception {
    super.observe(expected,label); // Required passive observation always precedes extra read-only evidence.
    if(!Files.exists(out.resolve(label+"-high.json")))return;
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
  @Override public void run()throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    // Launcher starts with no current Program: no enclosing script transaction is held here.
    var manager=state.getTool().getService(ProgramManager.class);currentProgram=manager.getCurrentProgram();
    var p=currentProgram;p.addConsumer(this);Program q=null;
    try {
    window=(DecompilerProvider)state.getTool().getComponentProvider("Decompiler");
    var seed=StockEntries.entries(p).stream().filter(e->e.generation()==null).findFirst().orElseThrow();
    Address seedAt=ProgramMapping.staticAddress(p,seed.carrier());target=getFunctionAt(seedAt);listen(p);
      if(Boolean.getBoolean("ghidraboy.publicReopen")) {
        require(!p.isChangeable(),"Second-session immutable Program required");String before=authority(p);long revision=p.getModificationNumber();
        drain();observe(target,"immutable-first");require(window.getController().getDecompileData().getHighFunction()!=null,"First immutable normal use failed before collector navigation");
        int index=0;for(String name:p.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames()) {
          navigate(getFunctionAt(ProgramMapping.staticAddress(p,name)),"immutable-"+index);observe(target,"immutable-"+index++);
          require(window.getController().getDecompileData().getHighFunction()!=null,"Immutable normal native use failed");
        }
        require(before.equals(authority(p))&&revision==p.getModificationNumber(),"Immutable use changed authority");
        String saved=ProgramMapping.JSON.fromJson(Files.readString(Path.of(System.getProperty("ghidraboy.publicBaseline"))),String.class);
        require(before.equals(saved),"First immutable session differs from the actual saved authority");
        save("public-window-complete.json",Map.of("immutable",true,"authority",before,"unchanged",true,"program",identity(p)));return;
      }
      String before=authority(p);save("before-inventory.json",Sm83PreservationInventory.inventory(p));
      Files.write(out.resolve("before-original.gb"),ProgramMapping.exportBytes(p,false,false,monitor));
      Files.write(out.resolve("before-current.gb"),ProgramMapping.exportBytes(p,true,false,monitor));
      // Use existing saved premises only as preparation; measured creation takes the real public apply route.
      var request=domain(PredicatedCalls.registeredProof(p,seedAt).callSite(),0xc180,0xc600);
      var initial=action("stock-predicate-apply",preview(request,"initial-public").toString());Address at=initial.lastOperation.entry();
      refreshAll("initial-domain-coherence");navigate(getFunctionAt(at),"public-initial");observe(target,"public-initial");
      chooserAudit(at,request);
      action("conditional-call-explain",at.toString());action("conditional-call-target",at.toString());action("conditional-call-continuation",at.toString());
      navigate(getFunctionAt(at),"back-to-owned-before-source-edit");
      var proof=PredicatedCalls.registeredProof(p,at);var callee=proof.boundaries().stream().filter(b->b.kind().equals("RET_DISPATCH")).findFirst().orElseThrow();
      var changed=ProgramMapping.staticAddress(p,callee.physical()).add(2);require((p.getMemory().getByte(changed)&255)==0x3c,"Use a fresh self-authored INC fixture");
      String oldRegistration=p.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(at.toString(),null);var mutation=new Mutation(p,"consumed-source-edit");boolean committed=false;mutation.affectedStart=changed.toString();
      try{p.getListing().clearCodeUnits(changed,changed,false);p.getMemory().setByte(changed,(byte)0x3d);committed=true;}finally{mutation.end(committed);}
      require(oldRegistration.equals(p.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(at.toString(),null)),"Source edit replaced old authority");
      save("source-edit.json",Map.of("program",identity(p),"source",changed.toString(),"old",0x3c,"new",0x3d,"old_registration_retained",true));
      drain();observe(target,"public-passive-stale");var data=window.getController().getDecompileData();
      require(data.getHighFunction()==null&&String.valueOf(data.getErrorMessage()).contains("Stale"),"Passive stale refusal missing");
      action("stock-predicate-refresh",preview(request,"explicit-fresh").toString(),at.toString());
      drain();observe(target,"public-event-recovery");ordinaryRefresh("public-enabled-refresh",false);observe(target,"public-toolbar-refresh");
      var second=domain(request,0xc200,0xc500);var applied=action("stock-predicate-apply",preview(second,"second-domain").toString());
      Address other=applied.lastOperation.entry();refreshAll("explicit-after-topology");
      for(var address:List.of(other,at,at,other)){navigate(getFunctionAt(address),"domain-order-"+(++operationSequence));observe(target,"domain-order-"+operationSequence);}
      save("positive-inventory.json",Sm83PreservationInventory.inventory(p));p.save("Public lifecycle positive candidate",monitor);save("saved-authority.json",authority(p));
      // Q is a new self-authored image/Program, not copied foreign executable authority.
      var image=ProgramMapping.exportBytes(p,true,false,monitor);
      q=new ghidra.program.database.ProgramDB("public-removal-variant",p.getLanguage(),p.getLanguage().getDefaultCompilerSpec(),this);
      try(var bytes=new ghidra.app.util.bin.ByteArrayProvider(image)) {
        CartridgeLayout.load(q,bytes,"CARTRIDGE","AUTO",GameBoyKind.GB,true,false,monitor,new ghidra.app.util.importer.MessageLog());
      }
      int preparation=q.startTransaction("Explicit self-authored second-Program fixture preparation");
      try{ghidra.program.util.GhidraProgramUtilities.markProgramAnalyzed(q);}finally{q.endTransaction(preparation,true);}
      // Same established fixture-startup policy as GhidraBoyStockWindowPrepare: future analysis events remain enabled.
      var folder=state.getProject().getProjectData().getRootFolder().createFolder("public-removal-variant");folder.createFile("variant.gb",q,monitor);
      final Program variant=q;listen(q);Swing.runNow(()->manager.openProgram(variant));currentProgram=q;target=null;
      save("Q-preparation.json",Map.of("source",identity(p),"source_export","current","image_sha256",Sha256.of(image),"target",identity(q),
          "foreign_authority_copied",false,"startup_prompt_policy","Explicit self-authored fixture prepared flag; future analysis events remain enabled"));
      save("Q-before-public.json",Sm83PreservationInventory.inventory(q));
      var qRequest=new ConditionalCallSites.Request(q.getUniqueProgramID(),ProgramMapping.inspect(q).originalSha256(),request.site(),request.mapper(),request.shadowCpu(),request.shadowValue(),request.memoryInputs(),request.footprint(),request.incomingStackBytes(),request.continuationSteps(),true,true,request.provenance());
      var qApply=action("stock-predicate-apply",preview(qRequest,"explicit-Q-premises").toString());Address qEntry=qApply.lastOperation.entry();
      target=q.getFunctionManager().getFunctionAt(qEntry);navigate(target,"Q-positive");observe(target,"Q-positive");q.save("Prepared self-authored variant",monitor);
      requestOrdering(p,at,q,qEntry,false);requestOrdering(p,at,q,qEntry,true);activationOnly(p,at,q);
      currentProgram=p;navigate(p.getFunctionManager().getFunctionAt(at),"before-native-switch");outstandingNativeSwitch(q,qEntry);
      for(int i=0;i<8;i++) {
        currentProgram=p;Swing.runNow(()->{manager.openProgram(p);manager.setCurrentProgram(p);});target=p.getFunctionManager().getFunctionAt(at);
        var gate=new GateWriter();var operation=start(gate,"conditional-call-explain",at.toString());
        try {
          require(gate.reached.await(30,TimeUnit.SECONDS),"Close publication gate");Swing.runNow(()->manager.closeProgram(p,true));
          require(!p.isClosed(),"Logical close must be distinguished from owned consumers");gate.release.countDown();
          require("TARGET_CLOSED".equals(operation.lastPresentation.get(30,TimeUnit.SECONDS)),"Closed target published");
          operation.lastOperation.released().get(30,TimeUnit.SECONDS);
          save("close-resources-"+i+".json",Map.of("operations",PredicateOperations.inventory(),"publication",PredicatePublication.inventory(),"programConsumers",p.getConsumerList().size()));
          require(PredicateOperations.inventory().get("observations")==0&&PredicatePublication.inventory().get("requests")==0,"Owned registrations after close");
        }finally{gate.release.countDown();}
      }
      closeDuringComputation(p,at);
      currentProgram=q;navigate(q.getFunctionManager().getFunctionAt(qEntry),"removal-variant");
      Files.write(out.resolve("removal-current-before.gb"),ProgramMapping.exportBytes(q,true,false,monitor));
      int tx=q.startTransaction("Later user explanation in disposable removal variant");try{q.getFunctionManager().getFunctionAt(qEntry).setComment("Later user explanation");}finally{q.endTransaction(tx,true);}
      save("removal-before.json",Sm83PreservationInventory.inventory(q));action("stock-predicate-remove",qEntry.toString());
      require(!PredicatedCalls.registered(q,qEntry)&&"Later user explanation".equals(q.getFunctionManager().getFunctionAt(qEntry).getComment()),"Removal lost later edit or retained authority");
      save("removal-after.json",Sm83PreservationInventory.inventory(q));drain();observe(target,"removal-passive");requireMissingRefusal();Files.write(out.resolve("removal-current-after.gb"),ProgramMapping.exportBytes(q,true,false,monitor));q.save("Removed authority; later user edit preserved",monitor);
      require(Arrays.equals(Files.readAllBytes(out.resolve("removal-current-before.gb")),Files.readAllBytes(out.resolve("removal-current-after.gb"))),"Removal changed ROM export");
      currentProgram=p;Swing.runNow(()->{manager.openProgram(p);manager.setCurrentProgram(p);});target=p.getFunctionManager().getFunctionAt(at);
      var gate=new GateWriter();var operation=start(gate,"conditional-call-explain",at.toString());
      try {
        require(gate.reached.await(30,TimeUnit.SECONDS),"Tool disposal publication gate");Swing.runNow(()->state.getTool().close());gate.release.countDown();
        require(!"PUBLISHED".equals(operation.lastPresentation.get(30,TimeUnit.SECONDS)),"Disposed consumer published");
        operation.lastOperation.released().get(30,TimeUnit.SECONDS);require(PredicatePublication.inventory().get("requests")==0,"Tool request resources remain");
        save("public-tool-disposed.json",Map.of("publication",PredicatePublication.inventory(),"operations",PredicateOperations.inventory()));
      }finally{gate.release.countDown();}
      require(before!=null&&Arrays.equals(Files.readAllBytes(out.resolve("before-original.gb")),ProgramMapping.exportBytes(p,false,false,monitor)),"Original export changed");
      Files.write(out.resolve("after-current.gb"),ProgramMapping.exportBytes(p,true,false,monitor));
      save("public-window-complete.json",Map.of("program",identity(p),"saved",true,"normal_second_session_required",true,"initial_authority_hash",Sha256.of(before.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
    }finally{if(q!=null){if(listeners.containsKey(q))unlisten(q);q.release(this);}if(listeners.containsKey(p))unlisten(p);p.release(this);}
  }
}
