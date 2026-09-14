import fi.gekkio.ghidraboy.*;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.*;
import ghidra.base.project.GhidraProject;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.app.services.ProgramManager;
import ghidra.app.script.GhidraState;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.Swing;
import ghidra.util.task.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.io.PrintWriter;

/** Hidden, headed stock service test. No screenshot or visible-window acceptance. */
public class ServiceProbe implements GhidraLaunchable {
  static void require(boolean ok,String why){if(!ok)throw new AssertionError(why);}
  static GhidraBoyTools run(GhidraTool tool,ProgramDB p,TaskMonitor monitor,PrintWriter writer,String... args)throws Exception {
    var script=new GhidraBoyTools();script.setScriptArgs(args);
    script.execute(new GhidraState(tool,tool.getProject(),p,null,null,null),monitor,writer);return script;
  }
  static final class GateWriter extends PrintWriter {
    final CountDownLatch reached=new CountDownLatch(1),release=new CountDownLatch(1);
    final String mutation;
    GateWriter(){this("NO_DATABASE_CHANGE");}
    GateWriter(String mutation){super(System.out,true);this.mutation=mutation;}
    @Override public void println(String text) {
      super.println(text);
      if(text.contains("\"mutation\": \""+mutation+"\"")) {
        require(!javax.swing.SwingUtilities.isEventDispatchThread(),"Worker gate must not block EDT");reached.countDown();
        try{require(release.await(30,TimeUnit.SECONDS),"publication gate timeout");}catch(InterruptedException e){throw new AssertionError(e);}
      }
    }
  }
  static Map<String,Object> thread(GhidraTool tool){return Map.of("id",Thread.currentThread().threadId(),"name",Thread.currentThread().getName(),"toolBackground",tool.threadIsBackgroundTaskThread(),"edt",javax.swing.SwingUtilities.isEventDispatchThread(),"stack",Arrays.stream(Thread.currentThread().getStackTrace()).map(Object::toString).toList());}
  static final class SchedulingWriter extends PrintWriter {
    final GhidraTool tool;final ProgramDB program;final Map<String,Object> submission;volatile Map<String,Object> worker;volatile boolean waiting;
    SchedulingWriter(GhidraTool t,ProgramDB p){super(System.out,true);tool=t;program=p;submission=thread(t);require(!t.threadIsBackgroundTaskThread()&&!javax.swing.SwingUtilities.isEventDispatchThread(),"Standalone submission context");}
    void observeWorker(){
      require(Arrays.stream(Thread.currentThread().getStackTrace()).anyMatch(x->x.getClassName().equals("GhidraBoyTools")&&x.getMethodName().equals("run")),"Missing actual shipped script worker frame");
      require(tool.threadIsBackgroundTaskThread()&&Thread.currentThread().threadId()!=((Number)submission.get("id")).longValue(),"Immediate path is not scheduled evidence");
      var tx=program.getCurrentTransactionInfo();require(tx!=null,"Worker transaction");worker=new LinkedHashMap<>(thread(tool));worker.put("transaction",tx.getID());worker.put("programId",program.getUniqueProgramID());worker.put("programObject",System.identityHashCode(program));
    }
  }
  static void settle(GhidraTool tool,ProgramDB p)throws Exception {
    long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(30);
    while(tool.isExecutingCommand()||p.getCurrentTransactionInfo()!=null){require(System.nanoTime()<deadline,"Tool analysis did not settle");Thread.sleep(20);}
    Swing.runNow(()->{});
  }
  static Object inventory(ProgramDB p)throws Exception {
    long revision=p.getModificationNumber();
    // Query the same public logical metadata before both observations. Ghidra's
    // rollback can clear cached default-option registrations; these reads neither
    // reset caches nor write defaults into the Program.
    p.getCompiler();ghidra.program.database.SpecExtension.checkFormatVersion(p);
    var result=Sm83PreservationInventory.inventory(p);require(revision==p.getModificationNumber(),"Inventory observation changed the Program");return result;
  }
  static GhidraBoyTools ownerArm(GhidraTool tool,ProgramDB p,Path proof,boolean abort,Path out,List<Object> rows)throws Exception {
    settle(tool,p);int prior=p.startTransaction("Earlier separately committed unrelated edit");
    try{p.getOptions("public-probe").setString("prior","survive");}finally{p.endTransaction(prior,true);}
    Files.writeString(out.resolve(abort?"owner-abort-before.json":"owner-commit-before.json"),ProgramMapping.JSON.toJson(inventory(p)));
    var returned=new CompletableFuture<GhidraBoyTools>();var ownerRelease=new CountDownLatch(1);var outer=new java.util.concurrent.atomic.AtomicReference<ghidra.framework.model.TransactionInfo>();
    var pending=new java.util.concurrent.atomic.AtomicReference<Object>();
    Swing.runNow(()->tool.executeBackgroundCommand(new ghidra.framework.cmd.BackgroundCommand<ghidra.program.model.listing.Program>("R3 public participant "+abort,true,true,false){
      @Override public boolean applyTo(ghidra.program.model.listing.Program program,TaskMonitor monitor){
        try(var owner=PredicateOperations.participate(p)){
          outer.set(p.getCurrentTransactionInfo());require(outer.get()!=null&&outer.get().getStatus()==ghidra.framework.model.TransactionInfo.Status.NOT_DONE,"Actual pending tool owner");
          p.getOptions("public-probe").setString("inside","owned");
          var script=ServiceProbe.run(tool,p,monitor,new PrintWriter(System.out,true),"stock-predicate-apply",proof.toString());
          require(script.lastOperation!=null&&!script.lastOperation.completion().isDone(),"Participating return must remain provisional");
          require(p.getCurrentTransactionInfo()==outer.get(),"Wrong encompassing transaction");
          pending.set(Map.of("thread",thread(tool),"outer",outer.get().getID(),"status",outer.get().getStatus().toString(),"provisional",script.lastOperation.provisional(),"terminalDone",script.lastOperation.completion().isDone()));
          returned.complete(script);
          require(ownerRelease.await(30,TimeUnit.SECONDS),"Foreground edit observation gate timeout");
          if(abort)throw new ghidra.util.exception.RollbackException("Deliberate test-owned rollback");
          return true;
        }catch(ghidra.util.exception.RollbackException e){throw e;}catch(Exception e){returned.completeExceptionally(e);throw new ghidra.util.exception.RollbackException(e.toString());}
      }
    },p));
    var script=returned.get(30,TimeUnit.SECONDS);var foreground=new LinkedHashMap<String,Object>();
    var commentAt=p.getAddressFactory().getDefaultAddressSpace().getAddress(0xc000);
    try{Swing.runNow(()->{
      var cmd=new ghidra.app.cmd.comments.SetCommentCmd(commentAt,ghidra.program.model.listing.CodeUnit.EOL_COMMENT,"R3 real foreground tool edit");
      foreground.put("submission",thread(tool));foreground.put("command",cmd.getClass().getName());foreground.put("outer",outer.get().getID());
      foreground.put("accepted",tool.execute(cmd,p));foreground.put("commentInside",String.valueOf(p.getListing().getComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT,commentAt)));
    });}finally{ownerRelease.countDown();}
    var result=script.lastOperation.completion().get(30,TimeUnit.SECONDS);
    script.lastPresentation.get(30,TimeUnit.SECONDS);script.lastOperation.released().get(30,TimeUnit.SECONDS);settle(tool,p);
    require("survive".equals(p.getOptions("public-probe").getString("prior",null)),"Prior unrelated commit lost");
    require(abort==!"owned".equals(p.getOptions("public-probe").contains("inside")?p.getOptions("public-probe").getString("inside",null):null),"Owner sentinel rollback boundary");
    require(abort==!PredicatedCalls.registered(p,script.lastOperation.entry()),"Owner authority rollback boundary");
    require(outer.get().getStatus()==(abort?ghidra.framework.model.TransactionInfo.Status.ABORTED:ghidra.framework.model.TransactionInfo.Status.COMMITTED),"Wrong retained outer outcome");
    Files.writeString(out.resolve(abort?"owner-abort-after.json":"owner-commit-after.json"),ProgramMapping.JSON.toJson(inventory(p)));
    String finalComment=p.getListing().getComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT,commentAt);
    foreground.put("commentAfter",String.valueOf(finalComment));foreground.put("ownerAborted",abort);
    if(Boolean.TRUE.equals(foreground.get("accepted")))require(abort?!"R3 real foreground tool edit".equals(finalComment):"R3 real foreground tool edit".equals(finalComment),"Foreground edit violated shared owner outcome");
    Files.writeString(out.resolve(abort?"foreground-abort.json":"foreground-commit.json"),ProgramMapping.JSON.toJson(foreground));
    var row=Map.of("row",abort?"TOOL_OWNER_ABORT":"TOOL_OWNER_COMMIT","pending",pending.get(),"outcome",result,"outerStatus",outer.get().getStatus().toString(),"rollbackMechanism",abort?"RollbackException":"normal return","priorSurvives",true,"insideSurvives",!abort,"presentation",script.lastPresentation.get());
    rows.add(row);Files.writeString(out.resolve(abort?"owner-abort.json":"owner-commit.json"),ProgramMapping.JSON.toJson(row));return script;
  }
  static void busyArm(GhidraTool tool,ProgramDB p,Path out,List<Object> rows)throws Exception {
    settle(tool,p);var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var returned=new CompletableFuture<Void>();
    String before=ProgramMapping.JSON.toJson(p.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames());
    Swing.runNow(()->tool.executeBackgroundCommand(new ghidra.framework.cmd.BackgroundCommand<ghidra.program.model.listing.Program>("R3 observed busy owner",true,true,false){
      public boolean applyTo(ghidra.program.model.listing.Program program,TaskMonitor monitor){
        entered.countDown();try{require(release.await(30,TimeUnit.SECONDS),"Busy owner gate timeout");p.getOptions("public-probe").setString("busy-owner-edit","retained");return true;}
        catch(InterruptedException failure){throw new ghidra.util.exception.RollbackException(failure.toString());}finally{returned.complete(null);}
      }
    },p));
    try {
      require(entered.await(30,TimeUnit.SECONDS),"Busy command not actually running");
      var tx=p.getCurrentTransactionInfo();require(tx!=null,"Busy owner not pending");
      String rejection="";try{run(tool,p,TaskMonitor.DUMMY,new PrintWriter(System.out,true),"conditional-call-explain",p.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames().getFirst());}
      catch(IllegalStateException expected){rejection=expected.toString()+" "+expected.getCause();}
      require(rejection.contains("foreign transaction pending"),"Busy request did not defer before writes");
      require(before.equals(ProgramMapping.JSON.toJson(p.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames())),"Deferred request changed authority");
      var row=Map.of("row","OBSERVED_BUSY_DEFERRAL","transaction",tx.getID(),"status",tx.getStatus().toString(),"rejection",rejection,"ownedWrites",false);
      rows.add(row);Files.writeString(out.resolve("busy-deferral.json"),ProgramMapping.JSON.toJson(row));
    }finally{release.countDown();returned.get(30,TimeUnit.SECONDS);settle(tool,p);}
    require("retained".equals(p.getOptions("public-probe").getString("busy-owner-edit",null)),"Supported owner's later edit lost");
  }
  static void hostedWaitArm(GhidraTool tool,ProgramDB p,ghidra.program.model.address.Address entry,boolean cancel,Path out,List<Object> rows)throws Exception {
    settle(tool,p);p.save("Clean baseline before hosted wait control",TaskMonitor.DUMMY);long revision=p.getModificationNumber();
    Path refreshProof=out.resolve("hosted-cancel-proof.json");
    if(cancel){Path request=out.resolve("hosted-cancel-request.json");Files.writeString(request,ProgramMapping.JSON.toJson(PredicatedCalls.registeredProof(p,entry).callSite()));run(tool,p,TaskMonitor.DUMMY,new PrintWriter(System.out,true),"conditional-call-preview",request.toString(),refreshProof.toString());settle(tool,p);}
    var monitor=new ghidra.util.task.WrappingTaskMonitor(new TaskMonitorAdapter(true));var gate=new GateWriter(cancel?"COMMITTED":"NO_DATABASE_CHANGE");var executor=Executors.newSingleThreadExecutor();
    var laterInfo=new java.util.concurrent.atomic.AtomicReference<ghidra.framework.model.TransactionInfo>();var laterAt=p.getAddressFactory().getDefaultAddressSpace().getAddress(0xc001);
    try {
      var future=executor.submit(()->cancel?run(tool,p,monitor,gate,"stock-predicate-refresh",refreshProof.toString(),entry.toString()):run(tool,p,monitor,gate,"conditional-call-explain",entry.toString()));
      require(gate.reached.await(30,TimeUnit.SECONDS),"Hosted wait did not reach deferred presentation");
      require(!future.isDone()&&p.getCurrentTransactionInfo()==null,"Hosted submitting task must wait after its owner completed");
      if(cancel){
        Swing.runNow(()->require(tool.execute(new ghidra.app.cmd.comments.SetCommentCmd(laterAt,ghidra.program.model.listing.CodeUnit.EOL_COMMENT,"Later committed edit after operation completion"){
          @Override public boolean applyTo(ghidra.program.model.listing.Program program){laterInfo.set(program.getCurrentTransactionInfo());return super.applyTo(program);}
        },p),"Later foreground edit refused"));settle(tool,p);
        require(laterInfo.get().getStatus()==ghidra.framework.model.TransactionInfo.Status.COMMITTED&&laterInfo.get().hasCommittedDBTransaction(),"Later edit was not separately committed");monitor.cancel();
      }
      gate.release.countDown();var script=future.get(30,TimeUnit.SECONDS);
      require(script.lastPresentation.get().equals(cancel?"CANCELLED_PUBLICATION":"PUBLISHED"),"Hosted task cancellation/presentation mismatch");
      require(script.lastOperation.completion().get().current(),"Hosted wait lost its committed outcome");
      if(cancel){require(script.lastOperation.completion().get().mutation()==PredicateOperations.Mutation.COMMITTED&&laterInfo.get().getID()!=script.lastOperation.completion().get().transactionId(),"Late cancel lacked separate commits");require("Later committed edit after operation completion".equals(p.getListing().getComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT,laterAt)),"Late cancellation lost the later edit");}
      else require(revision==p.getModificationNumber(),"Hosted read wait changed source");
      require(PredicatedCalls.registered(p,entry),"Late cancellation undid committed authority");
      require(PredicateOperations.inventory().get("cancellationListeners")==0,"Hosted cancellation listener leaked");
      var row=Map.of("row",cancel?"HOSTED_WAIT_CANCEL":"HOSTED_WAIT_SUCCESS","waited_after_owner_end",true,"cancel_requested",cancel,"outcome",script.lastOperation.completion().get(),"presentation",script.lastPresentation.get(),"unchanged",!cancel,"later_committed_edit_preserved",cancel,"later_transaction",cancel?laterInfo.get().getID():-1,"resources",PredicateOperations.inventory());
      rows.add(row);Files.writeString(out.resolve(cancel?"hosted-wait-cancel.json":"hosted-wait-success.json"),ProgramMapping.JSON.toJson(row));
    }finally{gate.release.countDown();executor.shutdownNow();executor.awaitTermination(30,TimeUnit.SECONDS);}
  }
  @Override public void launch(GhidraApplicationLayout layout,String[] args)throws Exception {
    Path out=Path.of(args[0]);Files.createDirectories(out);
    var config=new GhidraApplicationConfiguration();config.setShowSplashScreen(false);Application.initializeApplication(layout,config);
    var project=GhidraProject.createProject(out.toString(),"service-project",false);
    var language=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("SM83:LE:16:default"));
    var preparedP=new ProgramDB("P",language,language.getDefaultCompilerSpec(),this);var preparedQ=new ProgramDB("Q",language,language.getDefaultCompilerSpec(),this);
    for(var program:List.of(preparedP,preparedQ))try(var bytes=new ByteArrayProvider(Files.readAllBytes(Path.of(args[1])))){
      CartridgeLayout.load(program,bytes,"CARTRIDGE","AUTO",GameBoyKind.GB,true,false,TaskMonitor.DUMMY,new MessageLog());
    }
    for(var program:List.of(preparedP,preparedQ)){int tx=program.startTransaction("Self-authored fixture startup policy");try{ghidra.program.util.GhidraProgramUtilities.markProgramAnalyzed(program);}finally{program.endTransaction(tx,true);}}
    var pFile=project.getProjectData().getRootFolder().createFile("P",preparedP,TaskMonitor.DUMMY);var qFile=project.getProjectData().getRootFolder().createFile("Q",preparedQ,TaskMonitor.DUMMY);
    preparedP.release(this);preparedQ.release(this);
    var p=(ProgramDB)pFile.getDomainObject(this,false,false,TaskMonitor.DUMMY);var q=(ProgramDB)qFile.getDomainObject(this,false,false,TaskMonitor.DUMMY);
    GhidraTool[] holder={null};Swing.runNow(()->{
      var tool=new GhidraTool(project.getProject(),"Public operation service probe");holder[0]=tool;
      try{tool.addPlugin("ghidra.app.plugin.core.progmgr.ProgramManagerPlugin");tool.addPlugin("ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin");tool.addPlugin("ghidra.app.plugin.core.analysis.AutoAnalysisPlugin");}
      catch(Exception e){throw new RuntimeException(e);}
      tool.getToolFrame().addNotify();
    });
    var tool=holder[0];var pm=tool.getService(ProgramManager.class);var writer=new PrintWriter(System.out,true);
    var rows=new ArrayList<Object>();var toolClosed=new java.util.concurrent.atomic.AtomicBoolean();var failed=new java.util.concurrent.atomic.AtomicBoolean();
    try {
      Swing.runNow(()->{pm.openProgram(p);pm.openProgram(q);pm.setCurrentProgram(p);});
      require(ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(p).getAnalysisTool()==tool,"Intended analysis tool not registered");
      rows.add(Map.of("row","ANALYSIS_TOOL","name",tool.getName(),"identity",System.identityHashCode(tool),"plugins",tool.getManagedPlugins().stream().map(x->x.getClass().getName()).toList()));
      var request=new ConditionalCallSites.Request(p.getUniqueProgramID(),ProgramMapping.inspect(p).originalSha256(),"rom1::42fd",new MapperKnowledge(1,0,null,null,null,null,null,null),0xffa1,1,List.of(),new SymbolicMemory.Footprint(0xc110,0xc7f8,-16,1),List.of(0,1),0,true,true,"Self-authored synchronous premises");
      var requestPath=out.resolve("request.json");var proofPath=out.resolve("proof.json");Files.writeString(requestPath,ProgramMapping.JSON.toJson(request));
      var scheduled=new SchedulingWriter(tool,p);var scheduledMonitor=new TaskMonitorAdapter(true){
        @Override public void setMessage(String message){super.setMessage(message);if(message.equals("Waiting for auto-analysis..."))scheduled.waiting=true;if(message.equals("Saving predicate preview"))scheduled.observeWorker();}
      };
      run(tool,p,scheduledMonitor,scheduled,"conditional-call-preview",requestPath.toString(),proofPath.toString());
      Files.writeString(out.resolve("scheduled-observation.json"),ProgramMapping.JSON.toJson(Map.of("submission",scheduled.submission,"worker",scheduled.worker==null?Map.of():scheduled.worker,"waitingMessage",scheduled.waiting)));
      require(scheduled.waiting && scheduled.worker!=null && !tool.threadIsBackgroundTaskThread(),"Missing behavioral scheduled worker witness");
      rows.add(Map.of("row","STANDALONE_SCHEDULED_PUBLIC_SCRIPT","submission",scheduled.submission,"worker",scheduled.worker,"waitingMessage",scheduled.waiting));
      settle(tool,p);
      var apply=ownerArm(tool,p,proofPath,false,out,rows);
      var analysis=ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(p);
      Files.writeString(out.resolve("analysis-follow-on.json"),ProgramMapping.JSON.toJson(Map.of("tasks",Arrays.asList(analysis.getTimedTasks()),"timing",analysis.getTaskTimesString(),"tool",System.identityHashCode(analysis.getAnalysisTool()))));
      var qRequest=new ConditionalCallSites.Request(q.getUniqueProgramID(),request.imageSha256(),request.site(),request.mapper(),request.shadowCpu(),request.shadowValue(),request.memoryInputs(),request.footprint(),request.incomingStackBytes(),request.continuationSteps(),true,true,request.provenance());
      Path qi=out.resolve("q-request.json"),qp=out.resolve("q-proof.json");Files.writeString(qi,ProgramMapping.JSON.toJson(qRequest));
      Swing.runNow(()->pm.setCurrentProgram(q));run(tool,q,TaskMonitor.DUMMY,writer,"conditional-call-preview",qi.toString(),qp.toString());settle(tool,q);
      ownerArm(tool,q,qp,true,out,rows);Swing.runNow(()->pm.setCurrentProgram(p));
      settle(tool,p);

      require(apply.lastOperation.completion().get(30,TimeUnit.SECONDS).current(),"public apply");
      apply.lastPresentation.get(30,TimeUnit.SECONDS);var entry=apply.lastOperation.entry();
      busyArm(tool,p,out,rows);
      for(boolean switchAway:new boolean[]{false,true}) {
        settle(tool,p);p.save("Explicit file save before unchanged-P ordering baseline",TaskMonitor.DUMMY);
        require(!p.isTemporary()&&!p.isChanged(),"Unchanged-P baseline must be persisted and clean before either request");
        Files.writeString(out.resolve("ordering-baseline-"+switchAway+".json"),ProgramMapping.JSON.toJson(Map.of("revision",p.getModificationNumber(),"changed",p.isChanged(),"temporary",p.isTemporary(),"domainFile",p.getDomainFile().getPathname(),"savedBeforeBothRequests",true)));

        var gate=new GateWriter();var a=run(tool,p,new TaskMonitorAdapter(true),gate,"conditional-call-explain",entry.toString());
        require(gate.reached.await(30,TimeUnit.SECONDS),"A publication gate");long revision=p.getModificationNumber();
        if(switchAway)Swing.runNow(()->{pm.setCurrentProgram(q);pm.setCurrentProgram(p);});
        var b=run(tool,p,new TaskMonitorAdapter(true),writer,"conditional-call-explain",entry.toString());
        require("PUBLISHED".equals(b.lastPresentation.get(30,TimeUnit.SECONDS)),"B must publish");
        require(revision==p.getModificationNumber(),"Unchanged P required");gate.release.countDown();
        String disposition=a.lastPresentation.get(30,TimeUnit.SECONDS);
        require(disposition.equals(switchAway?"ACTIVATION_SUPERSEDED":"REQUEST_SUPERSEDED"),"A supersession: "+disposition);
        rows.add(Map.of("row",switchAway?"P_Q_P_B_BEFORE_A":"P_B_BEFORE_A","program",p.getUniqueProgramID(),"revision",revision,"A",disposition,"B","PUBLISHED"));
      }
      hostedWaitArm(tool,p,entry,false,out,rows);hostedWaitArm(tool,p,entry,true,out,rows);
      var gate=new GateWriter();var a=run(tool,p,new TaskMonitorAdapter(true),gate,"conditional-call-explain",entry.toString());
      require(gate.reached.await(30,TimeUnit.SECONDS),"close gate");
      Swing.runNow(()->require(pm.closeProgram(p,true),"Pending-publication close was deferred"));require(!p.isClosed(),"owned work/fixture consumer retains actual Program");gate.release.countDown();
      require("TARGET_CLOSED".equals(a.lastPresentation.get(30,TimeUnit.SECONDS)),"closed target publication");
      require(PredicatedCalls.registered(p,entry),"Closing does not undo committed authority");
      rows.add(Map.of("row","CLOSE_PENDING_PUBLICATION","disposition","TARGET_CLOSED","committedAuthorityRetained",true,"closeAccepted",true));
      for(int i=0;i<8;i++) {
        Swing.runNow(()->{pm.openProgram(p);pm.setCurrentProgram(p);});
        var repeatedGate=new GateWriter();var repeated=run(tool,p,new TaskMonitorAdapter(true),repeatedGate,"conditional-call-explain",entry.toString());
        require(repeatedGate.reached.await(30,TimeUnit.SECONDS),"repeated request gate");
        Swing.runNow(()->require(pm.closeProgram(p,true),"Repeated actual close refused"));repeatedGate.release.countDown();
        require("TARGET_CLOSED".equals(repeated.lastPresentation.get(30,TimeUnit.SECONDS)),"repeated close publication");
        repeated.lastOperation.released().get(30,TimeUnit.SECONDS);
        require(PredicatePublication.inventory().get("requests")==0 && PredicateOperations.inventory().get("observations")==0,"owned registrations after close");
      }
      Swing.runNow(()->{pm.openProgram(p);pm.setCurrentProgram(p);});
      var disposedGate=new GateWriter();var disposed=run(tool,p,new TaskMonitorAdapter(true),disposedGate,"conditional-call-explain",entry.toString());
      require(disposedGate.reached.await(30,TimeUnit.SECONDS),"tool disposal gate");
      Swing.runNow(()->{pm.closeAllPrograms(true);tool.close();toolClosed.set(true);});disposedGate.release.countDown();
      require(!"PUBLISHED".equals(disposed.lastPresentation.get(30,TimeUnit.SECONDS)),"disposed consumer published");
      require(PredicatePublication.inventory().get("requests")==0,"tool-owned request resources");
      rows.add(Map.of("row","REPEATED_CLOSE_AND_TOOL_DISPOSE","iterations",8,"requests",PredicatePublication.inventory(),"operations",PredicateOperations.inventory()));
      Files.writeString(out.resolve("service-results.json"),ProgramMapping.JSON.toJson(Map.of("kind","HIDDEN_HEADED_SERVICE_NOT_GUI_ACCEPTANCE","rows",rows)));
    }catch(Throwable failure){failed.set(true);failure.printStackTrace();Files.writeString(out.resolve("failure.txt"),failure.toString());throw failure;}
    finally{
      Files.writeString(out.resolve("partial-rows.json"),ProgramMapping.JSON.toJson(rows));
      if(failed.get()){tool.cancelCurrentTask();try{settle(tool,p);}catch(Exception cleanup){System.err.println("Failure cleanup did not settle: "+cleanup);}}
      if(!toolClosed.get())Swing.runNow(()->{pm.closeAllPrograms(true);tool.close();});p.release(this);q.release(this);project.close();
    }
    System.out.println("PUBLIC_SERVICE_PROBE_PASS");System.exit(0);
  }
}
