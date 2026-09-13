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
    GateWriter(){super(System.out,true);}
    @Override public void println(String text) {
      super.println(text);
      if(text.contains("\"mutation\": \"NO_DATABASE_CHANGE\"")) {
        require(!javax.swing.SwingUtilities.isEventDispatchThread(),"Worker gate must not block EDT");reached.countDown();
        try{require(release.await(30,TimeUnit.SECONDS),"publication gate timeout");}catch(InterruptedException e){throw new AssertionError(e);}
      }
    }
  }
  @Override public void launch(GhidraApplicationLayout layout,String[] args)throws Exception {
    Path out=Path.of(args[0]);Files.createDirectories(out);
    var config=new GhidraApplicationConfiguration();config.setShowSplashScreen(false);Application.initializeApplication(layout,config);
    var project=GhidraProject.createProject(out.toString(),"service-project",false);
    var language=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("SM83:LE:16:default"));
    var p=new ProgramDB("P",language,language.getDefaultCompilerSpec(),this);var q=new ProgramDB("Q",language,language.getDefaultCompilerSpec(),this);
    for(var program:List.of(p,q))try(var bytes=new ByteArrayProvider(Files.readAllBytes(Path.of(args[1])))){
      CartridgeLayout.load(program,bytes,"CARTRIDGE","AUTO",GameBoyKind.GB,true,false,TaskMonitor.DUMMY,new MessageLog());
    }
    GhidraTool[] holder={null};Swing.runNow(()->{
      var tool=new GhidraTool(project.getProject(),"Public operation service probe");holder[0]=tool;
      try{tool.addPlugin("ghidra.app.plugin.core.progmgr.ProgramManagerPlugin");tool.addPlugin("ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin");}
      catch(Exception e){throw new RuntimeException(e);}
      tool.getToolFrame().addNotify();
    });
    var tool=holder[0];var pm=tool.getService(ProgramManager.class);var writer=new PrintWriter(System.out,true);
    var rows=new ArrayList<Object>();
    try {
      Swing.runNow(()->{pm.openProgram(p);pm.openProgram(q);pm.setCurrentProgram(p);});
      var actual=new java.util.concurrent.atomic.AtomicReference<ghidra.framework.model.TransactionInfo>();
      var commandReturned=new CompletableFuture<String>();var commandCommitted=new CompletableFuture<String>();
      var listener=new ghidra.framework.model.TransactionListener(){
        public void transactionStarted(ghidra.framework.data.DomainObjectAdapterDB object,ghidra.framework.model.TransactionInfo info){}
        public void transactionEnded(ghidra.framework.data.DomainObjectAdapterDB object){var retained=actual.get();if(retained!=null && retained.getStatus()==ghidra.framework.model.TransactionInfo.Status.COMMITTED)commandCommitted.complete(retained.getStatus().toString());}
        public void undoStackChanged(ghidra.framework.data.DomainObjectAdapterDB object){}
        public void undoRedoOccurred(ghidra.framework.data.DomainObjectAdapterDB object){}
      };
      p.addTransactionListener(listener);
      try {
        Swing.runNow(()->tool.executeBackgroundCommand(new ghidra.framework.cmd.BackgroundCommand<ghidra.program.model.listing.Program>("Actual stock scheduler probe",true,true,false){
          public boolean applyTo(ghidra.program.model.listing.Program program,TaskMonitor monitor){actual.set(program.getCurrentTransactionInfo());program.getOptions("public-probe").setString("command-sentinel","committed");return true;}
          @Override public void taskCompleted(){commandReturned.complete(actual.get().getStatus().toString());}
        },p));
        require("NOT_DONE".equals(commandReturned.get(30,TimeUnit.SECONDS)),"Command completion must precede commit");
        require("COMMITTED".equals(commandCommitted.get(30,TimeUnit.SECONDS)),"Actual correlated tool commit");
        rows.add(Map.of("row","REAL_TOOL_BACKGROUND_COMMAND","transaction",actual.get().getID(),"commandCompletionStatus","NOT_DONE","outerStatus",actual.get().getStatus().toString()));
      }finally{p.removeTransactionListener(listener);}
      var request=new ConditionalCallSites.Request(p.getUniqueProgramID(),ProgramMapping.inspect(p).originalSha256(),"rom1::42fd",new MapperKnowledge(1,0,null,null,null,null,null,null),0xffa1,1,List.of(),new SymbolicMemory.Footprint(0xc110,0xc7f8,-16,1),List.of(0,1),0,true,true,"Self-authored synchronous premises");
      var requestPath=out.resolve("request.json");var proofPath=out.resolve("proof.json");Files.writeString(requestPath,ProgramMapping.JSON.toJson(request));
      run(tool,p,TaskMonitor.DUMMY,writer,"conditional-call-preview",requestPath.toString(),proofPath.toString());
      var apply=run(tool,p,TaskMonitor.DUMMY,writer,"stock-predicate-apply",proofPath.toString());
      require(apply.lastOperation.completion().get(30,TimeUnit.SECONDS).current(),"public apply");
      apply.lastPresentation.get(30,TimeUnit.SECONDS);var entry=apply.lastOperation.entry();
      for(boolean switchAway:new boolean[]{false,true}) {
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
      var gate=new GateWriter();var a=run(tool,p,new TaskMonitorAdapter(true),gate,"conditional-call-explain",entry.toString());
      require(gate.reached.await(30,TimeUnit.SECONDS),"close gate");
      Swing.runNow(()->pm.closeProgram(p,true));require(!p.isClosed(),"owned work/fixture consumer retains actual Program");gate.release.countDown();
      require("TARGET_CLOSED".equals(a.lastPresentation.get(30,TimeUnit.SECONDS)),"closed target publication");
      require(PredicatedCalls.registered(p,entry),"Closing does not undo committed authority");
      rows.add(Map.of("row","CLOSE_PENDING_PUBLICATION","disposition","TARGET_CLOSED","committedAuthorityRetained",true));
      for(int i=0;i<8;i++) {
        Swing.runNow(()->{pm.openProgram(p);pm.setCurrentProgram(p);});
        var repeatedGate=new GateWriter();var repeated=run(tool,p,new TaskMonitorAdapter(true),repeatedGate,"conditional-call-explain",entry.toString());
        require(repeatedGate.reached.await(30,TimeUnit.SECONDS),"repeated request gate");
        Swing.runNow(()->pm.closeProgram(p,true));repeatedGate.release.countDown();
        require("TARGET_CLOSED".equals(repeated.lastPresentation.get(30,TimeUnit.SECONDS)),"repeated close publication");
        repeated.lastOperation.released().get(30,TimeUnit.SECONDS);
        require(PredicatePublication.inventory().get("requests")==0 && PredicateOperations.inventory().get("observations")==0,"owned registrations after close");
      }
      Swing.runNow(()->{pm.openProgram(p);pm.setCurrentProgram(p);});
      var disposedGate=new GateWriter();var disposed=run(tool,p,new TaskMonitorAdapter(true),disposedGate,"conditional-call-explain",entry.toString());
      require(disposedGate.reached.await(30,TimeUnit.SECONDS),"tool disposal gate");
      Swing.runNow(()->{pm.closeAllPrograms(true);tool.close();});disposedGate.release.countDown();
      require(!"PUBLISHED".equals(disposed.lastPresentation.get(30,TimeUnit.SECONDS)),"disposed consumer published");
      require(PredicatePublication.inventory().get("requests")==0,"tool-owned request resources");
      rows.add(Map.of("row","REPEATED_CLOSE_AND_TOOL_DISPOSE","iterations",8,"requests",PredicatePublication.inventory(),"operations",PredicateOperations.inventory()));
      Files.writeString(out.resolve("service-results.json"),ProgramMapping.JSON.toJson(Map.of("kind","HIDDEN_HEADED_SERVICE_NOT_GUI_ACCEPTANCE","rows",rows)));
    }finally{
      Swing.runNow(()->{pm.closeAllPrograms(true);tool.close();});p.release(this);q.release(this);project.close();
    }
    System.out.println("PUBLIC_SERVICE_PROBE_PASS");System.exit(0);
  }
}
