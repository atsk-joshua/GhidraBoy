import fi.gekkio.ghidraboy.*;
import ghidra.app.script.*;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;
import java.io.PrintWriter;
import java.nio.file.*;
import java.util.List;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

@org.junit.jupiter.api.Timeout(60)
public class PublicPredicateOperationsTest extends IntegrationTest {
  @TempDir Path output;
  private static final String TRACE_RUN=java.util.UUID.randomUUID().toString();
  private static final java.util.concurrent.atomic.AtomicInteger TRACE_SEQUENCE=new java.util.concurrent.atomic.AtomicInteger();
  private static void event(String kind,PredicateOperations.Outcome outcome,ghidra.framework.model.TransactionInfo actual,String publication) {
    System.out.println("LIFECYCLE_EVENT "+new com.google.gson.Gson().toJson(java.util.Map.of(
        "run",TRACE_RUN,"sequence",TRACE_SEQUENCE.incrementAndGet(),"kind",kind,"outcome",outcome,
        "actualTransaction",actual.getID(),"actualStatus",actual.getStatus().toString(),"publication",publication)));
  }
  private ProgramDB fixture() throws Exception {
    var p=new ProgramDB("public-conditional",getLanguage(),getLanguage().getDefaultCompilerSpec(),this);
    try(var bytes=new ByteArrayProvider(Files.readAllBytes(Path.of("src/test/resources/conditional/carry.gb")))) {
      CartridgeLayout.load(p,bytes,"CARTRIDGE","AUTO",GameBoyKind.GB,true,false,TaskMonitor.DUMMY,new MessageLog());
    }
    return p;
  }
  private Path preview(ProgramDB p) throws Exception {
    var request=new ConditionalCallSites.Request(p.getUniqueProgramID(),ProgramMapping.inspect(p).originalSha256(),"rom1::42fd",
      new MapperKnowledge(1,0,null,null,null,null,null,null),0xffa1,1,List.of(),new SymbolicMemory.Footprint(0xc110,0xc7f8,-16,1),List.of(0,1),0,true,true,"Self-authored explicit synchronous premises");
    Path requestPath=output.resolve("request-"+System.nanoTime()+".json"),proof=output.resolve("proof-"+System.nanoTime()+".json");
    Files.writeString(requestPath,ProgramMapping.JSON.toJson(request));
    execute(p,TaskMonitor.DUMMY,"conditional-call-preview",requestPath.toString(),proof.toString());
    return proof;
  }
  private GhidraBoyTools execute(ProgramDB p,TaskMonitor monitor,String... args) throws Exception {
    var script=new GhidraBoyTools();script.setScriptArgs(args);
    script.execute(new GhidraState(null,null,p,null,null,null),monitor,new PrintWriter(System.out,true));
    return script;
  }
  private PredicateOperations.Outcome done(GhidraBoyTools script) throws Exception {
    var result=script.lastOperation.completion().get(30,TimeUnit.SECONDS);
    System.out.println("PUBLIC_OUTCOME "+ProgramMapping.JSON.toJson(result));
    return result;
  }
  @Test public void cancelledPreviewDoesNotWriteOrPublishAfterDerivation() throws Exception {
    var p=fixture();try {
      var proof=PredicatedCalls.readProof(Files.readString(preview(p)));var request=output.resolve("cancel-request.json");var target=output.resolve("cancel-preview.json");
      Files.writeString(request,ProgramMapping.JSON.toJson(proof.callSite()));
      var monitor=new TaskMonitorAdapter(true){@Override public void setMessage(String message){super.setMessage(message);if(message.equals("Saving predicate preview"))cancel();}};
      var script=new GhidraBoyTools();script.setScriptArgs(new String[]{"conditional-call-preview",request.toString(),target.toString()});
      assertThrows(CancelledException.class,()->script.execute(new GhidraState(null,null,p,null,null,null),monitor,new PrintWriter(System.out,true)));
      assertEquals("CANCELLED_PUBLICATION",script.lastPresentation.get(30,TimeUnit.SECONDS));
      assertFalse(Files.exists(target));assertNull(p.getCurrentTransactionInfo());assertEquals(0,PredicatePublication.inventory().get("requests"));
    }finally{p.release(this);}
  }
  @Test public void T1_actualPublicApplyRefreshRemove() throws Exception {
    var p=fixture();try {
      var proof=preview(p);var apply=execute(p,TaskMonitor.DUMMY,"stock-predicate-apply",proof.toString());
      assertEquals(PredicateOperations.Mutation.COMMITTED,done(apply).mutation());
      var entry=apply.lastOperation.entry();assertTrue(PredicatedCalls.emitStock(p,entry,0x200000,TaskMonitor.DUMMY).length>0);
      var refresh=execute(p,TaskMonitor.DUMMY,"stock-predicate-refresh",preview(p).toString(),entry.toString());
      assertTrue(done(refresh).current());
      var remove=execute(p,TaskMonitor.DUMMY,"stock-predicate-remove",entry.toString());
      assertEquals(PredicateOperations.Mutation.COMMITTED,done(remove).mutation());
      assertFalse(PredicatedCalls.registered(p,entry));assertNull(p.getCurrentTransactionInfo());
    }finally{p.release(this);}
  }
  @Test public void T2_foreignOuterDeferredWithoutLosingSentinelAndPositiveRecovery() throws Exception {
    var p=fixture();try {
      var proof=preview(p);int tx=p.startTransaction("foreign user");p.getOptions("sentinel").setString("user","retain");
      assertThrows(IllegalStateException.class,()->execute(p,TaskMonitor.DUMMY,"stock-predicate-apply",proof.toString()));
      assertTrue(p.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames().isEmpty());p.endTransaction(tx,true);
      var apply=execute(p,TaskMonitor.DUMMY,"stock-predicate-apply",preview(p).toString());assertTrue(done(apply).current());
      assertEquals("retain",p.getOptions("sentinel").getString("user",null));
    }finally{p.release(this);}
  }
  @Test public void T4_actualNestedWrapperReturnsBeforeOuterCommitOrAbort() throws Exception {
    for(boolean commit:new boolean[]{true,false}) {
      var p=fixture();try {
        var proof=preview(p);int tx=p.startTransaction("explicit outer owner");var actual=p.getCurrentTransactionInfo();
        GhidraBoyTools script;
        try(var caller=PredicateOperations.participate(p)) {
          script=execute(p,TaskMonitor.DUMMY,"stock-predicate-apply",proof.toString());
        }
        assertFalse(script.lastOperation.completion().isDone());
        assertEquals(PredicateOperations.Mutation.PENDING_IN_OWNER,script.lastOperation.provisional().mutation());
        assertEquals(actual.getID(),script.lastOperation.provisional().transactionId());
        event("RETURN_PENDING",script.lastOperation.provisional(),actual,"PENDING");
        p.endTransaction(tx,commit);
        var result=done(script);
        event("OUTER_RESOLVED",result,actual,script.lastPresentation.get(30,TimeUnit.SECONDS));assertEquals(commit?PredicateOperations.Mutation.COMMITTED:PredicateOperations.Mutation.ABORTED,result.mutation());
        assertEquals(commit,PredicatedCalls.registered(p,script.lastOperation.entry()));
      }finally{p.release(this);}
    }
  }
  @Test public void T5_actualWriteCancellationRollsBackAdmittedOwner() throws Exception {
    var p=fixture();try {
      var proof=preview(p);int tx=p.startTransaction("earlier user");p.getOptions("sentinel").setString("user","retain");p.endTransaction(tx,true);
      // Preview again: the user edit changes the input fingerprint.
      proof=preview(p);final Path candidate=proof;
      var monitor=new TaskMonitorAdapter(true) {
        @Override public void checkCancelled() throws CancelledException {
          if(p.getFunctionManager().getFunctionCount()>0)cancel();super.checkCancelled();
        }
      };
      assertThrows(CancelledException.class,()->execute(p,monitor,"stock-predicate-apply",candidate.toString()));
      assertEquals(0,p.getFunctionManager().getFunctionCount());
      assertTrue(p.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames().isEmpty());
      assertEquals("retain",p.getOptions("sentinel").getString("user",null));assertNull(p.getCurrentTransactionInfo());
    }finally{p.release(this);}
  }
  @Test public void T3_supportedSubmissionsSerializeAndRejectSupersededProof() throws Exception {
    var p=fixture();var executor=Executors.newFixedThreadPool(2);var entered=new CountDownLatch(1);var release=new CountDownLatch(1);
    try {
      var proof=preview(p);var once=new java.util.concurrent.atomic.AtomicBoolean();
      var firstMonitor=new TaskMonitorAdapter(true) {
        @Override public void checkCancelled() throws CancelledException {
          if(p.getCurrentTransactionInfo()!=null && once.compareAndSet(false,true)) {
            entered.countDown();try{assertTrue(release.await(30,TimeUnit.SECONDS));}catch(InterruptedException e){throw new AssertionError(e);}
          }super.checkCancelled();
        }
      };
      var a=executor.submit(()->execute(p,firstMonitor,"stock-predicate-apply",proof.toString()));
      assertTrue(entered.await(30,TimeUnit.SECONDS));
      var waiting=new CountDownLatch(1);var checks=new java.util.concurrent.atomic.AtomicInteger();
      var secondMonitor=new TaskMonitorAdapter(true) {
        @Override public void checkCancelled() throws CancelledException {if(checks.incrementAndGet()>1)waiting.countDown();super.checkCancelled();}
      };
      var b=executor.submit(()->execute(p,secondMonitor,"stock-predicate-apply",proof.toString()));
      assertTrue(waiting.await(30,TimeUnit.SECONDS));assertFalse(b.isDone());release.countDown();
      var first=a.get(30,TimeUnit.SECONDS);assertEquals(PredicateOperations.Mutation.COMMITTED,done(first).mutation());
      assertThrows(ExecutionException.class,()->b.get(30,TimeUnit.SECONDS));
      assertEquals(1,p.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames().size());
      assertTrue(PredicatedCalls.emitStock(p,first.lastOperation.entry(),0x200000,TaskMonitor.DUMMY).length>0);
    }finally{release.countDown();executor.shutdownNow();executor.awaitTermination(30,TimeUnit.SECONDS);p.release(this);}
  }
  @Test public void T5_cancelWhileWaitingWritesNothing() throws Exception {
    var p=fixture();var executor=Executors.newSingleThreadExecutor();
    try {
      var proof=preview(p);
      try(var first=PredicateOperations.scheduleScript(p,TaskMonitor.DUMMY)) {
        var waiting=new CountDownLatch(1);var checks=new java.util.concurrent.atomic.AtomicInteger();
        var monitor=new TaskMonitorAdapter(true) {
          @Override public void checkCancelled() throws CancelledException {if(checks.incrementAndGet()>1)waiting.countDown();super.checkCancelled();}
        };
        var b=executor.submit(()->execute(p,monitor,"stock-predicate-apply",proof.toString()));
        assertTrue(waiting.await(30,TimeUnit.SECONDS));monitor.cancel();
        assertThrows(ExecutionException.class,()->b.get(30,TimeUnit.SECONDS));
        assertTrue(p.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames().isEmpty());assertNull(p.getCurrentTransactionInfo());
      }
      assertTrue(done(execute(p,TaskMonitor.DUMMY,"stock-predicate-apply",proof.toString())).current());
    }finally{executor.shutdownNow();executor.awaitTermination(30,TimeUnit.SECONDS);p.release(this);}
  }
  @Test public void T6_failedRemovalRestoresAuthorityThenPreservesLaterEdit() throws Exception {
    var p=fixture();try {
      var failedProof=preview(p);
      var creationFailure=new TaskMonitorAdapter(true) {
        @Override public void checkCancelled() throws CancelledException {if(p.getFunctionManager().getFunctionCount()>0)throw new IllegalStateException("Failure after real carrier creation");super.checkCancelled();}
      };
      assertThrows(IllegalStateException.class,()->execute(p,creationFailure,"stock-predicate-apply",failedProof.toString()));
      assertEquals(0,p.getFunctionManager().getFunctionCount());
      int later=p.startTransaction("unrelated edit after failed creation");p.getOptions("sentinel").setString("later-create","retain");p.endTransaction(later,true);
      var apply=execute(p,TaskMonitor.DUMMY,"stock-predicate-apply",preview(p).toString());done(apply);
      apply.lastPresentation.get(30,TimeUnit.SECONDS);var entry=apply.lastOperation.entry();
      String before=p.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(entry.toString(),null);
      var monitor=new TaskMonitorAdapter(true) {
        @Override public void checkCancelled() throws CancelledException {if(p.getFunctionManager().getFunctionCount()==0)throw new IllegalStateException("Failure after real owned deletion");super.checkCancelled();}
      };
      assertThrows(IllegalStateException.class,()->execute(p,monitor,"stock-predicate-remove",entry.toString()));
      assertEquals(before,p.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(entry.toString(),null));
      int tx=p.startTransaction("later committed user edit after failed removal");p.getFunctionManager().getFunctionAt(entry).setComment("later user annotation");p.endTransaction(tx,true);
      var remove=execute(p,TaskMonitor.DUMMY,"stock-predicate-remove",entry.toString());done(remove);
      assertEquals("later user annotation",p.getFunctionManager().getFunctionAt(entry).getComment());
      assertFalse(PredicatedCalls.registered(p,entry));
      assertEquals("retain",p.getOptions("sentinel").getString("later-create",null));
    }finally{p.release(this);}
  }
  @Test public void T8_observeAdHocWriterSharedTransactionUnsupportedIsolation() throws Exception {
    var p=fixture();var executor=Executors.newSingleThreadExecutor();var written=new CountDownLatch(1);var release=new CountDownLatch(1);
    try {
      var proof=preview(p);var once=new java.util.concurrent.atomic.AtomicBoolean();
      var monitor=new TaskMonitorAdapter(true) {
        @Override public void checkCancelled() throws CancelledException {
          if(p.getFunctionManager().getFunctionCount()>0 && once.compareAndSet(false,true)) {
            written.countDown();try{assertTrue(release.await(30,TimeUnit.SECONDS));}catch(InterruptedException e){throw new AssertionError(e);}
          }super.checkCancelled();
        }
      };
      var operation=executor.submit(()->execute(p,monitor,"stock-predicate-apply",proof.toString()));
      assertTrue(written.await(30,TimeUnit.SECONDS));var actual=p.getCurrentTransactionInfo();
      // This thread deliberately does not acquire any extension gate or declare participation.
      int foreign=p.startTransaction("ad-hoc writer outside supported scheduler");
      assertSame(actual,p.getCurrentTransactionInfo());p.getOptions("sentinel").setString("ad-hoc","retained");p.endTransaction(foreign,true);
      release.countDown();var applied=operation.get(30,TimeUnit.SECONDS);assertEquals(PredicateOperations.Mutation.COMMITTED,done(applied).mutation());
      assertEquals("retained",p.getOptions("sentinel").getString("ad-hoc",null));
      System.out.println("T8 OPEN_UNSUPPORTED_WRITER_SHARED_TRANSACTION outer="+actual.getID()+" foreignHandle="+foreign+" observed=COMMITTED_SENTINEL_RETAINED");
    }finally{release.countDown();executor.shutdownNow();executor.awaitTermination(30,TimeUnit.SECONDS);p.release(this);}
  }
  @Test public void boundedRepeatedPublicOperationsReleaseOwnedResources() throws Exception {
    for(int i=0;i<8;i++) {
      var p=fixture();try {
        var apply=execute(p,TaskMonitor.DUMMY,"stock-predicate-apply",preview(p).toString());done(apply);
        apply.lastPresentation.get(30,TimeUnit.SECONDS);apply.lastOperation.released().get(30,TimeUnit.SECONDS);
        var explain=execute(p,TaskMonitor.DUMMY,"conditional-call-explain",apply.lastOperation.entry().toString());done(explain);
        explain.lastPresentation.get(30,TimeUnit.SECONDS);explain.lastOperation.released().get(30,TimeUnit.SECONDS);
        var remove=execute(p,TaskMonitor.DUMMY,"stock-predicate-remove",apply.lastOperation.entry().toString());done(remove);
        remove.lastPresentation.get(30,TimeUnit.SECONDS);remove.lastOperation.released().get(30,TimeUnit.SECONDS);
        assertEquals(0,PredicateOperations.inventory().get("observations"));assertEquals(0,PredicateOperations.inventory().get("gateUsers"));
        assertEquals(0,PredicatePublication.inventory().get("requests"));assertEquals(1,p.getConsumerList().size());
      }finally{p.release(this);}
    }
  }
  @Test public void hardwarePremiseMissingFalseAndReachedDmaControls() throws Exception {
    var p=fixture();try {
      var proof=PredicatedCalls.readProof(Files.readString(preview(p)));var request=proof.callSite();
      for(String premise:List.of("bootInactive","synchronous")) {
        var missing=ProgramMapping.JSON.toJsonTree(request).getAsJsonObject();missing.remove(premise);
        assertThrows(IllegalArgumentException.class,()->ConditionalCallSites.readRequest(missing.toString()));
        var falseValue=ProgramMapping.JSON.toJsonTree(request).getAsJsonObject();falseValue.addProperty(premise,false);
        assertThrows(RuntimeException.class,()->ConditionalCallSites.readRequest(falseValue.toString()));
      }
      var overlap=ProgramMapping.JSON.toJsonTree(request).getAsJsonObject();var inputs=new com.google.gson.JsonArray();inputs.add(0xc120);overlap.add("memoryInputs",inputs);
      assertThrows(IllegalArgumentException.class,()->ConditionalCallSites.preview(p,ConditionalCallSites.readRequest(overlap.toString()),TaskMonitor.DUMMY));
      int tx=p.startTransaction("self-authored reached DMA store");
      p.getMemory().setBytes(ProgramMapping.staticAddress(p,"rom2::5210"),new byte[]{(byte)0xe0,0x46,(byte)0xc9});p.endTransaction(tx,true);
      var dma=ConditionalCallSites.preview(p,request,TaskMonitor.DUMMY);
      assertFalse(dma.complete());assertFalse(dma.frontier().isEmpty());
      System.out.println("REACHED_DMA_FRONTIER "+ProgramMapping.JSON.toJson(dma.frontier()));
      assertThrows(IllegalArgumentException.class,()->PredicatedCalls.install(p,dma,TaskMonitor.DUMMY));
    }finally{p.release(this);}
  }
  @Test public void T7_committedThenUndoDoesNotReviveQueuedPublicResult() throws Exception {
    var p=fixture();var reached=new CountDownLatch(1);var release=new CountDownLatch(1);
    try {
      var proof=preview(p);var script=new GhidraBoyTools();script.setScriptArgs(new String[]{"stock-predicate-apply",proof.toString()});
      var writer=new PrintWriter(System.out,true) {
        @Override public void println(String text){super.println(text);if(text.contains("\"mutation\": \"COMMITTED\"")) {
          reached.countDown();try{assertTrue(release.await(30,TimeUnit.SECONDS));}catch(InterruptedException e){throw new AssertionError(e);}
        }}
      };
      script.execute(new GhidraState(null,null,p,null,null,null),new TaskMonitorAdapter(true),writer);
      assertTrue(reached.await(30,TimeUnit.SECONDS));
      int tx=p.startTransaction("later user edit then undo");p.getOptions("sentinel").setString("transient","edit");p.endTransaction(tx,true);p.undo();
      release.countDown();assertEquals("SOURCE_STALE",script.lastPresentation.get(30,TimeUnit.SECONDS));
      assertTrue(PredicatedCalls.emitStock(p,script.lastOperation.entry(),0x200000,TaskMonitor.DUMMY).length>0);
    }finally{release.countDown();p.release(this);}
  }
  @Test public void T5_cancelAtProvisionalReceiptBeforeWrapperFinalVote() throws Exception {
    for(boolean nested:new boolean[]{false,true}) {
      var p=fixture();try {
        var proof=preview(p);var monitor=new TaskMonitorAdapter(true);var script=new GhidraBoyTools();
        script.setScriptArgs(new String[]{"stock-predicate-apply",proof.toString()});
        var writer=new PrintWriter(System.out,true){@Override public void println(String text){super.println(text);if(text.contains("\"mutation\": \"PENDING_IN_OWNER\""))monitor.cancel();}};
        int outer=nested?p.startTransaction("explicit caller cancellation policy"):-1;
        try {
          if(nested)try(var caller=PredicateOperations.participate(p)) {
            assertThrows(CancelledException.class,()->script.execute(new GhidraState(null,null,p,null,null,null),monitor,writer));
          }
          else assertThrows(CancelledException.class,()->script.execute(new GhidraState(null,null,p,null,null,null),monitor,writer));
        }finally{if(nested)p.endTransaction(outer,true);}
        assertEquals(PredicateOperations.Mutation.ABORTED,done(script).mutation());
        assertTrue(p.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames().isEmpty());assertEquals(0,p.getFunctionManager().getFunctionCount());
        assertEquals("CANCELLED_PUBLICATION",script.lastPresentation.get(30,TimeUnit.SECONDS));
      }finally{p.release(this);}
    }
  }
  @Test public void headlessNavigationPublishesAfterWrapperStateUpdate() throws Exception {
    var p=fixture();try {
      var apply=execute(p,TaskMonitor.DUMMY,"stock-predicate-apply",preview(p).toString());done(apply);apply.lastPresentation.get(30,TimeUnit.SECONDS);
      var entry=apply.lastOperation.entry();var proof=PredicatedCalls.registeredProof(p,entry);
      for(String action:List.of("conditional-call-target","conditional-call-continuation")) {
        var state=new GhidraState(null,null,p,new ghidra.program.util.ProgramLocation(p,entry),null,null);
        var script=new GhidraBoyTools();script.setScriptArgs(new String[]{action,entry.toString()});
        script.execute(state,new TaskMonitorAdapter(true),new PrintWriter(System.out,true));
        assertEquals("PUBLISHED",script.lastPresentation.get(30,TimeUnit.SECONDS));
        String kind=action.endsWith("target")?"RET_DISPATCH":"MATCHED_CALL_COMPLETION";
        assertEquals(proof.boundaries().stream().filter(b->b.kind().equals(kind)).findFirst().orElseThrow().physical(),state.getCurrentAddress().toString());
      }
    }finally{p.release(this);}
  }
  private static void requestEvent(String kind,java.util.Map<String,Object> detail) {
    System.out.println("LIFECYCLE_REQUEST_EVENT "+new com.google.gson.Gson().toJson(java.util.Map.of("kind",kind,"detail",detail,"consumer_mode","HEADLESS_STATE")));
  }
  @Test public void sameHeadlessConsumerPublishesBFirstWithoutRevivingAAfterPQP() throws Exception {
    var p=fixture();var q=fixture();try {
      var apply=execute(p,TaskMonitor.DUMMY,"stock-predicate-apply",preview(p).toString());done(apply);apply.lastPresentation.get(30,TimeUnit.SECONDS);
      var entry=apply.lastOperation.entry();var proof=PredicatedCalls.registeredProof(p,entry);
      for(boolean switched:new boolean[]{false,true}) {
        var state=new GhidraState(null,null,p,new ghidra.program.util.ProgramLocation(p,entry),null,null);
        var reached=new CountDownLatch(1);var release=new CountDownLatch(1);var a=new GhidraBoyTools();a.setScriptArgs(new String[]{"conditional-call-target",entry.toString()});
        var writer=new PrintWriter(System.out,true){@Override public void println(String text){super.println(text);if(text.contains("\"mutation\": \"NO_DATABASE_CHANGE\"")) {
          reached.countDown();try{assertTrue(release.await(30,TimeUnit.SECONDS));}catch(InterruptedException e){throw new AssertionError(e);}
        }}};
        try {
          a.execute(state,new TaskMonitorAdapter(true),writer);assertTrue(reached.await(30,TimeUnit.SECONDS));long revision=p.getModificationNumber();
          var identity=java.util.Map.of("program_id",p.getUniqueProgramID(),"program_object",System.identityHashCode(p));
          requestEvent("public-action-return",java.util.Map.of("program",identity,"operation",a.lastOperation.id(),"arguments",List.of("conditional-call-target",entry.toString())));
          if(switched){state.setCurrentProgram(q);state.setCurrentProgram(p);state.setCurrentAddress(entry);}
          var b=new GhidraBoyTools();b.setScriptArgs(new String[]{"conditional-call-continuation",entry.toString()});
          b.execute(state,new TaskMonitorAdapter(true),new PrintWriter(System.out,true));
          requestEvent("public-action-return",java.util.Map.of("program",identity,"operation",b.lastOperation.id(),"arguments",List.of("conditional-call-continuation",entry.toString())));
          assertEquals("PUBLISHED",b.lastPresentation.get(30,TimeUnit.SECONDS));
          requestEvent("request-B-published",java.util.Map.of("A",a.lastOperation.completion().get(30,TimeUnit.SECONDS),"B",b.lastOperation.completion().get(30,TimeUnit.SECONDS),"revision",revision,"switchAway",switched));
          var destination=state.getCurrentAddress();release.countDown();assertEquals("REQUEST_SUPERSEDED",a.lastPresentation.get(30,TimeUnit.SECONDS));
          assertEquals(revision,p.getModificationNumber());assertEquals(destination,state.getCurrentAddress());
          assertEquals(proof.boundaries().stream().filter(x->x.kind().equals("MATCHED_CALL_COMPLETION")).findFirst().orElseThrow().physical(),destination.toString());
          requestEvent("request-A-disposition",java.util.Map.of("operation",a.lastOperation.id(),"disposition",a.lastPresentation.get(30,TimeUnit.SECONDS),"revision",p.getModificationNumber(),"switchAway",switched));
        }finally{release.countDown();}
      }
    }finally{p.release(this);q.release(this);}
  }
  @Test public void switchedHeadlessStateDoesNotReceivePendingPNavigation() throws Exception {
    var p=fixture();var q=fixture();try {
      var apply=execute(p,TaskMonitor.DUMMY,"stock-predicate-apply",preview(p).toString());done(apply);apply.lastPresentation.get(30,TimeUnit.SECONDS);
      var entry=apply.lastOperation.entry();var state=new GhidraState(null,null,p,new ghidra.program.util.ProgramLocation(p,entry),null,null);
      int tx=p.startTransaction("deliberately pending read owner");var script=new GhidraBoyTools();script.setScriptArgs(new String[]{"conditional-call-target",entry.toString()});
      try(var caller=PredicateOperations.participate(p)){script.execute(state,new TaskMonitorAdapter(true),new PrintWriter(System.out,true));}
      state.setCurrentProgram(q);var selected=ProgramMapping.staticAddress(q,"rom1::42fd");state.setCurrentAddress(selected);p.endTransaction(tx,true);
      assertEquals("TARGET_INACTIVE",script.lastPresentation.get(30,TimeUnit.SECONDS));assertSame(q,state.getCurrentProgram());assertEquals(selected,state.getCurrentAddress());
    }finally{p.release(this);q.release(this);}
  }
  @Test public void closingProvisionalObserverReleasesResourcesWithoutEndingCaller() throws Exception {
    var p=fixture();try {
      var proof=preview(p);int tx=p.startTransaction("pending caller detach");GhidraBoyTools script;
      try(var caller=PredicateOperations.participate(p)){script=execute(p,TaskMonitor.DUMMY,"stock-predicate-apply",proof.toString());}
      script.lastOperation.abandonObservation();
      assertEquals(PredicateOperations.Mutation.PENDING_IN_OWNER,script.lastOperation.completion().get(30,TimeUnit.SECONDS).mutation());
      script.lastPresentation.get(30,TimeUnit.SECONDS);assertNotNull(p.getCurrentTransactionInfo());
      assertEquals(0,PredicateOperations.inventory().get("observations"));assertEquals(0,PredicatePublication.inventory().get("requests"));
      p.endTransaction(tx,true);assertTrue(PredicatedCalls.emitStock(p,script.lastOperation.entry(),0x200000,TaskMonitor.DUMMY).length>0);
    }finally{p.release(this);}
  }
  @Test public void T9_cancelAfterCommitKeepsLaterCommittedEdit() throws Exception {
    var p=fixture();var publicationReached=new CountDownLatch(1);var releasePublication=new CountDownLatch(1);
    try {
      var proof=preview(p);var monitor=new TaskMonitorAdapter(true);
      var script=new GhidraBoyTools();script.setScriptArgs(new String[]{"stock-predicate-apply",proof.toString()});
      var writer=new PrintWriter(System.out,true) {
        @Override public void println(String text) {
          super.println(text);
          if(text.contains("\"mutation\": \"COMMITTED\"")) {
            assertFalse(javax.swing.SwingUtilities.isEventDispatchThread());
            publicationReached.countDown();
            try {assertTrue(releasePublication.await(30,TimeUnit.SECONDS));}
            catch(InterruptedException e){Thread.currentThread().interrupt();throw new AssertionError(e);}
          }
        }
      };
      int owner=p.startTransaction("late cancellation explicit outer");var actual=p.getCurrentTransactionInfo();
      try(var caller=PredicateOperations.participate(p)){script.execute(new GhidraState(null,null,p,null,null,null),monitor,writer);}
      event("RETURN_PENDING",script.lastOperation.provisional(),actual,"PENDING");p.endTransaction(owner,true);
      assertTrue(publicationReached.await(30,TimeUnit.SECONDS));
      assertEquals(PredicateOperations.Mutation.COMMITTED,script.lastOperation.completion().get(30,TimeUnit.SECONDS).mutation());
      int tx=p.startTransaction("later unrelated user edit");p.getOptions("sentinel").setString("later","preserve");p.endTransaction(tx,true);
      event("LATER_EDIT_COMMITTED",script.lastOperation.completion().get(30,TimeUnit.SECONDS),actual,"PENDING");
      monitor.cancel();releasePublication.countDown();
      assertEquals("CANCELLED_PUBLICATION",script.lastPresentation.get(30,TimeUnit.SECONDS));
      event("OUTER_RESOLVED",script.lastOperation.completion().get(30,TimeUnit.SECONDS),actual,script.lastPresentation.get(30,TimeUnit.SECONDS));
      assertEquals("preserve",p.getOptions("sentinel").getString("later",null));
      assertTrue(PredicatedCalls.registered(p,script.lastOperation.entry()));
    }finally{releasePublication.countDown();p.release(this);}
  }
}
