package fi.gekkio.ghidraboy;

import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.TransactionInfo;
import ghidra.framework.model.TransactionListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/** Runtime-only public operation outcomes. Participation agrees to whole-owner rollback on failure. */
public final class PredicateOperations {
  private PredicateOperations() {}
  private static final java.util.concurrent.atomic.AtomicInteger observations=new java.util.concurrent.atomic.AtomicInteger();
  public static java.util.Map<String,Integer> inventory(){synchronized(GATES){return java.util.Map.of("observations",observations.get(),"programGates",GATES.size(),"gateUsers",GATES.values().stream().mapToInt(g->g.users).sum());}}
  private static final ThreadLocal<Caller> CALLER = new ThreadLocal<>();

  /** Explicit authorization by the enclosing owner, not an ownership inference from a transaction name. */
  public static final class Caller implements AutoCloseable {
    private final Program program;
    private final TransactionInfo transaction;
    private final Caller previous;
    private Caller(Program p) {
      program=p;transaction=p.getCurrentTransactionInfo();previous=CALLER.get();
      if(transaction==null || transaction.getStatus()!=TransactionInfo.Status.NOT_DONE)
        throw new IllegalStateException("Caller must own a pending transaction");
      CALLER.set(this);
    }
    @Override public void close(){if(CALLER.get()!=this)throw new IllegalStateException("Caller scopes must close in order");CALLER.set(previous);}
  }
  public static Caller participate(Program program) { return new Caller(program); }
  public static void admitScript(Program p) {
    var transaction=p.getCurrentTransactionInfo();
    if(transaction==null)return;
    var caller=CALLER.get();
    if(caller==null || caller.program!=p || caller.transaction!=transaction
        || transaction.getStatus()!=TransactionInfo.Status.NOT_DONE)
      throw new IllegalStateException("Deferred: foreign transaction pending; finish its owner or explicitly participate with whole-owner rollback policy");
  }

  private static String stored(Program program,Address entry) {
    var options=program.getOptions(PredicatedCalls.STOCK_OPTIONS);
    return options.contains(entry.toString())?options.getString(entry.toString(),null):null;
  }
  private static final java.util.Map<Program,GateState> GATES=new java.util.IdentityHashMap<>();
  private static final class GateState {final java.util.concurrent.Semaphore semaphore=new java.util.concurrent.Semaphore(1,true);int users;}
  /** Serializes participating public script submissions only; AutoAnalysisManager coordinates analysis. */
  public static final class Gate implements AutoCloseable {
    private final Program program;private final GateState state;private boolean acquired,closed;
    private Gate(Program p,TaskMonitor monitor) throws Exception {
      program=p;
      if(javax.swing.SwingUtilities.isEventDispatchThread())throw new IllegalStateException("Public derivation must run off EDT");
      if(CALLER.get()!=null){admitScript(p);state=null;return;}
      synchronized(GATES){state=GATES.computeIfAbsent(p,k->new GateState());state.users++;}
      try {
        monitor.checkCancelled();
        while(!state.semaphore.tryAcquire(50,java.util.concurrent.TimeUnit.MILLISECONDS))monitor.checkCancelled();
        acquired=true;monitor.checkCancelled();admitScript(p);
      }catch(Exception failure){close();throw failure;}
    }
    @Override public void close(){if(closed)return;closed=true;if(state==null)return;
      if(acquired)state.semaphore.release();
      synchronized(GATES){if(--state.users==0)GATES.remove(program);}
    }
  }
  public static Gate scheduleScript(Program p,TaskMonitor monitor) throws Exception{return new Gate(p,monitor);}

  public enum Mutation { PENDING_IN_OWNER, COMMITTED, NO_DATABASE_CHANGE, ABORTED }
  public record Outcome(String operationId,long programId,int programObject,String entry,long transactionId,Mutation mutation,
      boolean databaseCommit,boolean cancelled,boolean current,long sourceRevision,String detail) {}
  @FunctionalInterface private interface Check { void run() throws Exception; }

  /** Keeps the exact outer TransactionInfo; notifications only trigger reconciliation of that object. */
  public static final class Operation implements AutoCloseable,TransactionListener {
    private final String id=UUID.randomUUID().toString();
    private final Program program;
    private final TransactionInfo transaction;
    private final TaskMonitor monitor;
    private final CompletableFuture<Outcome> completion=new CompletableFuture<>();
    private Check check;
    private final CompletableFuture<Void> released=new CompletableFuture<>();
    private boolean armed,closed,scheduled;
    private Address entry;
    private ConditionalCallSites.Explanation explanation;
    private boolean writes=true;
    private List<String> diagnostics=List.of();
    private Operation(Program p,TaskMonitor m) {
      if(javax.swing.SwingUtilities.isEventDispatchThread())throw new IllegalStateException("Public derivation must run off EDT");
      program=p;monitor=m;admitScript(p);transaction=p.getCurrentTransactionInfo();
      if(transaction==null || transaction.getStatus()!=TransactionInfo.Status.NOT_DONE)
        throw new IllegalStateException("Public mutation requires an admitted pending owner");
      p.addConsumer(this);
      p.addTransactionListener(this);observations.incrementAndGet();
      if(p.getCurrentTransactionInfo()!=transaction) {close();throw new IllegalStateException("Owner ended during admission");}
    }
    public String id(){return id;}
    public CompletableFuture<Void> released(){return released;}
    public Address entry(){return entry;}
    public ConditionalCallSites.Explanation explanation(){return explanation;}
    public List<String> diagnostics(){return diagnostics;}
    public CompletableFuture<Outcome> completion(){return completion;}
    /** Detach a closed consumer from a still-pending owner, without ending or undoing its transaction. */
    public synchronized void abandonObservation() {
      reconcile();
      if(scheduled || closed)return;
      completion.complete(new Outcome(id,program.getUniqueProgramID(),System.identityHashCode(program),String.valueOf(entry),transaction.getID(),Mutation.PENDING_IN_OWNER,
          false,monitor.isCancelled(),false,program.getModificationNumber(),"Consumer closed while owner pending; outcome unobserved; no rollback claimed"));
      close();
    }
    public Outcome provisional(){return new Outcome(id,program.getUniqueProgramID(),System.identityHashCode(program),String.valueOf(entry),transaction.getID(),Mutation.PENDING_IN_OWNER,false,monitor.isCancelled(),false,program.getModificationNumber(),"Applied provisionally; outer owner pending; file save unverified");}
    private synchronized void arm(Check validation){
      String expected=stored(program,entry);
      check=()->{
        if(!java.util.Objects.equals(expected,stored(program,entry)))
          throw new IllegalStateException("Operation authority superseded");
        validation.run();
      };armed=true;reconcile();
    }
    private synchronized void reconcile() {
      if(!armed || closed || scheduled)return;
      // Getter acquires the transaction-manager synchronization before reading the retained object.
      program.getCurrentTransactionInfo();
      var status=transaction.getStatus();
      if(status==TransactionInfo.Status.NOT_DONE || status==TransactionInfo.Status.NOT_DONE_BUT_ABORTED)return;
      scheduled=true;
      CompletableFuture.runAsync(()->{
        boolean current=false;long revision=program.getModificationNumber();String detail="Outer owner aborted; no active result";
        boolean committed=status==TransactionInfo.Status.COMMITTED;
        if(committed)try {check.run();if(revision!=program.getModificationNumber())throw new IllegalStateException("Source changed during outcome validation");current=true;detail="Committed in open Program; file save unverified";}
        catch(Exception failure){detail="Committed, surviving state unavailable: "+failure.getMessage();}
        var result=new Outcome(id,program.getUniqueProgramID(),System.identityHashCode(program),String.valueOf(entry),transaction.getID(),
            committed?(writes && transaction.hasCommittedDBTransaction()?Mutation.COMMITTED:Mutation.NO_DATABASE_CHANGE):Mutation.ABORTED,
            transaction.hasCommittedDBTransaction(),monitor.isCancelled(),current,revision,detail);
        completion.complete(result);
        close();
      });
    }
    @Override public void transactionStarted(DomainObjectAdapterDB object,TransactionInfo info){}
    @Override public void transactionEnded(DomainObjectAdapterDB object){if(object==program)reconcile();}
    @Override public void undoStackChanged(DomainObjectAdapterDB object){}
    @Override public void undoRedoOccurred(DomainObjectAdapterDB object){}
    @Override public synchronized void close(){if(closed)return;closed=true;program.removeTransactionListener(this);observations.decrementAndGet();program.release(this);released.complete(null);}
  }
  public static Operation explain(Program p,Address entry,TaskMonitor monitor) throws Exception {
    var op=new Operation(p,monitor);
    try {op.entry=entry;op.writes=false;op.explanation=ConditionalCallSites.explanation(p,entry,monitor);
      op.arm(()->op.explanation.requireCurrent(p));return op;}
    catch(Exception failure){op.close();throw failure;}
  }
  public static Operation apply(Program p,PredicatedCallGraph.Proof proof,TaskMonitor monitor) throws Exception {
    var op=new Operation(p,monitor);
    try {op.entry=PredicatedCalls.install(p,proof,monitor);op.arm(()->PredicatedCalls.emitStock(p,op.entry,0x200000,monitor));return op;}
    catch(Exception failure){op.close();throw failure;}
  }
  public static Operation refresh(Program p,Address entry,PredicatedCallGraph.Proof proof,TaskMonitor monitor) throws Exception {
    var op=new Operation(p,monitor);
    try {op.entry=entry;PredicatedCalls.refresh(p,entry,proof,monitor);op.arm(()->PredicatedCalls.emitStock(p,entry,0x200000,monitor));return op;}
    catch(Exception failure){op.close();throw failure;}
  }
  public static Operation remove(Program p,Address entry,TaskMonitor monitor) throws Exception {
    var op=new Operation(p,monitor);
    try {op.entry=entry;op.diagnostics=PredicatedCalls.remove(p,entry,monitor);op.arm(()->{
      if(PredicatedCalls.registered(p,entry))throw new IllegalStateException("Removal superseded by surviving authority");
      // Removal does not claim an executable proof or delete retired carrier spaces.
    });return op;}
    catch(Exception failure){op.close();throw failure;}
  }
}
