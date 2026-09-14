package fi.gekkio.ghidraboy;

import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginEventListener;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/** Consumer-local runtime request identity. Never written into Program authority. */
public final class PredicatePublication {
  private PredicatePublication() {}
  private static final AtomicInteger requests=new AtomicInteger();
  private static final Map<Object,Context> CONTEXTS=new IdentityHashMap<>();
  private static final class Context {long generation;int users;}
  public static Map<String,Integer> inventory(){synchronized(CONTEXTS){return Map.of("requests",requests.get(),"toolContexts",(int)CONTEXTS.keySet().stream().filter(k->k instanceof PluginTool).count(),"consumerContexts",CONTEXTS.size());}}

  public static final class Request implements AutoCloseable {
    private final PluginTool tool;
    private final Object consumer;
    private final Program program;
    private final TaskMonitor monitor;
    private final Supplier<Program> activeProgram;
    private final Context context;
    private long generation;
    private boolean obsolete,closed;
    private String disposition="PENDING";
    private Runnable invalidation=()->{};
    private final PluginEventListener events;
    private final WindowAdapter window=new WindowAdapter(){
      @Override public void windowClosed(WindowEvent e){obsolete=true;disposition="CONSUMER_CLOSED";monitor.cancel();invalidation.run();}
    };
    private Request(PluginTool t,Object key,Program p,TaskMonitor m,Supplier<Program> active) {
      tool=t;consumer=t==null?key:t;program=p;monitor=m;activeProgram=java.util.Objects.requireNonNull(active);
      events=event->{
        if(event instanceof ProgramActivatedPluginEvent){obsolete=true;disposition="ACTIVATION_SUPERSEDED";}
        if(event instanceof ProgramClosedPluginEvent e && e.getProgram()==program){obsolete=true;disposition="TARGET_CLOSED";monitor.cancel();invalidation.run();}
      };
      p.addConsumer(this);
      synchronized(CONTEXTS){context=CONTEXTS.computeIfAbsent(consumer,k->new Context());context.users++;}
      requests.incrementAndGet();
      RuntimeException[] failure={null};
      dispatch(()->{try {
        generation=++context.generation;
        if(tool!=null) {
          tool.addEventListener(ProgramActivatedPluginEvent.class,events);
          tool.addEventListener(ProgramClosedPluginEvent.class,events);
          tool.getToolFrame().addWindowListener(window);
          var manager=tool.getService(ProgramManager.class);
          if(manager==null || Arrays.stream(manager.getAllOpenPrograms()).noneMatch(open->open==program)) {
            obsolete=true;disposition="TARGET_CLOSED";monitor.cancel();
          } else if(manager.getCurrentProgram()!=program){obsolete=true;disposition="TARGET_INACTIVE";}
        }
      }catch(RuntimeException e){failure[0]=e;}});
      if(failure[0]!=null){close();throw failure[0];}
    }
    /** Ghidra Swing.runNow runs inline headlessly; use a private per-consumer lock there. */
    private void dispatch(Runnable action){if(tool==null){synchronized(context){action.run();}}else Swing.runNow(action);}
    public void onClosed(Runnable action){dispatch(()->{invalidation=action;if(closed || disposition.equals("TARGET_CLOSED") || disposition.equals("CONSUMER_CLOSED"))action.run();});}
    /** Final cheap source/consumer checks and publication share the consumer's serialization point. */
    public boolean publish(long sourceRevision,Runnable publication) {
      boolean[] result={false};
      dispatch(()->{
        if(closed || obsolete)return;
        if(monitor.isCancelled()){disposition="CANCELLED_PUBLICATION";return;}
        if(program.isClosed()){disposition="TARGET_CLOSED";return;}
        if(context.generation!=generation){disposition="REQUEST_SUPERSEDED";return;}
        Program active=tool==null?activeProgram.get():tool.getService(ProgramManager.class)==null?null:tool.getService(ProgramManager.class).getCurrentProgram();
        if(active!=program){disposition="TARGET_INACTIVE";return;}
        if(program.getModificationNumber()!=sourceRevision){disposition="SOURCE_STALE";return;}
        try{publication.run();disposition="PUBLISHED";result[0]=true;}
        catch(RuntimeException failure){disposition="PUBLICATION_FAILED";throw failure;}
      });
      return result[0];
    }
    public void suppress(String reason){dispatch(()->{if(!obsolete && !closed)disposition=monitor.isCancelled()?"CANCELLED_PUBLICATION":reason;});}
    public String disposition(){String[] value={null};dispatch(()->value[0]=disposition);return value[0];}
    @Override public void close(){dispatch(()->{
      if(closed)return;closed=true;if(disposition.equals("PENDING"))disposition=monitor.isCancelled()?"CANCELLED_PUBLICATION":"CONSUMER_CLOSED";invalidation.run();
      if(tool!=null){
        tool.removeEventListener(ProgramActivatedPluginEvent.class,events);
        tool.removeEventListener(ProgramClosedPluginEvent.class,events);
        if(tool.getToolFrame()!=null)tool.getToolFrame().removeWindowListener(window);
      }
      requests.decrementAndGet();
      synchronized(CONTEXTS){if(--context.users==0)CONTEXTS.remove(consumer);}
      program.release(this);
    });}
  }
  public static Request capture(PluginTool tool,Program program,TaskMonitor monitor){return capture(tool,new Object(),program,monitor,()->program);}
  public static Request capture(PluginTool tool,Object consumer,Program program,TaskMonitor monitor,Supplier<Program> activeProgram){
    return new Request(tool,java.util.Objects.requireNonNull(consumer),program,monitor,activeProgram);
  }
}
