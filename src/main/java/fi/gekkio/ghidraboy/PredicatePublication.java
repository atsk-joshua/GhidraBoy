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
import java.util.IdentityHashMap;
import java.util.Map;

/** Consumer-local runtime request identity. Never written into Program authority. */
public final class PredicatePublication {
  private PredicatePublication() {}
  private static int requests;
  public static Map<String,Integer> inventory(){java.util.concurrent.atomic.AtomicReference<Map<String,Integer>> result=new java.util.concurrent.atomic.AtomicReference<>();Swing.runNow(()->result.set(Map.of("requests",requests,"toolContexts",CONTEXTS.size())));return result.get();}
  private static final Map<PluginTool,Context> CONTEXTS=new IdentityHashMap<>();
  private static final class Context {long generation;int users;}
  public static final class Request implements AutoCloseable {
    private final PluginTool tool;
    private final Program program;
    private final TaskMonitor monitor;
    private Context context;
    private long generation;
    private boolean obsolete,closed;
    private String disposition="PENDING";
    private Runnable invalidation=()->{};
    private final PluginEventListener events;
    private final WindowAdapter window=new WindowAdapter(){
      @Override public void windowClosed(WindowEvent e){obsolete=true;disposition="CONSUMER_CLOSED";monitor.cancel();invalidation.run();}
    };
    private Request(PluginTool t,Program p,TaskMonitor m) {
      tool=t;program=p;monitor=m;p.addConsumer(this);
      events=event->{
      if(event instanceof ProgramActivatedPluginEvent) {obsolete=true;disposition="ACTIVATION_SUPERSEDED";}
      if(event instanceof ProgramClosedPluginEvent e && e.getProgram()==program) {
        obsolete=true;disposition="TARGET_CLOSED";monitor.cancel();invalidation.run();
      }
    };

      Swing.runNow(()->{
        requests++;
        if(tool!=null) {
          context=CONTEXTS.computeIfAbsent(tool,k->new Context());context.users++;generation=++context.generation;
          tool.addEventListener(ProgramActivatedPluginEvent.class,events);
          tool.addEventListener(ProgramClosedPluginEvent.class,events);
          tool.getToolFrame().addWindowListener(window);
          var manager=tool.getService(ProgramManager.class);
          if(manager==null || manager.getCurrentProgram()!=program){obsolete=true;disposition="TARGET_INACTIVE";}
        }
      });
    }
    public void onClosed(Runnable action){Swing.runNow(()->{invalidation=action;if(disposition.equals("TARGET_CLOSED") || disposition.equals("CONSUMER_CLOSED"))action.run();});}
    /** Final cheap source and consumer checks occur together at actual EDT publication. */
    public boolean publish(long sourceRevision,Runnable publication) {
      boolean[] result={false};
      Swing.runNow(()->{
        if(closed || obsolete)return;
        if(monitor.isCancelled()){disposition="CANCELLED_PUBLICATION";return;}
        if(program.isClosed()){disposition="TARGET_CLOSED";return;}
        if(tool!=null && (CONTEXTS.get(tool)!=context || context.generation!=generation
            || tool.getService(ProgramManager.class)==null
            || tool.getService(ProgramManager.class).getCurrentProgram()!=program)) {
          disposition="REQUEST_SUPERSEDED";return;
        }
        if(program.getModificationNumber()!=sourceRevision){disposition="SOURCE_STALE";return;}
        publication.run();disposition="PUBLISHED";result[0]=true;
      });
      return result[0];
    }
    public void suppress(String reason){Swing.runNow(()->{if(!obsolete && !closed)disposition=monitor.isCancelled()?"CANCELLED_PUBLICATION":reason;});}
    public String disposition(){String[] value={null};Swing.runNow(()->value[0]=disposition);return value[0];}
    @Override public void close(){Swing.runNow(()->{
      if(closed)return;closed=true;requests--;program.release(this);
      if(tool!=null){
        tool.removeEventListener(ProgramActivatedPluginEvent.class,events);
        tool.removeEventListener(ProgramClosedPluginEvent.class,events);
        tool.getToolFrame().removeWindowListener(window);
        if(--context.users==0)CONTEXTS.remove(tool);
      }
    });}
  }
  public static Request capture(PluginTool tool,Program program,TaskMonitor monitor){return new Request(tool,program,monitor);}
}
