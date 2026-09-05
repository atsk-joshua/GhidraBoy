package ghigbc;

import java.util.*;
import java.util.concurrent.*;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.services.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.*;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.util.Msg;
import ghidra.util.Swing;
import docking.action.builder.ActionBuilder;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;

@PluginInfo(status=PluginStatus.RELEASED,packageName="Debugger",category=PluginCategoryNames.DEBUGGER,shortDescription="GBC bank mapping",description="Maps captured SameBoy physical banks into verified static GhidraBoy program blocks.",servicesRequired={DebuggerTraceManagerService.class,ProgramManager.class,GoToService.class,TraceRmiService.class},eventsConsumed={ProgramActivatedPluginEvent.class,TraceActivatedPluginEvent.class,TraceClosedPluginEvent.class})
public class GbcPlugin extends Plugin {
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final Set<Trace> traces=ConcurrentHashMap.newKeySet();
    private volatile Program program;
    private volatile BankMappings mappings;
    private volatile boolean disposed;
    private StudyProvider provider;
    private final DomainObjectListener listener=event->schedule();
    public GbcPlugin(PluginTool tool){super(tool);}
    @Override protected void init(){
        provider=new StudyProvider(tool,this);
        new ActionBuilder("GBC physical breakpoint",getName()).withContext(ProgramLocationActionContext.class)
            .popupMenuPath("GBC","Breakpoint in this physical bank")
            .onAction(ctx->worker.submit(()->{
                try {var p=ctx.getProgram();var map=new BankMappings(p);var id=map.reverse(ctx.getAddress());
                    bankBreakpoint(id.region(),id.bank(),id.offset(),1);
                }catch(Exception e){Msg.showError(this,tool.getToolFrame(),"GBC breakpoint",e.getMessage());}
            })).buildAndInstall(tool);
    }
    private Trace currentTrace(){return tool.getService(DebuggerTraceManagerService.class).getCurrentTrace();}
    private void bankBreakpoint(String region,int bank,long offset,int kinds) throws Exception {
        Trace t=currentTrace();if(t==null)throw new IllegalStateException("No active GBC trace");
        var machine=t.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
        long snap=tool.getService(DebuggerTraceManagerService.class).getCurrentSnap();
        if(mappings==null||!mappings.hash().equals(StudyProvider.value(machine,snap,"ROMHash")))throw new IllegalStateException("Open the matching static program first");
        for(var connection:tool.getService(TraceRmiService.class).getAllConnections())if(connection.isTarget(t)) {
            connection.getMethods().get("bank_breakpoint").invokeAsync(Map.of("process",machine,"region",region,"bank",(long)bank,"offset",offset,"kinds",(long)kinds));return;
        }
        throw new IllegalStateException("Trace is disconnected");
    }
    void watchHP(int slot){worker.submit(()->{try{
        if(slot<0||slot>=100)throw new IllegalArgumentException("Invalid slot");
        var t=currentTrace();var m=t.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
        if(!"GBW3".equals(StudyProvider.value(m,tool.getService(DebuggerTraceManagerService.class).getCurrentSnap(),"Profile")))throw new IllegalStateException("Exact GBW3 profile required");
        bankBreakpoint("wram",3,slot*16+4,4);
    }catch(Exception e){Msg.showError(this,tool.getToolFrame(),"GBC HP watch",e.getMessage());}});}
    void goWriter(ghidra.trace.model.target.TraceObject event,boolean bookmark){worker.submit(()->{try{
        var manager=tool.getService(DebuggerTraceManagerService.class);long selected=manager.getCurrentSnap();
        long snap=((Number)StudyProvider.value(event,selected,"Snapshot")).longValue();
        Trace t=event.getTrace();var machine=t.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
        if(!BankMappings.isReady(machine,snap))throw new IllegalStateException("Capture mappings are not ready");
        Address writer=(Address)StudyProvider.value(event,selected,"Writer");
        var map=t.getStaticMappingManager().findContaining(writer,snap);if(map==null)throw new IllegalStateException("Writer has no static mapping");
        Program destination=program;
        if(destination==null||destination.isClosed()||!map.getStaticProgramURL().equals(ghidra.app.plugin.core.debug.utils.ProgramURLUtils.getUrlFromProgram(destination)))throw new IllegalStateException("Open the capture's mapped static program before navigating");
        Address address=destination.getAddressFactory().getAddress(map.getStaticAddress()).add(writer.subtract(map.getMinTraceAddress()));
        if(bookmark)try(var tx=destination.openTransaction("Save GBC observation")){
            String observation="Captured HP/access observation at trace snapshot "+snap+". Writer observed; caller unknown.";
            var existing=destination.getBookmarkManager().getBookmark(address,"Note","GBC Study");
            String comment=existing==null?observation:existing.getComment().contains(observation)?existing.getComment():existing.getComment()+"\n"+observation;
            destination.getBookmarkManager().setBookmark(address,"Note","GBC Study",comment);
        }
        Swing.runLater(()->{
            if(t.isClosed()||destination.isClosed())return;
            var control=tool.getService(DebuggerControlService.class);
            // Target modes follow the live stop and reject historical coordinates.
            // A captured writer is an observation, so inspect it in read-only Trace mode.
            if(control!=null&&control.getCurrentMode(t).followsPresent()&&snap!=t.getTimeManager().getMaxSnap())
                control.setCurrentMode(t,ghidra.debug.api.control.ControlMode.RO_TRACE);
            manager.activateTrace(t);manager.activateSnap(snap);
            tool.getService(GoToService.class).goTo(new ProgramLocation(destination,address));
        });
    }catch(Exception e){Msg.showError(this,tool.getToolFrame(),"GBC writer",e.getMessage());}});}

    @Override public void processEvent(PluginEvent event){
        if(event instanceof ProgramActivatedPluginEvent e){program=e.getActiveProgram();mappings=null;schedule();}
        if(event instanceof TraceActivatedPluginEvent e){Trace t=e.getActiveCoordinates().getTrace();if(t!=null&&traces.add(t))t.addListener(listener);schedule();}
        if(event instanceof TraceClosedPluginEvent e){Trace t=e.getTrace();traces.remove(t);t.removeListener(listener);}
    }
    private final java.util.concurrent.atomic.AtomicBoolean pending=new java.util.concurrent.atomic.AtomicBoolean();
    private final java.util.concurrent.atomic.AtomicBoolean dirty=new java.util.concurrent.atomic.AtomicBoolean();
    private void schedule(){
        dirty.set(true);
        if(disposed||!pending.compareAndSet(false,true))return;
        worker.submit(()->{try{do{dirty.set(false);update();}while(dirty.get()&&!disposed);}finally{pending.set(false);if(dirty.get()&&!disposed)schedule();}});
    }
    private void update(){
        Program p=program;if(p==null||p.isClosed()||!p.getLanguageID().toString().equals("SM83:LE:16:default"))return;
        try {
            if(mappings==null)mappings=new BankMappings(p);
            for(Trace t:List.copyOf(traces)) {
                if(t.isClosed())continue;
                var machine=t.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));if(machine==null)continue;
                for(var snapshot:t.getTimeManager().getAllSnapshots()) {
                    long snap=snapshot.getKey();var hash=machine.getValue(snap,"ROMHash");
                    if(hash!=null&&mappings.hash().equals(hash.getValue())&&!BankMappings.isReady(machine,snap))mappings.apply(t,snap);
                }
            }
        var manager=tool.getService(DebuggerTraceManagerService.class);
            Trace current=manager.getCurrentTrace();long selected=manager.getCurrentSnap();
            if(provider!=null)Swing.runLater(()->{
                if(disposed)return;
                try {provider.refresh(current!=null&&!current.isClosed()?current:null,selected);}
                catch(Exception failure){if(current==null||current.isClosed())provider.refresh(null,0);else Msg.error(this,"Unable to read captured study values",failure);}
            });
        }catch(Exception e){Msg.error(this,"GBC mapping unavailable: "+e.getMessage(),e);}
    }
    @Override protected void dispose(){disposed=true;for(Trace t:traces)t.removeListener(listener);worker.shutdownNow();if(provider!=null)tool.removeComponentProvider(provider);super.dispose();}
}
