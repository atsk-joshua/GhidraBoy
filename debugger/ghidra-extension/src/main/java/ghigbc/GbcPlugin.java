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

@PluginInfo(status=PluginStatus.RELEASED,packageName="Debugger",category=PluginCategoryNames.DEBUGGER,shortDescription="GBC bank mapping",description="Maps captured GB/GBC physical banks into verified static GhidraBoy program blocks.",servicesRequired={DebuggerTraceManagerService.class,DebuggerControlService.class,ProgramManager.class,GoToService.class,TraceRmiService.class},servicesProvided={GbcActionService.class},eventsConsumed={ProgramActivatedPluginEvent.class,TraceActivatedPluginEvent.class,TraceClosedPluginEvent.class})
public class GbcPlugin extends Plugin implements GbcActionService {
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private record BindingAttempt(String identity,int count,boolean failed) {}
    private final Map<Trace,BindingAttempt> sentBindings=new ConcurrentHashMap<>();
    private final Set<Trace> traces=ConcurrentHashMap.newKeySet();
    private volatile Program program;
    private volatile BankMappings mappings;
    private volatile String selectedView="canonical";
    private volatile boolean disposed;
    private StudyProvider provider;
    private final DomainObjectListener listener=event->schedule();
    private final DomainObjectListener programListener=event->{mappings=null;schedule();};
    public GbcPlugin(PluginTool tool){super(tool);}
    @Override protected void init(){
        provider=new StudyProvider(tool,this);
        new ActionBuilder("GBC static view",getName()).withContext(ProgramLocationActionContext.class)
            .popupMenuPath("GBC","Inspect physical views and select mapping view")
            .onAction(ctx->{try {
                var map=new BankMappings(ctx.getProgram());var id=map.reverse(ctx.getAddress());
                var candidates=map.candidates(id.region(),id.bank(),id.offset());
                Object selected=javax.swing.JOptionPane.showInputDialog(tool.getToolFrame(),"Select a static view for future captures. Historical mappings are retained.","GBC physical candidates",javax.swing.JOptionPane.PLAIN_MESSAGE,null,candidates.toArray(),ctx.getAddress());
                if(selected instanceof Address address){selectedView=address.getAddressSpace().getName();mappings=null;schedule();tool.getService(GoToService.class).goTo(new ProgramLocation(ctx.getProgram(),address));}
            }catch(Exception error){Msg.showError(this,tool.getToolFrame(),"GBC static views",error.getMessage());}}).buildAndInstall(tool);
        new ActionBuilder("GBC physical breakpoint",getName()).withContext(ProgramLocationActionContext.class)
            .popupMenuPath("GBC","Breakpoint in this physical bank")
            .onAction(ctx->{
                Trace selectedTrace=currentTrace();long selectedSnap=tool.getService(DebuggerTraceManagerService.class).getCurrentSnap();
                worker.submit(()->{
                    try {var p=ctx.getProgram();var map=new BankMappings(p);var id=map.reverse(ctx.getAddress());
                        bankBreakpoint(selectedTrace,selectedSnap,id.region(),id.bank(),id.offset(),1);
                    }catch(Exception e){Msg.showError(this,tool.getToolFrame(),"GBC breakpoint",e.getMessage());}
                });
            }).buildAndInstall(tool);
    }
    private Trace currentTrace(){return tool.getService(DebuggerTraceManagerService.class).getCurrentTrace();}
    private void bankBreakpoint(Trace t,long snap,String region,int bank,long offset,int kinds) throws Exception {
        if(t==null||t!=currentTrace()||t.isClosed()||snap!=t.getTimeManager().getMaxSnap())throw new IllegalStateException("Select the current target capture before arming a breakpoint");
        var machine=t.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
        if(mappings==null||!mappings.hash().equals(StudyProvider.value(machine,snap,"ROMHash")))throw new IllegalStateException("Open the matching static program first");
        for(var connection:tool.getService(TraceRmiService.class).getAllConnections())if(connection.isTarget(t)) {
            connection.getMethods().get("bank_breakpoint").invokeAsync(Map.of("process",machine,"region",region,"bank",(long)bank,"offset",offset,"kinds",(long)kinds,"expected_session",StudyProvider.value(machine,snap,"Session"),"expected_epoch",((Number)StudyProvider.value(machine,snap,"Epoch")).longValue(),"expected_capture",((Number)StudyProvider.value(machine,snap,"Capture")).longValue()));return;
        }
        throw new IllegalStateException("Trace is disconnected");
    }
    @Override public void watch(Trace trace,long selected,String region,int bank,long offset,int length){
        // Freeze selection on the UI caller, before the worker can observe a different target.
        var m=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
        Object session=StudyProvider.value(m,selected,"Session"),epoch=StudyProvider.value(m,selected,"Epoch"),capture=StudyProvider.value(m,selected,"Capture");
        worker.submit(()->{try{
            if(trace.isClosed()||trace!=currentTrace()||selected!=trace.getTimeManager().getMaxSnap())throw new IllegalStateException("Historical selections are observational; select the current stopped capture");
            for(var connection:tool.getService(TraceRmiService.class).getAllConnections())if(connection.isTarget(trace)){
                var action=connection.getMethods().get("profile_watch");
                if(action==null)throw new IllegalStateException("Selected backend does not support physical watches");
                action.invokeAsync(Map.of("process",m,"region",region,"bank",(long)bank,"offset",offset,"length",(long)length,"expected_session",session,"expected_epoch",((Number)epoch).longValue(),"expected_capture",((Number)capture).longValue())).get(15,TimeUnit.SECONDS);return;
            }
            throw new IllegalStateException("Trace is disconnected");
        }catch(Exception error){Msg.showError(this,tool.getToolFrame(),"GBC physical watch",error.getMessage());}});
    }
    @Override public void goWriter(ghidra.trace.model.target.TraceObject event,boolean bookmark){worker.submit(()->{try{
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
            String observation="Captured CPU access observation at trace snapshot "+snap+". Writer observed; caller unknown.";
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
        if(event instanceof ProgramActivatedPluginEvent e){if(program!=null)program.removeListener(programListener);program=e.getActiveProgram();if(program!=null)program.addListener(programListener);mappings=null;schedule();}
        if(event instanceof TraceActivatedPluginEvent e){Trace t=e.getActiveCoordinates().getTrace();if(t!=null&&traces.add(t))t.addListener(listener);schedule();}
        if(event instanceof TraceClosedPluginEvent e){Trace t=e.getTrace();traces.remove(t);sentBindings.remove(t);t.removeListener(listener);}
    }
    private final java.util.concurrent.atomic.AtomicBoolean pending=new java.util.concurrent.atomic.AtomicBoolean();
    private final java.util.concurrent.atomic.AtomicBoolean dirty=new java.util.concurrent.atomic.AtomicBoolean();
    private void schedule(){
        dirty.set(true);
        if(disposed||!pending.compareAndSet(false,true))return;
        worker.submit(()->{try{do{dirty.set(false);update();}while(dirty.get()&&!disposed);}finally{pending.set(false);if(dirty.get()&&!disposed)schedule();}});
    }
    private void updateMappings(){
        Program p=program;if(p==null||p.isClosed()||!p.getLanguageID().toString().equals("SM83:LE:16:default"))return;
        try {
            if(mappings==null)mappings=new BankMappings(p,selectedView);
            BankMappings active=mappings;if(active==null)return;
            for(Trace t:List.copyOf(traces)) {
                if(t.isClosed())continue;
                var machine=t.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));if(machine==null)continue;
                Long latestValue=t.getTimeManager().getMaxSnap();if(latestValue==null)continue;long latest=latestValue;
                Object barrier=StudyProvider.value(machine,latest,"MappingSaveBarrier"),ready=StudyProvider.value(machine,latest,"MappingSaveReady");
                if(barrier instanceof Number b&&b.longValue()>0&&ready instanceof Number r&&r.longValue()==b.longValue())continue;
                var session=StudyProvider.value(machine,latest,"Session");var epoch=StudyProvider.value(machine,latest,"Epoch");
                String binding=active.generation()+":"+session+":"+epoch;
                var prior=sentBindings.get(t);
                boolean same=prior!=null&&binding.equals(prior.identity());
                boolean needsTransfer=!same||(prior.failed()&&prior.count()<3);
                if(active.fullCoverage()&&active.hash().equals(StudyProvider.value(machine,latest,"ROMHash"))&&needsTransfer) {
                    for(var connection:tool.getService(TraceRmiService.class).getAllConnections())if(connection.isTarget(t)&&connection.getMethods().get("static_mapping")!=null&&session instanceof String&&epoch instanceof Number) {
                        var attempt=new BindingAttempt(binding,same?prior.count()+1:1,false);
                        sentBindings.put(t,attempt);
                        String envelope=active.envelope(),generation=active.generation();int count=(envelope.length()+15999)/16000;
                        CompletionStage<Object> transfer=CompletableFuture.completedFuture(null);
                        for(int index=0;index<count;index++) {
                            int chunk=index;
                            transfer=transfer.thenCompose(ignored->connection.getMethods().get("static_mapping").invokeAsync(Map.of("process",machine,"generation",generation,"index",(long)chunk,"count",(long)count,"part",envelope.substring(chunk*16000,Math.min(envelope.length(),(chunk+1)*16000)),"expected_session",session,"expected_epoch",((Number)epoch).longValue())));
                        }
                        transfer.whenComplete((ignored,error)->{
                            if(error!=null&&!disposed&&sentBindings.replace(t,attempt,new BindingAttempt(binding,attempt.count(),true))) {
                                Msg.warn(this,"Static snapshot transfer incomplete (attempt "+attempt.count()+"/3): "+error.getMessage());
                                if(attempt.count()<3)schedule();
                            }
                        });
                        break;
                    }
                }
                for(var snapshot:t.getTimeManager().getAllSnapshots()) {
                    long snap=snapshot.getKey();var hash=machine.getValue(snap,"ROMHash");
                    if(hash!=null&&active.hash().equals(hash.getValue())&&!BankMappings.isReady(machine,snap))active.apply(t,snap);
                }
            }
        }catch(Exception e){Msg.error(this,"GBC mapping unavailable: "+e.getMessage(),e);}
    }
    private void acknowledgeSaveBarriers(){
        for(Trace t:List.copyOf(traces))try {
            if(t.isClosed())continue;Long currentSnap=t.getTimeManager().getMaxSnap();if(currentSnap==null)continue;long snap=currentSnap;
            var machine=t.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));if(machine==null)continue;
            Object requested=StudyProvider.value(machine,snap,"MappingSaveBarrier"),ready=StudyProvider.value(machine,snap,"MappingSaveReady");
            if(requested instanceof Number n&&n.longValue()>0&&(!(ready instanceof Number r)||r.longValue()!=n.longValue()))
                try(var tx=t.openTransaction("Quiesce GBC mappings for save")){machine.setValue(Lifespan.at(snap),"MappingSaveReady",n.longValue());}
        }catch(Exception error){if(!disposed&&!t.isClosed())Msg.warn(this,"Mapping save barrier unavailable: "+error.getMessage());}
    }
    private void update(){
        updateMappings();
        acknowledgeSaveBarriers();
        var manager=tool.getService(DebuggerTraceManagerService.class);
        Trace current=manager.getCurrentTrace();long selected=manager.getCurrentSnap();
        if(provider!=null)Swing.runLater(()->{
            if(disposed)return;
            try {
                long shown=selected;
                var control=tool.getService(DebuggerControlService.class);
                if(current!=null&&!current.isClosed()&&current==manager.getCurrentTrace()&&control!=null&&control.getCurrentMode(current).followsPresent()) {
                    Long latest=current.getTimeManager().getMaxSnap();
                    var machine=current.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
                    var completed=machine==null?null:StudyProvider.value(machine,latest==null?0:latest,"CaptureSnapshot");
                    if(latest!=null&&completed instanceof Number n&&n.longValue()==latest&&latest>manager.getCurrentSnap()){manager.activateSnap(latest);shown=latest;}
                }
                provider.refresh(current!=null&&!current.isClosed()?current:null,shown);
            }
            catch(Exception failure){if(current==null||current.isClosed())provider.refresh(null,0);else Msg.error(this,"Unable to read captured history",failure);}
        });
    }
    @Override protected void dispose(){disposed=true;if(program!=null)program.removeListener(programListener);for(Trace t:traces)t.removeListener(listener);worker.shutdownNow();if(provider!=null)tool.removeComponentProvider(provider);super.dispose();}
}
