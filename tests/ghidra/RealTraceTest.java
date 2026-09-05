import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.model.*;
import ghidra.framework.project.*;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.app.services.*;
import ghidra.debug.api.tracermi.*;
import ghidra.trace.model.*;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.util.Swing;
import ghidra.app.util.importer.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghigbc.BankMappings;

/** Real Ghidra integration executable; no substitute trace or mocked RMI client. */
public class RealTraceTest {
    static class Manager extends DefaultProjectManager { Manager(){super();} }
    static Trace trace;
    static TraceObject object(String path){return trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse(path));}
    static TraceObject latestEdit(){
        return object("Machine.Edits").getElements(Lifespan.at(snap())).stream()
            .map(v->(TraceObject)v.getValue()).filter(e->((Number)e.getValue(snap(),"Snapshot").getValue()).longValue()==snap())
            .findFirst().orElseThrow(()->new AssertionError("No edit record at current snapshot"));
    }
    static void rejectedEdit(TraceRmiConnection connection,Map<String,Object> arguments,String message) throws Exception {
        try{connection.getMethods().get("experiment_register").invokeAsync(arguments).get(15,TimeUnit.SECONDS);throw new AssertionError(message);}
        catch(ExecutionException expected){require(expected.getCause().getMessage().contains("paused experiment mode"),message);}
    }
    static long snap(){return trace.getTimeManager().getMaxSnap();}
    static void restoreAndAwait(TraceRmiConnection connection,Path checkpoint)throws Exception{
        long previous=((Number)attr("Machine","Capture")).longValue();
        connection.getMethods().get("restore").invokeAsync(Map.of("process",object("Machine"),"path",checkpoint.toString())).get(15,TimeUnit.SECONDS);
        waitCapture(previous);
        require(checkpoint.toAbsolutePath().toString().equals(attr("Machine","ParentCheckpoint")),"restored capture identifies its source checkpoint");
    }
    static Object attr(String path,String name){return object(path).getValue(snap(),name).getValue();}
    static void require(boolean ok,String message){if(!ok)throw new AssertionError(message);System.out.println("PASS "+message);}
    static long rssKiB(long pid)throws Exception{
        var process=new ProcessBuilder("ps","-o","rss=","-p",Long.toString(pid)).start();
        if(!process.waitFor(5,TimeUnit.SECONDS)){process.destroyForcibly();throw new IOException("RSS probe timed out");}
        if(process.exitValue()!=0)throw new IOException("RSS unavailable for owned process "+pid);
        return Long.parseLong(new String(process.getInputStream().readAllBytes()).trim());
    }
    static void measureGrowth(Path root,TraceRmiConnection connection,Process agent)throws Exception{
        var samples=new ArrayList<Object>();long started=System.nanoTime();long initial=snap();
        for(int count=0;count<=250;count++){
            if(count>0)connection.getMethods().get("step_into").invokeAsync(Map.of("thread",object("Machine.Threads[0]"))).get(15,TimeUnit.SECONDS);
            if(count%125==0){
                connection.getMethods().get("save_trace").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
                samples.add(Map.of("stops",count,"snapshot",snap(),"agent_rss_kib",rssKiB(agent.pid()),"ghidra_rss_kib",rssKiB(ProcessHandle.current().pid()),"trace_file_bytes",trace.getDomainFile().length(),"dropped_events",attr("Machine","Dropped")));
            }
        }
        require(snap()>=initial+250,"growth probe published 250 successive stopped captures");
        require(((Number)attr("Machine","Dropped")).longValue()==0,"growth probe reports no dropped events");
        var report=Map.of("host",java.net.InetAddress.getLocalHost().getHostName(),"os",System.getProperty("os.name")+" "+System.getProperty("os.version"),"architecture",System.getProperty("os.arch"),"ghidra","12.1.2","seconds",(System.nanoTime()-started)/1e9,"samples",samples,"scope","250 sequential real Trace RMI step/stop captures after warmup, including documented wait boundaries; saved trace intentionally retains history. Not a long-duration leak proof or saturated request-queue test.");
        Files.writeString(root.resolve("docs/evidence/integrated-growth.json"),new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(report));
    }
    static int read(long s,String space,long offset){ByteBuffer b=ByteBuffer.allocate(1);trace.getMemoryManager().getBytes(s,trace.getBaseAddressFactory().getAddressSpace(space).getAddress(offset),b);return b.array()[0]&255;}
    static void waitCapture(long old) throws Exception {
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);
        while(System.nanoTime()<end){
            var m=object("Machine");
            if(m!=null&&m.getValue(snap(),"Capture")!=null && m.getValue(snap(),"CaptureSnapshot")!=null && ((Number)attr("Machine","CaptureSnapshot")).longValue()==snap() && ((Number)attr("Machine","Capture")).longValue()>old && "STOPPED".equals(String.valueOf(attr("Machine","_state")))) {Thread.sleep(100);return;}
            Thread.sleep(20);
        }
        throw new AssertionError("Timed out awaiting real stopped capture");
    }
    public static void main(String[] args) {
        try {runTest(args);}catch(Throwable error){error.printStackTrace();System.exit(1);}
    }
    public static void runTest(String[] args) throws Exception {
        Path root=Path.of(args[0]).toAbsolutePath();
        Application.initializeApplication(new GhidraApplicationLayout(new File(System.getenv().getOrDefault("GHIDRA_INSTALL_DIR",root.resolve(".deps/ghidra_11.3.1_PUBLIC").toString()))),new GhidraApplicationConfiguration());
        Project project=new Manager().createProject(new ProjectLocator(root.resolve("build/projects").toString(),"TraceTest-"+System.currentTimeMillis()),null,false);
        var imported=AutoImporter.importByUsingBestGuess(root.resolve("build/teaching.gbc").toFile(),project,"/",RealTraceTest.class,new MessageLog(),TaskMonitor.DUMMY);
        imported.save(TaskMonitor.DUMMY);
        Program staticProgram=imported.getPrimaryDomainObject();
        try(var tx=staticProgram.openTransaction("Student annotations on fixture copy")) {
            var block=staticProgram.getMemory().getBlock("rom2");block.setName("student_second_bank");
            staticProgram.getSymbolTable().createLabel(block.getStart().add(0x29),"StudentBankTwo",SourceType.USER_DEFINED);
        }
        staticProgram.save("Fixture annotations",TaskMonitor.DUMMY);
        long directWriter=Files.lines(root.resolve("build/teaching.sym")).filter(line->line.endsWith(" DirectWriter")).map(line->Long.parseLong(line.split(" ")[0].split(":")[1],16)).findFirst().orElseThrow();
        try(var tx=staticProgram.openTransaction("Student writer label")){staticProgram.getSymbolTable().createLabel(staticProgram.getAddressFactory().getDefaultAddressSpace().getAddress(directWriter),"StudentHPWriter",SourceType.USER_DEFINED);}
        BankMappings mappings=new BankMappings(staticProgram);
        require(staticProgram.getAddressFactory().getAddress("rom1:4029")!=null,"single-colon overlay mapping address resolves in static program");
        final GhidraTool[] holder=new GhidraTool[1];
        Swing.runNow(()->{
            try {
                GhidraTool tool=new GhidraTool(project,"GBC Debugger Integration");holder[0]=tool;
                tool.addPlugins(List.of("ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin","ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin","ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersPlugin","ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPlugin","ghidra.app.plugin.core.debug.gui.time.DebuggerTimePlugin","ghidra.app.plugin.core.debug.gui.model.DebuggerModelPlugin","ghigbc.GbcPlugin","ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLauncherServicePlugin"));
                tool.getService(ProgramManager.class).openProgram(staticProgram);
                tool.setVisible(true);
            }catch(Exception e){throw new RuntimeException(e);}
        });
        GhidraTool tool=holder[0];
        var acceptor=tool.getService(TraceRmiService.class).acceptOne(new InetSocketAddress("127.0.0.1",0));acceptor.setTimeout(15000);
        int port=((InetSocketAddress)acceptor.getAddress()).getPort();
        ProcessBuilder pb=new ProcessBuilder(System.getenv().getOrDefault("GBC_PYTHON",root.resolve(".venv/bin/python").toString()),"-m","ghigbc.agent","--connect","127.0.0.1:"+port,"--rom",root.resolve("build/teaching.gbc").toString(),"--fixture-ready","--experiment");
        pb.environment().put("PYTHONPATH",root.resolve("python").toString());pb.redirectErrorStream(true);pb.redirectOutput(root.resolve("docs/evidence/real-agent.log").toFile());
        Process agent=pb.start();
        try {
            TraceRmiConnection conn=acceptor.accept();trace=conn.waitForTrace(15000);waitCapture(0);
            var methods=conn.getMethods();
            mappings.apply(trace,snap());
            require(BankMappings.isReady(object("Machine"),snap()),"completed mapping marker identifies this snapshot");
            require(!BankMappings.isReady(object("Machine"),snap()+1000),"mapping marker cannot mark an uncaptured future snapshot ready");
            var firstMapping=trace.getStaticMappingManager().findContaining(trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(0x4029),snap());
            require(firstMapping!=null&&firstMapping.getStaticAddress().contains("rom1"),"snapshot 1 CPU window maps explicitly to static bank 1");
            var staticBankTwo=staticProgram.getMemory().getBlock("student_second_bank").getStart().add(0x29);
            var identity=mappings.reverse(staticBankTwo);
            require(identity.bank()==2&&identity.offset()==0x29,"renamed static block reverses to canonical bank 2");
            require(read(snap(),"ram",0x402a)==0x11,"CPU bytes from bank 1 at initial stop");
            require(read(snap(),"rom2",0x402a)==0x22,"inactive physical ROM bank 2 bytes");
            long first=snap();
            long cap=((Number)attr("Machine","Capture")).longValue();
            methods.get("step_into").invokeAsync(Map.of("thread",object("Machine.Threads[0]"))).get(15,TimeUnit.SECONDS);waitCapture(cap);
            var thread=trace.getThreadManager().getAllThreads().iterator().next();
            var regs=trace.getMemoryManager().getMemoryRegisterSpace(thread,0,false);
            require(regs.getValue(snap(),trace.getBaseLanguage().getRegister("PC")).getUnsignedValue().intValue()==0x402b,"native Step updates real Ghidra PC");
            methods.get("bank_breakpoint").invokeAsync(Map.of("process",object("Machine"),"region","rom","bank",2L,"offset",0x29L,"kinds",1L)).get(15,TimeUnit.SECONDS);
            cap=((Number)attr("Machine","Capture")).longValue();
            methods.get("resume").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);waitCapture(cap);
            require(((Number)attr("Machine","ROMX")).intValue()==2,"inactive-bank breakpoint hits bank 2");
            mappings.apply(trace,snap());
            var mapped=trace.getStaticMappingManager().findContaining(trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(0x4029),snap());
            require(mapped!=null&&mapped.getStaticAddress().contains(staticBankTwo.getAddressSpace().getName()),"bank 2 CPU mapping follows renamed static overlay");
            require(trace.getStaticMappingManager().findContaining(trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(0x4029),first).getStaticAddress().equals(firstMapping.getStaticAddress()),"old mapping survives later bank switch");
            require(read(first,"ram",0x402a)==0x11&&read(snap(),"ram",0x402a)==0x22,"historic CPU bytes survive bank switch");
            methods.get("bank_breakpoint").invokeAsync(Map.of("process",object("Machine"),"region","wram","bank",3L,"offset",0x34L,"kinds",4L)).get(15,TimeUnit.SECONDS);
            cap=((Number)attr("Machine","Capture")).longValue();
            methods.get("resume").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);waitCapture(cap);
            var event=object("Machine.Events[1]");
            require(event!=null&&((Number)event.getValue(snap(),"After").getValue()).intValue()==0x35,"real RMI WRAM watchpoint publishes committed final byte");
            require(((ghidra.program.model.address.Address)event.getValue(snap(),"Writer").getValue()).getOffset()==directWriter,"real RMI event retains arbitrary instruction writer");
            mappings.apply(trace,snap());
            require(ghigbc.StudyProvider.writerLabel(trace,event,snap(),staticProgram).startsWith("StudentHPWriter"),"study panel uses authoritative renamed Ghidra writer label");
            String details=ghigbc.StudyProvider.eventDescription(event,snap());
            require(details.contains("wram bank 3 +0x34")&&details.contains("Origin: cpu")&&details.contains("attempted access value: 0x35")&&details.contains("instruction boundary"),"study details expose captured physical target, origin, attempt and precision");
            require(!details.contains("slot 3 HP"),"generic ROM receives no game-specific field label");
            long originalEventSnapshot=((Number)event.getValue(snap(),"Snapshot").getValue()).longValue();
            methods.get("delete_breakpoint").invokeAsync(Map.of("breakpoint",object("Machine.Breakpoints[3]"))).get(15,TimeUnit.SECONDS);
            require(((Number)event.getValue(snap(),"Snapshot").getValue()).longValue()==originalEventSnapshot,"breakpoint edits do not move a captured writer event into a new snapshot");
            require(object("Machine.Breakpoints[3]").isAlive(originalEventSnapshot),"deleting a breakpoint preserves its historical specification");
            methods.get("bank_breakpoint").invokeAsync(Map.of("process",object("Machine"),"region","rom","bank",2L,"offset",0x567L,"kinds",1L)).get(15,TimeUnit.SECONDS);
            cap=((Number)attr("Machine","Capture")).longValue();methods.get("resume").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);waitCapture(cap);
            // Exercise arbitrary native writer watchpoints through the real Ghidra method registry.
            String[] names={"AF","BC","DE","HL","PC","SP","A","F","B","C"};int[] expected={0x12b0,0x3456,0x789a,0xbcde,0x4567,0xcffe,0x12,0xb0,0x34,0x56};
            for(int i=0;i<names.length;i++) require(regs.getValue(snap(),trace.getBaseLanguage().getRegister(names[i])).getUnsignedValue().intValue()==expected[i],"register "+names[i]+" = "+Integer.toHexString(expected[i]));
            var checkpointDir=root.resolve("build/trace-checkpoint-"+System.currentTimeMillis());
            methods.get("checkpoint").invokeAsync(Map.of("process",object("Machine"),"path",checkpointDir.toString())).get(15,TimeUnit.SECONDS);
            var editPaths=new ArrayList<KeyPath>();
            int guestEvents=object("Machine.Events").getElements(Lifespan.at(snap())).size();
            var registerRecovery=root.resolve("build/edit-register-"+System.currentTimeMillis());
            methods.get("experiment_register").invokeAsync(Map.of("process",object("Machine"),"register","BC","value",0xabcdL,"recovery",registerRecovery.toString())).get(15,TimeUnit.SECONDS);
            long registerEditSnap=snap();var registerEdit=latestEdit();editPaths.add(registerEdit.getCanonicalPath());
            require(regs.getValue(snap(),trace.getBaseLanguage().getRegister("BC")).getUnsignedValue().intValue()==0xabcd,"remote experiment register edit changes real Ghidra register value");
            require("debugger".equals(registerEdit.getValue(snap(),"Origin").getValue())&&((Number)registerEdit.getValue(snap(),"Before").getValue()).intValue()==0x3456&&((Number)registerEdit.getValue(snap(),"After").getValue()).intValue()==0xabcd,"register edit has debugger-origin before/after provenance");
            require(Files.exists(registerRecovery.resolve("state.sbs"))&&registerRecovery.toString().equals(registerEdit.getValue(snap(),"RecoveryCheckpoint").getValue()),"trace edit links to a full recovery checkpoint");
            restoreAndAwait(conn,registerRecovery);
            long registerRestoreSnap=snap();
            require(regs.getValue(snap(),trace.getBaseLanguage().getRegister("BC")).getUnsignedValue().intValue()==0x3456,"remote register edit is recoverable");
            require(regs.getValue(registerEditSnap,trace.getBaseLanguage().getRegister("BC")).getUnsignedValue().intValue()==0xabcd,"restoring does not rewrite edited register history");
            methods.get("bank_breakpoint").invokeAsync(Map.of("process",object("Machine"),"region","wram","bank",1L,"offset",0x34L,"kinds",4L)).get(15,TimeUnit.SECONDS);
            var memoryRecovery=root.resolve("build/edit-memory-"+System.currentTimeMillis());
            methods.get("experiment_memory").invokeAsync(Map.of("process",object("Machine"),"address",0xf034L,"value",0xa6L,"recovery",memoryRecovery.toString())).get(15,TimeUnit.SECONDS);
            long memoryEditSnap=snap();var memoryEdit=latestEdit();editPaths.add(memoryEdit.getCanonicalPath());
            require(read(snap(),"wram1",0xd034)==0xa6&&read(snap(),"ram",0xf034)==0xa6,"remote echo-RAM edit changes the selected physical bank");
            require("wram".equals(memoryEdit.getValue(snap(),"TargetRegion").getValue())&&((Number)memoryEdit.getValue(snap(),"TargetBank").getValue()).intValue()==1&&((Number)memoryEdit.getValue(snap(),"TargetOffset").getValue()).intValue()==0x34,"memory edit records canonical bank and offset");
            require(object("Machine.Events").getElements(Lifespan.at(snap())).size()==guestEvents,"debugger edit does not create a guest CPU watch event");
            restoreAndAwait(conn,memoryRecovery);
            require(read(snap(),"wram1",0xd034)==0x58&&read(memoryEditSnap,"wram1",0xd034)==0xa6,"remote RAM recovery preserves both historical values");
            long epoch=((Number)attr("Machine","Epoch")).longValue();
            java.util.List<Double> times=new ArrayList<>();
            for(int i=0;i<20;i++) {
                long started=System.nanoTime();methods.get("step_into").invokeAsync(Map.of("thread",object("Machine.Threads[0]"))).get(15,TimeUnit.SECONDS);times.add((System.nanoTime()-started)/1e6);
            }
            Collections.sort(times);System.out.println("REMOTE_STEP_P95_MS "+times.get(18));
            if(Arrays.asList(args).contains("--growth"))measureGrowth(root,conn,agent);
            restoreAndAwait(conn,checkpointDir);
            require(((Number)attr("Machine","Epoch")).longValue()>epoch,"remote checkpoint restore creates new epoch");
            require(regs.getValue(snap(),trace.getBaseLanguage().getRegister("PC")).getUnsignedValue().intValue()==0x4567,"remote checkpoint restores registers");
            long beforePause=((Number)attr("Machine","Capture")).longValue();
            methods.get("resume").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
            waitCapture(beforePause);
            require("breakpoint".equals(String.valueOf(attr("Machine","StopReason"))),"checkpoint restore re-arms the execution breakpoint at restored PC");
            beforePause=((Number)attr("Machine","Capture")).longValue();
            methods.get("resume").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
            methods.get("bank_breakpoint").invokeAsync(Map.of("process",object("Machine"),"region","rom","bank",2L,"offset",0x100L,"kinds",1L)).get(15,TimeUnit.SECONDS);
            require("RUNNING".equals(String.valueOf(attr("Machine","_state"))),"breakpoint edits during execution do not falsely report a stop");
            var deniedRunning=root.resolve("build/denied-running-"+System.currentTimeMillis());
            rejectedEdit(conn,Map.of("process",object("Machine"),"register","BC","value",1L,"recovery",deniedRunning.toString()),"running machine rejects experiment edits");
            require(!Files.exists(deniedRunning),"rejected running edit creates no recovery artifact");
            long pauseStarted=System.nanoTime();methods.get("interrupt").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);waitCapture(beforePause);
            System.out.println("REMOTE_PAUSE_MS "+((System.nanoTime()-pauseStarted)/1e6));
            methods.get("save_trace").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
            System.out.println("TRACE_FILE "+trace.getDomainFile().getPathname());
            var traceFile=trace.getDomainFile();
            var reopened=(Trace)traceFile.getReadOnlyDomainObject(RealTraceTest.class,-1,TaskMonitor.DUMMY);
            try {
                ByteBuffer bytes=ByteBuffer.allocate(1);reopened.getMemoryManager().getBytes(first,reopened.getBaseAddressFactory().getDefaultAddressSpace().getAddress(0x402a),bytes);
                require((bytes.array()[0]&255)==0x11,"reopened persisted trace retains historic CPU bytes");
                for(var path:editPaths){
                    var edit=reopened.getObjectManager().getObjectByCanonicalPath(path);
                    require(edit!=null&&"debugger".equals(edit.getValue(reopened.getTimeManager().getMaxSnap(),"Origin").getValue()),"debugger edit provenance survives trace reopen");
                    require(edit.getValue(reopened.getTimeManager().getMaxSnap(),"RecoverySHA256").getValue().toString().length()==64,"reopened edit retains recovery state fingerprint");
                }
                require(reopened.getStaticMappingManager().findContaining(reopened.getBaseAddressFactory().getDefaultAddressSpace().getAddress(0x4029),first).getStaticAddress().equals(firstMapping.getStaticAddress()),"reopened persisted trace retains historic mapping");
                require(BankMappings.isReady(reopened.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine")),first),"reopened historical mapping retains its exact completion marker");
                var reopenedMachine=reopened.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
                require(registerRecovery.toString().equals(reopenedMachine.getValue(registerRestoreSnap,"ParentCheckpoint").getValue()),"reopened restore retains its original checkpoint link");
                require(reopenedMachine.getValue(registerRestoreSnap,"ParentCheckpointSHA256").getValue().toString().length()==64,"reopened restore retains the checkpoint state fingerprint");
            }finally{reopened.release(RealTraceTest.class);}
            require(staticProgram.getSymbolTable().getPrimarySymbol(staticBankTwo).getName().equals("StudentBankTwo"),"student annotations preserved");
            // Ghidra owns acceptor, subprocess and terminals for this launch; no manual socket.
            var offers=tool.getService(TraceRmiLauncherService.class).getOffers(staticProgram);
            var offer=offers.stream().filter(o->o.getTitle().equals("GBC / SameBoy")).findFirst().orElseThrow(()->new AssertionError("SameBoy launcher not discovered"));
            try(var launched=offer.launchProgram(TaskMonitor.DUMMY,new TraceRmiLaunchOffer.LaunchConfigurator(){
                public Map<String,ghidra.debug.api.ValStr<?>> configureLauncher(TraceRmiLaunchOffer o,Map<String,ghidra.debug.api.ValStr<?>> suggested,TraceRmiLaunchOffer.RelPrompt rel){
                    var values=new HashMap<String,ghidra.debug.api.ValStr<?>>(suggested);
                    values.put("env:OPT_GBC_HOME",o.getParameters().get("env:OPT_GBC_HOME").defaultValue());
                    for(var entry:Map.of("arg:1",root.resolve("build/teaching.gbc").toString(),"env:OPT_GBC_DISPLAY",Arrays.asList(args).contains("--display-close")?"true":"false").entrySet())values.put(entry.getKey(),o.getParameters().get(entry.getKey()).decode(entry.getValue()));
                    return values;
                }
            })){
                if(launched.exception()!=null)throw new AssertionError("Ghidra launcher failed",launched.exception());
                require(launched.trace()!=null&&launched.connection()!=null,"Ghidra SameBoy menu launcher starts real agent automatically");
                Trace previousTrace=trace;trace=launched.trace();waitCapture(0);
                launched.connection().getMethods().get("save_trace").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
                require(object("Machine").getValue(snap(),"Capture")!=null,"automatic launcher publishes and saves a complete initial capture");
                var deniedDefault=root.resolve("build/denied-default-"+System.currentTimeMillis());
                rejectedEdit(launched.connection(),Map.of("process",object("Machine"),"register","BC","value",1L,"recovery",deniedDefault.toString()),"default launcher rejects experiment writes");
                require(!Files.exists(deniedDefault),"default-mode rejection leaves original state and files untouched");
                if(Arrays.asList(args).contains("--display-close")) {
                    System.out.println("DISPLAY_CLOSE_READY: close the paused SDL window using desktop controls");
                    System.out.flush();
                    long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(60);
                    while(!launched.connection().isClosed()&&System.nanoTime()<deadline)Thread.sleep(25);
                    require(launched.connection().isClosed(),"desktop window close disconnects the Ghidra-launched agent");
                    require("TERMINATED".equals(String.valueOf(attr("Machine","_state"))),"desktop close records truthful terminated state");
                    var closedFile=trace.getDomainFile();
                    var saved=(Trace)closedFile.getReadOnlyDomainObject(RealTraceTest.class,-1,TaskMonitor.DUMMY);
                    try {
                        var machine=saved.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
                        require("TERMINATED".equals(String.valueOf(machine.getValue(saved.getTimeManager().getMaxSnap(),"_state").getValue())),"desktop-close termination survives trace reopen");
                    }finally{saved.release(RealTraceTest.class);}
                }else{
                    launched.connection().getMethods().get("kill").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
                    launched.connection().waitClosed();
                }
                trace=previousTrace;
                Swing.runNow(()->tool.getService(DebuggerTraceManagerService.class).activateTrace(previousTrace));
            }
            if(Arrays.asList(args).contains("--keep-open")) {
                methods.get("restore").invokeAsync(Map.of("process",object("Machine"),"path",checkpointDir.toString())).get(15,TimeUnit.SECONDS);
                Thread.sleep(120000);
            }
            methods.get("kill").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
            conn.waitClosed();
            require(agent.waitFor(3,TimeUnit.SECONDS),"owned sidecar exits after structured termination");
            require("TERMINATED".equals(String.valueOf(attr("Machine","_state"))),"trace retains truthful terminated state");
            System.out.println("REAL_TRACE_TEST_PASSED");
            conn.close();
        } finally {
            agent.destroy();if(!agent.waitFor(3,TimeUnit.SECONDS))agent.destroyForcibly();
            Swing.runNow(()->tool.dispose());imported.close();project.close();
        }
        System.exit(0);
    }
}
