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
    static final Queue<Throwable> asyncErrors=new ConcurrentLinkedQueue<>();
    static TraceObject object(String path){return trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse(path));}
    static TraceObject latestEdit(){
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);
        while(System.nanoTime()<deadline){
            var machine=object("Machine");long at=snap();
            var marker=machine.getValue(at,"CaptureSnapshot");
            if(marker!=null&&marker.getValue() instanceof Number n&&n.longValue()==at&&object("Machine.Edits").getElements(Lifespan.at(at)).stream().anyMatch(v->v.getValue() instanceof TraceObject e&&e.getValue(at,"Snapshot")!=null&&((Number)e.getValue(at,"Snapshot").getValue()).longValue()==at))break;
            try{Thread.sleep(10);}catch(InterruptedException e){throw new RuntimeException(e);}
        }
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
    static Path evidence(Path root)throws Exception{var path=Path.of(System.getenv().getOrDefault("GBC_EVIDENCE_DIR",root.resolve("docs/evidence").toString()));Files.createDirectories(path);return path;}
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
                require(attr("Machine","MappingSaveReady") instanceof Number ready&&attr("Machine","MappingSaveBarrier") instanceof Number barrier&&ready.longValue()==barrier.longValue(),"mapping writer quiesces before trace save");
                samples.add(Map.of("stops",count,"snapshot",snap(),"agent_rss_kib",rssKiB(agent.pid()),"ghidra_rss_kib",rssKiB(ProcessHandle.current().pid()),"trace_file_bytes",trace.getDomainFile().length(),"dropped_events",attr("Machine","Dropped")));
            }
        }
        require(snap()>=initial+250,"growth probe published 250 successive stopped captures");
        require(((Number)attr("Machine","Dropped")).longValue()==0,"growth probe reports no dropped events");
        var report=Map.of("host",java.net.InetAddress.getLocalHost().getHostName(),"os",System.getProperty("os.name")+" "+System.getProperty("os.version"),"architecture",System.getProperty("os.arch"),"ghidra",Application.getApplicationVersion(),"seconds",(System.nanoTime()-started)/1e9,"samples",samples,"scope","250 sequential real Trace RMI step/stop captures after warmup, including documented wait boundaries; saved trace intentionally retains history. Not a long-duration leak proof or saturated request-queue test.");
        Files.writeString(evidence(root).resolve("integrated-growth.json"),new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(report));
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
    static GhidraApplicationConfiguration testConfiguration(){
        var config=new GhidraApplicationConfiguration();config.setShowSplashScreen(false);return config;
    }
    static void awaitClosed(TraceRmiConnection connection)throws Exception {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        while(!connection.isClosed()&&System.nanoTime()<deadline)Thread.sleep(20);
        require(connection.isClosed(),"disconnected target closes its real RMI connection within the bound");
    }
    static void failureLifecycle(Path root,GhidraTool tool)throws Exception {
        Trace previous=trace;String formerSession=null;
        try {
            for(String mode:List.of("disconnect","crash","replacement")) {
                var acceptor=tool.getService(TraceRmiService.class).acceptOne(new InetSocketAddress("127.0.0.1",0));
                acceptor.setTimeout(15000);
                int port=((InetSocketAddress)acceptor.getAddress()).getPort();
                var builder=new ProcessBuilder(System.getenv().getOrDefault("GBC_PYTHON",root.resolve(".venv12/bin/python").toString()),
                    "-m","ghigbc.agent","--connect","127.0.0.1:"+port,"--rom",root.resolve("build/teaching.gbc").toString(),"--fixture-ready");
                builder.environment().put("PYTHONPATH",root.resolve("python").toString());
                builder.redirectErrorStream(true);builder.redirectOutput(evidence(root).resolve(mode+"-agent.log").toFile());
                Process process=builder.start();TraceRmiConnection connection=null;
                try {
                    connection=acceptor.accept();trace=connection.waitForTrace(15000);waitCapture(0);
                    String session=String.valueOf(attr("Machine","Session"));
                    long savedSnap=snap();
                    connection.getMethods().get("save_trace").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
                    var file=trace.getDomainFile();
                    if(mode.equals("replacement")) {
                        require(!session.equals(formerSession),"replacement target has a new session identity");
                        int count=object("Machine.Breakpoints").getElements(Lifespan.at(snap())).size();
                        var request=new HashMap<String,Object>();request.put("process",object("Machine"));request.put("region","wram");
                        request.put("bank",1L);request.put("offset",0x34L);request.put("length",1L);
                        request.put("expected_session",formerSession);request.put("expected_epoch",attr("Machine","Epoch"));
                        request.put("expected_capture",attr("Machine","Capture"));
                        try {
                            connection.getMethods().get("profile_watch").invokeAsync(request).get(5,TimeUnit.SECONDS);
                            throw new AssertionError("Replacement accepted former target context");
                        }catch(ExecutionException expected){require(expected.getCause().getMessage().contains("Stale"),"real replacement target rejects former-session action");}
                        require(object("Machine.Breakpoints").getElements(Lifespan.at(snap())).size()==count,"former-session request creates no replacement breakpoint");
                        connection.getMethods().get("kill").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
                    }else if(mode.equals("disconnect")) {
                        formerSession=session;
                        connection.close();
                    }else {
                        formerSession=session;
                        process.destroyForcibly();
                    }
                    awaitClosed(connection);
                    require(process.waitFor(5,TimeUnit.SECONDS),mode+" leaves no owned agent process running");
                    var reopened=(Trace)file.getReadOnlyDomainObject(RealTraceTest.class,-1,TaskMonitor.DUMMY);
                    try {
                        ByteBuffer value=ByteBuffer.allocate(1);
                        reopened.getMemoryManager().getBytes(savedSnap,reopened.getBaseAddressFactory().getDefaultAddressSpace().getAddress(0x402a),value);
                        require((value.array()[0]&255)==0x11,mode+" preserves saved raw capture bytes after target loss");
                        var machine=reopened.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
                        require(session.equals(machine.getValue(savedSnap,"Session").getValue()),mode+" preserves historical source identity");
                        require(BankMappings.isReady(machine,savedSnap),mode+" preserves completed historical mappings");
                    }finally{reopened.release(RealTraceTest.class);}
                }finally {
                    if(connection!=null)connection.close();
                    if(process.isAlive()){process.destroyForcibly();process.waitFor(5,TimeUnit.SECONDS);}
                    if(!acceptor.isClosed())acceptor.cancel();
                    Swing.runNow(()->tool.getService(DebuggerTraceManagerService.class).activateTrace(null));
                }
            }
        }finally {
            trace=previous;
            Swing.runNow(()->tool.getService(DebuggerTraceManagerService.class).activateTrace(previous));
        }
    }
    public static void main(String[] args) {
        Thread.setDefaultUncaughtExceptionHandler((thread,error)->{asyncErrors.add(error);error.printStackTrace();});
        try {runTest(args);}catch(Throwable error){error.printStackTrace();System.exit(1);}
    }
    public static void runTest(String[] args) throws Exception {
        Path root=Path.of(args[0]).toRealPath();
        boolean studyExpected=Arrays.asList(args).contains("--with-study");
        try{Class.forName("ghibw3.StudyPlugin");require(studyExpected,"optional study classes are present only in the selected consumer gate");}
        catch(ClassNotFoundException expected){require(!studyExpected,"generic classpath has no GhiBW3");}
        Application.initializeApplication(new GhidraApplicationLayout(new File(System.getenv().getOrDefault("GHIDRA_INSTALL_DIR",root.resolve(".deps/ghidra_11.3.1_PUBLIC").toString()))),testConfiguration());
        String projectName="TraceTest-"+System.currentTimeMillis();
        Project project=new Manager().createProject(new ProjectLocator(root.resolve("build/projects").toString(),projectName),null,false);
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
        MappingContractTest.run(staticProgram);
        BankMappings mappings=new BankMappings(staticProgram);
        require(staticProgram.getAddressFactory().getAddress("rom1:4029")!=null,"single-colon overlay mapping address resolves in static program");
        final GhidraTool[] holder=new GhidraTool[1];
        final Throwable[] startupError=new Throwable[1];
        Swing.runNow(()->{
            try {
                GhidraTool tool=new GhidraTool(project,"GBC Debugger Integration");holder[0]=tool;
                tool.addPlugins(List.of("ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin","ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin","ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersPlugin","ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPlugin","ghidra.app.plugin.core.debug.gui.time.DebuggerTimePlugin","ghidra.app.plugin.core.debug.gui.model.DebuggerModelPlugin","ghigbc.GbcPlugin","ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLauncherServicePlugin"));
                if(studyExpected)tool.addPlugins(List.of("ghibw3.StudyPlugin"));
                tool.getService(ProgramManager.class).openProgram(staticProgram);
                tool.setVisible(true);
            }catch(Exception e){startupError[0]=e;}
        });
        if(startupError[0]!=null)throw new AssertionError("Debugger plugin initialization failed",startupError[0]);
        GhidraTool tool=holder[0];
        require(tool.getManagedPlugins().stream().anyMatch(p->p instanceof ghigbc.GbcPlugin)&&tool.getService(ghigbc.GbcActionService.class)!=null,"generic plugin initializes with its action service");
        if(studyExpected)require(tool.getManagedPlugins().stream().anyMatch(p->p.getClass().getName().equals("ghibw3.StudyPlugin")),"optional study plugin links to the integrated action/mapping services");
        var acceptor=tool.getService(TraceRmiService.class).acceptOne(new InetSocketAddress("127.0.0.1",0));acceptor.setTimeout(15000);
        int port=((InetSocketAddress)acceptor.getAddress()).getPort();
        ProcessBuilder pb=new ProcessBuilder(System.getenv().getOrDefault("GBC_PYTHON",root.resolve(".venv/bin/python").toString()),"-m","ghigbc.agent","--connect","127.0.0.1:"+port,"--rom",root.resolve("build/teaching.gbc").toString(),"--fixture-ready","--experiment");
        pb.environment().put("PYTHONPATH",root.resolve("python").toString());pb.redirectErrorStream(true);pb.redirectOutput(evidence(root).resolve("real-agent.log").toFile());
        Process agent=pb.start();
        try {
            TraceRmiConnection conn=acceptor.accept();trace=conn.waitForTrace(15000);waitCapture(0);
            var methods=conn.getMethods();
            String expectedProfile=Arrays.asList(args).contains("--synthetic-profile")?"synthetic-counter":"generic";
            require(expectedProfile.equals(attr("Machine","Profile")),"selected test profile is recognized without game-specific classes");
            if(Arrays.asList(args).contains("--failing-profile"))require(String.valueOf(attr("Machine","ProfileError")).contains("deliberate profile failure"),"failing provider reports its error while the generic target remains usable");
            if(expectedProfile.equals("synthetic-counter"))require(((Number)attr("Machine","ProfileRecordCount")).intValue()==1,"synthetic profile publishes its one bounded field");
            require("sameboy".equals(attr("Machine","Backend"))&&"CGB-E".equals(attr("Machine","Model")),"capture publishes the selected backend and actual hardware model");
            require(((Number)attr("Machine","TicksPerSecond")).longValue()==8388608&&attr("Machine","Ticks").equals(attr("Machine","Ticks8MHz")),"generic timebase agrees with the compatible legacy tick field");
            require(object("Machine.ProfileFields")!=null,"generic typed profile container is discoverable");
            for(String stale:List.of("session","epoch","capture")) {
                var request=new HashMap<String,Object>();request.put("process",object("Machine"));request.put("region","wram");request.put("bank",1L);request.put("offset",0x34L);request.put("length",1L);
                request.put("expected_session",stale.equals("session")?"different-session":attr("Machine","Session"));
                request.put("expected_epoch",((Number)attr("Machine","Epoch")).longValue()+(stale.equals("epoch")?1:0));
                request.put("expected_capture",((Number)attr("Machine","Capture")).longValue()+(stale.equals("capture")?1:0));
                int before=object("Machine.Breakpoints").getElements(Lifespan.at(snap())).size();
                try{methods.get("profile_watch").invokeAsync(request).get(15,TimeUnit.SECONDS);throw new AssertionError("Accepted stale "+stale);}
                catch(ExecutionException expected){require(expected.getCause().getMessage().contains("Stale action"),"real remote rejects stale "+stale);}
                require(before==object("Machine.Breakpoints").getElements(Lifespan.at(snap())).size(),"stale watch creates no breakpoint");
            }

            // Reserve a user-owned physical range before automatic mapping; it must survive.
            var userFrom=trace.getBaseAddressFactory().getAddressSpace("rom3").getAddress(0x4000);
            try(var tx=trace.openTransaction("User mapping fixture")) {
                trace.getStaticMappingManager().add(new ghidra.program.model.address.AddressRangeImpl(userFrom,0x10),Lifespan.at(snap()+1),ghidra.app.plugin.core.debug.utils.ProgramURLUtils.getUrlFromProgram(staticProgram),"ram:100");
            }
            mappings.apply(trace,snap());
            require(trace.getStaticMappingManager().findContaining(userFrom,snap()+1).getStaticAddress().equals("ram:100"),"user-owned conflicting mapping is preserved");
            require(object("Machine").getValue(snap(),"StaticMappingEnvelope").getValue() instanceof byte[],"versioned immutable static envelope published to trace");
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
            mappings.apply(trace,snap());
            require(trace.getStaticMappingManager().findContaining(userFrom,snap()).getStaticAddress().equals("ram:100"),"automatic mapping leaves user destination intact");
            var thread=trace.getThreadManager().getAllThreads().iterator().next();
            var regs=trace.getMemoryManager().getMemoryRegisterSpace(thread,0,false);
            require(regs.getValue(snap(),trace.getBaseLanguage().getRegister("PC")).getUnsignedValue().intValue()==0x402b,"native Step updates real Ghidra PC");
            long followDeadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
            while(tool.getService(DebuggerTraceManagerService.class).getCurrentSnap()!=snap()&&System.nanoTime()<followDeadline)Thread.sleep(10);
            System.out.println("FOLLOW_STATE snap="+tool.getService(DebuggerTraceManagerService.class).getCurrentSnap()+" latest="+snap()+" mode="+(tool.getService(DebuggerControlService.class)==null?"absent":tool.getService(DebuggerControlService.class).getCurrentMode(trace)));
            require(tool.getService(DebuggerTraceManagerService.class).getCurrentSnap()==snap(),"native target follows the completed stop without reactivating its sole thread");
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
            var registerEdit=latestEdit();long registerEditSnap=snap();editPaths.add(registerEdit.getCanonicalPath());
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
            var memoryEdit=latestEdit();long memoryEditSnap=snap();editPaths.add(memoryEdit.getCanonicalPath());
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
            var fixture=Map.of("schema",1,"directory",root.resolve("build/projects").toString(),"project",projectName,
                "trace",traceFile.getPathname(),"snapshot",first,"backend","sameboy","profile",expectedProfile,
                "profileFields",expectedProfile.equals("synthetic-counter")?1:0,"requireEdits",true);
            Files.writeString(evidence(root).resolve("trace-fixture.json"),new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(fixture));
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
                require("sameboy".equals(reopenedMachine.getValue(registerRestoreSnap,"Backend").getValue()),"reopened history retains captured backend identity");
                require(registerRecovery.toString().equals(reopenedMachine.getValue(registerRestoreSnap,"ParentCheckpoint").getValue()),"reopened restore retains its original checkpoint link");
                require(reopenedMachine.getValue(registerRestoreSnap,"ParentCheckpointSHA256").getValue().toString().length()==64,"reopened restore retains the checkpoint state fingerprint");
            }finally{reopened.release(RealTraceTest.class);}
            require(staticProgram.getSymbolTable().getPrimarySymbol(staticBankTwo).getName().equals("StudentBankTwo"),"student annotations preserved");
            if(Arrays.asList(args).contains("--failure-lifecycle"))failureLifecycle(root,tool);
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
                if(studyExpected)require("generic".equals(attr("Machine","Profile")),"installed game profile rejects a nonmatching ROM while generic controls remain usable");
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
                    Swing.runNow(()->tool.getService(DebuggerTraceManagerService.class).activateTrace(null));
                    launched.connection().getMethods().get("kill").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
                    launched.connection().waitClosed();
                    Swing.runNow(()->{});
                }
                trace=previousTrace;
                Swing.runNow(()->tool.getService(DebuggerTraceManagerService.class).activateTrace(previousTrace));
            }
            if(Arrays.asList(args).contains("--keep-open")) {
                methods.get("restore").invokeAsync(Map.of("process",object("Machine"),"path",checkpointDir.toString())).get(15,TimeUnit.SECONDS);
                Thread.sleep(120000);
            }
            Swing.runNow(()->{tool.setVisible(false);tool.getService(DebuggerTraceManagerService.class).activateTrace(null);});
            methods.get("kill").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
            conn.waitClosed();
            require(agent.waitFor(3,TimeUnit.SECONDS),"owned sidecar exits after structured termination");
            require("TERMINATED".equals(String.valueOf(attr("Machine","_state"))),"trace retains truthful terminated state");
            conn.close();
        } finally {
            agent.destroy();if(!agent.waitFor(3,TimeUnit.SECONDS))agent.destroyForcibly();
            Swing.runNow(()->{tool.setVisible(false);tool.getService(DebuggerTraceManagerService.class).activateTrace(null);});
            Swing.runNow(()->{});
            Swing.runNow(()->tool.dispose());imported.close();project.close();
        }
        Swing.runNow(()->{});
        require(asyncErrors.isEmpty(),"no asynchronous JVM errors through cleanup");
        System.out.println("REAL_TRACE_TEST_PASSED");
        System.exit(0);
    }
}
