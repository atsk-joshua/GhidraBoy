import java.io.File;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;
import com.google.gson.*;
import ghidra.trace.model.target.path.KeyPath;
import ghigbc.ObservationReport;
import java.util.*;
import java.util.concurrent.TimeUnit;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.app.services.*;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.app.util.importer.*;
import ghidra.trace.model.Trace;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;
import ghigbc.BankMappings;

/** Same real Trace RMI / mapping / saved-history contract for every selected engine. */
public final class BackendTraceTest extends RealTraceTest {
    static void captureOnlySoak(Path root,TraceRmiConnection connection,Process process,GhidraTool tool,String backend)throws Exception {
        if(connection.getMethods().get("checkpoint")!=null)throw new IllegalArgumentException("Use the checkpoint/restore soak for checkpoint-capable backends");
        long started=System.nanoTime();int cycles=0;var samples=new ArrayList<Map<String,Object>>();
        while((System.nanoTime()-started)/1e9<1800||cycles<100) {
            connection.getMethods().get("resume").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
            Thread.sleep(15000);long prior=((Number)attr("Machine","Capture")).longValue();long pause=System.nanoTime();
            connection.getMethods().get("interrupt").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);awaitPublished(prior);
            double pauseMs=(System.nanoTime()-pause)/1e6;require(pauseMs<2000,"capture-only soak pause stays within original native-host budget");
            for(int step=0;step<5;step++)connection.getMethods().get("step_into").invokeAsync(Map.of("thread",object("Machine.Threads[0]"))).get(15,TimeUnit.SECONDS);
            connection.getMethods().get("save_trace").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
            cycles++;if(cycles==30||cycles==60)failureLifecycle(root,tool,backend);
            var sample=new LinkedHashMap<String,Object>();sample.put("cycle",cycles);sample.put("seconds",(System.nanoTime()-started)/1e9);sample.put("capture",attr("Machine","Capture"));sample.put("snapshot",snap());sample.put("pause_ms",pauseMs);
            sample.put("agent_rss_kib",rssKiB(process.pid()));sample.put("ghidra_rss_kib",rssKiB(ProcessHandle.current().pid()));sample.put("agent_threads",countThreads(process.pid()));sample.put("ghidra_threads",java.lang.management.ManagementFactory.getThreadMXBean().getThreadCount());
            sample.put("agent_handles",countHandles(process.pid()));sample.put("ghidra_handles",countHandles(ProcessHandle.current().pid()));sample.put("trace_bytes",trace.getDomainFile().length());sample.put("dropped",attr("Machine","Dropped"));samples.add(sample);
            var report=Map.of("schema",1,"status","RUNNING","requested_seconds",1800,"cycles",cycles,"samples",samples,"backend",backend,"scope","Real RMI capture-only backend; no checkpoint capability. Separate crash/disconnect/replacement targets at cycles 30/60.");
            Files.writeString(evidence(root).resolve("backend-soak.json"),new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(report));
            System.out.println("BACKEND_SOAK_PROGRESS "+backend+" cycles="+cycles);System.out.flush();
        }
        Files.writeString(evidence(root).resolve("backend-soak.json"),new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(Map.of("schema",1,"status","COMPLETED_MEASUREMENTS","requested_seconds",1800,"cycles",cycles,"samples",samples,"backend",backend,"scope","No checkpoint capability; assessed against predeclared native-host resource budgets.")));
    }
    // A copied runtime makes the production ROOT manifest discovery independent of the
    // developer's install. Native libraries/boot fixtures remain the selected real artifacts.
    static Path profileRuntime(Path root,Path work,String backend,String mode)throws Exception {
        Path runtime=Files.createDirectories(work.resolve(backend+"-"+mode));
        try(var paths=Files.walk(root.resolve("python"))) {
            for(Path source:paths.filter(p->!p.toString().contains("__pycache__")).toList()) {
                Path target=runtime.resolve("python").resolve(root.resolve("python").relativize(source));
                if(Files.isDirectory(source))Files.createDirectories(target);else Files.copy(source,target);
            }
        }
        Files.createDirectories(runtime.resolve("build"));
        try(var paths=Files.list(root.resolve("build"))) {
            for(Path source:paths.filter(p->Files.isRegularFile(p)&&(p.getFileName().toString().startsWith("libghigbc")||p.getFileName().toString().equals("teaching.gbc"))).toList())
                Files.copy(source,runtime.resolve("build").resolve(source.getFileName()));
        }
        for(String name:List.of("backends",".deps"))if(Files.exists(root.resolve(name)))Files.createSymbolicLink(runtime.resolve(name),root.resolve(name));
        if(Files.exists(root.resolve("runtime-backends.json")))Files.copy(root.resolve("runtime-backends.json"),runtime.resolve("runtime-backends.json"));
        Files.copy(root.resolve("tests/shared_profile_fixture.py"),runtime.resolve("python/shared_profile_fixture.py"));
        if(!mode.equals("absent"))Files.writeString(runtime.resolve("profiles.json"),"{\"schema\":1,\"modules\":[\""+(mode.equals("missing")?"deliberately_missing_profile": "shared_profile_fixture")+"\"]}");
        return runtime;
    }
    static Object captured(Trace target,long at,String key) {
        return ObservationReport.value(target.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine")),at,key);
    }
    static void profileHistory(Trace target,long at,String backend,String mode,int bank)throws Exception {
        require(backend.equals(captured(target,at,"Backend")),"historical backend identity "+backend+"/"+mode);
        String expected=mode.equals("synthetic")?"shared-synthetic-counter":"generic";
        require(expected.equals(captured(target,at,"Profile")),"installed profile selection "+backend+"/"+mode);
        int count=((Number)captured(target,at,"ProfileRecordCount")).intValue();
        require(count==(mode.equals("synthetic")?1:0),"exact bounded profile record count "+backend+"/"+mode);
        String error=String.valueOf(captured(target,at,"ProfileError"));
        require(mode.equals("failing")?error.contains("deliberate shared profile failure"):mode.equals("missing")?error.contains("deliberately_missing_profile"):error.isEmpty(),"profile error contract "+backend+"/"+mode);
        var report=ObservationReport.capture(target,at,new ObservationReport.Selection("cpu",0,0x402a,1)).getAsJsonObject("observation");
        require(report.getAsJsonObject("memory").getAsJsonArray("bytes").get(0).getAsInt()==bank*0x11,"selected historical CPU bytes "+backend+"/"+mode);
        var machine=target.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
        require(BankMappings.isReady(machine,at),"selected historical mapping complete "+backend+"/"+mode);
        var mapping=target.getStaticMappingManager().findContaining(target.getBaseAddressFactory().getDefaultAddressSpace().getAddress(0x4029),at);
        require(mapping!=null&&mapping.getStaticAddress().contains("rom"+bank+":"),"selected historical mapping resolves bank "+bank+" "+backend+"/"+mode);
        if(count==1) {
            var batch=target.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine.ProfileFields[0]"));
            require(((Number)batch.getValue(at,"Snapshot").getValue()).longValue()==at,"field batch belongs to selected snapshot");
            var fields=JsonParser.parseString(new String((byte[])batch.getValue(at,"Data").getValue(),StandardCharsets.UTF_8)).getAsJsonArray();
            require(fields.size()==1,"persisted field batch has exactly one record");var field=fields.get(0).getAsJsonObject();var source=field.getAsJsonObject("source");
            require(field.get("name").getAsString().equals("counter")&&field.get("kind").getAsString().equals("integer")&&field.get("validity").getAsString().equals("observed")&&field.get("profile").getAsString().equals(expected)&&field.get("version").getAsString().equals("1.0.0"),"typed field identity and validity survive capture");
            require(field.get("session").getAsString().equals(captured(target,at,"Session"))&&field.get("epoch").getAsLong()==((Number)captured(target,at,"Epoch")).longValue()&&field.get("capture").getAsLong()==((Number)captured(target,at,"Capture")).longValue(),"field session epoch and capture match selected observation");
            require(source.get("region").getAsString().equals("wram")&&source.get("bank").getAsInt()==1&&source.get("offset").getAsInt()==0x34&&source.get("length").getAsInt()==1,"field records exact physical raw provenance");
            var raw=ObservationReport.capture(target,at,new ObservationReport.Selection("wram",1,0x34,1)).getAsJsonObject("observation").getAsJsonObject("memory").getAsJsonArray("bytes").get(0).getAsInt();
            require(field.get("value").getAsInt()==raw,"decoded counter equals captured physical raw byte");
        }
    }
    static void selectedHistory(GhidraTool tool,TraceRmiConnection connection,long first,String backend,String mode)throws Exception {
        long current=snap(),capture=((Number)attr("Machine","Capture")).longValue();
        var manager=tool.getService(DebuggerTraceManagerService.class);
        var control=tool.getService(DebuggerControlService.class);var previousMode=control.getCurrentMode(trace);
        Swing.runNow(()->{control.setCurrentMode(trace,ghidra.debug.api.control.ControlMode.RO_TRACE);manager.activateTrace(trace);manager.activateSnap(first);});
        require(manager.getCurrentSnap()==first&&first<current,"real debugger selects historical snapshot "+backend+"/"+mode);
        profileHistory(trace,manager.getCurrentSnap(),backend,mode,1);profileHistory(trace,current,backend,mode,2);
        require(snap()==current&&((Number)attr("Machine","Capture")).longValue()==capture,"historical selection preserves current target capture");
        var request=new HashMap<String,Object>();request.put("process",object("Machine"));request.put("region","rom");request.put("bank",2L);request.put("offset",0x29L);request.put("kinds",1L);
        request.put("expected_session",captured(trace,first,"Session"));request.put("expected_epoch",((Number)captured(trace,first,"Epoch")).longValue());request.put("expected_capture",((Number)captured(trace,first,"Capture")).longValue());
        try{connection.getMethods().get("bank_breakpoint").invokeAsync(request).get(15,TimeUnit.SECONDS);throw new AssertionError("Accepted historical selected capture");}
        catch(ExecutionException expected){require(expected.getCause().getMessage().contains("Stale action"),"real target rejects historical selected-capture action "+backend+"/"+mode);}
        require(snap()==current&&((Number)attr("Machine","Capture")).longValue()==capture,"rejected historical action leaves raw current/history usable");
        var watch=connection.getMethods().get("profile_watch");
        if(watch!=null) {
            var selectedWatch=new HashMap<>(request);selectedWatch.remove("kinds");selectedWatch.put("region","wram");selectedWatch.put("bank",1L);selectedWatch.put("offset",0x34L);selectedWatch.put("length",1L);
            try{watch.invokeAsync(selectedWatch).get(15,TimeUnit.SECONDS);throw new AssertionError("Accepted historical profile watch");}
            catch(ExecutionException expected){require(expected.getCause().getMessage().contains("Stale action"),"historical profile watch explicitly rejects stale capture "+backend);}
        }else {
            require(!String.valueOf(attr("Machine","Capabilities")).contains("physical-watch-v1"),"profile watch unavailable exactly when capability is absent "+backend);
            try{connection.getMethods().get("bank_breakpoint").invokeAsync(Map.of("process",object("Machine"),"region","wram","bank",1L,"offset",0x34L,"kinds",4L)).get(15,TimeUnit.SECONDS);throw new AssertionError("Accepted unsupported physical watch");}
            catch(ExecutionException expected){require(expected.getCause().getMessage().contains("physical-watch-v1"),"unsupported physical watch returns an explicit capability error "+backend);}
        }
        require(snap()==current&&((Number)attr("Machine","Capture")).longValue()==capture,"watch rejection leaves current capture and history unchanged");
        Swing.runNow(()->{manager.activateSnap(current);control.setCurrentMode(trace,previousMode);});
    }
    static void reopenProfiles(String[] args)throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),new ghidra.framework.HeadlessGhidraApplicationConfiguration());
        var fixture=JsonParser.parseString(Files.readString(Path.of(args[1]))).getAsJsonObject();
        var project=new Manager().openProject(new ProjectLocator(fixture.get("directory").getAsString(),"BackendContract"),false,false);
        try {
            for(var item:fixture.getAsJsonArray("traces")) {
                var row=item.getAsJsonObject();Path runtime=Path.of(row.get("runtime").getAsString());
                require(!Files.exists(runtime.resolve("profiles.json"))&&!Files.exists(runtime.resolve("python/shared_profile_fixture.py")),"provider manifest and code absent before separate JVM reopen");
                var file=project.getProjectData().getFile(row.get("trace").getAsString());
                var saved=(Trace)file.getReadOnlyDomainObject(BackendTraceTest.class,-1,TaskMonitor.DUMMY);
                try{profileHistory(saved,row.get("first").getAsLong(),row.get("backend").getAsString(),row.get("mode").getAsString(),1);profileHistory(saved,row.get("last").getAsLong(),row.get("backend").getAsString(),row.get("mode").getAsString(),2);}
                finally{saved.release(BackendTraceTest.class);}
            }
        }finally{project.close();}
        assertNoAsyncErrors();System.out.println("PROVIDER_FREE_BACKEND_HISTORY_PASSED");
    }
    public static void main(String[] args) {
        installAsyncErrorCollector();
        try {if(args[0].equals("--reopen"))reopenProfiles(args);else runBackends(args);System.exit(0);}
        catch(Throwable error){error.printStackTrace();System.exit(1);}
    }
    static void runBackends(String[] args)throws Exception {
        Path root=Path.of(args[0]).toRealPath();
        Application.initializeApplication(new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),testConfiguration());
        injectAsyncErrorIfRequested(args);
        Path work=Files.createTempDirectory(root.resolve("build"),"backend-rmi-");
        var project=new Manager().createProject(new ProjectLocator(work.toString(),"BackendContract"),null,false);
        var imported=AutoImporter.importByUsingBestGuess(root.resolve("build/teaching.gbc").toFile(),project,"/",BackendTraceTest.class,new MessageLog(),TaskMonitor.DUMMY);
        imported.save(TaskMonitor.DUMMY);var program=imported.getPrimaryDomainObject();
        final GhidraTool[] holder=new GhidraTool[1];
        Swing.runNow(()->{
            try {
                var tool=new GhidraTool(project,"Backend contract");holder[0]=tool;
                tool.addPlugins(List.of("ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin","ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin","ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersPlugin","ghigbc.GbcPlugin"));
                tool.getService(ProgramManager.class).openProgram(program);tool.setVisible(true);
            }catch(Exception error){throw new RuntimeException(error);}
        });
        var tool=holder[0];
        boolean profiles=Arrays.asList(args).contains("--profile-contract");
        var history=new ArrayList<Map<String,Object>>();
        try {
            for(String backend:Arrays.stream(Arrays.copyOfRange(args,1,args.length)).filter(arg->!arg.startsWith("--")).toList()) {
              for(String mode:profiles?List.of("synthetic","absent","missing","failing","wrong-revision"):List.of("baseline")) {
                Path runtime=profiles?profileRuntime(root,work,backend,mode):root;
                var acceptor=tool.getService(TraceRmiService.class).acceptOne(new InetSocketAddress("127.0.0.1",0));acceptor.setTimeout(15000);
                var command=new ArrayList<String>();command.add(System.getenv().getOrDefault("GBC_PYTHON",root.resolve(".venv12/bin/python").toString()));
                if("true".equals(System.getenv("GBC_TEST_STATIC_RETRY")))command.add(root.resolve("tests/static_retry_agent.py").toString());
                else command.addAll(List.of("-m","ghigbc.agent"));
                command.addAll(List.of("--backend",backend,"--rom",root.resolve("build/teaching.gbc").toString(),"--connect","127.0.0.1:"+((InetSocketAddress)acceptor.getAddress()).getPort(),"--fixture-ready"));
                var builder=new ProcessBuilder(command);
                builder.environment().put("PYTHONPATH",runtime.resolve("python").toString());
                if(profiles){builder.environment().put("GBC_SHARED_PROFILE_MODE",mode);builder.environment().put("PYTHONDONTWRITEBYTECODE","1");builder.environment().put("HOME",Files.createDirectories(runtime.resolve("home")).toString());}
                builder.redirectErrorStream(true);builder.redirectOutput(evidence(root).resolve((profiles?backend+"-"+mode:backend)+"-backend-agent.log").toFile());
                Process process=builder.start();
                System.out.println("OWNED_PROCESS backend="+backend+" phase="+mode+" agent="+process.pid());
                try(var connection=acceptor.accept()) {
                    trace=connection.waitForTrace(15000);waitCapture(0);
                    require(backend.equals(attr("Machine","Backend")),"actual selected backend identity: "+backend);
                    require(String.valueOf(attr("Machine","BootHash")).matches("[0-9a-f]{64}"),"loaded boot/no-BIOS identity is captured: "+backend);
                    require(((Number)attr("Machine","ROMX")).intValue()==1&&read(snap(),"ram",0x402a)==0x11,"first physical bank capture: "+backend);
                    long first=snap();
                    var methods=connection.getMethods();
                    if(profiles){methods.get("save_trace").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);profileHistory(trace,first,backend,mode,1);}
                    String capabilities=String.valueOf(attr("Machine","Capabilities"));
                    for(var optional:Map.of("step_over","step-over","step_out","step-out","checkpoint","checkpoint","break_write","physical-watch-v1","experiment_register","register-edit").entrySet())
                        require((methods.get(optional.getKey())!=null)==capabilities.contains("\""+optional.getValue()+"\""),"negotiated optional action matches capability: "+optional.getKey());
                    methods.get("bank_breakpoint").invokeAsync(Map.of("process",object("Machine"),"region","rom","bank",2L,"offset",0x29L,"kinds",1L)).get(15,TimeUnit.SECONDS);
                    long before=((Number)attr("Machine","Capture")).longValue();
                    methods.get("resume").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);waitCapture(before);
                    require(((Number)attr("Machine","ROMX")).intValue()==2&&read(snap(),"ram",0x402a)==0x22,"same CPU PC stops in second physical bank: "+backend);
                    if(profiles){methods.get("save_trace").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);selectedHistory(tool,connection,first,backend,mode);}
                    for(int i=0;i<5;i++) {
                        before=((Number)attr("Machine","Capture")).longValue();
                        methods.get("step_into").invokeAsync(Map.of("thread",object("Machine.Threads[0]"))).get(15,TimeUnit.SECONDS);waitCapture(before);
                    }
                    methods.get("save_trace").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
                    require(BankMappings.isReady(object("Machine"),snap()),"shared static mappings complete: "+backend);
                    require(attr("Machine","BoundStaticGeneration").equals(attr("Machine","StaticMappingGeneration")),"automatic static upload recovers and binds this unchanged epoch: "+backend);
                    if(profiles)selectedHistory(tool,connection,first,backend,mode);
                    if(Arrays.asList(args).contains("--failure-lifecycle"))failureLifecycle(root,tool,backend);
                    if(Arrays.asList(args).contains("--soak"))captureOnlySoak(root,connection,process,tool,backend);
                    long saved=snap();var file=trace.getDomainFile();
                    if(profiles)history.add(Map.of("trace",file.getPathname(),"first",first,"last",saved,"backend",backend,"mode",mode,"runtime",runtime.toString()));
                    methods.get("kill").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
                    awaitClosed(connection);require(process.waitFor(5,TimeUnit.SECONDS),"owned backend process exits: "+backend);
                    var reopened=(Trace)file.getReadOnlyDomainObject(BackendTraceTest.class,-1,TaskMonitor.DUMMY);
                    try {
                        var machine=reopened.getObjectManager().getObjectByCanonicalPath(ghidra.trace.model.target.path.KeyPath.parse("Machine"));
                        require(backend.equals(machine.getValue(saved,"Backend").getValue())&&BankMappings.isReady(machine,saved),"backend-neutral saved observation reopens: "+backend);
                        if(profiles){profileHistory(reopened,first,backend,mode,1);profileHistory(reopened,saved,backend,mode,2);}
                    }finally{reopened.release(BackendTraceTest.class);}
                }finally{
                    if(process.isAlive()){process.destroyForcibly();process.waitFor(5,TimeUnit.SECONDS);}
                    if(!acceptor.isClosed())acceptor.cancel();
                    Swing.runNow(()->tool.getService(DebuggerTraceManagerService.class).activateTrace(null));
                }
              }
            }
        }finally{
            Swing.runNow(tool::dispose);imported.close();project.close();
        }
        if(profiles) {
            for(var row:history){Path runtime=Path.of((String)row.get("runtime"));Files.deleteIfExists(runtime.resolve("profiles.json"));Files.delete(runtime.resolve("python/shared_profile_fixture.py"));}
            Path fixture=evidence(root).resolve("backend-profile-history.json");Files.writeString(fixture,new GsonBuilder().setPrettyPrinting().create().toJson(Map.of("directory",work.toString(),"traces",history)));
            var child=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),"-Duser.home="+System.getProperty("user.home"),"-cp",System.getProperty("java.class.path"),"BackendTraceTest","--reopen",fixture.toString()).redirectErrorStream(true).redirectOutput(evidence(root).resolve("backend-provider-free-reopen.log").toFile()).start();
            System.out.println("OWNED_PROCESS phase=provider-free-reopen jvm="+child.pid());
            try{require(child.waitFor(60,TimeUnit.SECONDS)&&child.exitValue()==0,"provider-free separate JVM reopens all shared backend histories");}finally{if(child.isAlive()){child.destroyForcibly();child.waitFor(5,TimeUnit.SECONDS);}}
        }
        assertNoAsyncErrors();
        System.out.println("BACKEND_TRACE_CONTRACT_PASSED");
    }
}
