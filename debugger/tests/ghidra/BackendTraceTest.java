import java.io.File;
import java.net.InetSocketAddress;
import java.nio.file.*;
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
    public static void main(String[] args) {
        try {runBackends(args);System.exit(0);}
        catch(Throwable error){error.printStackTrace();System.exit(1);}
    }
    static void runBackends(String[] args)throws Exception {
        Path root=Path.of(args[0]).toRealPath();
        Application.initializeApplication(new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),testConfiguration());
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
        try {
            for(String backend:Arrays.stream(Arrays.copyOfRange(args,1,args.length)).filter(arg->!arg.startsWith("--")).toList()) {
                var acceptor=tool.getService(TraceRmiService.class).acceptOne(new InetSocketAddress("127.0.0.1",0));acceptor.setTimeout(15000);
                var command=new ArrayList<String>();command.add(System.getenv().getOrDefault("GBC_PYTHON",root.resolve(".venv12/bin/python").toString()));
                if("true".equals(System.getenv("GBC_TEST_STATIC_RETRY")))command.add(root.resolve("tests/static_retry_agent.py").toString());
                else command.addAll(List.of("-m","ghigbc.agent"));
                command.addAll(List.of("--backend",backend,"--rom",root.resolve("build/teaching.gbc").toString(),"--connect","127.0.0.1:"+((InetSocketAddress)acceptor.getAddress()).getPort(),"--fixture-ready"));
                var builder=new ProcessBuilder(command);
                builder.environment().put("PYTHONPATH",root.resolve("python").toString());
                builder.redirectErrorStream(true);builder.redirectOutput(evidence(root).resolve(backend+"-backend-agent.log").toFile());
                Process process=builder.start();
                try(var connection=acceptor.accept()) {
                    trace=connection.waitForTrace(15000);waitCapture(0);
                    require(backend.equals(attr("Machine","Backend")),"actual selected backend identity: "+backend);
                    require(String.valueOf(attr("Machine","BootHash")).matches("[0-9a-f]{64}"),"loaded boot/no-BIOS identity is captured: "+backend);
                    require(((Number)attr("Machine","ROMX")).intValue()==1&&read(snap(),"ram",0x402a)==0x11,"first physical bank capture: "+backend);
                    var methods=connection.getMethods();
                    String capabilities=String.valueOf(attr("Machine","Capabilities"));
                    for(var optional:Map.of("step_over","step-over","step_out","step-out","checkpoint","checkpoint","break_write","physical-watch-v1","experiment_register","register-edit").entrySet())
                        require((methods.get(optional.getKey())!=null)==capabilities.contains("\""+optional.getValue()+"\""),"negotiated optional action matches capability: "+optional.getKey());
                    methods.get("bank_breakpoint").invokeAsync(Map.of("process",object("Machine"),"region","rom","bank",2L,"offset",0x29L,"kinds",1L)).get(15,TimeUnit.SECONDS);
                    long before=((Number)attr("Machine","Capture")).longValue();
                    methods.get("resume").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);waitCapture(before);
                    require(((Number)attr("Machine","ROMX")).intValue()==2&&read(snap(),"ram",0x402a)==0x22,"same CPU PC stops in second physical bank: "+backend);
                    for(int i=0;i<5;i++) {
                        before=((Number)attr("Machine","Capture")).longValue();
                        methods.get("step_into").invokeAsync(Map.of("thread",object("Machine.Threads[0]"))).get(15,TimeUnit.SECONDS);waitCapture(before);
                    }
                    methods.get("save_trace").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
                    require(BankMappings.isReady(object("Machine"),snap()),"shared static mappings complete: "+backend);
                    require(attr("Machine","BoundStaticGeneration").equals(attr("Machine","StaticMappingGeneration")),"automatic static upload recovers and binds this unchanged epoch: "+backend);
                    if(Arrays.asList(args).contains("--failure-lifecycle"))failureLifecycle(root,tool,backend);
                    if(Arrays.asList(args).contains("--soak"))captureOnlySoak(root,connection,process,tool,backend);
                    long saved=snap();var file=trace.getDomainFile();
                    methods.get("kill").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
                    awaitClosed(connection);require(process.waitFor(5,TimeUnit.SECONDS),"owned backend process exits: "+backend);
                    var reopened=(Trace)file.getReadOnlyDomainObject(BackendTraceTest.class,-1,TaskMonitor.DUMMY);
                    try {
                        var machine=reopened.getObjectManager().getObjectByCanonicalPath(ghidra.trace.model.target.path.KeyPath.parse("Machine"));
                        require(backend.equals(machine.getValue(saved,"Backend").getValue())&&BankMappings.isReady(machine,saved),"backend-neutral saved observation reopens: "+backend);
                    }finally{reopened.release(BackendTraceTest.class);}
                }finally{
                    if(process.isAlive()){process.destroyForcibly();process.waitFor(5,TimeUnit.SECONDS);}
                    if(!acceptor.isClosed())acceptor.cancel();
                    Swing.runNow(()->tool.getService(DebuggerTraceManagerService.class).activateTrace(null));
                }
            }
        }finally{
            Swing.runNow(tool::dispose);imported.close();project.close();
        }
        System.out.println("BACKEND_TRACE_CONTRACT_PASSED");
    }
}
