import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.model.*;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.project.tool.*;
import ghidra.app.services.*;
import ghidra.app.util.importer.*;
import ghidra.trace.model.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

/** Observes the real HP button against the private, previously verified battle checkpoint. */
public class HpWatchUiTest extends UiActionTest {
    public static void main(String[] args){
        root=Path.of(args[0]).toAbsolutePath();
        try{
            var output=new PrintStream(root.resolve("docs/evidence/hp-ui.log").toFile());System.setOut(output);System.setErr(output);
            Runtime.getRuntime().addShutdownHook(new Thread(()->{
                try(var log=new PrintStream(root.resolve("docs/evidence/hp-ui-shutdown.log").toFile())){
                    Thread.getAllStackTraces().forEach((thread,stack)->{if(thread.getName().equals("main")||thread.getName().startsWith("AWT-EventQueue")){
                        log.println(thread.getName());for(var frame:stack)log.println("  "+frame);
                    }});
                }catch(IOException ignored){}
            }));
            run(args);System.out.println("HP_UI_PASSED");phase("passed","HP_UI_PASSED");System.exit(0);
        }catch(Throwable failure){failure.printStackTrace();System.exit(1);}
    }
    static void run(String[] args)throws Exception{
        Path gzf=root.resolve(".local/student-copy.gzf"),rom=root.resolve("build/experiments/student12.gbc"),checkpoint=root.resolve(".local/game-evidence/class2-fire-ready");
        if(!Files.isRegularFile(gzf)||!Files.isRegularFile(rom)||!Files.isDirectory(checkpoint))
            throw new IllegalStateException("Requires the private copied GZF, matching exported ROM and verified class2-fire-ready checkpoint; see ACTUAL_BATTLE.md");
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[1])),new GhidraApplicationConfiguration());
        var pm=new Manager();var project=pm.createProject(new ProjectLocator(root.resolve("build/projects").toString(),"HPUI-"+System.currentTimeMillis()),null,false);
        var imported=AutoImporter.importByUsingBestGuess(gzf.toFile(),project,"/",HpWatchUiTest.class,new MessageLog(),TaskMonitor.DUMMY);
        imported.save(TaskMonitor.DUMMY);var program=imported.getPrimaryDomainObject();
        ghidra.program.util.GhidraProgramUtilities.markProgramNotToAskToAnalyze(program);
        GhidraTool[] holder=new GhidraTool[1];FrontEndTool[] frontend=new FrontEndTool[1];
        Swing.runNow(()->{try{
            frontend[0]=new TestFrontEnd(pm);frontend[0].setActiveProject(project);
            var resource=HpWatchUiTest.class.getClassLoader().getResourceAsStream("defaultTools/Debugger.tool");
            var xml=ghidra.util.xml.XmlUtilities.createSecureSAXBuilder(false,false).build(resource).getRootElement();
            var tool=new GhidraTool(project,new GhidraToolTemplate(xml,"Debugger.tool"));holder[0]=tool;
            tool.setToolName("GhiGBC HP UI Validation");tool.addPlugin("ghigbc.GbcPlugin");
            tool.getService(ProgramManager.class).openProgram(program);tool.setVisible(true);
        }catch(Exception e){throw new RuntimeException(e);}});
        var tool=holder[0];var acceptor=tool.getService(TraceRmiService.class).acceptOne(new InetSocketAddress("127.0.0.1",0));acceptor.setTimeout(15000);
        var python=System.getenv().getOrDefault("GBC_PYTHON",root.resolve(".venv12/bin/python").toString());
        var pb=new ProcessBuilder(python,"-m","ghigbc.agent","--connect","127.0.0.1:"+((InetSocketAddress)acceptor.getAddress()).getPort(),"--rom",rom.toString());
        pb.environment().put("PYTHONPATH",root.resolve("python").toString());pb.redirectErrorStream(true);pb.redirectOutput(root.resolve("docs/evidence/hp-ui-agent.log").toFile());
        var agent=pb.start();
        try{
            var connection=acceptor.accept();trace=connection.waitForTrace(15000);
            await(()->ghigbc.BankMappings.isReady(object("Machine"),snap()),"initial exact-profile mappings ready");
            if(!"GBW3".equals(attr("Profile"))||!"e779a6b56575a2afafb7e1e99411b23d7400a8fddbda8bd52c660b7903c3b451".equals(attr("ROMHash")))
                throw new AssertionError("Wrong battle profile/fingerprint");
            connection.getMethods().get("restore").invokeAsync(Map.of("process",object("Machine"),"path",checkpoint.toString())).get(15,TimeUnit.SECONDS);
            await(()->ghigbc.BankMappings.isReady(object("Machine"),snap())&&attr("Epoch") instanceof Number n&&n.longValue()>0,"real pre-attack checkpoint restored with complete mappings");
            var units=com.google.gson.JsonParser.parseString(new String((byte[])attr("UnitsData"),java.nio.charset.StandardCharsets.UTF_8)).getAsJsonArray();
            var apc=units.asList().stream().map(e->e.getAsJsonObject()).filter(u->u.get("slot").getAsInt()==50).findFirst().orElseThrow();
            if(!apc.get("active").getAsBoolean()||apc.get("hp").getAsInt()!=10||!apc.get("name").getAsString().equals("APC"))throw new AssertionError("Battle APC fixture differs");
            phase("hp_button","Open Window > GBC Study > Units. Select APC slot 50 (HP10), then click Watch selected HP.");
            await(()->object("Machine.Breakpoints").getElements(Lifespan.at(snap())).stream().map(v->(TraceObject)v.getValue()).anyMatch(o->
                "wram".equals(value(o,snap(),"Region"))&&value(o,snap(),"Bank") instanceof Number b&&b.intValue()==3&&
                value(o,snap(),"Offset") instanceof Number offset&&offset.intValue()==0x324&&"WRITE".equals(value(o,snap(),"_kinds"))),
                "actual HP button creates physical WRAM3 offset0324 write watch for APC slot50");
            connection.getMethods().get("save_trace").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
            System.out.println("HP_BUTTON_ACTION_PASSED");phase("hp_action_verified","HP button verified; saving and closing the test session.");
            connection.getMethods().get("kill").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);connection.waitClosed();
        }catch(Throwable failure){
            failure.printStackTrace();System.err.flush();throw failure;
        }finally{
            agent.destroy();if(!agent.waitFor(3,TimeUnit.SECONDS))agent.destroyForcibly();
            Swing.runNow(()->tool.getService(DebuggerTraceManagerService.class).activateTrace(null));
            Swing.runNow(()->{tool.dispose();frontend[0].dispose();});imported.close();project.close();
        }
    }
}
