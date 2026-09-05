import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.BooleanSupplier;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.model.*;
import ghidra.framework.project.*;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.app.services.*;
import ghidra.app.util.importer.*;
import ghidra.debug.api.tracermi.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.model.*;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

/** Sets up real fixtures, then observes CUA/user actions. Does not invoke UI actions. */
public class UiActionTest {
    static class Manager extends DefaultProjectManager { Manager(){super();} }
    static class TestFrontEnd extends ghidra.framework.main.FrontEndTool {
        TestFrontEnd(ProjectManager manager){super(manager);}
        // The observer must finish cleanup and report failures before exiting the JVM.
        @Override protected void shutdown(){}
    }
    static Path root;
    static Trace trace;
    static long snap(){Long latest=trace.getTimeManager().getMaxSnap();return latest==null?Long.MIN_VALUE:latest;}
    static TraceObject object(String path){return trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse(path));}
    static Object value(TraceObject object,long snap,String key){var v=object.getValue(snap,key);return v==null?null:v.getValue();}
    static Object attr(String key){var m=object("Machine");return m==null?null:value(m,snap(),key);}
    static void phase(String name,String instruction)throws Exception{
        System.out.println("PHASE "+name+": "+instruction);System.out.flush();
        Files.writeString(root.resolve("docs/evidence/ui-action-phase.txt"),name+"\n"+instruction+"\n");
    }
    static void await(BooleanSupplier test,String assertion)throws Exception{
        long end=System.nanoTime()+TimeUnit.MINUTES.toNanos(8);
        while(System.nanoTime()<end){if(test.getAsBoolean()){System.out.println("PASS "+assertion);return;}Thread.sleep(50);}
        throw new AssertionError("Timed out: "+assertion);
    }
    static boolean pcIs(long pc){var frame=object("Machine.Threads[0].Stack[0]");return frame!=null&&value(frame,snap(),"_pc") instanceof Address address&&address.getOffset()==pc;}
    static boolean hasBankBreakpoint(){
        var c=object("Machine.Breakpoints");if(c==null)return false;
        return c.getElements(Lifespan.at(snap())).stream().map(v->(TraceObject)v.getValue()).anyMatch(o->
            "rom".equals(value(o,snap(),"Region"))&&value(o,snap(),"Bank") instanceof Number bank&&bank.intValue()==2&&
            value(o,snap(),"Offset") instanceof Number offset&&offset.intValue()==0x29);
    }
    public static void main(String[] args){
        root=Path.of(args[0]).toAbsolutePath().normalize();
        try{
            PrintStream output=new PrintStream(root.resolve("docs/evidence/ui-actions.log").toFile());System.setOut(output);System.setErr(output);
            run(args);System.exit(0);
        }catch(Throwable failure){failure.printStackTrace();System.exit(1);}
    }
    static void run(String[] args)throws Exception{
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[1])),new GhidraApplicationConfiguration());
        var projectManager=new Manager();
        var project=projectManager.createProject(new ProjectLocator(root.resolve("build/projects").toString(),"UIActions-"+System.currentTimeMillis()),null,false);
        var imported=AutoImporter.importByUsingBestGuess(root.resolve("build/teaching.gbc").toFile(),project,"/",UiActionTest.class,new MessageLog(),TaskMonitor.DUMMY);
        imported.save(TaskMonitor.DUMMY);var program=imported.getPrimaryDomainObject();
        long writerOffset=Files.lines(root.resolve("build/teaching.sym")).filter(s->s.endsWith(" DirectWriter")).map(s->Long.parseLong(s.split(" ")[0].split(":")[1],16)).findFirst().orElseThrow();
        Address writer=program.getAddressFactory().getDefaultAddressSpace().getAddress(writerOffset);
        try(var tx=program.openTransaction("UI acceptance fixture labels")){
            var bank=program.getMemory().getBlock("rom2");bank.setName("student_second_bank");
            program.getSymbolTable().createLabel(bank.getStart().add(0x29),"StudentBankTwo",SourceType.USER_DEFINED);
            program.getSymbolTable().createLabel(writer,"StudentHPWriter",SourceType.USER_DEFINED);
            program.getBookmarkManager().setBookmark(writer,"Note","GBC Study","Existing student observation");
        }
        ghidra.program.util.GhidraProgramUtilities.markProgramNotToAskToAnalyze(program);
        program.save("UI acceptance fixture",TaskMonitor.DUMMY);
        final GhidraTool[] holder=new GhidraTool[1];
        final Throwable[] startupError=new Throwable[1];
        final ghidra.framework.main.FrontEndTool[] frontEnd=new ghidra.framework.main.FrontEndTool[1];
        Swing.runNow(()->{try{
            frontEnd[0]=new TestFrontEnd(projectManager);
            frontEnd[0].setActiveProject(project);
            var resource=UiActionTest.class.getClassLoader().getResourceAsStream("defaultTools/Debugger.tool");
            if(resource==null)throw new IllegalStateException("Shipped Debugger template unavailable");
            var xml=ghidra.util.xml.XmlUtilities.createSecureSAXBuilder(false,false).build(resource).getRootElement();
            var tool=new GhidraTool(project,new ghidra.framework.project.tool.GhidraToolTemplate(xml,"Debugger.tool"));
            holder[0]=tool;tool.setToolName("GhiGBC UI Validation");
            for(String plugin:List.of("ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin","ghigbc.GbcPlugin")){
                if(tool.getManagedPlugins().stream().noneMatch(p->p.getClass().getName().equals(plugin)))tool.addPlugin(plugin);
            }
            tool.getService(ProgramManager.class).openProgram(program);tool.setVisible(true);
        }catch(Exception e){startupError[0]=e;}});
        if(startupError[0]!=null)throw new AssertionError("UI plugin initialization failed",startupError[0]);
        var tool=holder[0];var acceptor=tool.getService(TraceRmiService.class).acceptOne(new InetSocketAddress("127.0.0.1",0));acceptor.setTimeout(15000);
        var python=System.getenv().getOrDefault("GBC_PYTHON",root.resolve(".venv12/bin/python").toString());
        var pb=new ProcessBuilder(python,"-m","ghigbc.agent","--connect","127.0.0.1:"+((InetSocketAddress)acceptor.getAddress()).getPort(),"--rom",root.resolve("build/teaching.gbc").toString(),"--fixture-ready");
        pb.environment().put("PYTHONPATH",root.resolve("python").toString());pb.redirectErrorStream(true);pb.redirectOutput(root.resolve("docs/evidence/ui-action-agent.log").toFile());
        var agent=pb.start();
        try{
            var connection=acceptor.accept();trace=connection.waitForTrace(15000);
            await(()->ghigbc.BankMappings.isReady(object("Machine"),snap()),"initial capture mappings ready");
            phase("bank_breakpoint","In the static Listing, go to StudentBankTwo, then right-click: GBC > Breakpoint in this physical bank.");
            await(UiActionTest::hasBankBreakpoint,"actual static-context action created canonical ROM bank 2 breakpoint");
            phase("continue_bank","Press the native debugger Continue button. Expect a stop at bank 2 CPU 4029.");
            await(()->attr("ROMX") instanceof Number n&&n.intValue()==2&&pcIs(0x4029)&&"breakpoint".equals(attr("StopReason")),"native Continue UI stops at the inactive-bank breakpoint");
            connection.getMethods().get("bank_breakpoint").invokeAsync(Map.of("process",object("Machine"),"region","wram","bank",3L,"offset",0x34L,"kinds",4L)).get(15,TimeUnit.SECONDS);
            phase("continue_writer","Press native Continue again to stop at the WRAM writer.");
            await(()->object("Machine.Events[1]")!=null&&ghigbc.BankMappings.isReady(object("Machine"),snap()),"real writer event captured");
            long eventSnap=((Number)value(object("Machine.Events[1]"),snap(),"Snapshot")).longValue();
            connection.getMethods().get("delete_breakpoint").invokeAsync(Map.of("breakpoint",object("Machine.Breakpoints[3]"))).get(15,TimeUnit.SECONDS);
            connection.getMethods().get("bank_breakpoint").invokeAsync(Map.of("process",object("Machine"),"region","rom","bank",2L,"offset",0x567L,"kinds",1L)).get(15,TimeUnit.SECONDS);
            phase("later_state","Press Continue to reach the later bank-2 register fixture, then select the write in GBC History and click Go to writer.");
            await(()->attr("ROMX") instanceof Number n&&n.intValue()==2&&pcIs(0x4567)&&"breakpoint".equals(attr("StopReason"))&&snap()>eventSnap,"later bank state reached");
            var manager=tool.getService(DebuggerTraceManagerService.class);var listing=tool.getService(CodeViewerService.class);
            await(()->{
                var location=listing.getCurrentLocation();
                return manager.getCurrentTrace()==trace&&manager.getCurrentSnap()==eventSnap&&location!=null&&location.getProgram()==program&&location.getAddress().equals(writer);
            },"Go to writer button selected the historical snapshot and exact static instruction");
            if(tool.getService(DebuggerControlService.class).getCurrentMode(trace)!=ghidra.debug.api.control.ControlMode.RO_TRACE)
                throw new AssertionError("Historical writer must use read-only Trace mode");
            System.out.println("PASS historical navigation uses read-only Trace mode");
            phase("bookmark","Select the write again and click Bookmark observation.");
            await(()->{var b=program.getBookmarkManager().getBookmark(writer,"Note","GBC Study");return b!=null&&b.getComment().contains("trace snapshot "+eventSnap);},"bookmark button recorded the captured observation");
            var comment=program.getBookmarkManager().getBookmark(writer,"Note","GBC Study").getComment();
            if(!comment.contains("Existing student observation"))throw new AssertionError("Student observation was overwritten");
            System.out.println("PASS existing student bookmark text preserved");
            connection.getMethods().get("save_trace").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
            phase("passed","UI_ACTIONS_PASSED");System.out.println("UI_ACTIONS_PASSED");
            connection.getMethods().get("kill").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
            connection.waitClosed();
        }finally{
            agent.destroy();if(!agent.waitFor(3,TimeUnit.SECONDS))agent.destroyForcibly();
            Swing.runNow(()->tool.getService(DebuggerTraceManagerService.class).activateTrace(null));
            Swing.runNow(()->{tool.dispose();frontEnd[0].dispose();});imported.close();project.close();
        }
    }
}
