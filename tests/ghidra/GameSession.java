import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.model.*;
import ghidra.framework.project.*;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.app.services.*;
import ghidra.app.util.importer.*;
import ghidra.debug.api.tracermi.*;
import ghidra.trace.model.*;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;
/** Developer acceptance console for a real Ghidra session. Game input uses SDL. */
public class GameSession {
 static class Manager extends DefaultProjectManager{Manager(){super();}}
 static Trace trace;static TraceRmiConnection connection;
 static TraceObject machine(){return trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));}
 static long snap(){return trace.getTimeManager().getMaxSnap();}
 static Object attr(String key){var v=machine().getValue(snap(),key);return v==null?null:v.getValue();}
 static void invoke(String name,Map<String,Object> args)throws Exception{connection.getMethods().get(name).invokeAsync(args).get(15,TimeUnit.SECONDS);}
 static void summary(){System.out.println("SNAP "+snap()+" STATE "+attr("_state")+" ROMX "+attr("ROMX")+" MAPPING_READY "+ghigbc.BankMappings.isReady(machine(),snap()));System.out.println("UNITS "+(attr("UnitsData") instanceof byte[] data?new String(data,java.nio.charset.StandardCharsets.UTF_8):attr("Units")));var events=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine.Events"));System.out.println("EVENTS "+events.getElements(Lifespan.at(snap())));System.out.flush();}
 public static void main(String[] args){try{run(args);System.exit(0);}catch(Throwable e){e.printStackTrace();System.exit(1);}}
 public static void run(String[] args)throws Exception{
  Path root=Path.of(args[0]).toAbsolutePath();
  Application.initializeApplication(new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),new GhidraApplicationConfiguration());
  Project project=new Manager().createProject(new ProjectLocator(root.resolve("build/projects").toString(),"Battle-"+System.currentTimeMillis()),null,false);
  var imported=AutoImporter.importByUsingBestGuess(root.resolve(".local/student-copy.gzf").toFile(),project,"/",GameSession.class,new MessageLog(),TaskMonitor.DUMMY);imported.save(TaskMonitor.DUMMY);var program=imported.getPrimaryDomainObject();
  GhidraTool[] holder=new GhidraTool[1];Swing.runNow(()->{try{
   var tool=new GhidraTool(project,"GBC / SameBoy - GBW3 acceptance");holder[0]=tool;
   tool.addPlugins(List.of("ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin","ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin","ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersPlugin","ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPlugin","ghidra.app.plugin.core.debug.gui.time.DebuggerTimePlugin","ghidra.app.plugin.core.debug.gui.model.DebuggerModelPlugin","ghidra.app.plugin.core.debug.gui.control.DebuggerControlPlugin","ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin","ghigbc.GbcPlugin"));
   tool.getService(ProgramManager.class).openProgram(program);tool.setVisible(true);
  }catch(Exception e){throw new RuntimeException(e);}});
  var tool=holder[0];var acceptor=tool.getService(TraceRmiService.class).acceptOne(new InetSocketAddress("127.0.0.1",0));acceptor.setTimeout(15000);
  int port=((InetSocketAddress)acceptor.getAddress()).getPort();
  var pb=new ProcessBuilder(root.resolve(".venv12/bin/python").toString(),"-m","ghigbc.agent","--connect","127.0.0.1:"+port,"--rom",root.resolve("build/experiments/student12.gbc").toString(),"--display");pb.environment().put("PYTHONPATH",root.resolve("python").toString());pb.redirectErrorStream(true);pb.redirectOutput(root.resolve("docs/evidence/game-agent.log").toFile());Process agent=pb.start();
  try {
   connection=acceptor.accept();trace=connection.waitForTrace(15000);
   for(int i=0;i<300;i++){if(machine()!=null&&attr("CaptureSnapshot") instanceof Number n&&n.longValue()==snap())break;Thread.sleep(50);}
   System.out.println("GAME_SESSION_READY "+project.getProjectLocator());System.out.flush();
   try(var input=new BufferedReader(new InputStreamReader(System.in))){String line;
    while((line=input.readLine())!=null){String[] parts=line.trim().split("\\s+",2);String cmd=parts[0];
     try{
      switch(cmd){
       case "run":invoke("resume",Map.of("process",machine()));break;
       case "pause":invoke("interrupt",Map.of("process",machine()));Thread.sleep(150);summary();break;
       case "watch":invoke("bank_breakpoint",Map.of("process",machine(),"region","wram","bank",3L,"offset",Long.parseLong(parts[1])*16+4,"kinds",4L));break;
       case "save":invoke("checkpoint",Map.of("process",machine(),"path",root.resolve(".local/game-evidence").resolve(parts[1]).toString()));break;
       case "restore":invoke("restore",Map.of("process",machine(),"path",root.resolve(".local/game-evidence").resolve(parts[1]).toString()));break;
       case "summary":summary();break;
       case "trace":invoke("save_trace",Map.of("process",machine()));System.out.println("TRACE_FILE "+trace.getDomainFile().getPathname());break;
       case "quit":invoke("kill",Map.of("process",machine()));return;
       default:System.out.println("Commands: run, pause, watch SLOT, save NEW_DIRECTORY, restore DIRECTORY, summary, trace, quit");
      }
     }catch(Exception e){e.printStackTrace();}System.out.flush();
    }
   }
  }finally{agent.destroy();if(!agent.waitFor(3,TimeUnit.SECONDS))agent.destroyForcibly();Swing.runNow(()->tool.dispose());imported.close();project.close();}
 }
}
