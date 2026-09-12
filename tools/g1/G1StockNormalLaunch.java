import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.base.project.GhidraProject;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramLocation;
import fi.gekkio.ghidraboy.*;
import javax.swing.SwingUtilities;
import java.awt.*;
import java.nio.file.*;
import java.util.*;
import javax.imageio.ImageIO;

/** Readiness only. Loads the stored CodeBrowser tool; never creates a decompiler. */
public class G1StockNormalLaunch implements GhidraLaunchable {
  static void widen(java.awt.Component component,java.awt.Component target) {
    if(component instanceof javax.swing.JSplitPane split && split.getOrientation()==javax.swing.JSplitPane.HORIZONTAL_SPLIT
        && split.getRightComponent()!=null && SwingUtilities.isDescendingFrom(target,split.getRightComponent()))split.setDividerLocation(0.4);
    if(component instanceof java.awt.Container container)for(var child:container.getComponents())widen(child,target);
  }
  @Override public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
    Path out = Path.of(args[2]);
    var config = new GhidraApplicationConfiguration();
    config.setShowSplashScreen(false);
    Application.initializeApplication(layout, config);
    var project = GhidraProject.openProject(args[0], args[1], true);
    var file = project.getProjectData().getFile("/F1234.gb");
    if (file == null) throw new IllegalStateException("Missing prepared fixture");
    PluginTool[] holder = new PluginTool[1];
    ghidra.framework.main.FrontEndTool[] frontend = new ghidra.framework.main.FrontEndTool[1];
    String mode=args.length>3?args[3]:"readiness";
    SwingUtilities.invokeAndWait(() -> {
      var front = new ghidra.framework.main.FrontEndTool(project.getProjectManager());
      frontend[0]=front;
      front.setActiveProject(project.getProject());
      front.setVisible(true);
      holder[0] = project.getProject().getToolServices().launchTool("CodeBrowser", mode.equals("reopen")?java.util.List.of():java.util.List.of(file));
    });
    var tool = holder[0];
    if(!mode.equals("readiness")) {
      var provider=(DecompilerProvider)tool.getComponentProvider("Decompiler");
      SwingUtilities.invokeAndWait(()->{
        tool.showComponentProvider(provider,true);
        var frame=SwingUtilities.getWindowAncestor(provider.getComponent());
        if(frame instanceof java.awt.Frame f)f.setExtendedState(java.awt.Frame.MAXIMIZED_BOTH);
        widen(frame,provider.getComponent());
      });
      var script=new GhidraBoyStockWindow();
      script.setPropertiesFileLocation(args[4],"GhidraBoyStockWindow");
      script.setScriptArgs(new String[]{out.toString(),mode,args[5],args.length>6?args[6]:""});
      try {
        script.execute(new ghidra.app.script.GhidraState(tool,project.getProject(),null,null,null,null),ghidra.util.task.TaskMonitor.DUMMY,new java.io.PrintWriter(System.out,true));
      } catch(Exception failure) {
        failure.printStackTrace();
        Files.writeString(out.resolve("execution-failure.txt"),failure.toString());
        SwingUtilities.invokeAndWait(()->{tool.getService(ProgramManager.class).closeAllPrograms(true);tool.close();frontend[0].setActiveProject(null);});
        project.close();SwingUtilities.invokeAndWait(()->frontend[0].dispose());
        System.exit(1);return;
      }
      if(mode.equals("full")||mode.equals("reopen")) {
        SwingUtilities.invokeAndWait(()->{tool.close();frontend[0].setActiveProject(null);});
        project.close();
        // FrontEndTool.dispose invokes System.exit(0). Record the already closed
        // CodeBrowser before requesting that exit; the external launcher verifies exit.
        Files.writeString(out.resolve("tool-closed.json"),ProgramMapping.JSON.toJson(java.util.Map.of("pid",ProcessHandle.current().pid(),"tool_visible",tool.isVisible(),"frontend_exit_requested",true,"utc",java.time.Instant.now().toString())));
        SwingUtilities.invokeAndWait(()->frontend[0].dispose());
      }
      return;
    }
    var pm = tool.getService(ProgramManager.class);
    var program = pm.getCurrentProgram();
    var entry = StockEntries.entries(program).stream().filter(e -> e.generation() == null).findFirst().orElseThrow();
    var at = program.getAddressFactory().getAddress(entry.carrier());
    DecompilerProvider[] providers = new DecompilerProvider[1];
    SwingUtilities.invokeAndWait(() -> {
      providers[0] = (DecompilerProvider)tool.getComponentProvider("Decompiler");
      tool.showComponentProvider(providers[0], true);
      tool.getService(GoToService.class).goTo(new ProgramLocation(program, at));
    });
    var provider = providers[0];
    long deadline = System.nanoTime() + 60_000_000_000L;
    int stable = 0; Object[] previous = new Object[1];
    while (System.nanoTime() < deadline && stable < 12) {
      boolean[] good = new boolean[1];
      SwingUtilities.invokeAndWait(() -> {
        var data = provider.getController().getDecompileData();
        good[0] = !provider.getController().isDecompiling() && data != null && data.getProgram() == program && data.getFunction() != null && data.getFunction().getEntryPoint().equals(at) && data.getHighFunction() != null && data == previous[0];
        previous[0] = data;
      });
      stable = good[0] ? stable + 1 : 0;
      Thread.sleep(250);
    }
    var record = new LinkedHashMap<String,Object>();
    final int stableSamples = stable;
    SwingUtilities.invokeAndWait(() -> {
      try {
        var data = provider.getController().getDecompileData();
        var frame = SwingUtilities.getWindowAncestor(provider.getComponent());
        record.put("phase", "readiness-only"); record.put("pid", ProcessHandle.current().pid());
        record.put("tool", tool.getName()); record.put("tool_class", tool.getClass().getName());
        record.put("provider", provider.getClass().getName()); record.put("controller", provider.getController().getClass().getName());
        record.put("controller_identity", System.identityHashCode(provider.getController()));
        record.put("provider_origin", provider.getClass().getProtectionDomain().getCodeSource().getLocation().toString());
        record.put("extension_origin", StockEntries.class.getProtectionDomain().getCodeSource().getLocation().toString());
        record.put("program", program.getName());record.put("program_id", program.getUniqueProgramID());
        record.put("language", program.getLanguageID().toString()); record.put("language_version", program.getLanguage().getVersion());
        record.put("compiler", program.getCompilerSpec().getCompilerSpecID().toString());
        record.put("revision", program.getModificationNumber());record.put("entry", entry);
        record.put("display_program_matches", data != null && data.getProgram() == program);
        record.put("display_entry", data == null || data.getFunction() == null ? "" : data.getFunction().getEntryPoint().toString());
        record.put("high_available", data != null && data.getHighFunction() != null);
        record.put("error", data == null ? "no data" : data.getErrorMessage());
        record.put("stable_samples_250ms", stableSamples);record.put("headless", GraphicsEnvironment.isHeadless());
        record.put("window_showing", frame != null && frame.isShowing());record.put("provider_showing", provider.getComponent().isShowing());
        record.put("settings", Application.getUserSettingsDirectory().toString());
        record.put("cache", Application.getUserCacheDirectory().toString());
        record.put("temp", Application.getUserTempDirectory().toString());
        if (data != null && data.getDecompileResults() != null && data.getDecompileResults().getDecompiledFunction() != null)
          Files.writeString(out.resolve("readiness-displayed.c"), data.getDecompileResults().getDecompiledFunction().getC());
        if (frame != null && frame.isShowing()) {
          Point p = frame.getLocationOnScreen();
          ImageIO.write(new Robot().createScreenCapture(new Rectangle(p.x,p.y,frame.getWidth(),frame.getHeight())), "png", out.resolve("readiness-desktop.png").toFile());
        }
        Files.writeString(out.resolve("readiness.json"), ProgramMapping.JSON.toJson(record));
      } catch (Exception e) { throw new RuntimeException(e); }
    });
    System.out.println("G1_READINESS_CAPTURE_COMPLETE_NOT_ACCEPTANCE " + ProgramMapping.JSON.toJson(record));
    // Keep the genuine tool open for operator inspection; no automatic qualification follows.
  }
}
