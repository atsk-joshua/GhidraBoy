package fi.gekkio.ghidraboy;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/** Minimal normal-CodeBrowser status and post-upgrade preparation actions. */
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "GhidraBoy",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "GhidraBoy Program status and preparation",
    description =
        "Shows physical mapping/analysis status and safely prepares recognized historical"
            + " GhidraBoy Programs.")
public final class GhidraBoyProgramPlugin extends ProgramPlugin {
  public GhidraBoyProgramPlugin(PluginTool tool) {
    super(tool);
    installStatusAction();
    installPreparationAction();
  }

  private void installStatusAction() {
    var action =
        new DockingAction("GhidraBoy Program Status", getName()) {
          @Override
          public void actionPerformed(ActionContext context) {
            var program = currentProgram;
            if (program == null) return;
            runTask(
                program,
                "Inspect GhidraBoy Program",
                monitor -> {
                  var status = GhidraBoyProgramStatus.inspect(program, monitor);
                  Msg.showInfo(
                      GhidraBoyProgramPlugin.this,
                      tool.getToolFrame(),
                      "GhidraBoy Program Status",
                      status.text());
                });
          }

          @Override
          public boolean isEnabledForContext(ActionContext context) {
            return supports(currentProgram);
          }
        };
    action.setMenuBarData(
        new MenuData(
            new String[] {ToolConstants.MENU_TOOLS, "GhidraBoy", "Program Status..."},
            "GhidraBoy"));
    action.setDescription("Show cartridge, physical identity, migration, and analysis status.");
    tool.addAction(action);
  }

  private void installPreparationAction() {
    var action =
        new DockingAction("Prepare Legacy GhidraBoy Program", getName()) {
          @Override
          public void actionPerformed(ActionContext context) {
            var program = currentProgram;
            if (program == null) return;
            runTask(
                program,
                "Prepare Legacy GhidraBoy Program",
                monitor -> {
                  var plan = LegacyPreparation.preview(program, monitor);
                  if (!plan.ready())
                    throw new IllegalArgumentException(
                        "Preparation refused before mutation: "
                            + String.join("; ", plan.diagnostics()));
                  LegacyPreparation.prepare(program, monitor);
                  Msg.showInfo(
                      GhidraBoyProgramPlugin.this,
                      tool.getToolFrame(),
                      "GhidraBoy Legacy Preparation",
                      plan.mutationCount() == 0
                          ? "Preparation is complete. Re-running made no semantic changes."
                          : "Preparation completed.");
                });
          }

          @Override
          public boolean isEnabledForContext(ActionContext context) {
            return supports(currentProgram) && currentProgram.isChangeable();
          }
        };
    action.setMenuBarData(
        new MenuData(
            new String[] {
              ToolConstants.MENU_TOOLS, "GhidraBoy", "Prepare Legacy Program..."
            },
            "GhidraBoy"));
    action.setDescription(
        "Conservatively reconstruct metadata and existing RAM identity after a language upgrade.");
    tool.addAction(action);
  }

  private boolean supports(Program program) {
    return program != null
        && "SM83:LE:16:default".equals(program.getLanguageID().toString());
  }

  private interface TaskBody {
    void run(TaskMonitor monitor) throws Exception;
  }

  private void runTask(Program program, String title, TaskBody body) {
    program.addConsumer(this);
    new TaskLauncher(
        new Task(title, true, true, false) {
          @Override
          public void run(TaskMonitor monitor) {
            try {
              body.run(monitor);
            } catch (Exception failure) {
              Msg.showError(
                  GhidraBoyProgramPlugin.this,
                  tool.getToolFrame(),
                  title,
                  failure.getMessage(),
                  failure);
            } finally {
              program.release(GhidraBoyProgramPlugin.this);
            }
          }
        },
        tool.getToolFrame());
  }
}
