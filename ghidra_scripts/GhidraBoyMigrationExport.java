// Export a verified saved Program outside any headless processing transaction.
// @category GhidraBoy Migration

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import java.nio.file.Path;

public class GhidraBoyMigrationExport extends GhidraScript {
  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length != 2)
      throw new IllegalArgumentException(
          "Usage: GhidraBoyMigrationExport.java <project-domain-path> <new-output.gzf>");
    var file = state.getProject().getProjectData().getRootFolder().getFile(args[0]);
    if (file == null) throw new IllegalArgumentException("Saved Program is absent: " + args[0]);
    var program = (Program) file.getImmutableDomainObject(this, -1, monitor);
    try {
      if (program.isChangeable()) throw new IllegalStateException("Immutable reopen required");
      program.saveToPackedFile(Path.of(args[1]).toFile(), monitor);
    } finally {
      program.release(this);
    }
    println("GHIDRABOY_MIGRATION_EXPORT_PASS " + args[1]);
  }
}
