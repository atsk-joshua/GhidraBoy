// Restore primacy, prepare recognized legacy topology, and write a new packed Program.
// @category GhidraBoy Migration

import fi.gekkio.ghidraboy.LegacyPreparation;
import fi.gekkio.ghidraboy.ProgramMapping;
import fi.gekkio.ghidraboy.UserReferencePrimacy;
import ghidra.app.script.GhidraScript;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;

public class GhidraBoyMigrationApply extends GhidraScript {
  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length != 2)
      throw new IllegalArgumentException(
          "Usage: GhidraBoyMigrationApply.java <snapshot.json> <new-receipt.json>");
    if (currentProgram == null || !currentProgram.isChangeable())
      throw new IllegalStateException("A writable upgraded Program copy is required");
    var snapshot =
        ProgramMapping.JSON.fromJson(
            Files.readString(Path.of(args[0])), UserReferencePrimacy.Snapshot.class);
    var restored = UserReferencePrimacy.restore(currentProgram, snapshot, monitor);
    var prepared = LegacyPreparation.prepare(currentProgram, monitor);
    monitor.checkCancelled();
    Files.writeString(
        Path.of(args[1]),
        ProgramMapping.JSON.toJson(
                Map.of(
                    "status", "PASS",
                    "program", currentProgram.getName(),
                    "restoredPrimaryStates", restored.changedPrimaryStates(),
                    "referenceCount", restored.referenceCount(),
                    "primaryReferenceCount", restored.primaryCount(),
                    "prepared", prepared.ready()))
            + "\n",
        StandardOpenOption.CREATE_NEW);
    println(
        "GHIDRABOY_MIGRATION_APPLY_PASS restored="
            + restored.changedPrimaryStates()
            + " prepared="
            + prepared.ready()
            + " receipt="
            + args[1]);
  }
}
