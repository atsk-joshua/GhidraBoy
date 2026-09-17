// Verify primacy and structural preparation in a separately imported packed Program.
// @category GhidraBoy Migration

import fi.gekkio.ghidraboy.GhidraBoyProgramStatus;
import fi.gekkio.ghidraboy.LegacyPreparation;
import fi.gekkio.ghidraboy.ProgramMapping;
import fi.gekkio.ghidraboy.UserReferencePrimacy;
import ghidra.app.script.GhidraScript;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;

public class GhidraBoyMigrationVerify extends GhidraScript {
  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length != 2)
      throw new IllegalArgumentException(
          "Usage: GhidraBoyMigrationVerify.java <snapshot.json> <new-receipt.json>");
    if (currentProgram == null) throw new IllegalStateException("A reopened Program is required");
    var snapshot =
        ProgramMapping.JSON.fromJson(
            Files.readString(Path.of(args[0])), UserReferencePrimacy.Snapshot.class);
    UserReferencePrimacy.verify(currentProgram, snapshot, monitor);
    var preparation = LegacyPreparation.preview(currentProgram, monitor);
    if (!preparation.ready() || preparation.mutationCount() != 0)
      throw new IllegalStateException("Reopened Program is not completely prepared");
    var status = GhidraBoyProgramStatus.inspect(currentProgram, monitor);
    Files.writeString(
        Path.of(args[1]),
        ProgramMapping.JSON.toJson(
                Map.of(
                    "status", "PASS",
                    "program", currentProgram.getName(),
                    "languageVersion", currentProgram.getLanguage().getVersion(),
                    "referenceCount", snapshot.referenceCount(),
                    "primaryReferenceCount", snapshot.primaryReferenceCount(),
                    "programStatus", status))
            + "\n",
        StandardOpenOption.CREATE_NEW);
    println("GHIDRABOY_MIGRATION_VERIFY_PASS " + args[1]);
  }
}
