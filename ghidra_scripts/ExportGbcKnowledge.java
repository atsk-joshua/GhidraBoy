// Compatibility entry point for ghigbc-knowledge-v1 exports, now owned by GhidraBoy.
// @category Game Boy
import fi.gekkio.ghidraboy.ProgramKnowledge;
import ghidra.app.script.GhidraScript;
import java.nio.file.Path;

public class ExportGbcKnowledge extends GhidraScript {
  public void run() throws Exception {
    String[] args = getScriptArgs();
    Path out =
        args.length > 0
            ? Path.of(args[0])
            : askFile("Export knowledge to a NEW .knowledge.json file", "Export").toPath();
    ProgramKnowledge.export(currentProgram, out, monitor);
    println("Exported authoritative Program knowledge to " + out);
  }
}
