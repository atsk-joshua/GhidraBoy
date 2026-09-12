// Generate only from the actual installed historical provider. Never relabel language 2.
// @category Game Boy Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.OldLanguageFactory;
import java.io.File;

public class GenerateSm83OldLanguage extends GhidraScript {
  @Override public void run() throws Exception {
    var language = getLanguage(new LanguageID("SM83:LE:16:default"));
    if (language.getVersion() != 1 || language.getRegister("gb_analysis_entry") != null)
      throw new AssertionError("Actual language 1 required");
    OldLanguageFactory.createOldLanguageFile(language, new File(getScriptArgs()[0]));
    println("ACTUAL_SM83_V1_DESCRIPTOR_GENERATED");
  }
}
