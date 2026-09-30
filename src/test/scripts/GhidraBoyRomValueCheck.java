// Bounded installed N1 LOAD/mapper oracle and persisted stale-result negative.
// @category Game Boy Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import java.util.Arrays;
import java.util.List;

public class GhidraBoyRomValueCheck extends GhidraScript {
  private void check(boolean condition, String message) {
    if (!condition) throw new AssertionError(message);
  }

  private AnalysisResult analyze() throws Exception {
    var p = currentProgram;
    var manager = AutoAnalysisManager.getAnalysisManager(p);
    var analyzer = manager.getAnalyzer(GhidraBoyBankAnalyzer.NAME);
    check(analyzer instanceof GhidraBoyBankAnalyzer, "Installed ClassSearcher analyzer");
    var options = p.getOptions(Program.ANALYSIS_PROPERTIES);
    for (var name : options.getOptionNames())
      if (manager.getAnalyzer(name) != null) options.setBoolean(name, false);
    options.getOptions(GhidraBoyBankAnalyzer.NAME).setBoolean("Create functions from proved entries", false);
    manager.initializeOptions();
    manager.scheduleOneTimeAnalysis(analyzer, new AddressSet(toAddr(0x150), toAddr(0x15e)));
    manager.startAnalysis(monitor);
    return AnalysisResult.read(p.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", null));
  }

  private void oracle(AnalysisResult result, int expected, String target) throws Exception {
    check(result.complete(), "Completed bounded analysis");
    check(result.findings().stream().anyMatch(f -> f.source().equals("0153") && f.access().equals("read")
        && f.targets().equals(List.of("0200"))), "Preserved physical read mapping");
    check(result.findings().stream().anyMatch(f -> f.source().equals("015c") && f.access().equals("jump")
        && f.targets().equals(List.of(target))), "Independent physical successor " + target);
    var trace = BankAnalysis.previewFetch(currentProgram, toAddr(0x150), null, AnalysisResult.Configuration.DEFAULT, monitor);
    var write = trace.steps().stream().flatMap(step -> step.writes().stream())
        .filter(w -> w.cpu() == 0x2000).findFirst().orElseThrow();
    check(Integer.valueOf(expected).equals(write.value()), "Independent loaded selector " + expected);
    check(Integer.valueOf(expected).equals(write.after().low()), "Independent MBC5 low register");
    var high = trace.steps().stream().flatMap(step -> step.writes().stream())
        .filter(w -> w.cpu() == 0x3000).findFirst().orElseThrow();
    check(Integer.valueOf(0).equals(high.after().high()), "Explicit MBC5 high register zero");
  }

  @Override public void run() throws Exception {
    var p = currentProgram;
    var options = p.getOptions(ProgramMapping.OPTIONS);
    if (getScriptArgs()[0].equals("prepare")) {
      Disassembler.getDisassembler(p, monitor, null).disassemble(toAddr(0x150), new AddressSet(toAddr(0x150), toAddr(0x15e)));
      check(Arrays.stream(p.getListing().getInstructionAt(toAddr(0x153)).getPcode(false))
          .anyMatch(op -> op.getOpcode() == PcodeOp.LOAD), "Actual compiled SLEIGH LOAD");
      var result = analyze();
      oracle(result, 2, "rom2::4000");
      ProgramFingerprint.requireCurrent(p, result, monitor);
      options.setString("n1.oldEngine", ProgramMapping.JSON.toJson(result)
          .replace(AnalysisResult.ENGINE_VERSION, "20260930-m2-native-analysis-3"));
      println("N1_INSTALLED_PREPARE_PASS selector=2 high=0 physical=ROM:2:0");
    } else {
      var saved = AnalysisResult.read(options.getString("analysis.latest", null));
      ProgramFingerprint.requireCurrent(p, saved, monitor);
      oracle(saved, 2, "rom2::4000");
      var old = options.getString("n1.oldEngine", null);
      boolean rejected = false;
      try { AnalysisResult.read(old); } catch (IllegalArgumentException expected) { rejected = true; }
      check(rejected, "Persisted old-engine result rejected");
      rejected = false;
      try { BankAnalysis.apply(p, ProgramMapping.JSON.fromJson(old, AnalysisResult.class), monitor); }
      catch (IllegalStateException expected) { rejected = true; }
      check(rejected, "Old-engine apply rejected");
      p.getMemory().setByte(toAddr(0x200), (byte) 3);
      rejected = false;
      try { BankAnalysis.apply(p, saved, monitor); } catch (IllegalStateException expected) { rejected = true; }
      check(rejected, "Persisted result rejected after current byte mutation");
      check(ProgramMapping.originalFile(p).getOriginalByte(0x200) == 2, "Original input remains two");
      oracle(analyze(), 3, "rom3::4000");
      println("N1_INSTALLED_REOPEN_PASS stale=REJECTED original=2 current=3 high=0 physical=ROM:3:0");
    }
  }
}
