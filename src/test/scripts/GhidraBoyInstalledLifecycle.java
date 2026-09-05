// Persistent analysis and symbol ownership checks against an installed extension.
// @category Game Boy Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import java.util.*;

public class GhidraBoyInstalledLifecycle extends GhidraScript {
  private void check(boolean ok, String message) {
    if (!ok) throw new AssertionError(message);
  }

  @Override
  public void run() throws Exception {
    var p = currentProgram;
    if (getScriptArgs()[0].equals("prepare")) {
      var symbols =
          SymbolFile.parse(
              "2:4050 SharedPersistent\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
      SymbolService.importSymbols(p, symbols, "first.sym", monitor);
      SymbolService.importSymbols(p, symbols, "second.sym", monitor);
      p.renameOverlaySpace("rom2", "persistent_bank");
      var target = ProgramMapping.fileToStatic(p, 0x8000).get(0);
      p.getMemory()
          .setBytes(
              toAddr(0x180),
              new byte[] {
                0x31,
                0,
                (byte) 0xc1,
                0x3e,
                2,
                (byte) 0xea,
                0,
                0x20,
                (byte) 0xcd,
                0,
                0x40,
                (byte) 0xc9
              });
      p.getMemory().setByte(target, (byte) 0xc9);
      var d = Disassembler.getDisassembler(p, monitor, null);
      d.disassemble(toAddr(0x180), new AddressSet(toAddr(0x180), toAddr(0x18b)));
      d.disassemble(target, new AddressSet(target));
      p.getMemory()
          .setBytes(toAddr(0x28), HexFormat.of().parseHex(FarCallConvention.SUPPORTED_BODY));
      for (int site : new int[] {0x200, 0x210}) {
        p.getMemory().setBytes(toAddr(site), new byte[] {(byte) 0xef, 2, 0, 0x40, (byte) 0xc9});
        d.disassemble(toAddr(site), new AddressSet(toAddr(site)));
      }
      new FarCallConvention(
              "0028", FarCallConvention.SUPPORTED_BODY, List.of("0200", "0210"), 0xc100)
          .apply(p, monitor);
      p.getListing().getInstructionAt(toAddr(0x210)).setFallThrough(toAddr(0x215));
      var result =
          BankAnalysis.preview(
              p, toAddr(0x180), MapperState.reset(), AnalysisResult.Configuration.DEFAULT, monitor);
      BankAnalysis.apply(p, result, monitor);
      FunctionDiscovery.discover(p, List.of(), result, monitor);
      check(p.getFunctionManager().getFunctionAt(target) != null, "owned function created");
      p.getOptions(ProgramMapping.OPTIONS)
          .setString(
              "fingerprint.components",
              ProgramMapping.JSON.toJson(ProgramFingerprint.components(p, monitor)));
      println("INSTALLED_LIFECYCLE_PREPARED");
    } else {
      check(
          SymbolService.sources(p).stream().anyMatch(s -> s.name().equals("first.sym")),
          "first source persisted");
      check(
          SymbolService.sources(p).stream().anyMatch(s -> s.name().equals("second.sym")),
          "second source persisted");
      SymbolService.removeOwned(p, "first.sym", monitor);
      check(
          p.getSymbolTable().getSymbols("SharedPersistent").hasNext(),
          "shared symbol after first removal");
      SymbolService.removeOwned(p, "second.sym", monitor);
      check(
          !p.getSymbolTable().getSymbols("SharedPersistent").hasNext(),
          "unclaimed owned symbol removed after rename/reopen");
      var result =
          ProgramMapping.JSON.fromJson(
              p.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", "null"),
              AnalysisResult.class);
      println(
          "BEFORE_COMPONENTS="
              + p.getOptions(ProgramMapping.OPTIONS).getString("fingerprint.components", ""));
      println(
          "AFTER_COMPONENTS="
              + ProgramMapping.JSON.toJson(ProgramFingerprint.components(p, monitor)));
      ProgramFingerprint.requireCurrent(p, result, monitor);
      var target = ProgramMapping.fileToStatic(p, 0x8000).get(0);
      check(
          p.getListing().getInstructionAt(toAddr(0x200)).isFallThroughOverridden(),
          "far override persisted");
      check(
          p.getListing().getInstructionAt(toAddr(0x200)).getFallThrough().equals(toAddr(0x204)),
          "far return persisted");
      AnalysisOwnership.removeAll(p, monitor);
      check(
          p.getListing().getInstructionAt(toAddr(0x210)).getFallThrough().equals(toAddr(0x215)),
          "later user override preserved after reopen and removal");
      check(
          !p.getListing().getInstructionAt(toAddr(0x200)).isFallThroughOverridden(),
          "far override removed after reopen");
      check(
          p.getFunctionManager().getFunctionAt(target) == null,
          "owned function removed after reopen");
      for (var ref : p.getReferenceManager().getReferencesFrom(toAddr(0x188)))
        check(ref.getOperandIndex() != -1, "owned reference removed");
      var refreshed =
          BankAnalysis.preview(
              p, toAddr(0x180), MapperState.reset(), AnalysisResult.Configuration.DEFAULT, monitor);
      BankAnalysis.apply(p, refreshed, monitor);
      FunctionDiscovery.discover(p, List.of(), refreshed, monitor);
      new FarCallConvention("0028", FarCallConvention.SUPPORTED_BODY, List.of("0200"), 0xc100)
          .apply(p, monitor);
      check(
          p.getListing().getInstructionAt(toAddr(0x200)).getFallThrough().equals(toAddr(0x204)),
          "far convention reapplied");
      println("INSTALLED_LIFECYCLE_REOPEN_REMOVE_REAPPLY_PASS");
    }
  }
}
