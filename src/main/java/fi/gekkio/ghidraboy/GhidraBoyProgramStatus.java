package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.Set;
import java.util.TreeSet;

/** Compact read-only status model shared by the CodeBrowser action and tests. */
public final class GhidraBoyProgramStatus {
  public record Status(
      String cartridge,
      String physicalIdentity,
      String migration,
      String analysis,
      String text) {}

  private GhidraBoyProgramStatus() {}

  public static Status inspect(Program program, TaskMonitor monitor) throws Exception {
    if (!"SM83:LE:16:default".equals(program.getLanguageID().toString()))
      throw new IllegalArgumentException("The active Program is not SM83/GhidraBoy");
    var snapshot = ProgramMapping.inspect(program);
    var cartridge = snapshot.cartridge();
    String cartridgeText =
        cartridge == null
            ? "descriptor missing"
            : cartridge.mapper()
                + ", "
                + cartridge.hardware()
                + ", ROM "
                + cartridge.actualRomBanks()
                + " banks, cartridge RAM "
                + cartridge.ramBytes()
                + " bytes";

    Set<Integer> rom = new TreeSet<>(), vram = new TreeSet<>(), wram = new TreeSet<>(), sram = new TreeSet<>();
    boolean hram = false;
    for (var range : snapshot.ranges()) {
      monitor.checkCancelled();
      switch (range.region()) {
        case "ROM" -> rom.add(range.bank());
        case "VRAM" -> vram.add(range.bank());
        case "WRAM" -> wram.add(range.bank());
        case "SRAM", "MBC2_RAM" -> sram.add(range.bank());
        case "HRAM" -> hram = true;
        default -> {}
      }
    }
    int declaredSram =
        cartridge == null
            ? 0
            : cartridge.mapper() == Cartridge.Mapper.MBC2
                ? 1
                : (cartridge.ramBytes() + 0x1fff) / 0x2000;
    String identityText =
        "ROM "
            + rom.size()
            + ", VRAM "
            + vram
            + ", WRAM "
            + wram
            + ", SRAM represented "
            + sram
            + " of declared "
            + declaredSram
            + ", HRAM "
            + (hram ? "identified" : "unresolved")
            + "; "
            + String.join("; ", snapshot.diagnostics());

    var options = program.getOptions(ProgramMapping.OPTIONS);
    String preparation =
        options.contains("legacyPreparationState")
            ? options.getString("legacyPreparationState", "UNKNOWN")
            : snapshot.diagnostics().stream()
                    .anyMatch(message -> message.startsWith("Legacy RAM identity unresolved:"))
                ? "REQUIRED"
                : "NOT_REQUIRED";
    String primacy =
        options.contains("migration.referencePrimacy")
            ? options.getString("migration.referencePrimacy", "UNKNOWN")
            : "NOT_RECORDED";
    String migrationText =
        "language "
            + program.getLanguageID()
            + " v"
            + program.getLanguage().getVersion()
            + ", preparation "
            + preparation
            + ", reference preservation "
            + primacy;

    String analysisText = "available; no accepted result";
    if (options.contains("analysis.latest")) {
      try {
        var result = AnalysisResult.read(options.getString("analysis.latest", null));
        ProgramFingerprint.requireCurrent(program, result, monitor);
        analysisText =
            "available; current "
                + result.completion()
                + ", "
                + result.exploredStates()
                + " states, "
                + result.starts().size()
                + " roots";
      } catch (Exception stale) {
        analysisText = "available; stale/incompatible result: " + stale.getMessage();
      }
    }
    String text =
        "Cartridge\n  "
            + cartridgeText
            + "\n\nPhysical Program identity\n  "
            + identityText
            + "\n\nMigration\n  "
            + migrationText
            + "\n\nAnalysis\n  "
            + analysisText;
    return new Status(cartridgeText, identityText, migrationText, analysisText, text);
  }
}
