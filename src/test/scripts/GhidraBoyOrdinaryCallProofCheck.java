// Separate-process certificate persistence/currentness and non-circularity witness.
// @category Game Boy Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.SourceType;
import java.util.*;

public class GhidraBoyOrdinaryCallProofCheck extends GhidraScript {
  private static final String ENGINE = "20261001-wux1p-ordinary-call-proof-1";
  private static final String OLD_ENGINE = "20260930-n8-finite-pointer-successor-1";

  private void check(boolean condition, String message) {
    if (!condition) throw new AssertionError(message);
  }

  private Address address(String identity) {
    return Objects.requireNonNull(ProgramMapping.staticAddress(currentProgram, identity));
  }

  private void define(String identity, int length) throws Exception {
    var first = address(identity);
    Disassembler.getDisassembler(currentProgram, monitor, null)
        .disassemble(first, new AddressSet(first, first.add(length - 1)));
  }

  private AnalysisResult preview() throws Exception {
    return BankAnalysis.preview(
        currentProgram,
        address("0150"),
        MapperState.reset(),
        AnalysisResult.Configuration.DEFAULT,
        monitor);
  }

  private void exact(AnalysisResult result) throws Exception {
    check(result.complete(), "Complete bounded result");
    var expected =
        new AnalysisResult.OrdinaryCallProof(
            "0158",
            new MapperState.Physical("ROM", 0, 0x158),
            "rom2::4100",
            new MapperState.Physical("ROM", 2, 0x100),
            "015b",
            new MapperState.Physical("ROM", 0, 0x15b));
    check(result.ordinaryCallProofs().equals(List.of(expected)), "All six exact identities");
    check(
        (currentProgram.getMemory().getByte(address("0158")) & 255) == 0xcd,
        "Independent actual CD opcode");
    check(
        (currentProgram.getMemory().getByte(address("rom2::4100")) & 255) == 0xc9,
        "Independent actual matched RET opcode");
    check(
        ProgramMapping.staticToPhysical(currentProgram, address("rom2::4100"))
            .equals(List.of(new MapperState.Physical("ROM", 2, 0x100))),
        "Independent physical target mapping");
  }

  private void annotations() {
    check(
        currentProgram.getSymbolTable().getSymbols("UserProofWitness").hasNext(),
        "Unrelated USER_DEFINED label preserved");
    check(
        "Unrelated user annotation survives recomputation".equals(
            currentProgram.getListing().getComment(CodeUnit.EOL_COMMENT, address("0220"))),
        "Unrelated user comment preserved");
  }

  private void stale(AnalysisResult result) throws Exception {
    boolean rejected = false;
    try {
      ProgramFingerprint.requireCurrent(currentProgram, result, monitor);
    } catch (IllegalStateException expected) {
      rejected = true;
    }
    check(rejected, "Consumed RET mutation rejects saved certificate currentness");
    rejected = false;
    try {
      BankAnalysis.apply(currentProgram, result, monitor);
    } catch (IllegalStateException expected) {
      rejected = true;
    }
    check(rejected, "Consumed RET mutation rejects stale result application");
  }

  @Override
  public void run() throws Exception {
    check(AnalysisResult.SCHEMA_VERSION == 4, "Installed schema 4");
    check(AnalysisResult.ENGINE_VERSION.equals(ENGINE), "Installed exact engine");
    var options = currentProgram.getOptions(ProgramMapping.OPTIONS);
    String phase = getScriptArgs()[0];
    if (phase.equals("prepare")) {
      define("0150", 12);
      define("rom2::4100", 1);
      currentProgram.getSymbolTable()
          .createLabel(address("0220"), "UserProofWitness", SourceType.USER_DEFINED);
      currentProgram.getListing()
          .setComment(
              address("0220"),
              CodeUnit.EOL_COMMENT,
              "Unrelated user annotation survives recomputation");
      var result = preview();
      exact(result);
      BankAnalysis.apply(currentProgram, result, monitor);
      ProgramFingerprint.requireCurrent(currentProgram, result, monitor);
      String json = ProgramMapping.JSON.toJson(result);
      options.setString("wux1p.saved", json);
      var preceding = com.google.gson.JsonParser.parseString(json).getAsJsonObject();
      preceding.addProperty("schemaVersion", 3);
      preceding.addProperty("engineVersion", OLD_ENGINE);
      preceding.remove("ordinaryCallProofs");
      options.setString("wux1p.preceding", preceding.toString());
      annotations();
      println("WUX1P_EXACT_SAVED " + json);
      println("WUX1P_PREPARE_PASS schema=4 certificates=1 userAnnotations=PRESERVED");
    } else {
      var saved = AnalysisResult.read(options.getString("wux1p.saved", null));
      check(
          saved.equals(AnalysisResult.read(options.getString("analysis.latest", null))),
          "Applied analysis.latest preserves exact saved result");
      annotations();
      if (phase.equals("reopen")) {
        exact(saved);
        ProgramFingerprint.requireCurrent(currentProgram, saved, monitor);
        var fresh = preview();
        exact(fresh);
        check(saved.ordinaryCallProofs().equals(fresh.ordinaryCallProofs()), "Recomputed proofs agree");
        check(saved.findings().equals(fresh.findings()), "Recomputed observations agree");
        boolean rejected = false;
        String old = options.getString("wux1p.preceding", null);
        try {
          AnalysisResult.read(old);
        } catch (IllegalArgumentException expected) {
          rejected = true;
        }
        check(rejected, "Preceding N8/schema 3 read rejected");
        var bypass = ProgramMapping.JSON.fromJson(old, AnalysisResult.class);
        check(bypass.ordinaryCallProofs().isEmpty(), "Direct old JSON exposes no authority");
        rejected = false;
        try {
          BankAnalysis.apply(currentProgram, bypass, monitor);
        } catch (IllegalStateException expected) {
          rejected = true;
        }
        check(rejected, "Preceding N8/schema 3 direct-JSON application rejected");
        var target = address("rom2::4100");
        currentProgram.getListing().clearCodeUnits(target, target, false);
        currentProgram.getMemory().setByte(target, (byte) 0);
        define("rom2::4100", 1);
        stale(saved);
        var changed = preview();
        check(changed.ordinaryCallProofs().isEmpty(), "Saved output cannot bootstrap fresh proof");
        check(
            changed.findings().stream()
                .anyMatch(f -> f.source().equals("0158") && f.access().equals("call")
                    && f.targets().equals(List.of("rom2::4100"))),
            "Generic singleton CALL observation remains distinguishable from refused proof");
        annotations();
        println("WUX1P_REOPEN_PASS current=ACCEPTED identities=EXACT recomputation=AGREES oldN8Read=REJECTED oldN8Apply=REJECTED userAnnotations=PRESERVED consumedRETMutation=STALE freshProof=ABSENT genericCALL=SINGLETON");
      } else {
        check(phase.equals("mutated-reopen"), "Known witness phase");
        check((currentProgram.getMemory().getByte(address("rom2::4100")) & 255) == 0,
            "Consumed dependency mutation saved across separate process");
        check(saved.ordinaryCallProofs().size() == 1, "Old output retained without rewriting history");
        stale(saved);
        check(preview().ordinaryCallProofs().isEmpty(), "Fresh analysis after reopen still refuses proof");
        annotations();
        println("WUX1P_MUTATED_REOPEN_PASS savedOldCertificate=RETAINED staleAuthority=REJECTED freshProof=ABSENT userAnnotations=PRESERVED");
      }
    }
  }
}
