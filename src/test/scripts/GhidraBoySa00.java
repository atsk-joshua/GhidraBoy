// Self-authored SA-00 baseline and separate-process saved dependency checks.
// @category Game Boy Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.util.*;

public class GhidraBoySa00 extends GhidraScript {
  private void check(boolean condition, String message) {
    if (!condition) throw new AssertionError(message);
  }

  private AnalysisResult preview(int root) throws Exception {
    return BankAnalysis.preview(
        currentProgram,
        toAddr(root),
        MapperState.reset(),
        AnalysisResult.Configuration.DEFAULT,
        monitor);
  }

  private List<String> ranges(BitSet bits) {
    var result = new ArrayList<String>();
    for (int start = bits.nextSetBit(0); start >= 0; ) {
      int end = bits.nextClearBit(start);
      result.add(String.format("%06x-%06x", start, end - 1));
      start = bits.nextSetBit(end);
    }
    return result;
  }

  private void collect(CodeUnit unit, BitSet bytes) throws Exception {
    for (int i = 0; i < unit.getLength(); i++)
      for (long offset : ProgramMapping.staticToFile(currentProgram, unit.getAddress().add(i)))
        bytes.set(Math.toIntExact(offset));
  }

  private void inventory(String phase, Path path) throws Exception {
    var p = currentProgram;
    var report = new TreeMap<String, Object>();
    report.put("schema", 1);
    report.put("phase", phase);
    report.put("fixture", "sa00-generic-mbc3-v1");
    report.put("fixtureSha256", getScriptArgs()[2]);
    report.put("engine", AnalysisResult.ENGINE_VERSION);
    report.put("language", p.getLanguageID().toString());
    report.put("languageVersion", p.getLanguage().getVersion());
    report.put("compiler", p.getCompilerSpec().getCompilerSpecID().toString());
    report.put("fingerprintComponents", ProgramFingerprint.components(p, monitor));
    report.put(
        "assumptions",
        Map.of(
            "mapper",
            MapperState.reset(),
            "roots",
            List.of("0150", "0180"),
            "rootOrigin",
            "self-authored fixture declarations; no whole-ROM reachability claim",
            "RAM_save_RTC",
            "unknown; SP established by code",
            "interrupts",
            "not modeled by bounded engine",
            "imageLifetime",
            "immutable self-authored file; annotated listing uses same bytes"));
    var code = new BitSet(65536);
    var data = new BitSet(65536);
    var instructions = new ArrayList<String>();
    for (var ins : p.getListing().getInstructions(true)) {
      collect(ins, code);
      instructions.add(ins.getAddress() + ":" + ins.getLength() + ":" + ins);
    }
    for (var unit : p.getListing().getDefinedData(true)) collect(unit, data);
    var unresolved = new BitSet(65536);
    unresolved.set(0, 65536);
    unresolved.andNot(code);
    unresolved.andNot(data);
    var overlap = (BitSet) code.clone();
    overlap.and(data);
    report.put(
        "coverage",
        Map.of(
            "physicalFileBytes",
            65536,
            "definedCodeBytes",
            code.cardinality(),
            "definedDataBytes",
            data.cardinality(),
            "unresolvedBytes",
            unresolved.cardinality(),
            "overlappingCodeDataBytes",
            overlap.cardinality(),
            "codeFileRanges",
            ranges(code),
            "dataFileRanges",
            ranges(data),
            "unresolvedFileRanges",
            ranges(unresolved),
            "meaning",
            "listing classification, not proven execution or semantic coverage"));
    Collections.sort(instructions);
    report.put("instructions", instructions);
    var functions = new ArrayList<Map<String, Object>>();
    for (var f : p.getFunctionManager().getFunctions(true)) {
      var body = new ArrayList<String>();
      for (var range : f.getBody().getAddressRanges()) body.add(range.toString());
      functions.add(
          Map.of(
              "entry",
              f.getEntryPoint().toString(),
              "name",
              f.getName(),
              "body",
              body,
              "source",
              f.getSymbol().getSource().toString()));
    }
    report.put("functions", functions);
    var entries = new ArrayList<String>();
    var entryIterator = p.getSymbolTable().getExternalEntryPointIterator();
    while (entryIterator.hasNext()) entries.add(entryIterator.next().toString());
    Collections.sort(entries);
    report.put("programEntryPoints", entries);
    var results = List.of(preview(0x150), preview(0x180));
    report.put("results", results);
    var warnings = new TreeMap<String, Integer>();
    var edges = new ArrayList<BankAnalysis.Finding>();
    for (var result : results)
      for (var finding : result.findings()) {
        if (finding.confidence() != AnalysisResult.Confidence.PROVEN) {
          warnings.merge(finding.access() + ":" + finding.reason(), 1, Integer::sum);
          if (List.of("flow", "jump", "call").contains(finding.access())) edges.add(finding);
        }
      }
    report.put("warningCategories", warnings);
    report.put("unresolvedEdges", edges);
    var failures = new ArrayList<String>();
    if (phase.equals("annotated-program")) {
      if (results.get(0).findings().stream()
          .noneMatch(
              f ->
                  f.access().equals("call")
                      && f.targets().equals(List.of("rom2::4000"))
                      && f.confidence() == AnalysisResult.Confidence.PROVEN))
        failures.add("expected bank-2 direct call missing");
      if (results.get(1).findings().stream().noneMatch(f -> f.reason().contains("Indirect flow")))
        failures.add("computed JP HL must remain unresolved");
    }
    report.put(
        "semanticChecks",
        phase.equals("annotated-program")
            ? List.of("bank-2 call destination", "JP HL unresolved")
            : List.of());
    report.put("semanticFailures", failures);
    report.put(
        "semanticScope",
        "Only named checks executed; all other bytes and whole-ROM behavior unqualified");
    Files.writeString(path, ProgramMapping.JSON.toJson(report) + "\n");
    check(failures.isEmpty(), failures.toString());
  }

  @Override
  public void run() throws Exception {
    var p = currentProgram;
    var options = p.getOptions(ProgramMapping.OPTIONS);
    var mode = getScriptArgs()[0];
    var output = Path.of(getScriptArgs()[1]);
    if (mode.equals("prepare")) {
      inventory("fresh-import", output.resolve("fresh-import.json"));
      var d = Disassembler.getDisassembler(p, monitor, null);
      d.disassemble(toAddr(0x150), new AddressSet(toAddr(0x150), toAddr(0x15b)));
      d.disassemble(toAddr(0x180), new AddressSet(toAddr(0x180)));
      var target = ProgramMapping.fileToStatic(p, 0x8000).get(0);
      d.disassemble(target, new AddressSet(target));
      p.getListing()
          .setComment(toAddr(0x150), CodeUnit.EOL_COMMENT, "SA-00 preserved user annotation");
      p.getFunctionManager()
          .createFunction(
              "user_entry",
              toAddr(0x150),
              new AddressSet(toAddr(0x150), toAddr(0x15b)),
              SourceType.USER_DEFINED);
      inventory("annotated-program", output.resolve("annotated-program.json"));
      var result = preview(0x150);
      BankAnalysis.apply(p, result, monitor);
      ProgramFingerprint.requireCurrent(p, result, monitor);
      var supplemental = p.getReferenceManager().getReference(toAddr(0x158), target, -1);
      check(supplemental != null, "owned bank navigation reference created");
      boolean editedPrimary = !supplemental.isPrimary();
      p.getReferenceManager().setPrimary(supplemental, editedPrimary);
      options.setBoolean("sa00.editedPrimary", editedPrimary);
      options.setString("sa00.result", ProgramMapping.JSON.toJson(result));
      println("SA00_PREPARE_PASS");
    } else if (mode.equals("reopen")) {
      var saved = AnalysisResult.read(options.getString("sa00.result", "null"));
      ProgramFingerprint.requireCurrent(p, saved, monitor);
      check(
          saved.equals(preview(0x150)),
          "independent rerun must equal saved result after reopen/application");
      AnalysisOwnership.remove(p, "bank-analysis", monitor);
      var target = ProgramMapping.fileToStatic(p, 0x8000).get(0);
      var edited = p.getReferenceManager().getReference(toAddr(0x158), target, -1);
      check(
          edited != null && edited.isPrimary() == options.getBoolean("sa00.editedPrimary", false),
          "primary-only user edit preserved after reopen/removal");
      BankAnalysis.apply(p, saved, monitor);
      check(
          "SA-00 preserved user annotation"
              .equals(p.getListing().getComment(CodeUnit.EOL_COMMENT, toAddr(0x150))),
          "comment preserved");
      check(
          p.getFunctionManager().getFunctionAt(toAddr(0x150)).getName().equals("user_entry"),
          "function preserved");
      p.getReferenceManager()
          .addMemoryReference(
              toAddr(0x158),
              toAddr(0x4100),
              RefType.UNCONDITIONAL_CALL,
              SourceType.USER_DEFINED,
              -1);
      try {
        BankAnalysis.apply(p, saved, monitor);
        throw new AssertionError("stale apply accepted");
      } catch (IllegalStateException expected) {
      }
      try {
        FunctionDiscovery.discover(p, List.of(), saved, monitor);
        throw new AssertionError("stale discovery accepted");
      } catch (IllegalStateException expected) {
      }
      println("SA00_REOPEN_REAPPLY_MUTATE_PASS");
    } else if (mode.equals("stale")) {
      var saved = AnalysisResult.read(options.getString("sa00.result", "null"));
      try {
        ProgramFingerprint.requireCurrent(p, saved, monitor);
        throw new AssertionError("saved reference mutation accepted");
      } catch (IllegalStateException expected) {
      }
      check(
          Arrays.stream(p.getReferenceManager().getReferencesFrom(toAddr(0x158)))
              .anyMatch(
                  r ->
                      r.getToAddress().equals(toAddr(0x4100))
                          && r.getSource() == SourceType.USER_DEFINED),
          "user ref persisted");
      var refreshed = preview(0x150);
      check(
          refreshed.findings().stream()
              .noneMatch(
                  f ->
                      f.source().equals("0158")
                          && f.access().equals("call")
                          && f.confidence() == AnalysisResult.Confidence.PROVEN),
          "unsupported edited call must not prove flow");
      inventory("edited-program", output.resolve("edited-program.json"));
      println("SA00_STALE_REOPEN_PASS");
    } else throw new IllegalArgumentException(mode);
  }
}
