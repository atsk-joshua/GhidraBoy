// Inspect, navigate, import symbols, and export a Game Boy program.
// @category Game Boy
import fi.gekkio.ghidraboy.*;
import ghidra.app.script.GhidraScript;
import java.nio.file.*;
import java.util.*;

public class GhidraBoyTools extends GhidraScript {
  @Override
  public void run() throws Exception {
    if (currentProgram == null) throw new IllegalStateException("Open a Game Boy program first");
    String[] args = getScriptArgs();
    String action =
        args.length > 0
            ? args[0]
            : askChoice(
                "GhidraBoy",
                "Action",
                List.of(
                    "inspect",
                    "stock-contexts",
                    "stock-current",
                    "stock-source",
                    "stock-predicate-install",
                    "mapping-json",
                    "navigate-file",
                    "navigate-physical",
                    "navigate-cpu",
                    "import-sym",
                    "export-retained-sym",
                    "export-sym",
                    "export-original",
                    "export-current",
                    "export-repair",
                    "enhance-legacy",
                    "analyze",
                    "discover-functions",
                    "far-call-convention",
                    "far-call-preview",
                    "far-call-remove",
                    "software-call-preview",
                    "software-call-apply",
                    "software-call-remove",
                    "software-call-contexts",
                    "software-call-select-context",
                    "analysis-preview",
                    "analysis-apply",
                    "analysis-remove",
                    "symbol-sources",
                    "reload-sym",
                    "remove-sym",
                    "preview-sym",
                    "companion-sym",
                    "identify-ram"),
                "inspect");
    String value = args.length > 1 ? args[1] : null;
    switch (action) {
      case "discover-functions" -> {
        String json =
            currentProgram.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest", "null");
        var findings = AnalysisResult.read(json);
        FunctionDiscovery.discover(currentProgram, List.of(), findings, monitor)
            .forEach(this::println);
      }
      case "far-call-convention", "far-call-preview" -> {
        Path file =
            value == null
                ? askFile("Explicit verified far-call JSON", "Apply").toPath()
                : Path.of(value);
        var convention =
            ProgramMapping.JSON.fromJson(Files.readString(file), FarCallConvention.class);
        var reviewed = convention.previewReviewed(currentProgram, monitor);
        reviewed.findings().forEach(this::println);
        if (action.equals("far-call-convention")
            && (isRunningHeadless()
                || askYesNo("Apply convention", "Apply the validated fixed-caller convention?")))
          convention.apply(currentProgram, reviewed, monitor);
      }
      case "software-call-preview", "software-call-apply" -> {
        Path file = value == null ? askFile("Software-call site configurations JSON", "Review").toPath() : Path.of(value);
        var configurations = SoftwareCallConfiguration.read(Files.readString(file));
        var reviewed = SoftwareCallApplication.preview(currentProgram, configurations, monitor);
        println(SoftwareCallRegistry.EXECUTION_CONDITIONS);
        println(ProgramMapping.JSON.toJson(java.util.Map.of("sites", reviewed.inventory(), "nestedRepairs", reviewed.nestedRepairs(), "executionViews", reviewed.executionViews(), "instructionDiscovery", reviewed.instructionDiscovery(), "stateContinuations", reviewed.stateContinuations(), "stateCallees", reviewed.stateCallees())));
        if (action.equals("software-call-apply") && (isRunningHeadless()
            || askYesNo("Apply software calls", "Apply exactly these reviewed payload and annotation changes?")))
          SoftwareCallApplication.apply(currentProgram, reviewed, monitor);
      }
      case "software-call-contexts", "software-call-select-context" -> {
        var canonical = currentProgram.getAddressFactory().getAddress(value == null
            ? askString("Canonical entry", "Canonical physical function address") : value);
        var contexts = SoftwareCallRegistry.stateContexts(currentProgram, canonical, monitor);
        println(ProgramMapping.JSON.toJson(contexts));
        if (action.equals("software-call-select-context")) {
          String selected = args.length > 2 ? args[2]
              : askChoice("Execution context", "Open the reviewed conditional entry",
                  contexts.stream().map(SoftwareCallRegistry.StateContext::entry).toList(), contexts.get(0).entry());
          var entry = currentProgram.getAddressFactory().getAddress(selected);
          if (SoftwareCallRegistry.stock(currentProgram)) {
            StockEntries.current(currentProgram, entry, monitor);
            goTo(entry);
          } else SoftwareCallRegistry.selectStateContext(currentProgram, canonical, entry, monitor);
        }
      }
      case "software-call-remove" ->
          AnalysisOwnership.remove(currentProgram, SoftwareCallApplication.FEATURE, monitor).forEach(this::println);
      case "far-call-remove" ->
          AnalysisOwnership.remove(currentProgram, "far-call", monitor).forEach(this::println);
      case "analysis-remove" ->
          AnalysisOwnership.removeAll(currentProgram, monitor).forEach(this::println);
      case "analysis-apply" -> {
        Path file =
            value == null
                ? askFile("Saved analysis preview JSON", "Apply").toPath()
                : Path.of(value);
        var result = AnalysisResult.read(Files.readString(file));
        BankAnalysis.apply(currentProgram, result, monitor);
        println("Applied " + result.completion() + "; only PROVEN conclusions can add references");
      }
      case "identify-ram" -> {
        String at = value == null ? askString("RAM interval", "Static start address") : value;
        String region =
            args.length > 2
                ? args[2]
                : askChoice(
                    "Physical region",
                    "Region",
                    List.of("WRAM", "VRAM", "SRAM", "MBC2_RAM"),
                    "WRAM");
        String bank = args.length > 3 ? args[3] : askString("Physical bank", "Hex bank number");
        String offset =
            args.length > 4 ? args[4] : askString("Bank offset", "Hex bank-relative offset");
        String length = args.length > 5 ? args[5] : askString("Interval length", "Hex length");
        ProgramMapping.identifyRam(
            currentProgram,
            currentProgram.getAddressFactory().getAddress(at),
            Long.parseLong(length, 16),
            region,
            Integer.parseInt(bank, 16),
            Long.parseLong(offset, 16),
            monitor);
      }
      case "enhance-legacy" -> {
        String hardware =
            args.length > 2
                ? args[2]
                : isRunningHeadless()
                    ? "UNKNOWN"
                    : askChoice(
                        "Historical hardware",
                        "Preserve known choice, or explicitly identify hardware",
                        List.of("UNKNOWN", "GB", "CGB"),
                        "UNKNOWN");
        println(
            ProgramMapping.JSON.toJson(
                LegacyEnhancement.enhance(
                    currentProgram,
                    value == null ? "AUTO" : value,
                    hardware.equals("UNKNOWN") ? null : GameBoyKind.valueOf(hardware),
                    monitor)));
      }
      case "analyze", "analysis-preview" -> {
        String json =
            value == null
                ? askString(
                    "Explicit assumption",
                    "MapperState JSON at current address (or null for unknown)")
                : value;
        var assumption = ProgramMapping.JSON.fromJson(json, MapperState.class);
        var start =
            args.length > 2
                ? currentProgram.getAddressFactory().getAddress(args[2])
                : currentAddress;
        if (start == null)
          throw new IllegalArgumentException("Select or supply a static start address");
        var config =
            args.length > 4
                ? ProgramMapping.JSON.fromJson(args[4], AnalysisResult.Configuration.class)
                : AnalysisResult.Configuration.DEFAULT;
        var result = BankAnalysis.preview(currentProgram, start, assumption, config, monitor);
        String output = ProgramMapping.JSON.toJson(result);
        println(output);
        if (action.equals("analyze")) BankAnalysis.apply(currentProgram, result, monitor);
        else if (args.length > 3)
          Files.writeString(Path.of(args[3]), output, StandardOpenOption.CREATE_NEW);
        else if (!isRunningHeadless()
            && askYesNo("Save preview", "Save this preview for later application?"))
          Files.writeString(
              askFile("New preview JSON", "Save").toPath(), output, StandardOpenOption.CREATE_NEW);
      }
      case "stock-contexts" -> {
        var entries=StockEntries.entries(currentProgram);
        if(entries.isEmpty()){println("No installed stock analysis entries");break;}
        println(ProgramMapping.JSON.toJson(entries));
        String selected=value!=null?value:askChoice("Conditional stock analysis", "Navigate to an explicitly owned entry",
            entries.stream().map(StockEntries.Entry::carrier).toList(),entries.getFirst().carrier());
        var entry=entries.stream().filter(e->e.carrier().equals(selected)).findFirst().orElseThrow();
        goTo(currentProgram.getAddressFactory().getAddress(entry.carrier()));
      }
      case "stock-current" -> {
        try {println(StockEntries.current(currentProgram,currentAddress,monitor));}
        catch(Exception failure){popup("Stock analysis unavailable: "+failure.getMessage());}
      }
      case "stock-source" -> {
        var function=getFunctionContaining(currentAddress);
        var entry=StockEntries.entries(currentProgram).stream().filter(e->function!=null&&e.carrier().equals(function.getEntryPoint().toString())).findFirst().orElseThrow();
        goTo(currentProgram.getAddressFactory().getAddress(entry.source()));
      }
      case "stock-predicate-install" -> {
        var function=getFunctionContaining(currentAddress);
        if(function==null)throw new IllegalArgumentException("Select a canonical source Function");
        var proof=PredicatedCalls.preview(currentProgram,function,PredicatedCallGraph.Limits.PRIMARY,monitor);
        goTo(PredicatedCalls.install(currentProgram,proof,monitor));
      }
      case "inspect" -> println(ProgramMapping.JSON.toJson(ProgramMapping.inspect(currentProgram)));
      case "mapping-json" -> {
        Path output =
            value == null ? askFile("New mapping JSON", "Export").toPath() : Path.of(value);
        Files.writeString(
            output,
            ProgramMapping.JSON.toJson(ProgramMapping.inspect(currentProgram)),
            StandardOpenOption.CREATE_NEW);
        println(output.toString());
      }
      case "navigate-file" -> {
        String off = value == null ? askString("ROM file offset", "Hexadecimal offset") : value;
        choose(ProgramMapping.fileToStatic(currentProgram, Long.parseLong(off, 16)));
      }
      case "navigate-physical" -> {
        String spec =
            value == null
                ? askString("Physical address", "REGION:hexBank:hexOffset (e.g. WRAM:3:34)")
                : value;
        String[] parts = spec.split(":");
        choose(
            ProgramMapping.physicalToStatic(
                currentProgram,
                new MapperState.Physical(
                    parts[0], Integer.parseInt(parts[1], 16), Integer.parseInt(parts[2], 16))));
      }
      case "navigate-cpu" -> {
        String spec = value == null ? askString("CPU address", "Hex CPU address") : value;
        String json =
            args.length > 2
                ? args[2]
                : askString(
                    "Explicit mapper state", "MapperState JSON (inspect documentation for fields)");
        var c = ProgramMapping.cartridge(currentProgram);
        if (c == null) throw new IllegalStateException("No cartridge descriptor");
        var state = ProgramMapping.JSON.fromJson(json, MapperState.class);
        var result = MapperState.translate(c, state, Integer.parseInt(spec, 16), false);
        println(ProgramMapping.JSON.toJson(result));
        if (result.physical() != null)
          choose(
              ProgramMapping.cpuToStatic(currentProgram, state, Integer.parseInt(spec, 16), false)
                  .addresses());
      }
      case "symbol-sources" ->
          SymbolService.sources(currentProgram)
              .forEach(
                  source -> println(source.name() + " (" + source.claims() + " label claims)"));
      case "remove-sym" -> SymbolService.removeOwned(currentProgram, source(value), monitor);
      case "import-sym", "reload-sym", "preview-sym", "companion-sym" -> {
        Path file;
        if (action.equals("companion-sym"))
          file =
              SymbolService.companion(currentProgram)
                  .orElseThrow(
                      () ->
                          new IllegalStateException(
                              "No same-directory .sym companion found; use import-sym to choose"
                                  + " explicitly"));
        else if (action.equals("reload-sym")) file = Path.of(source(value));
        else file = value == null ? askFile("RGBDS .sym file", "Preview").toPath() : Path.of(value);
        file = file.toAbsolutePath().normalize();
        if (Files.size(file) > 0x1000000)
          throw new IllegalArgumentException("Symbol input exceeds 16 MiB limit");
        var parsed = SymbolFile.parse(Files.readAllBytes(file));
        parsed.diagnostics().forEach(this::println);
        var preview = SymbolService.preview(currentProgram, parsed);
        String filter =
            isRunningHeadless()
                ? "all"
                : askChoice(
                    "Preview filter",
                    "Show placements",
                    List.of("all", "resolved", "unresolved", "locals"),
                    "all");
        var choices = new TreeMap<String, String>();
        if (args.length > 2)
          choices.putAll(
              ProgramMapping.JSON.fromJson(
                  Files.readString(Path.of(args[2])),
                  new com.google.gson.reflect.TypeToken<Map<String, String>>() {}.getType()));
        for (var placement : preview) {
          monitor.checkCancelled();
          boolean show =
              filter.equals("all")
                  || filter.equals("resolved") && !placement.addresses().isEmpty()
                  || filter.equals("unresolved") && placement.addresses().isEmpty()
                  || filter.equals("locals") && placement.symbol().name().contains(".");
          if (show)
            println(
                placement
                    + " parent="
                    + SymbolFile.parent(placement.symbol(), parsed.symbols())
                        .map(SymbolFile.Symbol::name)
                        .orElse(""));
          if (placement.addresses().isEmpty()) {
            var candidates = SymbolService.boundaryCandidates(currentProgram, placement.symbol());
            if (!candidates.isEmpty()) {
              println(
                  "Boundary choices for "
                      + SymbolService.entryKey(placement.symbol())
                      + ": "
                      + candidates);
              if (!isRunningHeadless() && !action.equals("preview-sym")) {
                var options = new ArrayList<String>();
                options.add("Keep unresolved");
                candidates.forEach(address -> options.add(address.toString()));
                String selected =
                    askChoice(
                        "Boundary/end marker",
                        SymbolService.entryKey(placement.symbol()),
                        options,
                        options.get(0));
                if (!selected.equals(options.get(0)))
                  choices.put(SymbolService.entryKey(placement.symbol()), selected);
              }
            }
          }
        }
        if (!action.equals("preview-sym")
            && (isRunningHeadless()
                || askYesNo(
                    "Import symbols", "Apply the displayed preview and explicit placements?")))
          SymbolService.importSymbols(currentProgram, parsed, file.toString(), choices, monitor);
      }
      case "export-sym" -> {
        Path output =
            value == null ? askFile("New .sym output", "Export").toPath() : Path.of(value);
        var exported = SymbolService.exportSymbols(currentProgram, monitor);
        exported.diagnostics().forEach(this::println);
        Files.writeString(output, exported.text(), StandardOpenOption.CREATE_NEW);
      }
      case "export-retained-sym" -> {
        String source =
            value == null
                ? askString("Original symbol source", "Absolute source file path")
                : value;
        Path output =
            args.length > 2 ? Path.of(args[2]) : askFile("New .sym output", "Export").toPath();
        Files.writeString(
            output,
            SymbolService.exportRetained(currentProgram, source),
            StandardOpenOption.CREATE_NEW);
      }
      case "export-original", "export-current", "export-repair" -> {
        Path output = value == null ? askFile("New ROM output", "Export").toPath() : Path.of(value);
        boolean current = !action.equals("export-original"),
            repair = action.equals("export-repair");
        byte[] bytes = ProgramMapping.exportBytes(currentProgram, current, repair, monitor);
        if (repair) {
          byte[] before = ProgramMapping.exportBytes(currentProgram, true, false, monitor);
          for (int i = 0; i < bytes.length; i++)
            if (bytes[i] != before[i])
              println(
                  String.format(
                      "Checksum repair %04x: %02x -> %02x", i, before[i] & 255, bytes[i] & 255));
        }
        monitor.checkCancelled();
        Files.write(output, bytes, StandardOpenOption.CREATE_NEW);
        println("SHA256 " + Sha256.of(bytes) + "  " + output);
      }
      default -> throw new IllegalArgumentException("Unknown action " + action);
    }
  }

  private String source(String value) throws Exception {
    if (value != null) return value;
    var sources =
        SymbolService.sources(currentProgram).stream().map(SymbolService.Source::name).toList();
    if (sources.isEmpty()) throw new IllegalStateException("No active symbol sources");
    if (isRunningHeadless()) throw new IllegalArgumentException("Supply a source ID");
    return askChoice("Symbol source", "Source", sources, sources.get(0));
  }

  private void choose(List<ghidra.program.model.address.Address> addresses) throws Exception {
    if (addresses.isEmpty()) {
      println("Unmapped or no static execution view");
      return;
    }
    addresses.forEach(a -> println(a.toString()));
    if (isRunningHeadless()) return;
    goTo(
        addresses.size() == 1
            ? addresses.get(0)
            : askChoice("Static execution views", "Choose address", addresses, addresses.get(0)));
  }
}
