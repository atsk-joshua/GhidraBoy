// Actual saved-v4 provider upgrade; compile/run capture with the old qualified provider first.
// Uses APIs present in that provider. No registry field rewriting or reflective API access.
// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class GhidraBoySa01StateMigration extends GhidraScript {
  private static final String REGISTRY = "softwareCall.sites.v1";
  private static final String OWNERSHIP = "analysis.ownership.v1";
  private static final String OLD_VERSION = "software-call-registry-4";
  private static final String VIEW_PREFIX = "gb_call_view_";

  private void require(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
  private boolean canonical(Address at) { return !at.getAddressSpace().getName().startsWith(VIEW_PREFIX); }
  private String option(String key) {
    var options = currentProgram.getOptions(ProgramMapping.OPTIONS);
    return options.contains(key) ? options.getString(key, "") : "absent";
  }
  private String registryVersion(String registry) {
    return com.google.gson.JsonParser.parseString(registry).getAsJsonObject().get("version").getAsString();
  }
  private String hash(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }

  private record RawInstruction(String bytes, int length, String mnemonic, List<String> rawPcode,
      List<String> physicalBytes) {}
  private record Knowledge(List<String> symbols, List<String> functions, List<String> comments,
      List<String> references) {}
  private record Snapshot(String registry, String ownership, String language, String compiler,
      String originalSha256, Map<String, String> canonicalMemory, Map<String, RawInstruction> instructions,
      Knowledge knowledge, Map<String, String> canonicalTargets, List<String> activeViews) {}

  private RawInstruction raw(Instruction instruction) throws Exception {
    var pcode = new ArrayList<String>();
    for (var operation : instruction.getPcode(false)) pcode.add(operation.toString());
    var physical = new ArrayList<String>();
    for (int offset = 0; offset < instruction.getLength(); offset++)
      physical.add(ProgramMapping.JSON.toJson(ProgramMapping.staticToPhysical(currentProgram, instruction.getAddress().add(offset))));
    return new RawInstruction(HexFormat.of().formatHex(instruction.getBytes()), instruction.getLength(),
        instruction.getMnemonicString(), List.copyOf(pcode), List.copyOf(physical));
  }

  private Map<String, RawInstruction> canonicalInstructions() throws Exception {
    var result = new TreeMap<String, RawInstruction>();
    for (var instruction : currentProgram.getListing().getInstructions(true))
      if (canonical(instruction.getAddress())) result.put(instruction.getAddress().toString(), raw(instruction));
    return result;
  }

  private Map<String, String> canonicalMemory() throws Exception {
    var result = new TreeMap<String, String>();
    for (var block : currentProgram.getMemory().getBlocks()) {
      monitor.checkCancelled();
      if (!canonical(block.getStart()) || !block.isInitialized()) continue;
      require(block.getSize() <= Integer.MAX_VALUE, "bounded self-authored migration fixture block");
      byte[] bytes = new byte[(int) block.getSize()];
      require(currentProgram.getMemory().getBytes(block.getStart(), bytes) == bytes.length, "complete physical image read");
      result.put(block.getStart() + ":" + block.getSize(), hash(bytes));
    }
    return result;
  }

  private Knowledge knowledge() throws Exception {
    var symbols = new ArrayList<String>();
    var functions = new ArrayList<String>();
    var comments = new ArrayList<String>();
    var references = new ArrayList<String>();
    for (var symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
      if (!canonical(symbol.getAddress()) || symbol.isDynamic() || symbol.getSource() != SourceType.USER_DEFINED) continue;
      symbols.add(ProgramMapping.JSON.toJson(List.of(symbol.getID(), symbol.getAddress().toString(),
          symbol.getName(true), symbol.getSymbolType().toString(), symbol.getSource().toString(), symbol.isPinned())));
    }
    for (var function : currentProgram.getFunctionManager().getFunctions(true)) {
      if (!canonical(function.getEntryPoint()) || (function.getSymbol().getSource() != SourceType.USER_DEFINED
          && function.getSignatureSource() != SourceType.USER_DEFINED)) continue;
      var fields = new LinkedHashMap<String, Object>();
      fields.put("entry", function.getEntryPoint().toString()); fields.put("name", function.getName(true));
      fields.put("source", function.getSymbol().getSource().toString());
      fields.put("signatureSource", function.getSignatureSource().toString());
      fields.put("prototype", function.getPrototypeString(true, true));
      fields.put("comment", function.getComment()); fields.put("repeatableComment", function.getRepeatableComment());
      fields.put("inline", function.isInline()); fields.put("varargs", function.hasVarArgs());
      fields.put("customStorage", function.hasCustomVariableStorage());
      fields.put("body", function.getBody().toString());
      // Thunk, fixup and noReturn fields are owned interpretation, not silently classified as
      // user losses when public removal restores them and reviewed application reinstalls them.
      functions.add(ProgramMapping.JSON.toJson(fields));
    }
    for (var type : CommentType.values()) {
      var iterator = currentProgram.getListing().getCommentAddressIterator(type, currentProgram.getMemory(), true);
      while (iterator.hasNext()) {
        var at = iterator.next();
        if (canonical(at)) comments.add(ProgramMapping.JSON.toJson(List.of(at.toString(), type.toString(), currentProgram.getListing().getComment(type, at))));
      }
    }
    var sources = currentProgram.getReferenceManager().getReferenceSourceIterator(currentProgram.getMemory(), true);
    while (sources.hasNext())
      for (var reference : currentProgram.getReferenceManager().getReferencesFrom(sources.next())) {
        if (reference.getSource() != SourceType.USER_DEFINED || !canonical(reference.getFromAddress()) || !canonical(reference.getToAddress())) continue;
        references.add(ProgramMapping.JSON.toJson(List.of(reference.getFromAddress().toString(), reference.getToAddress().toString(),
            reference.getReferenceType().toString(), reference.getOperandIndex(), reference.getSource().toString(), reference.isPrimary(), reference.getSymbolID())));
      }
    Collections.sort(symbols); Collections.sort(functions); Collections.sort(comments); Collections.sort(references);
    return new Knowledge(List.copyOf(symbols), List.copyOf(functions), List.copyOf(comments), List.copyOf(references));
  }

  private Map<String, String> canonicalTargets(String registry) {
    var result = new TreeMap<String, String>();
    var sites = com.google.gson.JsonParser.parseString(registry).getAsJsonObject().getAsJsonArray("sites");
    for (var value : sites) {
      var site = value.getAsJsonObject();
      String at = site.get("address").getAsString();
      if (at.equals(site.get("canonicalAddress").getAsString())) {
        require(result.put(at, site.get("target").getAsString()) == null, "unique canonical recorded site " + at);
      }
    }
    return Map.copyOf(result);
  }

  private Snapshot snapshot() throws Exception {
    var active = new TreeSet<String>();
    for (var block : currentProgram.getMemory().getBlocks())
      if (!canonical(block.getStart()) && block.isExecute()) active.add(block.getStart().getAddressSpace().getName());
    return new Snapshot(option(REGISTRY), option(OWNERSHIP), currentProgram.getLanguageID().toString(),
        currentProgram.getCompilerSpec().getCompilerSpecID().toString(), ProgramMapping.inspect(currentProgram).originalSha256(),
        canonicalMemory(), canonicalInstructions(), knowledge(), canonicalTargets(option(REGISTRY)), List.copyOf(active));
  }

  private void compareRawAndFresh(Snapshot original, Path work, String phase) throws Exception {
    require(currentProgram.getLanguageID().toString().equals(original.language), "language ID retained");
    require(currentProgram.getCompilerSpec().getCompilerSpecID().toString().equals(original.compiler), "compiler ID retained");
    require(ProgramMapping.inspect(currentProgram).originalSha256().equals(original.originalSha256), "original physical input identity retained");
    require(canonicalMemory().equals(original.canonicalMemory), "canonical initialized images and patches unchanged");
    var current = canonicalInstructions();
    var mismatches = new ArrayList<String>();
    var fresh = new PseudoDisassembler(currentProgram);
    for (var entry : original.instructions.entrySet()) {
      monitor.checkCancelled();
      var saved = current.get(entry.getKey());
      if (!entry.getValue().equals(saved)) mismatches.add(entry.getKey() + ": saved canonical raw decode differs");
      var at = currentProgram.getAddressFactory().getAddress(entry.getKey());
      var pseudo = fresh.disassemble(at);
      if (pseudo == null || !entry.getValue().equals(raw(pseudo)))
        mismatches.add(entry.getKey() + ": fresh candidate decode differs from actual old-provider persisted decode");
    }
    var added = new TreeSet<>(current.keySet()); added.removeAll(original.instructions.keySet());
    Files.writeString(work.resolve("decode-" + phase + ".json"), ProgramMapping.JSON.toJson(Map.of(
        "originalCanonicalCount", original.instructions.size(), "currentCanonicalCount", current.size(),
        "addedCanonicalInstructions", added, "mismatches", mismatches)));
    require(mismatches.isEmpty(), "raw/fresh saved-provider compatibility failures: " + mismatches);
  }

  private void compareKnowledge(Snapshot original, Path work, String phase) throws Exception {
    var current = knowledge();
    var lost = new TreeMap<String, List<String>>();
    for (var pair : Map.of("symbols", List.of(original.knowledge.symbols, current.symbols),
        "functions", List.of(original.knowledge.functions, current.functions),
        "comments", List.of(original.knowledge.comments, current.comments),
        "references", List.of(original.knowledge.references, current.references)).entrySet()) {
      var missing = new ArrayList<>(pair.getValue().get(0)); missing.removeAll(pair.getValue().get(1));
      if (!missing.isEmpty()) lost.put(pair.getKey(), missing);
    }
    Files.writeString(work.resolve("knowledge-" + phase + ".json"), ProgramMapping.JSON.toJson(Map.of(
        "original", original.knowledge, "current", current, "lostOrChanged", lost)));
    require(lost.isEmpty(), "original canonical user knowledge lost or changed: " + lost);
  }

  private void verifyRetirement(Snapshot original, Path work, String phase) throws Exception {
    var results = new TreeMap<String, List<String>>();
    for (String name : original.activeViews) {
      var blocks = Arrays.stream(currentProgram.getMemory().getBlocks()).filter(block -> block.getStart().getAddressSpace().getName().equals(name)).toList();
      require(!blocks.isEmpty(), "old active view address-space identity retained " + name);
      var ranges = new ArrayList<String>();
      for (var block : blocks) {
        require(block.isMapped() && !block.isExecute() && block.getComment() != null
            && block.getComment().startsWith("software-call-retired-view-1;"), "old owned view retired without loss of physical mapping " + name);
        require(!currentProgram.getListing().getInstructions(new AddressSet(block.getStart(), block.getEnd()), true).hasNext(), "retired old view has no residual instructions " + name);
        ranges.add(block.getStart() + ":" + block.getEnd() + ":" + block.getSourceInfos());
      }
      for (var function : currentProgram.getFunctionManager().getFunctions(true))
        require(!function.getEntryPoint().getAddressSpace().getName().equals(name), "retired old view has no residual Function " + name);
      results.put(name, ranges);
    }
    Files.writeString(work.resolve("retirement-" + phase + ".json"), ProgramMapping.JSON.toJson(results));
  }

  private void verifyNative(Snapshot original, Path work, String phase) throws Exception {
    var currentTargets = canonicalTargets(option(REGISTRY));
    require(currentTargets.equals(original.canonicalTargets), "original canonical site roster and physical targets retained exactly");
    var decompiler = new DecompInterface();
    var outputs = new ArrayList<String>();
    try {
      require(decompiler.openProgram(currentProgram), "normal public native decompiler open");
      for (var site : new TreeMap<>(original.canonicalTargets).entrySet()) {
        var at = currentProgram.getAddressFactory().getAddress(site.getKey());
        var target = currentProgram.getAddressFactory().getAddress(site.getValue());
        require(SoftwareCallRegistry.resolve(currentProgram, at) != null, "new executable canonical registry resolves " + at);
        var function = currentProgram.getFunctionManager().getFunctionContaining(at);
        require(function != null, "original canonical call site has its retained native Function " + at);
        var result = decompiler.decompileFunction(function, 30, monitor);
        require(result.decompileCompleted(), at + ": " + result.getErrorMessage());
        String c = result.getDecompiledFunction().getC();
        String filename = "canonical-" + at.toString().replaceAll("[^A-Za-z0-9_-]", "_") + "-" + phase + ".c";
        Files.writeString(work.resolve(filename), c); outputs.add(filename);
        boolean physicalCall = false;
        var operations = result.getHighFunction().getPcodeOps();
        while (operations.hasNext()) {
          var operation = operations.next();
          if (operation.getOpcode() == PcodeOp.CALL && operation.getInput(0).getAddress().equals(target)) physicalCall = true;
        }
        require(physicalCall, "original physical native call endpoint retained at " + at + " -> " + target + "\n" + c);
        require(!c.toLowerCase().contains("bad instruction") && !c.toLowerCase().contains("truncating control flow")
            && !c.contains("halt_baddata"), "no hidden native decode/truncation failure at " + at);
      }
    } finally { decompiler.dispose(); }
    Files.writeString(work.resolve("native-roster-" + phase + ".json"), ProgramMapping.JSON.toJson(outputs));
  }

  @Override public void run() throws Exception {
    String[] args = getScriptArgs();
    require(args.length == 2 || args.length == 3, "Expected capture|migrate|check evidence-directory [old-configurations.json]");
    String mode = args[0]; Path work = Path.of(args[1]); Files.createDirectories(work);
    Path capture = work.resolve("actual-v4-capture.json");
    if (mode.equals("capture")) {
      require(!Files.exists(capture), "preserve original actual-v4 capture receipt");
      require(registryVersion(option(REGISTRY)).equals(OLD_VERSION), "capture must run against an actual saved v4 registry");
      var original = snapshot();
      require(!original.instructions.isEmpty() && !original.canonicalTargets.isEmpty() && !original.activeViews.isEmpty(), "nontrivial saved original canonical/view artifact");
      compareRawAndFresh(original, work, "old-provider");
      for (String at : original.canonicalTargets.keySet())
        require(SoftwareCallRegistry.resolve(currentProgram, currentProgram.getAddressFactory().getAddress(at)) != null, "old qualified provider still validates actual saved v4 site " + at);
      Files.writeString(capture, ProgramMapping.JSON.toJson(original));
      Files.writeString(work.resolve("actual-v4-registry.json"), original.registry);
      Files.writeString(work.resolve("actual-v4-ownership.json"), original.ownership);
      if (args.length == 3) Files.copy(Path.of(args[2]), work.resolve("configurations.json"));
      println("SA01_STATE_MIGRATION_CAPTURE_PASS"); return;
    }
    require(mode.equals("migrate") || mode.equals("check"), "unsupported migration mode");
    var original = ProgramMapping.JSON.fromJson(Files.readString(capture), Snapshot.class);
    require(registryVersion(original.registry).equals(OLD_VERSION), "actual old-provider receipt remains v4");
    compareRawAndFresh(original, work, mode + "-before");
    compareKnowledge(original, work, mode + "-before");
    if (mode.equals("migrate")) {
      require(option(REGISTRY).equals(original.registry), "old saved executable records were not silently rewritten on reopen");
      require(option(OWNERSHIP).equals(original.ownership), "old saved ownership was not silently rebaselined on reopen");
      boolean rejected = false;
      try { SoftwareCallRegistry.resolve(currentProgram, currentProgram.getAddressFactory().getAddress(original.canonicalTargets.keySet().iterator().next())); }
      catch (IllegalArgumentException expected) {
        require(expected.getMessage().contains("Incompatible software-call registry"), "expected registry-version migration rejection");
        Files.writeString(work.resolve("expected-old-registry-rejection.txt"), expected.toString() + "\n"); rejected = true;
      }
      require(rejected, "new provider must reject old executable registry without mutating it");
      require(option(REGISTRY).equals(original.registry) && option(OWNERSHIP).equals(original.ownership), "rejection preserves old saved registry and ownership");
      Path configurations = args.length == 3 ? Path.of(args[2]) : work.resolve("configurations.json");
      require(Files.isRegularFile(configurations), "original old-provider configurations are required for review");
      runScript("GhidraBoyTools.java", new String[] {"software-call-remove"});
      verifyRetirement(original, work, "removed-old");
      runScript("GhidraBoyTools.java", new String[] {"software-call-preview", configurations.toString()});
      runScript("GhidraBoyTools.java", new String[] {"software-call-apply", configurations.toString()});
      require(!registryVersion(option(REGISTRY)).equals(OLD_VERSION), "public reapplication writes new versioned executable contract");
      Files.writeString(work.resolve("migrated-registry.json"), option(REGISTRY));
      Files.writeString(work.resolve("migrated-ownership.json"), option(OWNERSHIP));
    } else {
      require(option(REGISTRY).equals(Files.readString(work.resolve("migrated-registry.json"))), "separate-process reopen preserves migrated executable registry");
      require(option(OWNERSHIP).equals(Files.readString(work.resolve("migrated-ownership.json"))), "separate-process reopen preserves migrated ownership");
    }
    compareRawAndFresh(original, work, mode + "-after");
    compareKnowledge(original, work, mode + "-after");
    verifyRetirement(original, work, mode + "-after");
    verifyNative(original, work, mode);
    println("SA01_STATE_MIGRATION_" + mode.toUpperCase() + "_PASS");
  }
}
