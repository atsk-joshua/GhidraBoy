// Fresh-import state-sensitive execution and rooted discovery, using installed public workflows.
// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import java.nio.file.*;
import java.util.*;

public class GhidraBoySa01State extends GhidraScript {
  private void require(boolean condition, String reason) { if (!condition) throw new AssertionError(reason); }

  private Address physical(long offset) throws Exception {
    long cpu = offset < 0x4000 ? offset : 0x4000 + offset % 0x4000;
    var values = ProgramMapping.fileToStatic(currentProgram, offset).stream()
        .filter(a -> a.getOffset() == cpu && !a.getAddressSpace().getName().startsWith(SoftwareCallExecutionView.PREFIX)).toList();
    require(values.size() == 1, "unique canonical physical source " + Long.toHexString(offset));
    return values.get(0);
  }

  private List<SoftwareCallValidation.Configuration> configurations() {
    return List.of(new SoftwareCallValidation.Configuration(0x4500,
        new SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null),
        SoftwareCallModel.EntryTransfer.HARDWARE_RST, 0xc100,
        new SoftwareCallModel.Registers(2, 0, 0, 0, 0x4000), MapperState.reset()),
        new SoftwareCallValidation.Configuration(0x150,
        new SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x200, 3, null),
        SoftwareCallModel.EntryTransfer.HARDWARE_CALL, 0xc100,
        new SoftwareCallModel.Registers(0, 0, 0, 0, 0), MapperState.reset()),
        new SoftwareCallValidation.Configuration(0x180,
        new SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null),
        SoftwareCallModel.EntryTransfer.HARDWARE_RST, 0xc100,
        new SoftwareCallModel.Registers(2, 0, 0, 0, 0x4600), MapperState.reset()),
        new SoftwareCallValidation.Configuration(0x190,
        new SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null),
        SoftwareCallModel.EntryTransfer.HARDWARE_RST, 0xc100,
        new SoftwareCallModel.Registers(2, 0x80, 0, 0, 0x4600), MapperState.reset()));
  }

  private Address alias() throws Exception {
    String registry = currentProgram.getOptions(ProgramMapping.OPTIONS).getString(SoftwareCallRegistry.KEY, "");
    var sites = com.google.gson.JsonParser.parseString(registry).getAsJsonObject().getAsJsonArray("sites");
    String canonical = physical(0x4500).toString();
    for (var value : sites) {
      var site = value.getAsJsonObject();
      if (site.get("address").getAsString().equals(canonical)) {
        require(site.get("stateContinuation").getAsBoolean(), "saved state continuation capability");
        return ProgramMapping.staticAddress(currentProgram, site.get("executionAlias").getAsString());
      }
    }
    throw new AssertionError("missing canonical registry entry");
  }

  private void tools(String action, Path work) throws Exception {
    runScript("GhidraBoyTools.java", action.equals("software-call-remove")
        ? new String[] {action} : new String[] {action, work.resolve("configurations.json").toString()});
  }

  private String inventory() throws Exception {
    var fields = new ArrayList<String>();
    for (var instruction : currentProgram.getListing().getInstructions(true))
      fields.add("instruction:" + instruction.getAddress() + ":" + instruction.getLength() + ":"
          + HexFormat.of().formatHex(instruction.getBytes()) + ":" + instruction.getFlowOverride() + ":"
          + instruction.isFallThroughOverridden() + ":" + instruction.getFallThrough());
    for (var data : currentProgram.getListing().getDefinedData(true))
      fields.add("data:" + data.getAddress() + ":" + data.getLength() + ":" + data.getDataType().getPathName());
    for (var function : currentProgram.getFunctionManager().getFunctions(true))
      fields.add("function:" + function.getID() + ":" + function.getEntryPoint() + ":" + function.getName(true)
          + ":" + function.getBody() + ":" + function.hasNoReturn() + ":" + function.getCallFixup()
          + ":" + function.getComment() + ":" + function.getCallingConventionName()
          + ":" + function.getPrototypeString(true, true) + ":" + function.getSignatureSource()
          + ":" + function.getStackPurgeSize() + ":" + function.getReturn().getVariableStorage()
          + ":locals=" + java.util.Arrays.toString(function.getLocalVariables()));
    for (var symbol : currentProgram.getSymbolTable().getAllSymbols(true))
      if (!symbol.isDynamic()) fields.add("symbol:" + symbol.getID() + ":" + symbol.getAddress() + ":"
          + symbol.getName(true) + ":" + symbol.getSource() + ":" + symbol.isPrimary() + ":" + symbol.isPinned());
    var sources = currentProgram.getReferenceManager().getReferenceSourceIterator(currentProgram.getMemory(), true);
    while (sources.hasNext())
      for (var reference : currentProgram.getReferenceManager().getReferencesFrom(sources.next()))
        fields.add("reference:" + reference.getFromAddress() + ":" + reference.getToAddress() + ":"
            + reference.getReferenceType() + ":" + reference.getSource() + ":" + reference.getOperandIndex()
            + ":" + reference.isPrimary() + ":" + reference.getSymbolID());
    for (var block : currentProgram.getMemory().getBlocks()) {
      fields.add("block:" + block.getStart() + ":" + block.getSize() + ":" + block.getFlags() + ":" + block.getComment());
      for (var source : block.getSourceInfos()) fields.add("mapping:" + block.getStart() + ":" + source.getMappedRange());
    }
    for (long file : new long[] {0x153, 0x154, 0x300, 0x810a, 0xc200})
      for (var type : CommentType.values()) fields.add("comment:" + file + ":" + type + ":"
          + currentProgram.getListing().getComment(type, physical(file)));
    for (String key : List.of(SoftwareCallRegistry.KEY, "analysis.ownership.v1"))
      fields.add("option:" + key + ":" + (currentProgram.getOptions(ProgramMapping.OPTIONS).contains(key)
          ? currentProgram.getOptions(ProgramMapping.OPTIONS).getString(key, null) : "absent"));
    Collections.sort(fields);
    return ProgramMapping.JSON.toJson(fields);
  }

  private void savedInventory(Path work, boolean write) throws Exception {
    String actual = currentProgram.getOptions(ProgramMapping.OPTIONS).getString("softwareCall.review.inventory.v1", "");
    require(!actual.isBlank(), "saved public review inventory");
    if (write) Files.writeString(work.resolve("current-review-inventory.json"), actual);
    else require(actual.equals(Files.readString(work.resolve("current-review-inventory.json"))), "review inventory survives separate process and ordinary analysis");
  }

  private void verifyPreserved(Path work) throws Exception {
    var listing = currentProgram.getListing();
    for (String name : List.of("state_source", "inline_source", "initial_target", "ordinary_target", "bank3_data", "bank2_data", "preserved_user_label"))
      require(currentProgram.getSymbolTable().getSymbols(name).hasNext(), "preserved user name " + name);
    require(listing.getDefinedDataAt(toAddr(0x153)).getLength() == 1, "original bank payload byte");
    require(listing.getDefinedDataAt(toAddr(0x154)).getLength() == 2, "original target payload word");
    for (int cpu = 0x153; cpu <= 0x155; cpu++) require(listing.getInstructionContaining(toAddr(cpu)) == null, "payload never decoded");
    require("User payload description".equals(listing.getComment(CommentType.EOL, toAddr(0x154))), "payload comment retained");
    require(currentProgram.getReferenceManager().getReferencesFrom(toAddr(0x350)).length == 1, "original user reference count");
    var reference = currentProgram.getReferenceManager().getReferencesFrom(toAddr(0x350))[0];
    require(reference.getToAddress().equals(physical(0xc200)) && reference.getSource() == SourceType.USER_DEFINED
        && reference.getReferenceType() == RefType.DATA && reference.getOperandIndex() == 0, "original user data reference retained");
    var original = com.google.gson.JsonParser.parseString(Files.readString(work.resolve("fresh-discovery-plan.json")))
        .getAsJsonObject().getAsJsonArray("candidates");
    for (var element : original) {
      var candidate = element.getAsJsonObject();
      var at = ProgramMapping.staticAddress(currentProgram, candidate.get("address").getAsString());
      var instruction = listing.getInstructionAt(at);
      require(instruction != null && instruction.getLength() == candidate.get("length").getAsInt()
          && HexFormat.of().formatHex(instruction.getBytes()).equals(candidate.get("bytes").getAsString()),
          "discovered canonical instruction survives save/reapply/remove " + at);
    }
    if (Files.exists(work.resolve("edited.marker"))) {
      require("Later user bank-data note".equals(listing.getComment(CommentType.EOL, physical(0xc200))), "saved bank-data comment");
      require("Later user continuation note".equals(listing.getComment(CommentType.EOL, physical(0x810a))), "saved continuation comment");
      require((currentProgram.getMemory().getByte(physical(0xc200)) & 255) == 0xb8, "saved patch distinct from original bank data");
    }
    var shared = currentProgram.getFunctionManager().getFunctionAt(physical(0x8600));
    require(shared != null, "prepared original shared callee Function survives");
    if (Files.exists(work.resolve("callee-edited.marker"))) {
      require(shared.getName().equals("shared_state_callee_user_renamed"), "late user callee rename retained");
      require("Later callee user note".equals(shared.getComment()), "late user callee comment retained");
    } else {
      require(shared.getName().equals("shared_state_callee"), "original shared callee name retained");
      require(shared.getComment() != null && shared.getComment().contains("Original shared callee note"), "original callee note survives context annotation");
    }
  }

  private void verifyNative(DecompInterface decompiler, Address entry, List<Address> calls,
      Map<Integer, Integer> writes, Path output) throws Exception {
    verifyNativeCode(decompiler, entry, calls, writes, output, false);
  }

  private void verifyNativeCode(DecompInterface decompiler, Address entry, List<Address> calls,
      Map<Integer, Integer> writes, Path output, boolean validatedStateEntry) throws Exception {
    if (!validatedStateEntry)
      require(SoftwareCallRegistry.resolve(currentProgram, entry) != null, "live canonical/alias registry " + entry);
    var function = currentProgram.getFunctionManager().getFunctionAt(entry);
    require(function != null, "normal navigable Function " + entry);
    var result = decompiler.decompileFunction(function, 30, monitor);
    require(result.decompileCompleted(), entry + ": " + result.getErrorMessage());
    String c = result.getDecompiledFunction().getC();
    Files.writeString(output, c);
    require(!c.toLowerCase().contains("bad instruction") && !c.toLowerCase().contains("truncating control flow")
        && !c.contains("halt_baddata"), "native code has no bad-instruction or truncation failure " + entry);
    var operations = new ArrayList<PcodeOp>();
    var iterator = result.getHighFunction().getPcodeOps();
    while (iterator.hasNext()) operations.add(iterator.next());
    for (var call : calls) require(operations.stream().anyMatch(op -> op.getOpcode() == PcodeOp.CALL
        && op.getInput(0).getAddress().equals(call)), "native physical call " + call + " from " + entry + "\n" + c);
    for (var expected : writes.entrySet()) require(operations.stream().anyMatch(op ->
        (op.getOpcode() == PcodeOp.COPY && op.getOutput() != null && op.getOutput().getAddress().equals(toAddr(expected.getKey()))
            && op.getInput(0).isConstant() && op.getInput(0).getOffset() == expected.getValue())
        || (op.getOpcode() == PcodeOp.STORE && op.getInput(1).isConstant() && op.getInput(1).getOffset() == expected.getKey()
            && op.getInput(2).isConstant() && op.getInput(2).getOffset() == expected.getValue())),
        "native memory result " + Integer.toHexString(expected.getKey()) + "=" + expected.getValue() + "\n" + c);
    require(operations.stream().anyMatch(op -> op.getOpcode() == PcodeOp.RETURN), "actual live return remains " + entry);
  }

  private int contextValue(SoftwareCallRegistry.StateContext context) {
    int flags = context.entryState().registers().f();
    require(flags == 0 || flags == 0x80, "fixture context flags are exact");
    require(context.entryState().cpu() == 0x4600 && context.entryState().sp() == 0xc0fe,
        "callee entry context retains 16-bit PC and live caller frame");
    return flags == 0 ? 0x33 : 0x22;
  }

  private void exerciseContextSelection(Path work, String phase) throws Exception {
    var canonical = physical(0x8600);
    runScript("GhidraBoyTools.java", new String[] {"software-call-contexts", canonical.toString()});
    var contexts = SoftwareCallRegistry.stateContexts(currentProgram, canonical, monitor);
    require(contexts.size() == 2, "same Program retains both flag-qualified physical callee contexts");
    var decompiler = new DecompInterface();
    try {
      require(decompiler.openProgram(currentProgram), "context-selection native interface");
      for (var context : contexts) {
        runScript("GhidraBoyTools.java", new String[] {"software-call-select-context", canonical.toString(), context.entry()});
        var selected = SoftwareCallRegistry.stateContexts(currentProgram, canonical, monitor).stream().filter(SoftwareCallRegistry.StateContext::selected).toList();
        require(selected.size() == 1 && selected.get(0).entry().equals(context.entry()), "public canonical selection exposes exact selected source");
        verifyNativeCode(decompiler, canonical, List.of(), Map.of(0xc211, contextValue(context)),
            work.resolve("context-selected-" + context.entryState().registers().f() + "-" + phase + ".c"), true);
        require(currentProgram.getFunctionManager().getFunctionAt(canonical).getComment().contains("Original shared callee note"),
            "context selection preserves original callee comment");
        Files.writeString(work.resolve("selected-context.json"), ProgramMapping.JSON.toJson(Map.of(
            "canonical", canonical.toString(), "site", context.site(), "entry", context.entry(), "expected", contextValue(context))));
      }
    } finally { decompiler.dispose(); }
    Files.writeString(work.resolve("contexts-" + phase + ".json"), ProgramMapping.JSON.toJson(SoftwareCallRegistry.stateContexts(currentProgram, canonical, monitor)));
  }

  private void verifyContexts(DecompInterface decompiler, Path work, String phase) throws Exception {
    var canonical = physical(0x8600);
    var contexts = SoftwareCallRegistry.stateContexts(currentProgram, canonical, monitor);
    require(contexts.size() == 2, "saved per-context callee entries survive ordinary analysis and reopen");
    var selected = contexts.stream().filter(SoftwareCallRegistry.StateContext::selected).toList();
    var saved = com.google.gson.JsonParser.parseString(Files.readString(work.resolve("selected-context.json"))).getAsJsonObject();
    require(selected.size() == 1 && selected.get(0).site().equals(saved.get("site").getAsString())
        && selected.get(0).entry().equals(saved.get("entry").getAsString()), "saved canonical context selection has exact source site and alias identity");
    var payload = currentProgram.getCompilerSpec().getPcodeInjectLibrary().getPayload(InjectPayload.CALLMECHANISM_TYPE, SoftwareCallStateEntryInjection.NAME);
    require(payload != null, "installed native entry-context protocol payload");
    for (var context : contexts) {
      var entry = ProgramMapping.staticAddress(currentProgram, context.entry());
      require(ProgramMapping.staticToPhysical(currentProgram, entry).equals(ProgramMapping.staticToPhysical(currentProgram, canonical)),
          "callee context aliases share original physical source bytes");
      var injection = new InjectContext(); injection.baseAddr = entry; injection.nextAddr = entry;
      require(payload.getPcode(currentProgram, injection).length > 0, "context entry payload independently validates");
      int expected = contextValue(context);
      String suffix = Integer.toHexString(context.entryState().registers().f()) + "-" + phase;
      verifyNativeCode(decompiler, entry, List.of(), Map.of(0xc211, expected), work.resolve("context-alias-" + suffix + ".c"), true);
      verifyNative(decompiler, ProgramMapping.staticAddress(currentProgram, context.site()), List.of(entry), Map.of(),
          work.resolve("context-caller-" + suffix + ".c"));
    }
    verifyNativeCode(decompiler, canonical, List.of(), Map.of(0xc211, saved.get("expected").getAsInt()),
        work.resolve("context-canonical-" + phase + ".c"), true);
    Files.writeString(work.resolve("contexts-verified-" + phase + ".json"), ProgramMapping.JSON.toJson(contexts));
  }

  private void cancelledContextSelection(Path work) throws Exception {
    var canonical = physical(0x8600);
    var contexts = SoftwareCallRegistry.stateContexts(currentProgram, canonical, monitor);
    var alternative = contexts.stream().filter(context -> !context.selected()).findFirst().orElseThrow();
    var function = currentProgram.getFunctionManager().getFunctionAt(canonical);
    String comment = function.getComment();
    String before = inventory();
    boolean[] sawMutation = {false};
    var cancellation = new TaskMonitorAdapter(true) {
      @Override public void checkCancelled() throws CancelledException {
        if (!Objects.equals(currentProgram.getFunctionManager().getFunctionAt(canonical).getComment(), comment)) {
          sawMutation[0] = true; throw new CancelledException();
        }
        super.checkCancelled();
      }
    };
    boolean cancelled = false;
    try { SoftwareCallRegistry.selectStateContext(currentProgram, canonical,
        ProgramMapping.staticAddress(currentProgram, alternative.entry()), cancellation); }
    catch (CancelledException expected) { cancelled = true; }
    require(cancelled && sawMutation[0], "selection cancellation follows actual context-comment mutation");
    require(before.equals(inventory()), "cancelled context selection rolls back registry ownership comment and selected context");
    require(contexts.equals(SoftwareCallRegistry.stateContexts(currentProgram, canonical, monitor)), "cancelled selection preserves every context identity");
    Files.writeString(work.resolve("cancelled-context-selection-inventory.json"), before);
  }

  private void verify(Path work, String phase) throws Exception {
    verifyPreserved(work); savedInventory(work, false);
    var root = physical(0x4500);
    var paired = alias();
    var validated = SoftwareCallRegistry.resolve(currentProgram, root);
    var effects = SoftwareCallRegistry.effects(currentProgram, validated, monitor);
    require(effects.nativeCompatible(), "initial raw callee proof remains native-compatible");
    var graph = SoftwareCallEffects.deriveContinuation(currentProgram, validated.frame(), effects.paths().get(0), configurations(), monitor);
    SoftwareCallContinuationView.requireTransport(currentProgram, graph, monitor);
    require(graph.steps().stream().filter(step -> step.before().cpu() == 0x4100).map(step -> step.before().physical().bank()).toList().equals(List.of(3, 2)),
        "same CPU address retains competing physical bank fetches");
    var later = graph.steps().stream().filter(step -> step.physicalTarget() != null && step.physicalTarget().equals(toAddr(0x260).toString())
        && step.afterCall() != null).findFirst().orElseThrow();
    require(later.afterCall().sp() == 0xc100 && later.afterCall().registers().a() == 0x5b
        && later.afterCall().registers().f() == 0x10, "later ordinary call restores live frame and carries A/F");
    require(graph.steps().stream().flatMap(step -> step.accesses().stream()).filter(access -> !access.write() && access.cpu() == 0x4200)
        .map(access -> access.physical().bank()).toList().equals(List.of(3, 2)), "code and banked data identities remain distinct");
    Files.writeString(work.resolve("graph-" + phase + ".json"), ProgramMapping.JSON.toJson(graph));
    Files.writeString(work.resolve("inventory-" + phase + ".json"), inventory());
    Files.writeString(work.resolve("navigation-" + phase + ".json"), ProgramMapping.JSON.toJson(Map.of(
        "canonical", root.toString(), "alias", paired.toString(), "initialTarget", physical(0x8000).toString(), "laterTarget", toAddr(0x260).toString())));
    int bank3 = Files.exists(work.resolve("edited.marker")) ? 0xb8 : 0xa7;
    var decompiler = new DecompInterface();
    try {
      require(decompiler.openProgram(currentProgram), "normal native decompiler open");
      var writes = Map.of(0xc210, bank3, 0xc211, 0x5c, 0xc212, 0x5b);
      var calls = List.of(physical(0x8000), toAddr(0x260));
      verifyNative(decompiler, root, calls, writes, work.resolve("canonical-" + phase + ".c"));
      verifyNative(decompiler, paired, calls, writes, work.resolve("alias-" + phase + ".c"));
      verifyNative(decompiler, toAddr(0x150), List.of(physical(0x8400)), Map.of(0xc214, 0x6a), work.resolve("inline-" + phase + ".c"));
      verifyContexts(decompiler, work, phase);
    } finally { decompiler.dispose(); }
  }

  private void verifyRemoved(Path work, boolean reopened) throws Exception {
    verifyPreserved(work);
    require(!currentProgram.getOptions(ProgramMapping.OPTIONS).contains(SoftwareCallRegistry.KEY), "executable registry removed");
    var shared = currentProgram.getFunctionManager().getFunctionAt(physical(0x8600));
    require(ProgramMapping.JSON.toJson(shared.getCallingConventionName()).equals(Files.readString(work.resolve("original-callee-convention.json"))),
        "original callee convention restored despite later name/comment edits");
    require(!SoftwareCallStateEntryInjection.CONVENTION.equals(shared.getCallingConventionName()), "removed callee has no registry-dependent entry protocol");
    var retired = new TreeSet<String>();
    for (var block : currentProgram.getMemory().getBlocks()) {
      if (block.getComment() == null || !block.getComment().startsWith("software-call-retired-view-1;")) continue;
      retired.add(block.getStart().getAddressSpace().getName());
      require(!block.isExecute() && block.isMapped(), "retired view retains shared physical mapping");
      require(!currentProgram.getListing().getInstructions(new AddressSet(block.getStart(), block.getEnd()), true).hasNext(), "retired view instructions absent");
    }
    require(!retired.isEmpty(), "state fragments retain saved address identities after removal");
    for (var function : currentProgram.getFunctionManager().getFunctions(true))
      require(!retired.contains(function.getEntryPoint().getAddressSpace().getName()), "retired view Function absent");
    String names = String.join("\n", retired) + "\n";
    if (reopened) require(names.equals(Files.readString(work.resolve("retired-spaces.txt"))), "retired identities survive separate-process reopen");
    else Files.writeString(work.resolve("retired-spaces.txt"), names);
    Files.writeString(work.resolve(reopened ? "removed-reopened-inventory.json" : "removed-inventory.json"), inventory());
  }

  @Override public void run() throws Exception {
    String mode = getScriptArgs()[0];
    Path work = Path.of(getScriptArgs()[1]);
    if (mode.equals("prepare")) {
      for (long file : new long[] {0x28, 0x150, 0x180, 0x190, 0x200, 0x240, 0x260, 0x300, 0x4500,
          0x8000, 0x8100, 0x8400, 0x8501, 0x8600, 0x8620, 0x8700, 0xc100, 0xc608, 0xc700}) {
        require(currentProgram.getListing().getInstructionAt(physical(file)) == null, "genuinely fresh instruction root " + file);
        require(currentProgram.getFunctionManager().getFunctionAt(physical(file)) == null, "genuinely fresh function root " + file);
      }
      for (var name : Map.of(0x4500L, "state_source", 0x150L, "inline_source", 0x8000L, "initial_target",
          0x260L, "ordinary_target", 0xc200L, "bank3_data", 0x8200L, "bank2_data", 0x350L, "preserved_user_label",
          0x180L, "context_caller_clear_z", 0x190L, "context_caller_set_z").entrySet())
        currentProgram.getSymbolTable().createLabel(physical(name.getKey()), name.getValue(), SourceType.USER_DEFINED);
      // This one annotation fixture is intentionally prepared separately from the fully fresh
      // state/inline roots. Its bytes still have no Instructions and never establish decoder proof.
      var sharedEntry = physical(0x8600);
      var shared = currentProgram.getFunctionManager().createFunction("shared_state_callee", sharedEntry,
          new AddressSet(sharedEntry, sharedEntry.add(7)), SourceType.USER_DEFINED);
      shared.setComment("Original shared callee note");
      Files.writeString(work.resolve("original-callee-convention.json"), ProgramMapping.JSON.toJson(shared.getCallingConventionName()));
      Files.writeString(work.resolve("fresh-versus-prepared.json"), ProgramMapping.JSON.toJson(Map.of(
          "fullyFreshFunctions", List.of(physical(0x4500).toString(), toAddr(0x150).toString(), toAddr(0x180).toString(), toAddr(0x190).toString()),
          "preparedAnnotationOnlyFunction", sharedEntry.toString(), "allConsumedInstructionsAbsent", true,
          "originalName", shared.getName(), "originalComment", shared.getComment())));
      currentProgram.getListing().createData(toAddr(0x153), ByteDataType.dataType);
      currentProgram.getListing().createData(toAddr(0x154), WordDataType.dataType);
      currentProgram.getListing().createData(physical(0xc200), ByteDataType.dataType);
      currentProgram.getListing().createData(physical(0x8200), ByteDataType.dataType);
      currentProgram.getListing().setComment(toAddr(0x154), CommentType.EOL, "User payload description");
      currentProgram.getReferenceManager().addMemoryReference(toAddr(0x350), physical(0xc200), RefType.DATA, SourceType.USER_DEFINED, 0);
      Files.writeString(work.resolve("configurations.json"), ProgramMapping.JSON.toJson(configurations()));
      String before = inventory();
      tools("software-call-preview", work);
      var review = SoftwareCallApplication.preview(currentProgram, configurations(), monitor);
      require(before.equals(inventory()), "public preview has no committed speculative decoding");
      require(review.instructionDiscovery().candidates().size() > 20, "rooted closure includes missing helpers callees continuations");
      Files.writeString(work.resolve("fresh-discovery-plan.json"), ProgramMapping.JSON.toJson(review.instructionDiscovery()));
      var cancelled = new TaskMonitorAdapter(true); cancelled.cancel();
      boolean rejected = false;
      try { SoftwareCallApplication.apply(currentProgram, review, cancelled); }
      catch (CancelledException expected) { rejected = true; }
      require(rejected && before.equals(inventory()), "cancelled application preserves fresh instructions functions data references and labels");
      Files.writeString(work.resolve("cancelled-preview-inventory.json"), before);
      tools("software-call-apply", work); exerciseContextSelection(work, "fresh"); savedInventory(work, true);
      Files.writeString(work.resolve("inventory-prepared.json"), inventory());
    } else if (mode.equals("context-cancel")) {
      verifyPreserved(work); savedInventory(work, false); cancelledContextSelection(work);
    } else if (mode.equals("verify")) {
      Files.writeString(work.resolve("inventory-before-verify.json"), inventory());
      String phase = Files.exists(work.resolve("edited.marker")) ? "patched" : Files.exists(work.resolve("annotated.marker")) ? "annotated" : Files.exists(work.resolve("verified.marker")) ? "reopened" : "fresh";
      verify(work, phase); Files.writeString(work.resolve("verified.marker"), phase);
    } else if (mode.equals("annotated-reapply")) {
      tools("software-call-remove", work);
      var ordinary = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x260));
      if (ordinary == null) ordinary = currentProgram.getFunctionManager().createFunction("ordinary_target", toAddr(0x260), new AddressSet(toAddr(0x260), toAddr(0x263)), SourceType.USER_DEFINED);
      ordinary.setNoReturn(true);
      currentProgram.getListing().getInstructionAt(physical(0x8107)).setFlowOverride(FlowOverride.CALL_RETURN);
      currentProgram.getListing().getInstructionAt(toAddr(0x150)).setFlowOverride(FlowOverride.CALL_RETURN);
      var review = SoftwareCallApplication.preview(currentProgram, configurations(), monitor);
      require(review.nestedRepairs().stream().anyMatch(repair -> repair.site().equals(physicalUnchecked(0x8107).toString()) && repair.originalNoReturn()
          && repair.originalFlow().equals("CALL_RETURN")), "reviewed later ordinary-call repair has exact original annotations");
      Files.writeString(work.resolve("annotated-review.json"), ProgramMapping.JSON.toJson(review.nestedRepairs()));
      tools("software-call-apply", work); exerciseContextSelection(work, "annotated"); savedInventory(work, true);
      Files.writeString(work.resolve("annotated.marker"), "reviewed false nonreturn and call flow");
    } else if (mode.equals("edit")) {
      verifyPreserved(work); savedInventory(work, false);
      currentProgram.getListing().setComment(physical(0xc200), CommentType.EOL, "Later user bank-data note");
      currentProgram.getListing().setComment(physical(0x810a), CommentType.EOL, "Later user continuation note");
      currentProgram.getMemory().setByte(physical(0xc200), (byte) 0xb8);
      Files.writeString(work.resolve("edited.marker"), "bank3 original a7; current patched b8");
    } else if (mode.equals("stale-reapply")) {
      verifyPreserved(work);
      var rejected = new ArrayList<String>();
      for (var entry : List.of(physical(0x4500), alias())) {
        try { SoftwareCallRegistry.resolve(currentProgram, entry); }
        catch (IllegalArgumentException expected) {
          require(expected.getMessage().contains("Stale software-call dependencies") || expected.getMessage().contains("Software-call annotations changed after review"), "expected stale saved rejection reason");
          rejected.add(entry + ": " + expected.getMessage());
        }
      }
      require(rejected.size() == 2, "both saved canonical and alias reject consumed physical-data drift");
      Files.writeString(work.resolve("expected-saved-rejections.json"), ProgramMapping.JSON.toJson(rejected));
      tools("software-call-remove", work); tools("software-call-apply", work); exerciseContextSelection(work, "patched"); savedInventory(work, true);
    } else if (mode.equals("remove")) {
      verifyPreserved(work);
      var shared = currentProgram.getFunctionManager().getFunctionAt(physical(0x8600));
      shared.setName("shared_state_callee_user_renamed", SourceType.USER_DEFINED);
      shared.setComment("Later callee user note");
      Files.writeString(work.resolve("callee-edited.marker"), "rename/comment retain original calling convention on public removal");
      tools("software-call-remove", work); verifyRemoved(work, false);
    } else if (mode.equals("removed-verify")) verifyRemoved(work, false);
    else if (mode.equals("removed-reopen")) verifyRemoved(work, true);
    else throw new IllegalArgumentException(mode);
    println("SA01_STATE_" + mode.toUpperCase().replace('-', '_') + "_PASS");
  }

  private Address physicalUnchecked(long offset) {
    try { return physical(offset); } catch (Exception failure) { throw new IllegalArgumentException(failure); }
  }
}
