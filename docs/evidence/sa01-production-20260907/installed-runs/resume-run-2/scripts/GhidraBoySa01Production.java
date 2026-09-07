// Installed public-workflow qualification using only self-authored cartridge bytes.
// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.util.*;

public class GhidraBoySa01Production extends GhidraScript {
  private void require(boolean condition, String reason) { if (!condition) throw new AssertionError(reason); }
  private List<SoftwareCallValidation.Configuration> configurations() throws Exception {
    var template = new SoftwareCallModel.Template(SoftwareCallModel.Family.INLINE_RET, 0x200, 3, null);
    var result = new ArrayList<>(List.of(0x150, 0x160).stream().map(site -> new SoftwareCallValidation.Configuration(site, template,
        SoftwareCallModel.EntryTransfer.HARDWARE_CALL, 0xc100,
        new SoftwareCallModel.Registers(0, 0x80, 0, 0, 0), MapperState.reset())).toList());
    result.add(new SoftwareCallValidation.Configuration(0x4200,
        new SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x28, 0, null),
        SoftwareCallModel.EntryTransfer.HARDWARE_RST, 0xc100,
        new SoftwareCallModel.Registers(2, 0, 0, 0, 0x4300), MapperState.reset()));
    result.add(new SoftwareCallValidation.Configuration(0x4500, template,
        SoftwareCallModel.EntryTransfer.HARDWARE_CALL, 0xc100,
        new SoftwareCallModel.Registers(0, 0x80, 0, 0, 0), MapperState.reset()));
    result.add(new SoftwareCallValidation.Configuration(0x170,
        new SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x300, 0, null),
        SoftwareCallModel.EntryTransfer.HARDWARE_CALL, 0xc100,
        new SoftwareCallModel.Registers(2, 0x80, 0, 0, 0x4600), MapperState.reset()));
    result.add(new SoftwareCallValidation.Configuration(0x4608,
        new SoftwareCallModel.Template(SoftwareCallModel.Family.RESTORING_REGISTER_JP, 0x320, 0, null),
        SoftwareCallModel.EntryTransfer.HARDWARE_CALL, 0xc0fe,
        new SoftwareCallModel.Registers(2, 0x80, 3, 0, 0x4300),
        MapperState.reset().write(ProgramMapping.cartridge(currentProgram), 0x2000, 2)));
    result.add(new SoftwareCallValidation.Configuration(0x4700,
        new SoftwareCallModel.Template(SoftwareCallModel.Family.RESTORING_REGISTER_JP, 0x320, 0, null),
        SoftwareCallModel.EntryTransfer.HARDWARE_CALL, 0xc100,
        new SoftwareCallModel.Registers(1, 0x80, 2, 0, 0x4400), MapperState.reset()));
    for (int site : new int[] {0x4800, 0x180}) result.add(new SoftwareCallValidation.Configuration(site,
        new SoftwareCallModel.Template(SoftwareCallModel.Family.CONSTANT_REGISTER_JP, 0x340, 0, 3),
        SoftwareCallModel.EntryTransfer.HARDWARE_CALL, 0xc100,
        new SoftwareCallModel.Registers(2, 0x80, 0, 0, site == 0x180 ? 0x4900 : 0x4400), MapperState.reset()));
    result.add(new SoftwareCallValidation.Configuration(0x190,
        new SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP, 0x300, 0, null),
        SoftwareCallModel.EntryTransfer.HARDWARE_CALL, 0xc100,
        new SoftwareCallModel.Registers(2, 0x80, 0, 0, 0x4a00), MapperState.reset()));
    return result;
  }
  private ghidra.program.model.address.Address physical(long file) throws Exception {
    return ProgramMapping.fileToStatic(currentProgram, file).stream()
        .filter(a -> !a.getAddressSpace().getName().startsWith(SoftwareCallExecutionView.PREFIX)).findFirst().orElseThrow();
  }
  private void prepareFunction(Disassembler dis, long file, int length, String name) throws Exception {
    var at = physical(file);
    dis.disassemble(at, new AddressSet(at, at.add(length - 1)));
    currentProgram.getFunctionManager().createFunction(name, at, new AddressSet(at, at.add(length - 1)), SourceType.USER_DEFINED);
  }
  private ghidra.app.decompiler.DecompileResults verifyNative(DecompInterface decompiler,
      ghidra.program.model.address.Address source, ghidra.program.model.address.Address target, String name, Path work) throws Exception {
    var result = decompiler.decompileFunction(currentProgram.getFunctionManager().getFunctionAt(source), 30, monitor);
    require(result.decompileCompleted(), name + ": " + result.getErrorMessage());
    boolean physicalCall = false;
    var ops = result.getHighFunction().getPcodeOps();
    while (ops.hasNext()) {
      var op = ops.next();
      if (op.getOpcode() == PcodeOp.CALL && target.equals(op.getInput(0).getAddress())) physicalCall = true;
    }
    require(physicalCall, name + " physical native CALL endpoint: " + result.getDecompiledFunction().getC());
    Files.writeString(work.resolve(name + ".c"), result.getDecompiledFunction().getC());
    return result;
  }
  private void verifyNestedRepairInventory(Path work) throws Exception {
    Path expected = work.resolve("reapplied-inventory.json");
    if (!Files.exists(expected)) return;
    String actual = currentProgram.getOptions(ProgramMapping.OPTIONS).getString("softwareCall.review.inventory.v1", "");
    require(actual.equals(Files.readString(expected)), "saved nested repair inventory survives ordinary analysis/reopen");
    var repairs = com.google.gson.JsonParser.parseString(actual).getAsJsonObject().getAsJsonArray("nestedRepairs");
    boolean found = false;
    for (var element : repairs) {
      var repair = element.getAsJsonObject();
      if (!ProgramMapping.staticAddress(currentProgram, repair.get("site").getAsString()).equals(physical(0xc300))) continue;
      require(ProgramMapping.staticAddress(currentProgram, repair.get("target").getAsString()).equals(toAddr(0x360)), "nested repair target identity");
      require(repair.get("originalNoReturn").getAsBoolean(), "nested repair records original false noReturn");
      require(repair.get("originalFlow").getAsString().equals("CALL_RETURN") && repair.get("appliedFlow").getAsString().equals("NONE"),
          "nested repair records CALL_RETURN to NONE migration");
      found = true;
    }
    require(found, "saved reviewed ordinary nested repair row");
  }
  private void verifyRemoved(Path work, boolean reopened) throws Exception {
    require(toAddr(0x15a).equals(currentProgram.getListing().getInstructionAt(toAddr(0x150)).getFallThrough()), "final saved user continuation");
    require("Later user payload note".equals(currentProgram.getListing().getComment(CommentType.EOL, toAddr(0x153))), "final saved user payload note");
    require(!AnalysisOwnership.softwareCallCurrent(currentProgram, toAddr(0x160)), "removed executable ownership remains absent");
    var retired = new TreeSet<String>();
    for (var block : currentProgram.getMemory().getBlocks()) {
      if (block.getComment() == null || !block.getComment().startsWith("software-call-retired-view-1;")) continue;
      retired.add(block.getStart().getAddressSpace().getName());
      require(!block.isExecute() && block.isMapped(), "retired view keeps non-executable shared mapping");
      require(!currentProgram.getListing().getInstructions(new AddressSet(block.getStart(), block.getEnd()), true).hasNext(), "retired listing stays cleared");
    }
    require(!retired.isEmpty(), "removal retains address-space identities");
    for (var function : currentProgram.getFunctionManager().getFunctions(true))
      require(!retired.contains(function.getEntryPoint().getAddressSpace().getName()), "retired view has no residual function");
    Path inventory = work.resolve("retired-spaces.txt");
    String contents = String.join("\n", retired) + "\n";
    if (reopened) require(contents.equals(Files.readString(inventory)), "saved retirement identity inventory");
    else Files.writeString(inventory, contents);
  }
  @Override public void run() throws Exception {
    String mode = getScriptArgs()[0];
    Path work = Path.of(getScriptArgs()[1]);
    if (mode.equals("prepare")) {
      // Import itself does not establish helper/callee instruction boundaries. Record this
      // separately before deliberately preparing the reproducible installed lifecycle fixture.
      require(currentProgram.getListing().getInstructionAt(toAddr(0x200)) == null, "fresh helper instruction absent");
      boolean missingRejected = false;
      try { SoftwareCallApplication.preview(currentProgram, configurations(), monitor); }
      catch (IllegalArgumentException expected) {
        missingRejected = true;
        Files.writeString(work.resolve("fresh-discovery-rejection.txt"), expected.toString() + "\n");
      }
      require(missingRejected, "unprepared import cannot claim a validated helper");
      var dis = Disassembler.getDisassembler(currentProgram, monitor, null);
      dis.disassemble(toAddr(0x200), new AddressSet(toAddr(0x200), toAddr(0x20b)));
      for (int index = 0; index < 2; index++) {
        int site = index == 0 ? 0x150 : 0x160;
        var target = ProgramMapping.fileToStatic(currentProgram, (index + 1) * 0x4000L + 0x100).get(0);
        dis.disassemble(toAddr(site), new AddressSet(toAddr(site), toAddr(site + 2)));
        dis.disassemble(toAddr(site + 6), new AddressSet(toAddr(site + 6), toAddr(site + 9)));
        dis.disassemble(target, new AddressSet(target, target.add(3)));
        currentProgram.getFunctionManager().createFunction("physical_target_" + index, target,
            new AddressSet(target, target.add(3)), SourceType.USER_DEFINED);
        var body = new AddressSet(toAddr(site), toAddr(site + 2)); body.add(toAddr(site + 6), toAddr(site + 9));
        currentProgram.getFunctionManager().createFunction("production_caller_" + index, toAddr(site), body, SourceType.USER_DEFINED);
      }
      dis.disassemble(toAddr(0x28), new AddressSet(toAddr(0x28), toAddr(0x2b)));
      var bankedSite = ProgramMapping.fileToStatic(currentProgram, 0x4200).get(0);
      var bankedNext = ProgramMapping.fileToStatic(currentProgram, 0x8201).get(0);
      var bankedTarget = ProgramMapping.fileToStatic(currentProgram, 0x8300).get(0);
      for (var at : List.of(bankedSite, bankedNext, bankedTarget)) dis.disassemble(at, new AddressSet(at));
      currentProgram.getFunctionManager().createFunction("banked_source", bankedSite, new AddressSet(bankedSite), SourceType.USER_DEFINED);
      currentProgram.getFunctionManager().createFunction("banked_destination", bankedTarget, new AddressSet(bankedTarget), SourceType.USER_DEFINED);
      var inlineSite = ProgramMapping.fileToStatic(currentProgram, 0x4500).get(0);
      var inlineNext = ProgramMapping.fileToStatic(currentProgram, 0x8506).get(0);
      dis.disassemble(inlineSite, new AddressSet(inlineSite, inlineSite.add(2)));
      dis.disassemble(inlineNext, new AddressSet(inlineNext));
      currentProgram.getFunctionManager().createFunction("banked_inline_source", inlineSite, new AddressSet(inlineSite, inlineSite.add(2)), SourceType.USER_DEFINED);
      currentProgram.getListing().createData(inlineSite.add(4), ghidra.program.model.data.WordDataType.dataType);
      currentProgram.getSymbolTable().createLabel(inlineSite.add(4), "unconsumed_old_bank_word", SourceType.USER_DEFINED);
      dis.disassemble(toAddr(0x170), new AddressSet(toAddr(0x170), toAddr(0x173)));
      dis.disassemble(toAddr(0x300), new AddressSet(toAddr(0x300), toAddr(0x303)));
      dis.disassemble(toAddr(0x320), new AddressSet(toAddr(0x320), toAddr(0x32f)));
      dis.disassemble(toAddr(0x32a), new AddressSet(toAddr(0x32a), toAddr(0x32f)));
      var nestedOuter = ProgramMapping.fileToStatic(currentProgram, 0x8600).get(0);
      var nestedInner = ProgramMapping.fileToStatic(currentProgram, 0xc300).get(0);
      dis.disassemble(nestedOuter, new AddressSet(nestedOuter, nestedOuter.add(11)));
      dis.disassemble(nestedInner, new AddressSet(nestedInner, nestedInner.add(6)));
      currentProgram.getFunctionManager().createFunction("nested_entry", toAddr(0x170), new AddressSet(toAddr(0x170), toAddr(0x173)), SourceType.USER_DEFINED);
      currentProgram.getFunctionManager().createFunction("nested_outer", nestedOuter, new AddressSet(nestedOuter, nestedOuter.add(11)), SourceType.USER_DEFINED);
      currentProgram.getFunctionManager().createFunction("nested_inner", nestedInner, new AddressSet(nestedInner, nestedInner.add(6)), SourceType.USER_DEFINED);
      prepareFunction(dis, 0x360, 2, "nested_ordinary");
      dis.disassemble(toAddr(0x340), new AddressSet(toAddr(0x340), toAddr(0x34d)));
      dis.disassemble(toAddr(0x348), new AddressSet(toAddr(0x348), toAddr(0x34d)));
      prepareFunction(dis, 0x4700, 7, "restoring_banked_source");
      prepareFunction(dis, 0x4800, 3, "constant_banked_source");
      var constantNext = physical(0xc803);
      dis.disassemble(constantNext, new AddressSet(constantNext, constantNext.add(3)));
      prepareFunction(dis, 0x8400, 4, "policy_target");
      prepareFunction(dis, 0x180, 7, "terminal_source");
      prepareFunction(dis, 0x8900, 2, "endless_target");
      prepareFunction(dis, 0x190, 6, "nonlocal_source");
      prepareFunction(dis, 0x8a00, 8, "nonlocal_target");
      dis.disassemble(toAddr(0x1b0), new AddressSet(toAddr(0x1b0), toAddr(0x1b2)));
      Path config = work.resolve("configurations.json");
      Files.writeString(config, ProgramMapping.JSON.toJson(configurations()));
      runScript("GhidraBoyTools.java", new String[] {"software-call-apply", config.toString()});
      println("SA01_PRODUCTION_PREPARE_PASS");
      return;
    }
    if (mode.equals("reapply")) {
      AnalysisOwnership.remove(currentProgram, SoftwareCallApplication.FEATURE, monitor);
      // Annotated-repair fixture: explicit false annotations, not claimed analyzer discoveries.
      var helper = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x200));
      if (helper == null) helper = currentProgram.getFunctionManager().createFunction("misannotated_helper", toAddr(0x200),
          new AddressSet(toAddr(0x200), toAddr(0x20b)), SourceType.ANALYSIS);
      helper.setNoReturn(true);
      currentProgram.getFunctionManager().getFunctionAt(toAddr(0x360)).setNoReturn(true);
      currentProgram.getListing().getInstructionAt(physical(0xc300)).setFlowOverride(FlowOverride.CALL_RETURN);
      currentProgram.getListing().getInstructionAt(toAddr(0x150)).setFlowOverride(FlowOverride.CALL_RETURN);
      currentProgram.getFunctionManager().getFunctionAt(ProgramMapping.fileToStatic(currentProgram, 0x4100).get(0)).setNoReturn(true);
      runScript("GhidraBoyTools.java", new String[] {"software-call-apply", work.resolve("configurations.json").toString()});
      Files.writeString(work.resolve("reapplied-inventory.json"), currentProgram.getOptions(ProgramMapping.OPTIONS).getString("softwareCall.review.inventory.v1", ""));
      verifyNestedRepairInventory(work);
      println("SA01_PRODUCTION_REAPPLY_PASS");
      return;
    }
    if (mode.equals("edit")) {
      verifyNestedRepairInventory(work);
      currentProgram.getListing().setComment(toAddr(0x153), CommentType.EOL, "Later user payload note");
      currentProgram.getListing().getInstructionAt(toAddr(0x150)).setFallThrough(toAddr(0x15a));
      println("SA01_PRODUCTION_EDIT_PASS");
      return;
    }
    if (mode.equals("edited-reopen")) {
      boolean stale = false;
      try { SoftwareCallRegistry.resolve(currentProgram, toAddr(0x150)); }
      catch (IllegalArgumentException expected) { stale = true; }
      require(stale, "edited executable contract rejects before removal");
      require(toAddr(0x15a).equals(currentProgram.getListing().getInstructionAt(toAddr(0x150)).getFallThrough()), "saved user continuation");
      AnalysisOwnership.remove(currentProgram, SoftwareCallApplication.FEATURE, monitor);
      require(toAddr(0x15a).equals(currentProgram.getListing().getInstructionAt(toAddr(0x150)).getFallThrough()), "preserved user continuation");
      require("Later user payload note".equals(currentProgram.getListing().getComment(CommentType.EOL, toAddr(0x153))), "preserved user payload note");
      boolean refused = false;
      try { SoftwareCallApplication.preview(currentProgram, configurations(), monitor); }
      catch (IllegalArgumentException expected) { refused = true; }
      require(refused, "edited continuation must prevent silent reapply");
      verifyRemoved(work, false);
      println("SA01_PRODUCTION_EDITED_REOPEN_PASS"); return;
    }
    if (mode.equals("removed-reopen")) {
      verifyRemoved(work, true);
      println("SA01_PRODUCTION_REMOVED_REOPEN_PASS"); return;
    }
    if (!mode.equals("verify")) throw new IllegalArgumentException(mode);
    verifyNestedRepairInventory(work);
    var decompiler = new DecompInterface();
    try {
      require(decompiler.openProgram(currentProgram), "normal native open");
      for (int index : new int[] {0, 1, 0}) {
        int site = index == 0 ? 0x150 : 0x160;
        var instruction = currentProgram.getListing().getInstructionAt(toAddr(site));
        require(instruction.getFlowOverride() == FlowOverride.NONE, "ordinary analyzer retained returning site");
        require(toAddr(site + 6).equals(instruction.getFallThrough()), "ordinary analyzer retained continuation");
        require(!currentProgram.getFunctionManager().getFunctionAt(toAddr(0x200)).hasNoReturn(), "helper remains returning-capable");
        require(SoftwareCallRegistry.resolve(currentProgram, toAddr(site)) != null, "saved executable registry resolves");
        var function = currentProgram.getFunctionManager().getFunctionAt(toAddr(site));
        require(function.getBody().contains(toAddr(site + 6)), "committed continuation body");
        var result = decompiler.decompileFunction(function, 30, monitor);
        require(result.decompileCompleted(), result.getErrorMessage());
        require(result.getDecompiledFunction().getC().contains("physical_target_" + index + "("), result.getDecompiledFunction().getC());
        var expected = ProgramMapping.fileToStatic(currentProgram, (index + 1) * 0x4000L + 0x100).get(0);
        boolean physical = false;
        var ops = result.getHighFunction().getPcodeOps();
        while (ops.hasNext()) { var op = ops.next(); if (op.getOpcode() == PcodeOp.CALL && expected.equals(op.getInput(0).getAddress())) physical = true; }
        require(physical, "native physical CALL endpoint");
        Files.writeString(work.resolve("native-" + index + ".c"), result.getDecompiledFunction().getC());
      }
      ghidra.program.model.listing.Function banked = null;
      for (var function : currentProgram.getFunctionManager().getFunctions(true))
        if (function.getName().equals("banked_source_software_call")) banked = function;
      require(banked != null, "saved banked execution function");
      var bankedSite = banked.getEntryPoint();
      require(SoftwareCallRegistry.resolve(currentProgram, bankedSite) != null, "saved banked registry alias");
      require(ProgramMapping.staticToPhysical(currentProgram, bankedSite.add(1)).equals(List.of(new MapperState.Physical("ROM", 2, 0x201))), "saved continuation physical bank");
      var bankedResult = decompiler.decompileFunction(banked, 30, monitor);
      require(bankedResult.decompileCompleted(), bankedResult.getErrorMessage());
      require(bankedResult.getDecompiledFunction().getC().contains("banked_destination("), bankedResult.getDecompiledFunction().getC());
      Files.writeString(work.resolve("native-banked.c"), bankedResult.getDecompiledFunction().getC());
      verifyNative(decompiler, physical(0x4200), physical(0x8300), "native-banked-canonical", work);
      ghidra.program.model.listing.Function inline = null;
      for (var function : currentProgram.getFunctionManager().getFunctions(true))
        if (function.getName().equals("banked_inline_source_software_call")) inline = function;
      require(inline != null, "saved banked inline execution function");
      var inlinePreview = SoftwareCallRegistry.resolve(currentProgram, inline.getEntryPoint());
      require(inlinePreview != null && inlinePreview.frame().targetCpu() == 0x4300, "selected-bank inline target");
      require(inlinePreview.frame().reads().stream().map(r -> r.physical().bank()).toList().equals(List.of(1, 2, 2)), "ordered payload physical banks");
      var inlineResult = decompiler.decompileFunction(inline, 30, monitor);
      require(inlineResult.decompileCompleted(), inlineResult.getErrorMessage());
      require(inlineResult.getDecompiledFunction().getC().contains("banked_destination("), inlineResult.getDecompiledFunction().getC());
      var untouched = ProgramMapping.fileToStatic(currentProgram, 0x4504).stream().filter(a -> a.getAddressSpace().getName().equals("rom1")).findFirst().orElseThrow();
      require(currentProgram.getListing().getDefinedDataAt(untouched) != null && currentProgram.getMemory().getShort(untouched) == 0x5000, "unconsumed old-bank data remains");
      Files.writeString(work.resolve("native-banked-inline.c"), inlineResult.getDecompiledFunction().getC());
      verifyNative(decompiler, physical(0x4500), physical(0x8300), "native-inline-canonical", work);
      var nestedAddress = ProgramMapping.fileToStatic(currentProgram, 0x8600).stream().filter(a -> a.getAddressSpace().getName().equals("rom2")).findFirst().orElseThrow();
      var nestedResult = decompiler.decompileFunction(currentProgram.getFunctionManager().getFunctionAt(nestedAddress), 30, monitor);
      require(nestedResult.decompileCompleted(), nestedResult.getErrorMessage());
      require(nestedResult.getDecompiledFunction().getC().contains("nested_inner("), nestedResult.getDecompiledFunction().getC());
      var nestedPreview = SoftwareCallRegistry.resolve(currentProgram, toAddr(0x170));
      require(SoftwareCallRegistry.effects(currentProgram, nestedPreview, monitor).paths().get(0).returned().registers().f() == 0x90, "nested callee F survives restoring wrapper");
      Files.writeString(work.resolve("native-nested.c"), nestedResult.getDecompiledFunction().getC());
      verifyNative(decompiler, toAddr(0x170), nestedAddress, "native-nested-entry", work);
      require(!currentProgram.getFunctionManager().getFunctionAt(toAddr(0x360)).hasNoReturn(), "nested ordinary matched RET repairs false noReturn");
      require(currentProgram.getListing().getInstructionAt(physical(0xc300)).getFlowOverride() == FlowOverride.NONE,
          "nested ordinary CALL_RETURN repair survives analysis/reopen");
      verifyNative(decompiler, physical(0xc300), toAddr(0x360), "native-nested-ordinary", work);
      for (int site : new int[] {0x4700, 0x4800}) {
        var preview = SoftwareCallRegistry.resolve(currentProgram, physical(site));
        var effects = SoftwareCallRegistry.effects(currentProgram, preview, monitor);
        require(effects.nativeCompatible() && effects.paths().size() == 1, "installed policy native proof");
        var returned = effects.paths().get(0).returned();
        int bank = site == 0x4700 ? 1 : 3;
        require(returned.exit() == SoftwareCallModel.Exit.MAY_RETURN && returned.sp() == 0xc100, "policy matched caller stack");
        require(returned.physical().equals(new MapperState.Physical("ROM", bank, site + 3 - 0x4000)), "policy physical continuation");
        require(returned.registers().f() == 0x90 && returned.registers().a() == bank, "policy epilogue A and callee F");
        verifyNative(decompiler, physical(site), physical(0x8400), "native-policy-canonical-" + site, work);
        if (site == 0x4800) {
          var canonical = currentProgram.getFunctionManager().getFunctionAt(physical(site));
          require(canonical.isThunk(), "constant-bank canonical execution association");
          var alias = canonical.getThunkedFunction(false);
          verifyNative(decompiler, alias.getEntryPoint(), physical(0x8400), "native-policy-alias-" + site, work);
        }
      }
      var terminal = currentProgram.getListing().getInstructionAt(toAddr(0x180));
      require(terminal.getFlowOverride() == FlowOverride.CALL_RETURN && terminal.getFallThrough() == null, "true nonreturn terminal interpretation");
      var terminalPreview = SoftwareCallRegistry.resolve(currentProgram, toAddr(0x180));
      require(SoftwareCallRegistry.effects(currentProgram, terminalPreview, monitor).paths().get(0).returned().exit()
          == SoftwareCallModel.Exit.NONRETURNING, "true loop has no fabricated epilogue");
      var terminalResult = verifyNative(decompiler, toAddr(0x180), physical(0x8900), "native-terminal", work);
      require(!terminalResult.getDecompiledFunction().getC().contains("c104"), "terminal omits unreachable continuation write");
      var nonlocal = currentProgram.getListing().getInstructionAt(toAddr(0x190));
      require(nonlocal.getFlowOverride() == FlowOverride.NONE && toAddr(0x1b0).equals(nonlocal.getFallThrough()), "known nonlocal destination");
      var nonlocalResult = verifyNative(decompiler, toAddr(0x190), physical(0x8a00), "native-nonlocal", work);
      boolean actualReturn = false;
      var nonlocalOps = nonlocalResult.getHighFunction().getPcodeOps();
      while (nonlocalOps.hasNext()) {
        var op = nonlocalOps.next();
        if (op.getOpcode() == PcodeOp.RETURN && op.getSeqnum().getTarget().equals(toAddr(0x1b2))) actualReturn = true;
        require(op.getSeqnum().getTarget().getOffset() < 0x193 || op.getSeqnum().getTarget().getOffset() > 0x195,
            "nonlocal never executes encoded continuation");
      }
      require(actualReturn, "nonlocal reaches proven destination RET");
    } finally { decompiler.dispose(); }
    println("SA01_PRODUCTION_VERIFY_PASS");
  }
}
