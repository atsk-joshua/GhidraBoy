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
  private List<SoftwareCallValidation.Configuration> configurations() {
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
    return result;
  }
  @Override public void run() throws Exception {
    String mode = getScriptArgs()[0];
    Path work = Path.of(getScriptArgs()[1]);
    if (mode.equals("prepare")) {
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
      currentProgram.getListing().getInstructionAt(toAddr(0x150)).setFlowOverride(FlowOverride.CALL_RETURN);
      currentProgram.getFunctionManager().getFunctionAt(ProgramMapping.fileToStatic(currentProgram, 0x4100).get(0)).setNoReturn(true);
      runScript("GhidraBoyTools.java", new String[] {"software-call-apply", work.resolve("configurations.json").toString()});
      println("SA01_PRODUCTION_REAPPLY_PASS");
      return;
    }
    if (mode.equals("edit")) {
      currentProgram.getListing().setComment(toAddr(0x153), CommentType.EOL, "Later user payload note");
      currentProgram.getListing().getInstructionAt(toAddr(0x150)).setFallThrough(toAddr(0x15a));
      println("SA01_PRODUCTION_EDIT_PASS");
      return;
    }
    if (mode.equals("edited-reopen")) {
      require(toAddr(0x15a).equals(currentProgram.getListing().getInstructionAt(toAddr(0x150)).getFallThrough()), "saved user continuation");
      AnalysisOwnership.remove(currentProgram, SoftwareCallApplication.FEATURE, monitor);
      require(toAddr(0x15a).equals(currentProgram.getListing().getInstructionAt(toAddr(0x150)).getFallThrough()), "preserved user continuation");
      require("Later user payload note".equals(currentProgram.getListing().getComment(CommentType.EOL, toAddr(0x153))), "preserved user payload note");
      boolean refused = false;
      try { SoftwareCallApplication.preview(currentProgram, configurations(), monitor); }
      catch (IllegalArgumentException expected) { refused = true; }
      require(refused, "edited continuation must prevent silent reapply");
      println("SA01_PRODUCTION_EDITED_REOPEN_PASS"); return;
    }
    if (!mode.equals("verify")) throw new IllegalArgumentException(mode);
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
    } finally { decompiler.dispose(); }
    println("SA01_PRODUCTION_VERIFY_PASS");
  }
}
