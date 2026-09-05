// Function edit ownership across separate installed Ghidra processes.
// @category Game Boy Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.util.*;

public class GhidraBoyInstalledFunctionOwnership extends GhidraScript {
  private void check(boolean ok, String message) {
    if (!ok) throw new AssertionError(message);
  }

  @Override
  public void run() throws Exception {
    var p = currentProgram;
    var options = p.getOptions(ProgramMapping.OPTIONS);
    var seeds = new ArrayList<ghidra.program.model.address.Address>();
    for (int at = 0x400; at <= 0x450; at += 0x10) seeds.add(toAddr(at));
    if (getScriptArgs()[0].equals("prepare")) {
      for (var at : seeds) {
        p.getMemory().setByte(at, (byte) 0xc9);
        Disassembler.getDisassembler(p, monitor, null).disassemble(at, new AddressSet(at));
      }
      FunctionDiscovery.discover(p, seeds, List.<BankAnalysis.Finding>of(), monitor);
      var local = p.getFunctionManager().getFunctionAt(toAddr(0x400));
      local.addLocalVariable(
          new LocalVariableImpl("saved_local", WordDataType.dataType, -2, p),
          SourceType.USER_DEFINED);
      local.getLocalVariables()[0].setComment("saved local comment");
      p.getFunctionManager().getFunctionAt(toAddr(0x410)).setInline(true);
      // 0x420 remains genuinely unchanged; 0x430 receives a legacy receipt.
      var registry =
          ProgramMapping.JSON.fromJson(
              options.getString("analysis.ownership.v1", ""), com.google.gson.JsonObject.class);
      var receipts =
          registry
              .getAsJsonObject("groups")
              .getAsJsonObject("functions")
              .getAsJsonArray("functions");
      var legacy = new com.google.gson.JsonArray();
      for (int i = receipts.size() - 1; i >= 0; i--) {
        var r = receipts.get(i).getAsJsonObject();
        if (r.getAsJsonObject("entry").get("offset").getAsLong() == 0x430) {
          receipts.remove(i);
          r.remove("version");
          legacy.add(r);
        }
      }
      var legacyGroup = new com.google.gson.JsonObject();
      legacyGroup.add("functions", legacy);
      registry.getAsJsonObject("groups").add("legacy-functions", legacyGroup);
      options.setString("analysis.ownership.v1", ProgramMapping.JSON.toJson(registry));
      var parameter = p.getFunctionManager().getFunctionAt(toAddr(0x440));
      parameter
          .addParameter(
              new ParameterImpl("input", WordDataType.dataType, 2, p), SourceType.USER_DEFINED)
          .setComment("saved parameter comment");
      var structure = new StructureDataType("PersistentMutable", 0);
      structure.add(ByteDataType.dataType, "field", null);
      var typed = p.getFunctionManager().getFunctionAt(toAddr(0x450));
      typed.setReturnType(structure, SourceType.ANALYSIS);
      var typedGroup = new AnalysisOwnership.Group();
      typedGroup.function(typed);
      AnalysisOwnership.save(p, "typed-function", typedGroup);
      ((Structure) typed.getReturnType()).getComponent(0).setComment("same path and size edit");
      println("INSTALLED_FUNCTION_OWNERSHIP_PREPARED");
    } else {
      var local = p.getFunctionManager().getFunctionAt(toAddr(0x400));
      check(
          local.getLocalVariables()[0].getComment().equals("saved local comment"),
          "local persisted");
      check(p.getFunctionManager().getFunctionAt(toAddr(0x410)).isInline(), "inline persisted");
      var messages = AnalysisOwnership.remove(p, "functions", monitor);
      check(
          messages.stream().anyMatch(s -> s.contains("Preserved")),
          "explicit removal reports retention");
      check(
          p.getFunctionManager().getFunctionAt(toAddr(0x420)) == null,
          "unchanged function removed after reopen");
      messages = AnalysisOwnership.removeAll(p, monitor);
      check(messages.stream().anyMatch(s -> s.contains("legacy")), "legacy reason after reopen");
      for (int at : new int[] {0x400, 0x410, 0x430, 0x440, 0x450})
        check(
            p.getFunctionManager().getFunctionAt(toAddr(at)) != null,
            "edited/legacy function preserved " + at);
      for (int i = 0; i < 2; i++)
        FunctionDiscovery.discover(p, seeds, List.<BankAnalysis.Finding>of(), monitor);
      AnalysisOwnership.removeAll(p, monitor);
      check(
          p.getFunctionManager().getFunctionAt(toAddr(0x420)) == null,
          "recreated unchanged function removed");
      check(
          local.getLocalVariables()[0].getName().equals("saved_local"),
          "local retained across reruns");
      check(
          p.getFunctionManager().getFunctionAt(toAddr(0x410)).isInline(),
          "inline retained across reruns");
      check(
          p.getFunctionManager().getFunctionAt(toAddr(0x430)) != null,
          "legacy ownership never reacquired");
      check(
          p.getFunctionManager()
              .getFunctionAt(toAddr(0x440))
              .getParameter(0)
              .getComment()
              .equals("saved parameter comment"),
          "parameter comment retained");
      check(
          ((Structure) p.getFunctionManager().getFunctionAt(toAddr(0x450)).getReturnType())
              .getComponent(0)
              .getComment()
              .equals("same path and size edit"),
          "in-place type edit retained");
      println("INSTALLED_FUNCTION_OWNERSHIP_REOPEN_REMOVE_RERUN_PASS");
    }
  }
}
