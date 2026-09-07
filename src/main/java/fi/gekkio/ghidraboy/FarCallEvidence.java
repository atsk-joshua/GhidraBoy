package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

/** Additional review dependencies, separate from SA-00's bounded traversal contract. */
final class FarCallEvidence {
  private FarCallEvidence() {}

  static String capture(Program p, TaskMonitor monitor) throws Exception {
    return capture(p, monitor, true);
  }

  static String captureWithoutOwnership(Program p, TaskMonitor monitor) throws Exception {
    return capture(p, monitor, false);
  }

  private static String capture(Program p, TaskMonitor monitor, boolean includeOwnership) throws Exception {
    var fields = new ArrayList<String>();
    fields.add("far-call-review-v2");
    fields.add(ProgramFingerprint.capture(p, monitor));
    var options = p.getOptions(ProgramMapping.OPTIONS);
    for (String key : java.util.List.of("analysis.ownership.v1", "farCallConvention"))
      if (includeOwnership || !key.equals("analysis.ownership.v1")) fields.add(key + ":" + (options.contains(key) ? options.getString(key, null) : "absent"));
    for (var block : p.getMemory().getBlocks())
      fields.add("permissions:" + block.getStart() + ":" + block.getFlags());
    var context = p.getProgramContext();
    var defaultContext = context.getDefaultDisassemblyContext();
    fields.add("defaultDisassemblyContext:" + (defaultContext == null ? "none" : Arrays.toString(defaultContext.toBytes())));
    for (var register : context.getRegisters()) {
      for (var range : context.getDefaultRegisterValueAddressRanges(register)) {
        monitor.checkCancelled();
        var value = context.getDefaultValue(register, range.getMinAddress());
        fields.add("defaultContext:" + register.getName() + ":" + range + ":"
            + (value == null ? "unknown" : Arrays.toString(value.toBytes())));
      }
      for (var range : context.getRegisterValueAddressRanges(register)) {
        monitor.checkCancelled();
        var value = context.getRegisterValue(register, range.getMinAddress());
        fields.add("context:" + register.getName() + ":" + range + ":"
            + (value == null ? "unknown" : Arrays.toString(value.toBytes())));
      }
    }
    for (var data : p.getListing().getDefinedData(true)) {
      monitor.checkCancelled();
      fields.add("dataClass:" + data.getAddress() + ":" + data.getDataType().getClass().getName());
      for (String name : data.getNames())
        fields.add("dataSetting:" + data.getAddress() + ":" + name + ":" + data.getValue(name));
      for (var type : ghidra.program.model.listing.CommentType.values())
        fields.add("dataComment:" + data.getAddress() + ":" + type + ":" + data.getComment(type));
    }
    // Include incoming payload/entry references as well as decoded instruction flow dependencies.
    var sources = p.getReferenceManager().getReferenceSourceIterator(p.getMemory(), true);
    while (sources.hasNext()) {
      monitor.checkCancelled();
      for (var ref : p.getReferenceManager().getReferencesFrom(sources.next()))
        fields.add("reference:" + ref.getFromAddress() + ":" + ref.getToAddress() + ":"
            + ref.getReferenceType() + ":" + ref.getOperandIndex() + ":" + ref.getSource()
            + ":" + ref.isPrimary() + ":" + ref.getSymbolID());
    }
    for (var symbol : p.getSymbolTable().getAllSymbols(true)) {
      monitor.checkCancelled();
      fields.add("symbol:" + symbol.getID() + ":" + symbol.getAddress() + ":"
          + symbol.getName(true) + ":" + symbol.getSource() + ":" + symbol.isPinned());
    }
    // Prototypes are conflicts/dependencies, never proof of actual callee return behavior.
    for (var f : p.getFunctionManager().getFunctions(true)) {
      monitor.checkCancelled();
      fields.add("function:" + f.getID() + ":" + f.getBody() + ":" + f.getPrototypeString(true, true)
          + ":" + f.getCallingConventionName() + ":" + f.getSignatureSource() + ":"
          + f.hasNoReturn() + ":" + f.isInline() + ":" + f.hasVarArgs() + ":"
          + f.getCallFixup() + ":" + f.getStackPurgeSize() + ":"
          + f.getReturn().getVariableStorage().getSerializationString());
      fields.add("functionAnnotations:" + f.getID() + ":" + f.getComment() + ":"
          + f.getRepeatableComment() + ":" + f.isThunk() + ":"
          + (f.isThunk() ? f.getThunkedFunction(false).getID() : "none"));
      for (var parameter : f.getParameters())
        fields.add("parameter:" + f.getID() + ":" + parameter.getOrdinal() + ":"
            + parameter.getVariableStorage().getSerializationString());
    }
    Collections.sort(fields);
    return Sha256.of(ProgramMapping.JSON.toJson(fields).getBytes(StandardCharsets.UTF_8)).toString();
  }
}
