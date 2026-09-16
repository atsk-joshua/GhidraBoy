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

  private static final java.util.concurrent.atomic.AtomicLong CAPTURE_SEQUENCE =
      new java.util.concurrent.atomic.AtomicLong();

  /** Opt-in execution evidence, emitted from the traversal used by the real dependency guard. */
  private static void recordCapture(Program p, boolean includeOwnership,
      java.util.List<String> fields, java.util.Map<String, String> components,
      byte[] preimage, String digest) throws java.io.IOException {
    String directory = System.getProperty("ghidraboy.farCallEvidenceDirectory");
    if (directory == null) return;
    long sequence = CAPTURE_SEQUENCE.incrementAndGet();
    var root = java.nio.file.Path.of(directory);
    java.nio.file.Files.createDirectories(root);
    String stem = String.format("%06d", sequence);
    var metadata = new java.util.LinkedHashMap<String, Object>();
    metadata.put("sequence", sequence);
    metadata.put("phase", System.getProperty("ghidraboy.farCallEvidencePhase", "startup"));
    metadata.put("javaPid", ProcessHandle.current().pid());
    metadata.put("programId", p.getUniqueProgramID());
    metadata.put("modification", p.getModificationNumber());
    metadata.put("includeOwnership", includeOwnership);
    metadata.put("components", components);
    metadata.put("fields", fields);
    metadata.put("digest", digest);
    metadata.put("stack", Arrays.stream(Thread.currentThread().getStackTrace()).map(Object::toString).toList());
    java.nio.file.Files.write(root.resolve(stem + ".preimage"), preimage,
        java.nio.file.StandardOpenOption.CREATE_NEW);
    java.nio.file.Files.writeString(root.resolve(stem + ".json"), ProgramMapping.JSON.toJson(metadata),
        StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.CREATE_NEW);
  }

  private static String capture(Program p, TaskMonitor monitor, boolean includeOwnership) throws Exception {
    var fields = new ArrayList<String>();
    fields.add("far-call-review-v3");
    var components = ProgramFingerprint.components(p, monitor);
    fields.add(Sha256.of(ProgramMapping.JSON.toJson(components).getBytes(StandardCharsets.UTF_8)).toString());
    var options = p.getOptions(ProgramMapping.OPTIONS);
    for (String key : java.util.List.of("analysis.ownership.v1", "farCallConvention"))
      if (includeOwnership || !key.equals("analysis.ownership.v1")) fields.add(key + ":" + java.util.Objects.toString(AuthorityOptions.string(options,key),"absent"));
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
      // Dynamic symbols have no durable record: their IDs encode observation-order address-map indices.
      // Keep stored ownership identity and reference associations unchanged.
      fields.add("symbol:" + (symbol.isDynamic() ? "dynamic" : symbol.getID()) + ":" + symbol.getAddress() + ":"
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
    byte[] preimage = ProgramMapping.JSON.toJson(fields).getBytes(StandardCharsets.UTF_8);
    String digest = Sha256.of(preimage).toString();
    recordCapture(p, includeOwnership, fields, components, preimage, digest);
    return digest;
  }
}
