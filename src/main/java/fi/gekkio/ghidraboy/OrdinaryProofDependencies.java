package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Ordinary-path dependency policy only. No caching or shared software-call policy. */
final class OrdinaryProofDependencies {
  private OrdinaryProofDependencies() {}

  private static String hash(Object value) {
    return Sha256.of(ProgramMapping.JSON.toJson(value).getBytes(StandardCharsets.UTF_8)).toString();
  }

  // Core components include current bytes, mapping, instructions and consumed flow. The new
  // option record is not a component. Add contexts, permissions and Function contracts here.
  static String fingerprint(Program p, TaskMonitor monitor) throws Exception {
    var parts = new TreeMap<String, Object>(ProgramFingerprint.coreComponents(p, monitor));
    var contexts = new ArrayList<String>(); var pc = p.getProgramContext();
    contexts.add(String.valueOf(pc.getDefaultDisassemblyContext()));
    for (var register : pc.getRegisters()) {
      for (var range : pc.getDefaultRegisterValueAddressRanges(register))
        contexts.add(register.getName() + ":default:" + range + ":" + pc.getDefaultValue(register, range.getMinAddress()));
      for (var range : pc.getRegisterValueAddressRanges(register))
        contexts.add(register.getName() + ":" + range + ":" + pc.getRegisterValue(register, range.getMinAddress()));
    }
    Collections.sort(contexts); parts.put("context", contexts);
    var functions = new ArrayList<String>();
    for (var f : p.getFunctionManager().getFunctions(true))
      functions.add(f.getEntryPoint() + ":" + f.getBody() + ":" + f.getCallingConventionName()
          + ":" + f.hasNoReturn() + ":" + f.getSignature() + ":" + f.getComment());
    Collections.sort(functions); parts.put("functions", functions);
    var blocks = new ArrayList<String>();
    for (var b : p.getMemory().getBlocks())
      blocks.add(b.getStart() + ":" + b.getSize() + ":" + b.isRead() + ":" + b.isWrite()
          + ":" + b.isExecute() + ":" + b.isVolatile() + ":" + b.isMapped());
    Collections.sort(blocks); parts.put("permissions", blocks); parts.put("provider", OrdinaryEntryAccess.VERSION);
    return hash(parts);
  }
  static void requireUnchanged(Program p, long revision, String dependencies, TaskMonitor monitor) throws Exception {
    if (!(revision == p.getModificationNumber() && dependencies.equals(fingerprint(p, monitor))))
      throw new IllegalArgumentException("Program changed during ordinary-entry proof");
  }

  static void requireCurrent(Program p, String dependencies, TaskMonitor monitor) throws Exception {
    if (!dependencies.equals(fingerprint(p, monitor)))
      throw new IllegalArgumentException("Stale ordinary-entry registration; preview and refresh required");
  }
}
