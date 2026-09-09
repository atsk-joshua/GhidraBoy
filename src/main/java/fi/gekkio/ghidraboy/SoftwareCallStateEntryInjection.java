package fi.gekkio.ghidraboy;

import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.InjectPayloadSleigh;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

/** Explicit pre-flow native protocol. The ordinary language and raw instruction stream are intact. */
public final class SoftwareCallStateEntryInjection extends InjectPayloadSleigh {
  public static final String CONVENTION = "__ghidraboy_state_entry_v1";
  public static final String NAME = CONVENTION + "@@inject_uponentry";
  public static final String VERSION = "software-call-state-entry-injection-2";
  private final long uniqueBase;

  SoftwareCallStateEntryInjection(String source, long uniqueBase) {
    super(NAME, InjectPayload.CALLMECHANISM_TYPE, source);
    this.uniqueBase = uniqueBase;
  }

  static String nativeIdentity() throws Exception {
    var binary = ghidra.framework.Application.getOSFile("decompile").toPath();
    var marker = binary.getParent().getParent().getParent().resolve("state-entry-native.json");
    if (!java.nio.file.Files.isRegularFile(marker))
      throw new IllegalArgumentException("State-qualified callee entries require the optional pre-flow native companion");
    var json = com.google.gson.JsonParser.parseString(java.nio.file.Files.readString(marker)).getAsJsonObject();
    if (!json.has("schema") || !"ghidraboy-state-entry-native-v1".equals(json.get("schema").getAsString())
        || !json.has("nativeDependencyVersion") || !"12.1.3+ghidraboy.switch-recovery.2.state-entry.1".equals(json.get("nativeDependencyVersion").getAsString())
        || !json.has("statePatchSha256") || !"91d8d2bfe6b2478cfb98f2c609d975036eb523a3c481c6f05d7516c87d503388".equals(json.get("statePatchSha256").getAsString())
        || !json.has("protocol") || !CONVENTION.equals(json.get("protocol").getAsString())
        || !json.has("binarySha256") || !json.get("binarySha256").getAsString().equals(
            Sha256.of(java.nio.file.Files.readAllBytes(binary)).toString()))
      throw new IllegalArgumentException("State-entry native companion identity mismatch");
    return Sha256.of(java.nio.file.Files.readAllBytes(marker)).toString();
  }

  @Override public PcodeOp[] getPcode(Program program, InjectContext context) {
    return SoftwareCallInjection.revalidated(program, () -> {
      try {
        if (SoftwareCallDomains.registered(program, context.baseAddr))
          return SoftwareCallDomains.emit(program, context.baseAddr, uniqueBase, ghidra.util.task.TaskMonitor.DUMMY);
        if (PredicatedCalls.registered(program, context.baseAddr))
          return PredicatedCalls.emit(program, context.baseAddr, uniqueBase, ghidra.util.task.TaskMonitor.DUMMY);
        if (OrdinaryEntryAccess.registered(program, context.baseAddr))
          return OrdinaryEntryAccess.emit(program, context.baseAddr, uniqueBase, ghidra.util.task.TaskMonitor.DUMMY);
        long before = program.getModificationNumber();
        var input = SoftwareCallRegistry.resolveStateEntry(program, context.baseAddr);
        var graph = SoftwareCallRegistry.entryGraph(program, context.baseAddr, input);
        var result = SoftwareCallContinuationView.emit(program, context.baseAddr, graph,
            SoftwareCallRegistry.configurations(program), uniqueBase, SoftwareCallRegistry.entryStep(program, context.baseAddr));
        if (before != program.getModificationNumber()) throw new IllegalArgumentException("Program changed during state-entry injection");
        return result;
      } catch (Exception failure) {
        throw new IllegalArgumentException("Unresolved state-qualified entry at " + context.baseAddr + ": " + failure.getMessage(), failure);
      }
    });
  }
}
