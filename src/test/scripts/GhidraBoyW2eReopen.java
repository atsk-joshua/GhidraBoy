// Current-format W2e persistence capture; reuses the existing native capture route.
// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.decompiler.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Never imports, disassembles, analyzes, previews, installs or refreshes a proof. */
public class GhidraBoyW2eReopen extends GhidraBoyW2eFinite {
  String bytesHash(byte[] bytes) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }
  void identity(String label, String registration) throws Exception {
    var proof = com.google.gson.JsonParser.parseString(registration).getAsJsonObject().getAsJsonObject("proof");
    var sources = new ArrayList<Object>();
    for (var read : proof.getAsJsonObject("finite").getAsJsonArray("reads")) {
      var alternatives = read.getAsJsonObject().getAsJsonArray("alternatives");
      for (var alternative : alternatives) for (var node : alternative.getAsJsonObject().getAsJsonArray("sources")) {
        var source = node.getAsJsonObject();
        var address = currentProgram.getAddressFactory().getAddress(source.get("address").getAsString());
        sources.add(Map.of("selector", alternative.getAsJsonObject().get("selector").getAsInt(),
            "stored_source", source, "actual_value", currentProgram.getMemory().getByte(address) & 255,
            "actual_physical", ProgramMapping.staticToPhysical(currentProgram, address),
            "block_writable", currentProgram.getMemory().getBlock(address).isWrite()));
      }
    }
    var record = new LinkedHashMap<String,Object>();
    record.put("java_pid", ProcessHandle.current().pid());
    record.put("java_start", ProcessHandle.current().info().startInstant().map(Object::toString).orElse("unknown"));
    record.put("java_version", System.getProperty("java.version"));
    record.put("java_home", System.getProperty("java.home"));
    record.put("program_id", currentProgram.getUniqueProgramID());
    record.put("domain_file", currentProgram.getDomainFile().getPathname());
    record.put("domain_file_id", currentProgram.getDomainFile().getFileID());
    record.put("live_object_identity_hash", System.identityHashCode(currentProgram));
    record.put("live_modification_number", currentProgram.getModificationNumber());
    record.put("stored_program_instance", proof.get("programInstance"));
    record.put("stored_revision", proof.get("revision"));
    record.put("original_image_sha256", currentProgram.getExecutableSHA256());
    record.put("current_export_sha256", bytesHash(ProgramMapping.exportBytes(currentProgram, true, false, monitor)));
    record.put("physical_sources", sources);
    record.put("provider_location", CartridgeLayout.class.getProtectionDomain().getCodeSource().getLocation().toString());
    save(label + "-identity.json", record);
  }
  @Override public void run() throws Exception {
    out = Path.of(getScriptArgs()[0]); Files.createDirectories(out);
    String label = getScriptArgs()[1];
    var options = currentProgram.getOptions(OrdinaryEntryAccess.OPTIONS);
    var names = options.getOptionNames();
    if (names.size() != 1) throw new IllegalStateException("Expected one actual saved registration: " + names);
    String name = names.get(0), registration = options.getString(name, null);
    if (registration == null) throw new IllegalStateException("Missing stored registration");
    var alias = currentProgram.getAddressFactory().getAddress(name);
    var function = getFunctionAt(alias);
    if (function == null) throw new IllegalStateException("Missing saved alias Function");
    Files.writeString(out.resolve(label + "-registration.json"), registration);
    identity(label + "-before", registration);
    save(label + "-canonical.json", canonical(getFunctionAt(toAddr(0x150))));
    // Read the actual serialized proof. The installed payload performs its normal read-only
    // dependency/derivation validation; this script never replaces stored authority.
    artifacts(label, OrdinaryEntryAccess.registeredProof(currentProgram, alias), alias);
    var owner = new DecompInterface();
    try {
      owner.setOptions(new DecompileOptions());
      if (!owner.setSimplificationStyle("decompile") || !owner.toggleSyntaxTree(true)
          || !owner.toggleCCode(true) || !owner.openProgram(currentProgram))
        throw new IllegalStateException("Native setup refused");
      capture(function, owner, label);
    } finally { owner.dispose(); }
    String after = options.getString(name, null);
    Files.writeString(out.resolve(label + "-registration-after.json"), after);
    if (!registration.equals(after)) throw new IllegalStateException("Stored registration changed");
    identity(label + "-after", after);
    println("W2E_REOPEN_CAPTURE_COMPLETE " + label);
  }
}
