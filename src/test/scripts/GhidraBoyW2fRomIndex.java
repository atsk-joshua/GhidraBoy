// Bounded W2f-ROM-INDEX installed/native and current-format persistence witness.
// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.disassemble.Disassembler;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Setup preserves unknown B. Saved/reopened modes only read existing authority. */
public class GhidraBoyW2fRomIndex extends GhidraBoyW2eFinite {
  String bytesHash(byte[] bytes) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }
  void identity(String label, String registration) throws Exception {
    var proof = com.google.gson.JsonParser.parseString(registration).getAsJsonObject().getAsJsonObject("proof");
    var sources = new ArrayList<Object>();
    for (var read : proof.getAsJsonObject("finite").getAsJsonArray("reads")) {
      for (var alternative : read.getAsJsonObject().getAsJsonArray("alternatives")) {
        for (var node : alternative.getAsJsonObject().getAsJsonArray("sources")) {
          var source = node.getAsJsonObject();
          var address = currentProgram.getAddressFactory().getAddress(source.get("address").getAsString());
          var item = new LinkedHashMap<String,Object>();
          item.put("read_instruction", read.getAsJsonObject().get("instruction"));
          item.put("choice", read.getAsJsonObject().get("choice"));
          item.put("key", alternative.getAsJsonObject().get("key"));
          item.put("stored_source", source);
          item.put("actual_value", currentProgram.getMemory().getByte(address) & 255);
          item.put("actual_physical", ProgramMapping.staticToPhysical(currentProgram, address));
          item.put("block_writable", currentProgram.getMemory().getBlock(address).isWrite());
          sources.add(item);
        }
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
    record.put("provider_jar_sha256", hash(Path.of(CartridgeLayout.class.getProtectionDomain().getCodeSource().getLocation().toURI())));
    save(label + "-identity.json", record);
  }
  DecompInterface owner() throws Exception {
    var owner = new DecompInterface(); owner.setOptions(new DecompileOptions());
    if (!owner.setSimplificationStyle("decompile") || !owner.toggleSyntaxTree(true)
        || !owner.toggleCCode(true) || !owner.openProgram(currentProgram)) {
      owner.dispose(); throw new IllegalStateException("Native setup refused");
    }
    return owner;
  }
  void retained(String label) throws Exception {
    var options = currentProgram.getOptions(OrdinaryEntryAccess.OPTIONS);
    var names = options.getOptionNames();
    if (names.size() != 1) throw new IllegalStateException("Expected one actual saved registration: " + names);
    String name = names.get(0), registration = options.getString(name, null);
    if (registration == null) throw new IllegalStateException("Missing registration");
    var alias = currentProgram.getAddressFactory().getAddress(name);
    var function = getFunctionAt(alias);
    if (function == null) throw new IllegalStateException("Missing saved alias");
    Files.writeString(out.resolve(label + "-registration.json"), registration);
    identity(label + "-before", registration);
    save(label + "-canonical.json", canonical(getFunctionAt(toAddr(0x150))));
    // Normal installed callback revalidation is read-only; no preview/reapply/refresh here.
    artifacts(label, OrdinaryEntryAccess.registeredProof(currentProgram, alias), alias);
    var owner = owner();
    try { capture(function, owner, label); } finally { owner.dispose(); }
    String after = options.getString(name, null);
    Files.writeString(out.resolve(label + "-registration-after.json"), after);
    if (!registration.equals(after)) throw new IllegalStateException("Stored registration changed");
    identity(label + "-after", after);
  }
  @Override public void run() throws Exception {
    out = Path.of(getScriptArgs()[0]); Files.createDirectories(out);
    String mode = getScriptArgs()[1];
    if (!mode.equals("setup")) {
      if (!Set.of("saved", "reopened").contains(mode)) throw new IllegalArgumentException("Unknown mode");
      retained(mode); println("W2F_ROM_INDEX_CAPTURE_COMPLETE " + mode); return;
    }
    var body = new AddressSet(toAddr(0x150), toAddr(0x169));
    Disassembler.getDisassembler(currentProgram, monitor, null).disassemble(toAddr(0x150), body);
    var canonical = getFunctionAt(toAddr(0x150));
    if (canonical == null) canonical = currentProgram.getFunctionManager().createFunction("w2f_rom_index", toAddr(0x150), body,
        ghidra.program.model.symbol.SourceType.ANALYSIS);
    if (canonical == null || !canonical.getBody().equals(body)) throw new IllegalStateException("Unexpected body");
    save("program.json", Map.of("image_sha256", currentProgram.getExecutableSHA256(),
        "program_id", currentProgram.getUniqueProgramID(), "cartridge", ProgramMapping.cartridge(currentProgram),
        "provider_location", CartridgeLayout.class.getProtectionDomain().getCodeSource().getLocation().toString(),
        "provider_jar_sha256", hash(Path.of(CartridgeLayout.class.getProtectionDomain().getCodeSource().getLocation().toURI())),
        "fresh_setup", true, "input_premise", "B unknown; no concrete input or selected-state premise"));
    var before = canonical(canonical); save("canonical-before.json", before);
    var proof = OrdinaryEntryAccess.preview(currentProgram, canonical, monitor);
    var alias = OrdinaryEntryAccess.install(currentProgram, proof, monitor);
    var after = canonical(canonical); save("canonical-after-install.json", after);
    if (!ProgramMapping.JSON.toJson(before).equals(ProgramMapping.JSON.toJson(after))) throw new IllegalStateException("Canonical changed");
    artifacts("original", proof, alias);
    var owner = owner();
    try {
      var function = getFunctionAt(alias); capture(function, owner, "original");
      byte[] bytesBefore = ProgramMapping.exportBytes(currentProgram, true, false, monitor);
      var source = ProgramMapping.fileToStatic(currentProgram, 0xa001).stream()
          .filter(a -> a.getAddressSpace().getName().equals("rom2")).findFirst().orElseThrow();
      if ((currentProgram.getMemory().getByte(source) & 255) != 3) throw new IllegalStateException("Wrong consumed table byte");
      currentProgram.getMemory().setByte(source, (byte) 4);
      byte[] bytesAfter = ProgramMapping.exportBytes(currentProgram, true, false, monitor);
      var changed = new ArrayList<Integer>();
      for (int i = 0; i < bytesBefore.length; i++) if (bytesBefore[i] != bytesAfter[i]) changed.add(i);
      if (!changed.equals(List.of(0xa001))) throw new IllegalStateException("Mutation was not one physical byte");
      save("mutation.json", Map.of("changed_file_offsets", changed, "old", 3, "new", 4,
          "source", source.toString(), "read_only_ROM", !currentProgram.getMemory().getBlock(source).isWrite(),
          "old_registration_retained", true));
      capture(function, owner, "stale");
      var stale = com.google.gson.JsonParser.parseString(Files.readString(out.resolve("stale-request.json"))).getAsJsonObject();
      if (stale.get("completed").getAsBoolean() || stale.get("highfunction_available").getAsBoolean()
          || !stale.get("error").getAsString().contains("Stale ordinary-entry registration")) throw new IllegalStateException("Stale result accepted");
      var fresh = OrdinaryEntryAccess.preview(currentProgram, canonical, monitor);
      OrdinaryEntryAccess.refresh(currentProgram, alias, fresh, monitor);
      save("refresh.json", Map.of("explicit", true, "native_owner_flush", owner.flushCache(), "alias", alias.toString()));
      artifacts("refreshed", fresh, alias); capture(function, owner, "refreshed");
    } finally { owner.dispose(); }
    println("W2F_ROM_INDEX_CAPTURE_COMPLETE setup");
  }
}
