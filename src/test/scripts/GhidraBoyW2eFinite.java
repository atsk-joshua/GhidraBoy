// Self-authored bounded W2e installed/native four-selector witness.
// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.disassemble.Disassembler;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** No concrete CPU/selector or display state is supplied to the provider. */
public class GhidraBoyW2eFinite extends GhidraScript {
  Path out;
  IdentityHashMap<Varnode, Integer> ids = new IdentityHashMap<>();
  String hash(Path path) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
  }
  void save(String name, Object value) throws Exception {
    Files.writeString(out.resolve(name), ProgramMapping.JSON.toJson(value) + "\n");
  }
  Object varnode(Varnode v) {
    if (v == null) return null;
    return Map.of("id", ids.computeIfAbsent(v, ignored -> ids.size()),
        "space", v.getAddress().getAddressSpace().getName(), "offset", v.getOffset(),
        "size", v.getSize(), "constant", v.isConstant(), "address", v.isAddress(), "register", v.isRegister());
  }
  Object operation(PcodeOp op) {
    var record = new LinkedHashMap<String, Object>();
    record.put("mnemonic", op.getMnemonic()); record.put("sequence", op.getSeqnum().toString());
    if (op.getOpcode() == PcodeOp.CALLOTHER)
      record.put("userop_name", currentProgram.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset()));
    record.put("output", varnode(op.getOutput()));
    record.put("inputs", Arrays.stream(op.getInputs()).map(this::varnode).toList());
    return record;
  }
  Object processes() {
    return ProcessHandle.current().descendants().map(p -> {
      var m = new LinkedHashMap<String, Object>();
      m.put("pid", p.pid()); m.put("parent", p.parent().map(ProcessHandle::pid).orElse(-1L));
      m.put("arguments",p.info().arguments().map(Arrays::asList).orElse(List.of()));
      try {
        var proc=Path.of("/proc",Long.toString(p.pid()));
        if(Files.isDirectory(proc)) {
          String cmdline=Files.readString(proc.resolve("cmdline"));m.put("proc_cmdline",cmdline.replace('\0',' '));
          m.put("proc_maps",Files.readString(proc.resolve("maps")));
          var executables=new ArrayList<Object>();
          for(String arg:cmdline.split("\u0000"))if(arg.endsWith("/decompile")&&Files.isRegularFile(Path.of(arg)))executables.add(Map.of("path",arg,"sha256",hash(Path.of(arg))));
          m.put("argv_native_files",executables);
        }
      }catch(Exception e){m.put("proc_observation_error",e.toString());}
      p.info().command().ifPresent(command -> {
        m.put("command", command);
        try { m.put("binary_sha256", hash(Path.of(command))); }
        catch (Exception e) { m.put("hash_error", e.toString()); }
      });
      return m;
    }).toList();
  }
  void capture(Function function, DecompInterface owner, String label) throws Exception {
    var request = new LinkedHashMap<String, Object>();
    request.put("entry", function.getEntryPoint().toString());
    request.put("owner_java_pid", ProcessHandle.current().pid());
    request.put("revision", currentProgram.getModificationNumber());
    Path debug = out.resolve(label + "-debug.xml"); owner.enableDebug(debug.toFile());
    var result = owner.decompileFunction(function, 90, monitor);
    request.put("completed", result.decompileCompleted()); request.put("error", result.getErrorMessage());
    request.put("highfunction_available", result.getHighFunction() != null);
    request.put("processes_after", processes());
    if (Files.exists(debug)) request.put("debug", Map.of("path", debug.toString(), "sha256", hash(debug)));
    if (result.getHighFunction() != null) {
      ids.clear(); var blocks = new ArrayList<Object>();
      for (var block : result.getHighFunction().getBasicBlocks()) {
        var incoming = new ArrayList<Integer>(); var outgoing = new ArrayList<Integer>();
        for (int i = 0; i < block.getInSize(); i++) incoming.add(block.getIn(i).getIndex());
        for (int i = 0; i < block.getOutSize(); i++) outgoing.add(block.getOut(i).getIndex());
        var ops = new ArrayList<Object>(); var iterator = block.getIterator();
        while (iterator.hasNext()) ops.add(operation(iterator.next()));
        blocks.add(Map.of("index", block.getIndex(), "in", incoming, "out", outgoing, "ops", ops));
      }
      save(label + "-high.json", blocks);
    }
    if (result.getDecompiledFunction() != null)
      Files.writeString(out.resolve(label + ".c"), result.getDecompiledFunction().getC());
    save(label + "-request.json", request);
  }
  Object canonical(Function function) throws Exception {
    var instructions = new ArrayList<Object>();
    for (var instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
      ids.clear(); instructions.add(Map.of("address", instruction.getAddress().toString(),
          "bytes", HexFormat.of().formatHex(instruction.getBytes()),
          "raw", Arrays.stream(instruction.getPcode(false)).map(this::operation).toList()));
    }
    return Map.of("entry", function.getEntryPoint().toString(), "body", function.getBody().toString(),
        "name", function.getName(), "instructions", instructions);
  }
  boolean stockOrdinary(){return Arrays.asList(getScriptArgs()).contains("stock");}
  void artifacts(String label, OrdinaryEntryAccess.Proof proof, Address alias) throws Exception {
    save(label + "-proof.json", proof);
    var payload = currentProgram.getCompilerSpec().getPcodeInjectLibrary().getPayload(
        stockOrdinary()?InjectPayload.CALLOTHERFIXUP_TYPE:InjectPayload.CALLMECHANISM_TYPE, stockOrdinary()?StockEntryInjection.NAME:SoftwareCallStateEntryInjection.NAME);
    var context = new InjectContext(); context.baseAddr = alias; context.nextAddr = alias;
    ids.clear(); save(label + "-requested-entry-pcode.json",
        Arrays.stream(payload.getPcode(currentProgram, context)).map(this::operation).toList());
  }
  @Override public void run() throws Exception {
    out = Path.of(getScriptArgs()[0]); Files.createDirectories(out);
    var body = new AddressSet(toAddr(0x150), toAddr(0x161));
    Disassembler.getDisassembler(currentProgram, monitor, null).disassemble(toAddr(0x150), body);
    var canonical = getFunctionAt(toAddr(0x150));
    if (canonical == null) canonical = currentProgram.getFunctionManager().createFunction("w2e_f1234", toAddr(0x150), body,
        ghidra.program.model.symbol.SourceType.ANALYSIS);
    if (canonical == null || !canonical.getBody().equals(body)) throw new IllegalStateException("Unexpected body");
    save("program.json", Map.of("image_sha256", currentProgram.getExecutableSHA256(),
        "program_id", currentProgram.getUniqueProgramID(), "cartridge", ProgramMapping.cartridge(currentProgram),
        "provider_location", CartridgeLayout.class.getProtectionDomain().getCodeSource().getLocation().toString()));
    var before = canonical(canonical); save("canonical-before.json", before);
    var proof = OrdinaryEntryAccess.preview(currentProgram, canonical, monitor);
    var alias = stockOrdinary()?OrdinaryEntryAccess.installStock(currentProgram, proof, monitor):OrdinaryEntryAccess.install(currentProgram, proof, monitor);
    var after = canonical(canonical); save("canonical-after-install.json", after);
    if (!ProgramMapping.JSON.toJson(before).equals(ProgramMapping.JSON.toJson(after))) throw new IllegalStateException("Canonical changed");
    artifacts("original", proof, alias);
    var owner = new DecompInterface();
    try {
      owner.setOptions(new DecompileOptions());
      if (!owner.setSimplificationStyle("decompile") || !owner.toggleSyntaxTree(true)
          || !owner.toggleCCode(true) || !owner.openProgram(currentProgram)) throw new IllegalStateException("Native setup refused");
      var function = getFunctionAt(alias); capture(function, owner, "original");
      byte[] bytesBefore = ProgramMapping.exportBytes(currentProgram, true, false, monitor);
      var source = ProgramMapping.fileToStatic(currentProgram, 0xe000).stream()
          .filter(a -> a.getAddressSpace().getName().equals("rom3")).findFirst().orElseThrow();
      if ((currentProgram.getMemory().getByte(source) & 255) != 0xd3) throw new IllegalStateException("Wrong consumed byte");
      currentProgram.getMemory().setByte(source, (byte) 0xe4);
      byte[] bytesAfter = ProgramMapping.exportBytes(currentProgram, true, false, monitor);
      var changed = new ArrayList<Integer>();
      for (int i = 0; i < bytesBefore.length; i++) if (bytesBefore[i] != bytesAfter[i]) changed.add(i);
      if (!changed.equals(List.of(0xe000))) throw new IllegalStateException("Mutation was not one physical byte");
      save("mutation.json", Map.of("changed_file_offsets", changed, "old", 0xd3, "new", 0xe4,
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
    println("W2E_FINITE_CAPTURE_COMPLETE");
  }
}
