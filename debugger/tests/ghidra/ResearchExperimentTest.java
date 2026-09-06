import java.io.File;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.app.services.*;
import ghidra.app.util.importer.*;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;
import ghigbc.*;

/** Bounded real RMI restore/repeat experiment. Does not claim general-purpose replay. */
public final class ResearchExperimentTest extends RealTraceTest {
    private static final Gson JSON=new GsonBuilder().serializeNulls().setPrettyPrinting().create();
    private static final ObservationReport.Selection RANGE=new ObservationReport.Selection("cpu",0,0x4029,3);
    static String hash(Path path)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));}
    static JsonObject body(JsonObject report){return report.getAsJsonObject("observation");}
    static JsonObject metadata(JsonObject report){return body(report).getAsJsonObject("metadata");}
    static int register(JsonObject report,String name){return Integer.decode(body(report).getAsJsonObject("registers").get(name).getAsString());}
    static JsonObject capture(TraceRmiConnection connection)throws Exception {
        connection.getMethods().get("save_trace").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);
        require(BankMappings.isReady(object("Machine"),snap()),"research selected capture has persisted static mappings");
        return ObservationReport.capture(trace,snap(),RANGE);
    }
    static JsonObject step(TraceRmiConnection connection)throws Exception {
        long before=((Number)attr("Machine","Capture")).longValue();
        connection.getMethods().get("step_into").invokeAsync(Map.of("thread",object("Machine.Threads[0]"))).get(15,TimeUnit.SECONDS);waitCapture(before);
        return capture(connection);
    }
    static void expectInstruction(JsonObject before,JsonObject after){
        require(register(before,"PC")==0x4029&&register(after,"PC")==0x402b,"exact one-instruction boundary 4029 → 402b");
        require(register(after,"AF")==((register(before,"AF")&255)|0x1100),"LD A,11 produces observed A=11 and preserves flags");
        for(String key:List.of("BC","DE","HL","SP"))require(register(before,key)==register(after,key),"declared unchanged register "+key);
        require(metadata(after).get("Instructions").getAsLong()-metadata(before).get("Instructions").getAsLong()==1,"one retired SameBoy instruction, not a host-time interval");
        require(body(before).getAsJsonObject("memory").getAsJsonArray("bytes").toString().equals("[62,17,201]"),"observed physical ROM1 bytes are 3e 11 c9");
        require(body(before).getAsJsonObject("memory").get("bytes").equals(body(after).getAsJsonObject("memory").get("bytes")),"declared ROM bytes remain unchanged");
    }
    static JsonObject withRecipe(JsonObject report,JsonObject recipe){
        var observation=body(report).deepCopy();observation.add("experimentSteps",recipe.get("steps").deepCopy());observation.add("recordedInputs",recipe.get("inputs").deepCopy());
        observation.add("experimentRecipe",recipe.deepCopy());
        // This is still an observation file; checkpoint payload remains an engine-specific sidecar.
        return ObservationReport.seal(observation);
    }
    static void runExperiment(Path root,Path output)throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),testConfiguration());
        Path work=Files.createTempDirectory(root.resolve("build"),"research-rmi-");
        var project=new Manager().createProject(new ProjectLocator(work.toString(),"ResearchContract"),null,false);
        try(var imported=AutoImporter.importByUsingBestGuess(root.resolve("build/teaching.gbc").toFile(),project,"/",ResearchExperimentTest.class,new MessageLog(),TaskMonitor.DUMMY)) {
            imported.save(TaskMonitor.DUMMY);var program=imported.getPrimaryDomainObject();
            final GhidraTool[] holder=new GhidraTool[1];
            Swing.runNow(()->{try{var tool=new GhidraTool(project,"Research conformance");holder[0]=tool;tool.addPlugins(List.of("ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin","ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin","ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersPlugin","ghigbc.GbcPlugin"));tool.getService(ProgramManager.class).openProgram(program);}catch(Exception error){throw new RuntimeException(error);}});
            var tool=holder[0];
            try {
                for(String backend:List.of("sameboy","mgba")) {
                    var acceptor=tool.getService(TraceRmiService.class).acceptOne(new InetSocketAddress("127.0.0.1",0));acceptor.setTimeout(15000);
                    var command=List.of(System.getenv().getOrDefault("GBC_PYTHON",root.resolve(".venv12/bin/python").toString()),"-m","ghigbc.agent","--backend",backend,"--rom",root.resolve("build/teaching.gbc").toString(),"--connect","127.0.0.1:"+((InetSocketAddress)acceptor.getAddress()).getPort(),"--fixture-ready");
                    var builder=new ProcessBuilder(command);builder.environment().put("PYTHONPATH",root.resolve("python").toString());builder.redirectErrorStream(true);builder.redirectOutput(output.resolve(backend+"-research-agent.log").toFile());var process=builder.start();
                    try(var connection=acceptor.accept()) {
                        trace=connection.waitForTrace(15000);waitCapture(0);var methods=connection.getMethods();
                        long armedCapture=((Number)attr("Machine","Capture")).longValue();
                        methods.get("delete_breakpoint").invokeAsync(Map.of("breakpoint",object("Machine.Breakpoints[1]"))).get(15,TimeUnit.SECONDS);waitCapture(armedCapture);
                        var initial=capture(connection);
                        require(backend.equals(metadata(initial).get("Backend").getAsString()),"research runtime backend identity "+backend);
                        require(register(initial,"PC")==0x4029&&metadata(initial).get("ROMX").getAsInt()==1,"research starts at physical ROM1 +29");
                        if(backend.equals("mgba")) {
                            require(methods.get("checkpoint")==null&&methods.get("restore")==null,"mGBA RMI refuses to advertise unavailable checkpoint/restore actions");
                            require(!metadata(initial).get("Capabilities").getAsString().contains("\"checkpoint\""),"mGBA observation records missing checkpoint capability");
                            ObservationReport.write(output.resolve("mgba-observation.json"),initial);
                        }else {
                            require((Files.readAllBytes(root.resolve("build/teaching.gbc"))[0x147]&255)==0x19,"fixture is MBC5 without a cartridge RTC");
                            require(hash(root.resolve("build/teaching.gbc")).equals(metadata(initial).get("ROMHash").getAsString()),"observed ROM hash identifies exact experiment input");
                            require(body(initial).get("bootHash").getAsString().matches("[0-9a-f]{64}"),"actual loaded boot hash accompanies observation");
                            Path checkpoint=output.resolve("bank1-checkpoint");methods.get("checkpoint").invokeAsync(Map.of("process",object("Machine"),"path",checkpoint.toString())).get(15,TimeUnit.SECONDS);
                            var facade=new BankMappings(program);
                            for(int index=0;index<3;index++){var source=body(initial).getAsJsonObject("memory").getAsJsonArray("sources").get(index).getAsJsonObject();var address=fi.gekkio.ghidraboy.ProgramMapping.staticAddress(program,source.get("staticStart").getAsString()).add(source.get("displacement").getAsLong());require(facade.reverse(address).equals(new BankMappings.Physical("rom",1,0x29+index)),"captured CPU byte "+index+" maps to exact physical ROM1 coordinate");}
                            var checkpointMetadata=JsonParser.parseString(Files.readString(checkpoint.resolve("metadata.json"))).getAsJsonObject();
                            String stateFile=checkpointMetadata.get("state_file").getAsString();
                            require(hash(checkpoint.resolve(stateFile)).equals(checkpointMetadata.get("state_sha256").getAsString()),"engine-specific checkpoint payload hash verified");
                            require(checkpointMetadata.get("rom_hash").equals(metadata(initial).get("ROMHash"))&&checkpointMetadata.get("boot_hash").equals(body(initial).get("bootHash")),"checkpoint and selected observation match ROM/boot identities");
                            require(checkpointMetadata.get("input").getAsString().equals("release-on-restore"),"restore has an explicit released-input policy");
                            var first=step(connection);expectInstruction(initial,first);
                            restoreAndAwait(connection,checkpoint);var restored=capture(connection);
                            require(body(initial).get("registers").equals(body(restored).get("registers")),"restore exactly recovers the declared starting registers");
                            require(metadata(restored).get("Epoch").getAsLong()>metadata(initial).get("Epoch").getAsLong(),"restore produces a distinct observation epoch");
                            var repeated=step(connection);expectInstruction(restored,repeated);
                            require(body(first).get("registers").equals(body(repeated).get("registers")),"restore/repeat reproduces all six declared registers");
                            require(body(first).getAsJsonObject("memory").get("bytes").equals(body(repeated).getAsJsonObject("memory").get("bytes")),"restore/repeat reproduces exact declared physical bytes");
                            require(metadata(first).get("Ticks").getAsLong()-metadata(initial).get("Ticks").getAsLong()==metadata(repeated).get("Ticks").getAsLong()-metadata(restored).get("Ticks").getAsLong(),"repeat has the same declared emulated-tick delta");
                            require(body(first).getAsJsonObject("memory").getAsJsonArray("sources").asList().stream().noneMatch(JsonElement::isJsonNull),"every declared instruction byte traces to an exact static source reference");
                            for(String key:List.of("ROMHash","Backend","Core","Config","Model","TimingUnits","Capabilities"))require(metadata(first).get(key).equals(metadata(repeated).get(key)),"repeat preserves setting "+key);
                            // Deliberately incompatible metadata is a negative fixture, never a new valid checkpoint.
                            Path divergent=output.resolve("incompatible-checkpoint");Files.createDirectory(divergent);Files.copy(checkpoint.resolve(stateFile),divergent.resolve(stateFile));var invalid=checkpointMetadata.deepCopy();invalid.addProperty("config",invalid.get("config").getAsString()+":incompatible-test");Files.writeString(divergent.resolve("metadata.json"),JSON.toJson(invalid));
                            try{methods.get("restore").invokeAsync(Map.of("process",object("Machine"),"path",divergent.toString())).get(15,TimeUnit.SECONDS);throw new AssertionError("Incompatible checkpoint accepted");}catch(ExecutionException expected){require(expected.getCause().getMessage().contains("Checkpoint metadata mismatch"),"divergent config rejected with a specific checkpoint diagnostic");}
                            var afterRejection=capture(connection);require(body(repeated).get("registers").equals(body(afterRejection).get("registers")),"rejected restore leaves usable, unchanged captured registers");
                            var altered=body(first).deepCopy();altered.getAsJsonObject("metadata").addProperty("Config","deliberately divergent comparison fixture");require(ObservationReport.compare(first,ObservationReport.seal(altered)).contains("Different setting Config"),"observation comparison reports divergent settings");
                            var recipe=new JsonObject();recipe.addProperty("format","ghidraboy-bounded-experiment");recipe.addProperty("version",1);recipe.addProperty("scope","one LD A,11 instruction in the self-authored MBC5 fixture, repeated in the same SameBoy process");
                            recipe.addProperty("romSHA256",hash(root.resolve("build/teaching.gbc")));recipe.addProperty("assemblySHA256",hash(root.resolve("tests/fixtures/banks.asm")));recipe.addProperty("assemblySource","tests/fixtures/banks.asm: BankOne");recipe.addProperty("coordinateEvidence","Captured CPU 4029..402b bytes, ROMX=1, with each persisted static source independently reversed to physical rom bank1 offsets29..2b by the authoritative Program mapping");recipe.addProperty("runnerSHA256",hash(root.resolve("tests/ghidra/ResearchExperimentTest.java")));
                            recipe.add("checkpoint",checkpointMetadata);recipe.addProperty("checkpointPath",checkpoint.toString());recipe.addProperty("clockControl","Checkpoint restores emulated state; advance exactly one retired opcode. Cartridge type 0x19 has no RTC; fixture has DI and LCD off at the selected boundary. No host-time run/input request occurs in the measured interval.");
                            recipe.addProperty("counterSemantics","Instrumentation tick/instruction counters are monotonic across restore; compare per-interval deltas, not absolute counter equality.");recipe.addProperty("declaredTickDelta",metadata(first).get("Ticks").getAsLong()-metadata(initial).get("Ticks").getAsLong());recipe.add("inputs",new JsonArray());recipe.addProperty("inputBoundary","No input transitions between checkpoint and either one-opcode step; restore releases all buttons.");
                            recipe.add("steps",JSON.toJsonTree(List.of("Stop at physical rom bank 1 offset 0x29 / CPU 0x4029 using fixture-ready","Delete the fixture-ready breakpoint before checkpoint so restore cannot re-arm a stop ahead of the opcode","Save backend-specific checkpoint and validate ROM/boot/state hashes","Step exactly one retired opcode; observe A=0x11, PC=0x402b, unchanged flags/BC/DE/HL/SP and ROM bytes 3e11c9","Restore that exact checkpoint into the compatible SameBoy session","Repeat one retired opcode and compare the declared observations","Reject incompatible checkpoint settings; keep captured observations usable")));
                            recipe.add("hypotheses",new JsonArray());recipe.addProperty("conclusion","The two controlled one-opcode intervals produced identical declared register/physical-byte results and equal emulated-tick deltas.");recipe.addProperty("limits","No portable state, reverse execution, general clock/input replay, causal stack, or cross-backend checkpoint parity is claimed.");recipe.addProperty("status","PASS");
                            Files.writeString(output.resolve("experiment-recipe.json"),JSON.toJson(recipe)+"\n");
                            ObservationReport.write(output.resolve("initial-observation.json"),withRecipe(initial,recipe));ObservationReport.write(output.resolve("first-observation.json"),withRecipe(first,recipe));ObservationReport.write(output.resolve("restored-observation.json"),withRecipe(restored,recipe));ObservationReport.write(output.resolve("repeat-observation.json"),withRecipe(repeated,recipe));
                            Files.writeString(output.resolve("comparison.txt"),ObservationReport.compare(first,repeated)+"\n");
                        }
                        methods.get("kill").invokeAsync(Map.of("process",object("Machine"))).get(15,TimeUnit.SECONDS);awaitClosed(connection);require(process.waitFor(5,TimeUnit.SECONDS),"research owned process exits: "+backend);
                    }finally{if(process.isAlive()){process.destroyForcibly();process.waitFor(5,TimeUnit.SECONDS);}if(!acceptor.isClosed())acceptor.cancel();Swing.runNow(()->tool.getService(DebuggerTraceManagerService.class).activateTrace(null));}
                }
            }finally{Swing.runNow(tool::dispose);}
        }finally{project.close();}
        require(asyncErrors.isEmpty(),"research harness has no uncaught asynchronous errors");System.out.println("RESEARCH_EXPERIMENT_PASSED");
    }
    static void reopen(Path output)throws Exception {
        var recipe=JsonParser.parseString(Files.readString(output.resolve("experiment-recipe.json"))).getAsJsonObject();String rom=recipe.get("romSHA256").getAsString();
        var initial=ObservationReport.read(output.resolve("initial-observation.json"),rom);var first=ObservationReport.read(output.resolve("first-observation.json"),rom);var restored=ObservationReport.read(output.resolve("restored-observation.json"),rom);var repeated=ObservationReport.read(output.resolve("repeat-observation.json"),rom);
        expectInstruction(initial,first);expectInstruction(restored,repeated);
        require(metadata(first).get("Ticks").getAsLong()-metadata(initial).get("Ticks").getAsLong()==recipe.get("declaredTickDelta").getAsLong()&&metadata(repeated).get("Ticks").getAsLong()-metadata(restored).get("Ticks").getAsLong()==recipe.get("declaredTickDelta").getAsLong(),"independent reader verifies both declared emulated-tick deltas");
        require(body(first).get("registers").equals(body(repeated).get("registers")),"independent reader verifies declared reproduced registers");
        require(body(first).get("recordedInputs").getAsJsonArray().isEmpty()&&body(first).get("hypotheses").getAsJsonArray().isEmpty(),"recorded empty input sequence and separate hypotheses survive reopen");
        require(body(first).getAsJsonObject("memory").getAsJsonArray("sources").asList().stream().noneMatch(JsonElement::isJsonNull),"independent reader traces declared bytes to saved source references");
        require(body(first).get("replay").getAsString().startsWith("unavailable"),"observation remains non-executable evidence after reopen");System.out.println("RESEARCH_EXPERIMENT_REOPEN_PASSED");
    }
    public static void main(String[] args){Thread.setDefaultUncaughtExceptionHandler((thread,error)->{asyncErrors.add(error);error.printStackTrace();});try{if(args[0].equals("reopen"))reopen(Path.of(args[1]));else runExperiment(Path.of(args[0]).toRealPath(),Path.of(args[1]).toRealPath());System.exit(0);}catch(Throwable error){error.printStackTrace();System.exit(1);}}
}
