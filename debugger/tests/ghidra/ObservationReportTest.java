import java.io.File;
import java.nio.ByteBuffer;
import java.nio.file.*;
import com.google.gson.*;
import ghigbc.*;
import ghidra.GhidraApplicationLayout;
import ghidra.app.util.importer.*;
import ghidra.framework.*;
import ghidra.framework.model.*;
import ghidra.framework.project.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.XmlSchemaContext;
import ghidra.util.task.TaskMonitor;

/** Real trace memory/states/mappings, without an emulator dependency. */
public final class ObservationReportTest {
    static class Manager extends DefaultProjectManager { Manager(){super();} }
    static void require(boolean ok,String reason){if(!ok)throw new AssertionError(reason);System.out.println("PASS observation: "+reason);}
    static void reject(Runnable action,String reason){try{action.run();throw new AssertionError("Accepted "+reason);}catch(IllegalArgumentException expected){System.out.println("PASS observation rejected: "+reason);}}
    static JsonObject body(JsonObject report){return report.getAsJsonObject("observation");}
    public static void main(String[] args)throws Exception {
        if(args[0].equals("reopen")){var report=ObservationReport.read(Path.of(args[1]),null);require(body(report).getAsJsonObject("memory").getAsJsonArray("bytes").get(0).getAsInt()==17,"separate Java process reopens captured bytes without trace or emulator");require(ObservationReport.describe(report).contains("current Program binding is unverified"),"human report exposes stale/unverified mapping limit");System.out.println("OBSERVATION_STANDALONE_REOPEN_PASSED");return;}
        Path root=Path.of(args[0]),work=Path.of(args[1]);
        Application.initializeApplication(new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),new HeadlessGhidraApplicationConfiguration());
        var project=new Manager().createProject(new ProjectLocator(work.toString(),"ObservationChecks"),null,false);
        try(var imported=AutoImporter.importByUsingBestGuess(root.resolve("build/teaching.gbc").toFile(),project,"/",ObservationReportTest.class,new MessageLog(),TaskMonitor.DUMMY)) {
            imported.save(TaskMonitor.DUMMY);var program=imported.getPrimaryDomainObject();var mappings=new BankMappings(program);
            var trace=new DBTrace("Observation contract",program.getCompilerSpec(),ObservationReportTest.class);
            try {
                TraceObject machine;
                try(var tx=trace.openTransaction("Fixture schema")) {
                    var schema=XmlSchemaContext.deserialize(root.resolve("python/ghigbc/schema.xml").toFile());trace.getObjectManager().createRootObject(schema.getSchema(schema.name("Session")));
                    machine=trace.getObjectManager().createObject(KeyPath.parse("Machine"));machine.insert(Lifespan.nowOn(0),TraceObject.ConflictResolution.DENY);
                    trace.getMemoryManager().createOverlayAddressSpace("wram0",trace.getBaseAddressFactory().getDefaultAddressSpace());
                    var container=trace.getObjectManager().createObject(KeyPath.parse("Machine.Events"));container.insert(Lifespan.nowOn(0),TraceObject.ConflictResolution.DENY);
                    var event=trace.getObjectManager().createObject(KeyPath.parse("Machine.Events[1]"));event.insert(Lifespan.nowOn(0),TraceObject.ConflictResolution.DENY);
                    for(var entry:java.util.Map.<String,Object>of("Snapshot",0,"Epoch",0,"TargetRegion",2,"TargetBank",1,"TargetOffset",0x23,"Access",4,"Valid",true,"Before",16,"After",17).entrySet())event.setValue(Lifespan.nowOn(0),entry.getKey(),entry.getValue());
                    for(int snap=0;snap<2;snap++) {
                        trace.getTimeManager().getSnapshot(snap,true);
                        for(var entry:java.util.Map.<String,Object>of("ROMHash",mappings.hash(),"Session","fixture-session","Epoch",snap,"Capture",snap+1,"Backend","sameboy","Model","CGB-E","ROM0",0,"ROMX",1,"WRAM",1,"VRAM",0).entrySet())machine.setValue(Lifespan.at(snap),entry.getKey(),entry.getValue());
                        machine.setValue(Lifespan.at(snap),"CaptureSnapshot",snap);
                        machine.setValue(Lifespan.at(snap),"BootHash","a".repeat(64));
                        machine.setValue(Lifespan.at(snap),"BootPolicy","image");
                        trace.getMemoryManager().putBytes(snap,trace.getBaseAddressFactory().getAddressSpace("wram0").getAddress(0xc000),ByteBuffer.wrap(new byte[]{(byte)(17+snap),34,51}));
                        trace.getMemoryManager().setState(snap,trace.getBaseAddressFactory().getAddressSpace("wram0").getAddress(0xc002),TraceMemoryState.UNKNOWN);
                    }
                }
                mappings.apply(trace,0);mappings.apply(trace,1);
                var range=new ObservationReport.Selection("wram",0,0,4);var first=ObservationReport.capture(trace,0,range);var second=ObservationReport.capture(trace,1,range);
                var event=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine.Events[1]"));
                require(new HistoryFilter("region:wram bank:1 offset:0x23 epoch:0 access:write").matches(event,0,"writer"),"exact physical/epoch/access history filtering");
                require(!new HistoryFilter("bank:10").matches(event,0,"bank 10 writer"),"bank filter uses physical metadata rather than substring matches");
                require(!new HistoryFilter("epoch:1").matches(event,0,"writer"),"epoch filter excludes another epoch");
                require(new HistoryFilter("writer").matches(event,0,"Writer @ address"),"free text search is literal and case insensitive");
                reject(()->new HistoryFilter("bank:many"),"malformed filter integer");reject(()->new HistoryFilter("bank:1 bank:2"),"duplicate physical filter");
                require(body(first).getAsJsonArray("events").size()==1&&body(second).getAsJsonArray("events").isEmpty(),"report includes only events observed at selected capture");
                require(body(first).getAsJsonObject("memory").getAsJsonArray("bytes").get(0).getAsInt()==17,"selected older capture retained independently of latest capture");
                require(body(first).getAsJsonObject("memory").getAsJsonArray("bytes").get(2).isJsonNull(),"UNKNOWN memory does not expose stale bytes");
                require(body(first).getAsJsonObject("metadata").get("Instructions").isJsonNull(),"unavailable instruction count remains unknown");
                require(body(first).get("bootHash").getAsString().equals("a".repeat(64))&&body(first).get("bootPolicy").getAsString().equals("image"),"captured boot identity and policy survive export");
                var bootDifferent=body(second).deepCopy();bootDifferent.addProperty("bootHash","b".repeat(64));
                require(ObservationReport.compare(first,ObservationReport.seal(bootDifferent)).contains("Different setting bootHash"),"different boot bytes cannot imply matched experiment settings");
                require(!body(first).getAsJsonObject("memory").getAsJsonArray("sources").get(0).isJsonNull(),"exact persisted static source mapping accompanies observed byte");
                require(ObservationReport.compare(first,second).contains("1 changed known bytes; 2 bytes not comparable"),"comparison separates changed and unknown bytes");
                require(ObservationReport.compare(first,second).contains("Unverified setting Config"),"missing settings do not establish matched replay");
                var different=body(second).deepCopy();different.getAsJsonObject("metadata").addProperty("Backend","mgba");require(ObservationReport.compare(first,ObservationReport.seal(different)).contains("Different setting Backend"),"backend differences are explicit");
                ObservationReport.write(work.resolve("observation.json"),first);var roundtrip=ObservationReport.read(work.resolve("observation.json"),mappings.hash());require(roundtrip.equals(first),"complete versioned hash-checked JSON roundtrip");
                var tampered=first.deepCopy();body(tampered).addProperty("snapshot",999);reject(()->ObservationReport.validate(tampered,null),"payload SHA-256 mismatch");
                var wrongVersion=first.deepCopy();wrongVersion.addProperty("version",2);reject(()->ObservationReport.validate(wrongVersion,null),"unsupported format version");
                reject(()->ObservationReport.validate(first,"0".repeat(64)),"selected ROM hash mismatch");
                var unknown=body(first).deepCopy();unknown.getAsJsonObject("memory").getAsJsonArray("bytes").set(2,new JsonPrimitive(99));reject(()->ObservationReport.validate(ObservationReport.seal(unknown),null),"unknown byte with fabricated value even with recomputed hash");
                var physical=body(first).deepCopy();physical.getAsJsonObject("memory").addProperty("address",1);reject(()->ObservationReport.validate(ObservationReport.seal(physical),null),"inconsistent physical coordinates");
                reject(()->new ObservationReport.Selection("wram",0,0,4097),"oversized capture");reject(()->new ObservationReport.Selection("wram",0,-1,2),"negative physical offset");
                reject(()->ObservationReport.capture(trace,2,range),"snapshot without completed marker");
                var missing=ObservationReport.capture(trace,0,new ObservationReport.Selection("vram",1,0,2));require(body(missing).getAsJsonObject("memory").getAsJsonArray("bytes").get(0).isJsonNull(),"uncaptured physical bank remains unknown");
                for(var invalid:java.util.Map.of("malformed","{malformed","duplicate","{\"format\":1,\"format\":2}","deep","[".repeat(30)+"0"+"]".repeat(30),"trailing",first.toString()+" true","oversized"," ".repeat(ObservationReport.MAX_FILE_BYTES+1)).entrySet()) {
                    Files.writeString(work.resolve("invalid.json"),invalid.getValue());try{ObservationReport.read(work.resolve("invalid.json"),null);throw new AssertionError(invalid.getKey()+" accepted");}catch(java.io.IOException expected){System.out.println("PASS observation rejected: "+invalid.getKey()+" JSON");}
                }
                Thread.currentThread().interrupt();try{ObservationReport.capture(trace,0,range);throw new AssertionError("cancel ignored");}catch(java.util.concurrent.CancellationException expected){System.out.println("PASS observation: capture cancellation");}finally{Thread.interrupted();}
            }finally{trace.release(ObservationReportTest.class);}
        }finally{project.close();}
        System.out.println("OBSERVATION_REPORT_TEST_PASSED");
    }
}
