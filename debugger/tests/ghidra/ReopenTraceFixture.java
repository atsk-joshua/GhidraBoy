import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.model.*;
import ghidra.framework.project.*;
import ghidra.trace.model.*;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.util.task.TaskMonitor;
import ghigbc.BankMappings;

/** Separate-process saved-history verification; no emulator or optional profile is loaded. */
public class ReopenTraceFixture {
    static class Manager extends DefaultProjectManager { Manager(){super();} }
    static void require(boolean condition,String message) {
        if(!condition)throw new AssertionError(message);
        System.out.println("PASS "+message);
    }
    public static void main(String[] args)throws Exception {
        try {Class.forName("ghibw3.StudyPlugin");throw new AssertionError("Optional study plugin installed");}
        catch(ClassNotFoundException expected) {}
        var fixture=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        Path copiedProjects=Path.of(args[1]);
        Application.initializeApplication(new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),new HeadlessGhidraApplicationConfiguration());
        var project=new Manager().openProject(new ProjectLocator(copiedProjects.toString(),fixture.get("project").getAsString()),false,false);
        var file=project.getProjectData().getFile(fixture.get("trace").getAsString());
        require(file!=null,"copied saved trace is present");
        boolean seedLegacy=args.length>2&&args[2].equals("seed-legacy");
        if(seedLegacy) {
            Path original=Path.of(fixture.get("directory").getAsString()).resolve(fixture.get("project").getAsString()+".rep").toRealPath();
            Path copied=copiedProjects.resolve(fixture.get("project").getAsString()+".rep").toRealPath();
            require(!original.equals(copied),"legacy fixture transformation is restricted to a copied project");
        }
        var trace=(Trace)(seedLegacy?file.getDomainObject(ReopenTraceFixture.class,true,false,TaskMonitor.DUMMY):file.getReadOnlyDomainObject(ReopenTraceFixture.class,-1,TaskMonitor.DUMMY));
        try {
            long snap=fixture.get("snapshot").getAsLong();
            if(seedLegacy) {
                var machine=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
                try(var transaction=trace.openTransaction("Synthetic legacy mapping marker fixture")) {
                    machine.setValue(Lifespan.at(snap),"MappingSnapshot",null);
                    machine.setValue(Lifespan.at(snap),"MappingReady",true);
                }
                trace.save("Synthetic legacy mapping marker fixture",TaskMonitor.DUMMY);
                System.out.println("LEGACY_BOOLEAN_FIXTURE_SAVED");
                return;
            }
            var bytes=ByteBuffer.allocate(1);
            trace.getMemoryManager().getBytes(snap,trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(0x402a),bytes);
            require((bytes.array()[0]&255)==0x11,"historic bank-1 CPU byte survives standalone reopen");
            var machine=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
            require(BankMappings.isReady(machine,snap),"historic mapping completion survives standalone reopen");
            if(fixture.has("legacyBooleanMapping")&&fixture.get("legacyBooleanMapping").getAsBoolean()) {
                require(machine.getValue(snap,"MappingSnapshot")==null&&Boolean.TRUE.equals(machine.getValue(snap,"MappingReady").getValue()),"legacy boolean mapping marker survives actual save/reopen");
            }
            var backend=machine.getValue(snap,"Backend");
            if(fixture.get("backend").isJsonNull())require(backend==null,"legacy trace remains readable without fabricated backend metadata");
            else require(backend!=null&&fixture.get("backend").getAsString().equals(backend.getValue()),"captured backend identity survives standalone reopen");
            require(fixture.get("profile").getAsString().equals(machine.getValue(snap,"Profile").getValue()),"profile identity remains observational after provider removal");
            if(fixture.has("requireEdits")&&fixture.get("requireEdits").getAsBoolean()) {
                long last=trace.getTimeManager().getMaxSnap();
                var edits=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine.Edits"));
                require(edits!=null&&!edits.getElements(Lifespan.at(last)).isEmpty(),"saved edit history remains present without an emulator");
                for(var entry:edits.getElements(Lifespan.at(last))) {
                    var edit=(ghidra.trace.model.target.TraceObject)entry.getValue();
                    require("debugger".equals(edit.getValue(last,"Origin").getValue())&&edit.getValue(last,"RecoverySHA256").getValue().toString().length()==64,"edit origin and recovery identity survive standalone reopen");
                }
                require(machine.getValue(last,"ParentCheckpoint")!=null&&machine.getValue(last,"ParentCheckpointSHA256").getValue().toString().length()==64,"checkpoint parent provenance survives standalone reopen");
            }
            int count=fixture.get("profileFields").getAsInt();
            if(count>0) {
                require(((Number)machine.getValue(snap,"ProfileRecordCount").getValue()).intValue()==count,"profile record count survives provider removal");
                var field=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine.ProfileFields[0]"));
                var data=(byte[])field.getValue(snap,"Data").getValue();
                var decoded=JsonParser.parseString(new String(data,StandardCharsets.UTF_8)).getAsJsonArray();
                require(decoded.size()==count&&decoded.get(0).getAsJsonObject().has("source"),"stored decoded fields retain raw provenance without decoder code");
            }
            System.out.println("STANDALONE_TRACE_REOPEN_PASS");
        }finally {trace.release(ReopenTraceFixture.class);project.close();}
    }
}
