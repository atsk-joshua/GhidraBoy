package ghigbc;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import ghidra.program.model.address.Address;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.path.KeyPath;

/** Bounded, engine-independent observations. An export is evidence, never executable state. */
public final class ObservationReport {
    public static final int VERSION=1, MAX_BYTES=4096, MAX_EVENTS=1000, MAX_FILE_BYTES=4*1024*1024;
    private static final Gson JSON=new GsonBuilder().serializeNulls().setPrettyPrinting().create();
    private static final String FORMAT="ghidraboy-observation";
    private static final String[] REGIONS={"cpu","rom","wram","vram","cart","boot","oam","hram","io"};
    private static final String[] METADATA={"ROMHash","Session","Epoch","Capture","Backend","BackendAPI","Core","CorePatch","Config","Model","HardwareMode","Capabilities","TimingUnits","TicksPerSecond","Ticks","Instructions","ExecutionBoundaries","Coverage","MemorySemantics","MappingGeneration","StaticMappingGeneration","BoundStaticGeneration","StaticMappingEnvelope","MappingIssues","MappingSnapshot","ROM0","ROMX","WRAM","VRAM","CartBank","Mapper","Boot","BootRanges","ObservationState","StopReason","Dropped","ParentCheckpointSHA256","CheckpointSourceSession","CheckpointSourceEpoch","CheckpointSourceTicks"};
    private static final String[] EVENT_FIELDS={"Snapshot","Epoch","Writer","WriterPC","WriterRegion","WriterBank","WriterOffset","TargetRegion","TargetBank","TargetOffset","TargetCPU","Before","After","Attempt","Access","Origin","Precision","Valid"};
    private ObservationReport() {}

    public record Selection(String region,int bank,int offset,int length) {
        public Selection {
            if(!List.of(REGIONS).contains(region))throw new IllegalArgumentException("Choose a known physical region.");
            int limit=switch(region){case "cpu"->65536;case "rom"->16384;case "wram"->4096;case "vram","cart"->8192;case "boot"->2304;case "oam"->160;case "hram"->127;default->128;};
            int banks=switch(region){case "rom"->512;case "wram"->8;case "vram"->2;case "cart"->16;default->1;};
            if(bank<0||bank>=banks||offset<0||length<1||length>MAX_BYTES||(long)offset+length>limit)
                throw new IllegalArgumentException("Range exceeds this region or the 4096-byte export limit.");
        }
        public String space(){return switch(region){case "cpu","oam","hram","io"->"ram";default->region+bank;};}
        public int base(){return switch(region){case "rom"->bank==0?0:0x4000;case "wram"->bank==0?0xc000:0xd000;case "vram"->0x8000;case "cart"->0xa000;case "oam"->0xfe00;case "hram"->0xff80;case "io"->0xff00;default->0;};}
    }
    public static Object value(TraceObject object,long snap,String name){var v=object==null?null:object.getValue(snap,name);return v==null?null:v.getValue();}
    private static JsonElement element(Object value){
        if(value instanceof byte[] b)return new JsonPrimitive(new String(b,StandardCharsets.UTF_8));
        if(value instanceof Address a)return new JsonPrimitive(a.toString());
        return JSON.toJsonTree(value);
    }
    private static void checkCancelled(){if(Thread.currentThread().isInterrupted())throw new java.util.concurrent.CancellationException();}
    public static JsonObject capture(Trace trace,long snap,Selection selected){
        Objects.requireNonNull(trace,"Select a captured trace first.");
        var machine=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
        if(!(value(machine,snap,"CaptureSnapshot") instanceof Number n)||n.longValue()!=snap)
            throw new IllegalArgumentException("Selected snapshot is incomplete or has no captured observation.");
        var body=new JsonObject();body.addProperty("traceName",trace.getName());
        var file=trace.getDomainFile();body.addProperty("traceFile",file==null?null:file.getPathname());
        body.addProperty("snapshot",snap);body.addProperty("provenance","observed trace bytes and metadata; static labels are captured mappings, not causal proof");
        var metadata=new JsonObject();for(String key:METADATA)metadata.add(key,element(value(machine,snap,key)));body.add("metadata",metadata);
        var registers=new JsonObject();var regs=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine.Threads[0].Stack[0].Registers"));
        for(String key:List.of("AF","BC","DE","HL","SP","PC"))registers.add(key,element(value(regs,snap,key)));body.add("registers",registers);
        var memory=JSON.toJsonTree(selected).getAsJsonObject();memory.addProperty("space",selected.space());memory.addProperty("address",selected.base()+selected.offset());
        var bytes=new JsonArray();var states=new JsonArray();var sources=new JsonArray();
        var space=trace.getBaseAddressFactory().getAddressSpace(selected.space());
        for(int i=0;i<selected.length();i++) {
            checkCancelled();Address address=space==null?null:space.getAddress(selected.base()+selected.offset()+i);
            var state=address==null?TraceMemoryState.UNKNOWN:trace.getMemoryManager().getState(snap,address);
            states.add(state.name());
            if(state==TraceMemoryState.KNOWN){var b=ByteBuffer.allocate(1);if(trace.getMemoryManager().getBytes(snap,address,b)!=1)throw new IllegalStateException("Known trace byte could not be read.");bytes.add(Byte.toUnsignedInt(b.array()[0]));}
            else bytes.add(JsonNull.INSTANCE);
            var mapping=address==null?null:trace.getStaticMappingManager().findContaining(address,snap);
            if(mapping==null)sources.add(JsonNull.INSTANCE);
            else {var source=new JsonObject();source.addProperty("programURL",mapping.getStaticProgramURL().toString());source.addProperty("staticStart",mapping.getStaticAddress());source.addProperty("displacement",address.subtract(mapping.getMinTraceAddress()));source.addProperty("bindingStatus","persisted mapping; current Program binding not verified by export");sources.add(source);}
        }
        memory.add("bytes",bytes);memory.add("states",states);memory.add("sources",sources);body.add("memory",memory);
        var events=new JsonArray();boolean truncated=false;
        var container=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine.Events"));
        if(container!=null)for(var entry:container.getElements(Lifespan.at(snap))) {
            checkCancelled();if(!(entry.getValue() instanceof TraceObject event)||!(value(event,snap,"Snapshot") instanceof Number observed)||observed.longValue()!=snap)continue;
            if(events.size()==MAX_EVENTS){truncated=true;break;}
            var item=new JsonObject();item.addProperty("path",event.getCanonicalPath().toString());
            for(String key:EVENT_FIELDS)item.add(key,element(value(event,snap,key)));events.add(item);
        }
        body.add("events",events);body.addProperty("eventsTruncated",truncated);body.add("hypotheses",new JsonArray());
        body.addProperty("experimentSteps",(String)null);body.addProperty("recordedInputs",(String)null);
        body.add("bootHash",element(value(machine,snap,"BootHash")));body.add("bootPolicy",element(value(machine,snap,"BootPolicy")));
        body.addProperty("replay","unavailable: no boundary-timed inputs, controlled clock, or portable checkpoint is included");
        return seal(body);
    }
    public static JsonObject seal(JsonObject body){
        var envelope=new JsonObject();envelope.addProperty("format",FORMAT);envelope.addProperty("version",VERSION);envelope.add("observation",body.deepCopy());envelope.addProperty("sha256",sha(canonical(body).getBytes(StandardCharsets.UTF_8)));return envelope;
    }
    private static String canonical(JsonElement element){
        if(element.isJsonObject()){var object=new JsonObject();new TreeSet<>(element.getAsJsonObject().keySet()).forEach(k->object.add(k,JsonParser.parseString(canonical(element.getAsJsonObject().get(k)))));return object.toString();}
        if(element.isJsonArray()){var array=new JsonArray();element.getAsJsonArray().forEach(e->array.add(JsonParser.parseString(canonical(e))));return array.toString();}
        return element.toString();
    }
    private static String sha(byte[] bytes){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}catch(java.security.NoSuchAlgorithmException impossible){throw new AssertionError(impossible);}}
    public static void write(Path path,JsonObject report)throws IOException {
        validate(report,null);byte[] data=(JSON.toJson(report)+"\n").getBytes(StandardCharsets.UTF_8);
        if(data.length>MAX_FILE_BYTES)throw new IOException("Observation exceeds the 4 MiB file limit.");
        Path destination=path.toAbsolutePath();Path temporary=Files.createTempFile(destination.getParent(),".observation-",".tmp");
        try {Files.write(temporary,data);checkCancelled();try{Files.move(temporary,destination,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}catch(AtomicMoveNotSupportedException unavailable){Files.move(temporary,destination,StandardCopyOption.REPLACE_EXISTING);}}finally{Files.deleteIfExists(temporary);}
    }
    /** expectedROMHash is optional; callers comparing with a selected ROM must provide it. */
    public static JsonObject read(Path path,String expectedROMHash)throws IOException {
        try(var stream=Files.newInputStream(path)) {
            byte[] bytes=stream.readNBytes(MAX_FILE_BYTES+1);if(bytes.length>MAX_FILE_BYTES)throw new IOException("Observation exceeds the 4 MiB file limit.");
            try{var reader=new JsonReader(new java.io.StringReader(new String(bytes,StandardCharsets.UTF_8)));reader.setLenient(false);var report=parseBounded(reader,0).getAsJsonObject();if(reader.peek()!=JsonToken.END_DOCUMENT)throw new IOException("Trailing JSON content.");validate(report,expectedROMHash);return report;}
            catch(RuntimeException error){throw new IOException("Invalid observation: "+error.getMessage(),error);}
        }
    }
    // Strict streaming parsing bounds nesting before Gson tree/canonicalization recursion,
    // and rejects duplicate keys so a hash cannot conceal an ambiguous observation.
    private static JsonElement parseBounded(JsonReader reader,int depth)throws IOException {
        checkCancelled();if(depth>24)throw new IOException("Observation JSON exceeds the nesting limit.");
        switch(reader.peek()) {
            case BEGIN_OBJECT: {
                reader.beginObject();var object=new JsonObject();while(reader.hasNext()){String key=reader.nextName();if(object.has(key))throw new IOException("Duplicate JSON field: "+key);object.add(key,parseBounded(reader,depth+1));}reader.endObject();return object;
            }
            case BEGIN_ARRAY: {
                reader.beginArray();var array=new JsonArray();while(reader.hasNext()){if(array.size()>=16384)throw new IOException("Observation array exceeds the element limit.");array.add(parseBounded(reader,depth+1));}reader.endArray();return array;
            }
            case STRING:return new JsonPrimitive(reader.nextString());
            case NUMBER: {
                String number=reader.nextString();if(number.length()>128)throw new IOException("Observation number exceeds the precision limit.");return JsonParser.parseString(number);
            }
            case BOOLEAN:return new JsonPrimitive(reader.nextBoolean());
            case NULL:reader.nextNull();return JsonNull.INSTANCE;
            default:throw new IOException("Expected a JSON value.");
        }
    }
    private static int integer(JsonElement element){if(!element.isJsonPrimitive()||!element.getAsJsonPrimitive().isNumber())throw new IllegalArgumentException("Expected an integer JSON number.");return element.getAsBigDecimal().intValueExact();}
    public static void validate(JsonObject report,String expectedROMHash){
        if(!FORMAT.equals(report.get("format").getAsString())||integer(report.get("version"))!=VERSION)throw new IllegalArgumentException("Unsupported observation format/version.");
        var body=report.getAsJsonObject("observation");if(!sha(canonical(body).getBytes(StandardCharsets.UTF_8)).equals(report.get("sha256").getAsString()))throw new IllegalArgumentException("Observation SHA-256 mismatch.");
        if(body.get("snapshot").getAsBigDecimal().longValueExact()<0)throw new IllegalArgumentException("Negative snapshot.");body.get("traceName").getAsString();
        var metadata=body.getAsJsonObject("metadata");for(String key:METADATA)if(!metadata.has(key))throw new IllegalArgumentException("Missing captured metadata field: "+key);
        var hash=metadata.get("ROMHash");if(!hash.isJsonNull()&&!hash.getAsString().matches("[0-9a-fA-F]{64}"))throw new IllegalArgumentException("Invalid ROM SHA-256.");
        if(expectedROMHash!=null&&(hash.isJsonNull()||!expectedROMHash.equalsIgnoreCase(hash.getAsString())))throw new IllegalArgumentException("Selected ROM SHA-256 does not match the observation.");
        if(body.has("bootHash")&&!body.get("bootHash").isJsonNull()&&!body.get("bootHash").getAsString().matches("[0-9a-fA-F]{64}"))throw new IllegalArgumentException("Invalid boot SHA-256.");
        var memory=body.getAsJsonObject("memory");var selection=new Selection(memory.get("region").getAsString(),integer(memory.get("bank")),integer(memory.get("offset")),integer(memory.get("length")));
        if(!selection.space().equals(memory.get("space").getAsString())||selection.base()+selection.offset()!=integer(memory.get("address")))throw new IllegalArgumentException("Physical coordinate mismatch.");
        var bytes=memory.getAsJsonArray("bytes");var states=memory.getAsJsonArray("states");var sources=memory.getAsJsonArray("sources");
        if(bytes.size()!=selection.length()||states.size()!=bytes.size()||sources.size()!=bytes.size())throw new IllegalArgumentException("Memory lengths disagree.");
        for(int i=0;i<bytes.size();i++) {
            var state=TraceMemoryState.valueOf(states.get(i).getAsString());var b=bytes.get(i);
            if(state==TraceMemoryState.KNOWN){if(b.isJsonNull()||integer(b)<0||integer(b)>255)throw new IllegalArgumentException("Known byte is invalid.");}
            else if(!b.isJsonNull())throw new IllegalArgumentException("Unknown/error byte cannot claim a value.");
            if(!sources.get(i).isJsonNull()){var source=sources.get(i).getAsJsonObject();source.get("programURL").getAsString();source.get("staticStart").getAsString();if(source.get("displacement").getAsBigDecimal().longValueExact()<0)throw new IllegalArgumentException("Negative source displacement.");source.get("bindingStatus").getAsString();}
        }
        if(body.getAsJsonArray("events").size()>MAX_EVENTS)throw new IllegalArgumentException("Too many events.");
        for(var event:body.getAsJsonArray("events")){var object=event.getAsJsonObject();for(String key:EVENT_FIELDS)if(!object.has(key))throw new IllegalArgumentException("Missing event field: "+key);if(object.get("Snapshot").getAsBigDecimal().longValueExact()!=body.get("snapshot").getAsLong())throw new IllegalArgumentException("Event belongs to a different capture.");}
        var registers=body.getAsJsonObject("registers");for(String key:List.of("AF","BC","DE","HL","SP","PC"))if(!registers.has(key))throw new IllegalArgumentException("Missing register field: "+key);
        body.getAsJsonArray("hypotheses");body.get("replay").getAsString();body.get("eventsTruncated").getAsBoolean();
    }
    public static String describe(JsonObject report){
        validate(report,null);var body=report.getAsJsonObject("observation");var metadata=body.getAsJsonObject("metadata");var memory=body.getAsJsonObject("memory");
        return "Captured observation · "+body.get("traceName").getAsString()+" · snapshot "+body.get("snapshot")+"\nSession "+metadata.get("Session")+" · epoch "+metadata.get("Epoch")+" · capture "+metadata.get("Capture")+"\nBackend "+metadata.get("Backend")+" · model "+metadata.get("Model")+" · mode "+metadata.get("HardwareMode")+"\nROM SHA-256 "+metadata.get("ROMHash")+"\n"+memory.get("region").getAsString()+" bank "+memory.get("bank")+" +0x"+Integer.toHexString(memory.get("offset").getAsInt())+" · "+memory.get("length")+" bytes\nBytes: "+memory.get("bytes")+"\nStates: "+memory.get("states")+"\nCoverage: "+metadata.get("Coverage")+"\nStatic mappings are persisted source references; current Program binding is unverified.\nNull fields mean unknown/unrecorded. Hypotheses are separate from observations.\nReplay: "+body.get("replay").getAsString()+"\n\n"+JSON.toJson(report);
    }
    public static String compare(JsonObject first,JsonObject second){
        validate(first,null);validate(second,null);var a=first.getAsJsonObject("observation");var b=second.getAsJsonObject("observation");var am=a.getAsJsonObject("memory");var bm=b.getAsJsonObject("memory");
        for(String key:List.of("region","bank","offset","length"))if(!am.get(key).equals(bm.get(key)))throw new IllegalArgumentException("Comparison requires the same physical region, bank, offset, and length.");
        var out=new StringBuilder("Observed capture comparison: snapshot "+a.get("snapshot")+" → "+b.get("snapshot")+"\n");
        out.append("From ").append(a.get("traceName")).append(" session ").append(a.getAsJsonObject("metadata").get("Session")).append(" epoch ").append(a.getAsJsonObject("metadata").get("Epoch")).append(" capture ").append(a.getAsJsonObject("metadata").get("Capture")).append('\n');
        out.append("To ").append(b.get("traceName")).append(" session ").append(b.getAsJsonObject("metadata").get("Session")).append(" epoch ").append(b.getAsJsonObject("metadata").get("Epoch")).append(" capture ").append(b.getAsJsonObject("metadata").get("Capture")).append('\n');
        for(String key:List.of("AF","BC","DE","HL","SP","PC")) {
            var av=a.getAsJsonObject("registers").get(key);var bv=b.getAsJsonObject("registers").get(key);
            if(av.isJsonNull()||bv.isJsonNull())out.append("Register ").append(key).append(": unavailable in one or both captures\n");
            else if(!av.equals(bv))out.append("Register ").append(key).append(": ").append(av).append(" → ").append(bv).append('\n');
        }
        for(String key:List.of("ROMHash","Backend","Core","CorePatch","Config","Model","HardwareMode","TimingUnits","Capabilities","Coverage","StaticMappingGeneration")) {
            var av=a.getAsJsonObject("metadata").get(key);var bv=b.getAsJsonObject("metadata").get(key);
            if(av.isJsonNull()||bv.isJsonNull())out.append("Unverified setting ").append(key).append(": unknown in one or both captures\n");
            else if(!av.equals(bv))out.append("Different setting ").append(key).append(": ").append(av).append(" → ").append(bv).append('\n');
        }
        for(String key:List.of("bootHash","bootPolicy")) {
            var av=a.has(key)?a.get(key):JsonNull.INSTANCE;var bv=b.has(key)?b.get(key):JsonNull.INSTANCE;
            if(av.isJsonNull()||bv.isJsonNull())out.append("Unverified setting ").append(key).append(": unknown in one or both captures\n");
            else if(!av.equals(bv))out.append("Different setting ").append(key).append(": ").append(av).append(" → ").append(bv).append('\n');
        }
        int changes=0,unknown=0;for(int i=0;i<am.getAsJsonArray("bytes").size();i++) {
            var av=am.getAsJsonArray("bytes").get(i);var bv=bm.getAsJsonArray("bytes").get(i);
            if(av.isJsonNull()||bv.isJsonNull()){unknown++;continue;}
            if(!av.equals(bv)){changes++;out.append("+0x").append(Integer.toHexString(am.get("offset").getAsInt()+i)).append(": ").append(av).append(" → ").append(bv).append('\n');}
        }
        return out.append(changes).append(" changed known bytes; ").append(unknown).append(" bytes not comparable.\nObservation differences do not establish causality or reproducible replay.").toString();
    }
}
