package ghigbc;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.*;
import fi.gekkio.ghidraboy.ProgramMapping;
import fi.gekkio.ghidraboy.MapperState;
import ghidra.app.plugin.core.debug.utils.ProgramURLUtils;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.*;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.util.task.TaskMonitor;

/** Immutable facade snapshot. Trace coordinates never contain a banked architectural PC. */
public final class BankMappings {
    public static final int ADAPTER_VERSION=1;
    public record Bank(String region,int bank,Address start,int length,long offset) {
        public String space(){return region+bank;}
        public int cpuBase(){return switch(region){case "rom"->bank==0?0:0x4000;case "wram"->bank==0?0xc000:0xd000;case "vram"->0x8000;case "boot"->0;default->0xa000;};}
    }
    public record Physical(String region,int bank,long offset) {}
    private final Program program;
    private final List<Bank> banks=new ArrayList<>();
    private final String hash,generation,envelope;
    private final boolean fullCoverage;
    private final String selectedView;
    public BankMappings(Program program) throws Exception {this(program,"canonical");}
    public BankMappings(Program program,String selectedView) throws Exception {
        this.program=program;this.selectedView=selectedView;
        var snapshot=ProgramMapping.inspect(program);
        if(snapshot.schemaVersion()!=2||!snapshot.language().equals("SM83:LE:16:default")||!snapshot.compiler().equals("default"))
            throw new IllegalArgumentException("Expected GhidraBoy mapping v2 / SM83 default compiler");
        var coverage=new BitSet(Math.toIntExact(snapshot.originalLength()));
        for(var r:snapshot.ranges()) {
            if(r.fileOffset()!=null&&r.region().equals("ROM"))coverage.set(Math.toIntExact(r.fileOffset()),Math.toIntExact(r.fileOffset()+r.length()));
            if(!Set.of("ROM","WRAM","VRAM","SRAM","BOOT").contains(r.region()))continue;
            String region=r.region().equals("SRAM")?"cart":r.region().toLowerCase(Locale.ROOT);
            banks.add(new Bank(region,r.bank(),program.getAddressFactory().getAddressSpace(r.space()).getAddress(r.start()),Math.toIntExact(r.length()),r.offset()));
        }
        String currentHash="",exportError="";
        try{currentHash=sha(ProgramMapping.exportBytes(program,true,false,TaskMonitor.DUMMY));}
        catch(java.io.IOException error){exportError=error.getMessage();}
        fullCoverage=coverage.nextClearBit(0)>=snapshot.originalLength()&&exportError.isEmpty();
        hash=currentHash;
        var body=new LinkedHashMap<String,Object>();body.put("adapterVersion",ADAPTER_VERSION);body.put("static",snapshot);
        body.put("exportDiagnostic",exportError);body.put("currentExportSha256",hash);body.put("fullMappedCoverage",fullCoverage);body.put("selectedView",selectedView);
        // SHA names a value snapshot, including block names: a rename cannot relabel old captures.
        body.put("blocks",Arrays.stream(program.getMemory().getBlocks()).map(b->b.getName()+"@"+b.getStart()).toList());
        String json=ProgramMapping.JSON.toJson(body);generation=sha(json.getBytes(StandardCharsets.UTF_8));
        body.put("generation",generation);envelope=ProgramMapping.JSON.toJson(body);
    }
    private static String sha(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    public String hash(){return hash;}
    public String generation(){return generation;}
    public String envelope(){return envelope;}
    public boolean fullCoverage(){return fullCoverage;}
    public Collection<Bank> banks(){return List.copyOf(banks);}
    public Physical reverse(Address address) throws Exception {
        var values=ProgramMapping.staticToPhysical(program,address).stream().distinct().toList();
        if(values.size()!=1)throw new IllegalArgumentException("Unresolved/ambiguous physical identity at "+address);
        var p=values.get(0);return new Physical(p.region().equals("SRAM")?"cart":p.region().toLowerCase(Locale.ROOT),p.bank(),p.offset());
    }
    public List<Address> candidates(String region,int bank,long offset)throws Exception {
        return ProgramMapping.physicalToStatic(program,new MapperState.Physical(region.equals("cart")?"SRAM":region.toUpperCase(Locale.ROOT),bank,Math.toIntExact(offset)));
    }
    private Object value(TraceObject m,long snap,String key){var v=m.getValue(snap,key);return v==null?null:v.getValue();}
    public static boolean isReady(TraceObject machine,long snap){
        if(machine==null)return false;
        var marker=machine.getValue(snap,"MappingSnapshot");
        if(marker!=null)return marker.getValue() instanceof Number n&&n.longValue()==snap;
        var legacy=machine.getValue(snap,"MappingReady");return legacy!=null&&Boolean.TRUE.equals(legacy.getValue());
    }
    /** One selected canonical file/anchor view, or explicit address-space view; never insert all aliases. */
    public Address resolve(String region,int bank,long offset,Integer cpu)throws Exception {
        var b=banks.stream().filter(x->x.region.equals(region)&&x.bank==bank&&offset>=x.offset&&offset<x.offset+x.length).findFirst();
        return b.isEmpty()?null:choose(b.get(),offset,cpu);
    }
    private Address choose(Bank b,long offset,Integer cpu)throws Exception {
        var all=candidates(b.region,b.bank,offset);
        if(!selectedView.equals("canonical")) {
            var chosen=all.stream().filter(a->a.getAddressSpace().getName().equals(selectedView)).toList();
            return chosen.size()==1?chosen.get(0):null;
        }
        if(cpu!=null){var window=all.stream().filter(a->a.getOffset()==cpu).toList();if(window.size()==1)return window.get(0);}
        var canonical=banks.stream().filter(x->x.region.equals(b.region)&&x.bank==b.bank&&offset>=x.offset&&offset<x.offset+x.length)
            .map(x->x.start.add(offset-x.offset)).distinct().toList();
        return canonical.size()==1?canonical.get(0):null;
    }
    private void map(Trace t,long snap,Address from,Bank b,long off,int len,Integer cpu,List<String> issues,List<String> owned)throws Exception {
        Address to=choose(b,off,cpu);
        if(to==null){issues.add("Unresolved "+b.region+"/"+b.bank+"/"+off+" candidates="+candidates(b.region,b.bank,off));return;}
        Address end=choose(b,off+len-1,cpu==null?null:cpu+len-1);
        if(end==null||!end.equals(to.add(len-1))){issues.add("Split selected view needs narrower range: "+from);return;}
        try {
            // Ghidra enforces overlap/destination agreement. Never delete or truncate user mappings.
            boolean existing=t.getStaticMappingManager().findContaining(from,snap)!=null;
            t.getStaticMappingManager().add(new AddressRangeImpl(from,len),Lifespan.at(snap),ProgramURLUtils.getUrlFromProgram(program),to.getAddressSpace().getName()+":"+Long.toHexString(to.getOffset()));
            if(!existing)owned.add(from+"+"+len+"->"+to);
        }catch(ghidra.trace.model.modules.TraceConflictedMappingException conflict){issues.add("Existing mapping preserved: "+from+" "+conflict.getMessage());}
    }
    private void window(Trace t,long snap,AddressSpace space,String region,int bank,int base,int lo,int hi,List<String> issues,List<String> owned)throws Exception {
        // Boundary partition also handles overlapping/split canonical storage without first-match loss.
        var edges=new TreeSet<Long>();edges.add((long)lo);edges.add((long)hi);
        for(var b:banks)if(b.region.equals(region)&&b.bank==bank){edges.add(Math.max((long)lo,Math.min((long)hi,b.offset)));edges.add(Math.max((long)lo,Math.min((long)hi,b.offset+b.length)));}
        Long prior=null;
        for(long edge:edges){if(prior!=null&&edge>prior){long off=prior;var found=banks.stream().filter(b->b.region.equals(region)&&b.bank==bank&&off>=b.offset&&edge<=b.offset+b.length).findFirst();
            if(found.isPresent())map(t,snap,space.getAddress(base+off),found.get(),off,Math.toIntExact(edge-off),space.isOverlaySpace()?null:base+(int)off,issues,owned);
        }prior=edge;}
    }
    public synchronized void apply(Trace trace,long snap)throws Exception {
        var machine=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));if(machine==null)return;
        Object completed=value(machine,snap,"CaptureSnapshot");if(!(completed instanceof Number n)||n.longValue()!=snap||isReady(machine,snap))return;
        if(!hash.equals(value(machine,snap,"ROMHash")))throw new IllegalArgumentException("Current Program export differs from running image; profile recognition is independent");
        if(!fullCoverage)throw new IllegalArgumentException("Partial mapped coverage: exact full-image binding unavailable");
        var af=trace.getBaseAddressFactory();var issues=new ArrayList<String>();var owned=new ArrayList<String>();
        try(var tx=trace.openTransaction("GBC mapping generation "+generation)) {
            var visited=new HashSet<String>();
            for(var b:banks)if(visited.add(b.space())){var s=af.getAddressSpace(b.space());if(s!=null)window(trace,snap,s,b.region,b.bank,b.cpuBase(),0,b.region.equals("rom")?0x4000:b.region.equals("wram")?0x1000:0x2000,issues,owned);}
            var ram=af.getDefaultAddressSpace();boolean boot=Boolean.TRUE.equals(value(machine,snap,"Boot"));
            for(var entry:Map.of("ROM0",0,"ROMX",0x4000,"WRAM",0xd000,"VRAM",0x8000).entrySet()) {
                Object selected=value(machine,snap,entry.getKey());if(!(selected instanceof Number number)||number.intValue()<0)continue;
                String r=entry.getKey().startsWith("ROM")?"rom":entry.getKey().equals("WRAM")?"wram":"vram";
                int size=r.equals("rom")?0x4000:r.equals("wram")?0x1000:0x2000;
                if(entry.getKey().equals("ROM0")&&boot){window(trace,snap,ram,r,number.intValue(),0,0x100,0x200,issues,owned);window(trace,snap,ram,r,number.intValue(),0,0x900,0x4000,issues,owned);}
                else window(trace,snap,ram,r,number.intValue(),entry.getValue(),0,size,issues,owned);
            }
            Object cart=value(machine,snap,"CartBank");
            if(Boolean.TRUE.equals(value(machine,snap,"CartEnabled"))&&!Boolean.TRUE.equals(value(machine,snap,"RTCSelected"))&&cart instanceof Number c&&c.intValue()>=0)
                window(trace,snap,ram,"cart",c.intValue(),0xa000,0,0x2000,issues,owned);
            window(trace,snap,ram,"wram",0,0xc000,0,0x1000,issues,owned);window(trace,snap,ram,"wram",0,0xe000,0,0x1000,issues,owned);
            Object selected=value(machine,snap,"WRAM");if(selected instanceof Number number)window(trace,snap,ram,"wram",number.intValue(),0xf000,0,0xe00,issues,owned);
            machine.setValue(Lifespan.at(snap),"StaticMappingGeneration",generation);
            machine.setValue(Lifespan.at(snap),"StaticMappingEnvelope",envelope.getBytes(StandardCharsets.UTF_8));
            machine.setValue(Lifespan.at(snap),"MappingIssues",ProgramMapping.JSON.toJson(issues).getBytes(StandardCharsets.UTF_8));
            machine.setValue(Lifespan.at(snap),"MappingOwned",ProgramMapping.JSON.toJson(owned).getBytes(StandardCharsets.UTF_8));
            machine.setValue(Lifespan.at(snap),"MappingSnapshot",snap);
        }
    }
}
