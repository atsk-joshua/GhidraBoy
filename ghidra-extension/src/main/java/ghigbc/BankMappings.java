package ghigbc;

import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;
import ghidra.app.plugin.core.debug.utils.ProgramURLUtils;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.model.*;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.path.KeyPath;

/** Maps physical identities from file offsets, never from student symbol names. */
public final class BankMappings {
    public record Bank(String region,int bank,Address start,int length) {
        public String space(){return region+bank;}
        public int cpuBase(){return switch(region){case "rom"->bank==0?0:0x4000;case "wram"->bank==0?0xc000:0xd000;case "vram"->0x8000;default->0xa000;};}
    }
    public record Physical(String region,int bank,long offset) {}
    private final Program program;
    private final Map<String,Bank> banks=new LinkedHashMap<>();
    private final String hash;
    public BankMappings(Program program) throws Exception {
        this.program=program;
        if(!program.getLanguageID().toString().equals("SM83:LE:16:default"))throw new IllegalArgumentException("Expected GhidraBoy SM83 language");
        // File-backed initialized ROM spans survive renamed blocks/overlays.
        for(MemoryBlock block:program.getMemory().getBlocks()) {
            if(block.isInitialized())for(var source:block.getSourceInfos()) {
                if(source.getFileBytes().isEmpty())continue;
                long fileOffset=source.getFileBytesOffset();
                if(fileOffset%0x4000!=0||source.getLength()%0x4000!=0||block.getStart().getOffset()>=0x8000)continue;
                for(long delta=0;delta<source.getLength();delta+=0x4000) {
                    int number=(int)((fileOffset+delta)/0x4000);
                    Bank b=new Bank("rom",number,source.getMinAddress().add(delta),0x4000);
                    if(banks.putIfAbsent(b.space(),b)!=null)throw new IllegalArgumentException("Ambiguous ROM file mapping for bank "+number);
                }
            }
            // Loader-generated RAM descriptions are independent of labels and block names.
            String comment=block.getComment();
            if(comment!=null) {
                Matcher match=Pattern.compile("^(Work|Video) RAM \\(bank ([0-9]+)\\)$").matcher(comment);
                if(match.matches()) {
                    String region=match.group(1).equals("Work")?"wram":"vram";int number=Integer.parseInt(match.group(2));
                    int length=region.equals("wram")?0x1000:0x2000;
                    if(block.getSize()!=length)continue;
                    Bank b=new Bank(region,number,block.getStart(),length);
                    if(banks.putIfAbsent(b.space(),b)!=null)throw new IllegalArgumentException("Ambiguous RAM mapping");
                }
            }
        }
        int count=(int)banks.values().stream().filter(b->b.region.equals("rom")).count();
        if(count==0)throw new IllegalArgumentException("No file-backed ROM banks; export a reviewed mapping manifest first");
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        for(int i=0;i<count;i++) {
            Bank b=banks.get("rom"+i);if(b==null)throw new IllegalArgumentException("Missing ROM bank "+i);
            byte[] bytes=new byte[0x4000];program.getMemory().getBytes(b.start,bytes);digest.update(bytes);
        }
        hash=HexFormat.of().formatHex(digest.digest());
    }
    public String hash(){return hash;}
    public Collection<Bank> banks(){return Collections.unmodifiableCollection(banks.values());}
    public Physical reverse(Address address) {
        for(Bank b:banks.values())if(address.getAddressSpace().equals(b.start.getAddressSpace())&&address.getOffset()>=b.start.getOffset()&&address.getOffset()-b.start.getOffset()<b.length)return new Physical(b.region,b.bank,address.subtract(b.start));
        throw new IllegalArgumentException("No verified physical mapping at "+address);
    }
    private Object value(TraceObject m,long snap,String key){var v=m.getValue(snap,key);return v==null?null:v.getValue();}
    public static boolean isReady(TraceObject machine,long snap){
        if(machine==null)return false;
        var marker=machine.getValue(snap,"MappingSnapshot");
        if(marker!=null)return marker.getValue() instanceof Number n&&n.longValue()==snap;
        // Saved traces from the earlier agent used a per-snapshot boolean.
        var legacy=machine.getValue(snap,"MappingReady");
        return legacy!=null&&Boolean.TRUE.equals(legacy.getValue());
    }
    private void map(Trace t,long snap,Address from,Bank to,int offset,int length) throws Exception {
        t.getStaticMappingManager().add(new AddressRangeImpl(from,length),Lifespan.at(snap),ProgramURLUtils.getUrlFromProgram(program),to.start.getAddressSpace().getName()+":"+Long.toHexString(to.start.add(offset).getOffset()));
    }
    public synchronized void apply(Trace trace,long snap) throws Exception {
        var machine=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
        if(machine==null)return;
        Object completed=value(machine,snap,"CaptureSnapshot");
        // Snapshot-added events may precede the agent's batched attribute/memory writes.
        // Inherited attributes must never create a mapping for a new, unfinished snapshot.
        if(!(completed instanceof Number completedSnap)||completedSnap.longValue()!=snap)return;
        if(!hash.equals(value(machine,snap,"ROMHash")))throw new IllegalArgumentException("Trace/static ROM fingerprints differ");
        if(isReady(machine,snap))return;
        if(value(machine,snap,"Capture")==null)return;
        var af=trace.getBaseAddressFactory();
        try(var tx=trace.openTransaction("GBC bank mappings at snapshot "+snap)) {
            for(Bank b:banks.values()) {
                var space=af.getAddressSpace(b.space());
                if(space!=null)map(trace,snap,space.getAddress(b.cpuBase()),b,0,b.length);
            }
            var ram=af.getDefaultAddressSpace();
            boolean boot=Boolean.TRUE.equals(value(machine,snap,"Boot"));
            for(var entry:Map.of("ROM0",0,"ROMX",0x4000,"WRAM",0xd000,"VRAM",0x8000).entrySet()) {
                Object selected=value(machine,snap,entry.getKey());if(!(selected instanceof Number n))continue;
                String region=entry.getKey().startsWith("ROM")?"rom":entry.getKey().equals("WRAM")?"wram":"vram";
                Bank b=banks.get(region+n.intValue());if(b==null)continue;
                if(entry.getKey().equals("ROM0")&&boot) {
                    map(trace,snap,ram.getAddress(0x100),b,0x100,0x100);
                    map(trace,snap,ram.getAddress(0x900),b,0x900,0x3700);
                } else map(trace,snap,ram.getAddress(entry.getValue()),b,0,b.length);
            }
            Bank fixed=banks.get("wram0");
            if(fixed!=null){map(trace,snap,ram.getAddress(0xc000),fixed,0,0x1000);map(trace,snap,ram.getAddress(0xe000),fixed,0,0x1000);}
            Object selected=value(machine,snap,"WRAM");
            if(selected instanceof Number n){Bank b=banks.get("wram"+n.intValue());if(b!=null)map(trace,snap,ram.getAddress(0xf000),b,0,0xe00);}
            machine.setValue(Lifespan.at(snap),"MappingSnapshot",snap);
        }
    }
}
