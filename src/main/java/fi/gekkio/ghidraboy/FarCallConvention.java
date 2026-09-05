package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Opt-in exact-byte validated inline bank:u8,target:u16 RST convention. */
public record FarCallConvention(String trampoline, String expectedBodyHex, List<String> callSites) {
    // POP HL; LD A,(HL+); LD (2000),A; LD E,(HL); INC HL; LD D,(HL); INC HL;
    // PUSH HL; PUSH DE; RET. Restores adjusted caller return and transfers via RET.
    public static final String SUPPORTED_BODY="e12aea00205e235623e5d5c9";
    public List<String> preview(Program p,TaskMonitor monitor) throws Exception {
        if(!SUPPORTED_BODY.equalsIgnoreCase(expectedBodyHex)) throw new IllegalArgumentException("Unsupported trampoline; only reviewed inline-three-byte convention accepted");
        var c=ProgramMapping.cartridge(p);
        if(c==null || c.mapper()!=Cartridge.Mapper.MBC3)
            throw new IllegalArgumentException("Convention requires ordinary MBC3");
        var t=p.getAddressFactory().getAddress(trampoline);
        if(t==null || t.getOffset()>0x38 || t.getOffset()%8!=0) throw new IllegalArgumentException("Expected explicit RST vector");
        byte[] body=HexFormat.of().parseHex(expectedBodyHex), actual=new byte[body.length];
        p.getMemory().getBytes(t,actual);
        if(!Arrays.equals(body,actual)) throw new IllegalArgumentException("Trampoline bytes do not match reviewed convention");
        var results=new ArrayList<String>();
        for(String site:callSites) {
            monitor.checkCancelled(); var a=p.getAddressFactory().getAddress(site);
            var ins=a==null?null:p.getListing().getInstructionAt(a);
            if(ins==null || (p.getMemory().getByte(a)&255)!=(0xc7|(int)t.getOffset())) throw new IllegalArgumentException("Call site is not the specified RST: "+site);
            int bank=p.getMemory().getByte(a.add(1))&255;
            int cpu=(p.getMemory().getByte(a.add(2))&255)|((p.getMemory().getByte(a.add(3))&255)<<8);
            var state=MapperState.reset().write(c,0x2000,bank);
            var physical=MapperState.translate(c,state,cpu,false).physical();
            if(physical==null) throw new IllegalArgumentException("Unresolved far target at "+site);
            var targets=ProgramMapping.physicalToStatic(p,physical).stream().filter(x->x.getOffset()==cpu).toList();
            if(targets.size()!=1) throw new IllegalArgumentException("Ambiguous static far target at "+site);
            results.add(site+" -> "+targets.get(0)+"; return "+a.add(4));
        }
        return List.copyOf(results);
    }
    public List<String> apply(Program p,TaskMonitor monitor) throws Exception {
        var findings=preview(p,monitor);
        int tx=p.startTransaction("Apply explicitly validated far-call convention"); boolean success=false;
        try {
            for(String site:callSites) {
                monitor.checkCancelled(); var a=p.getAddressFactory().getAddress(site);
                var ins=p.getListing().getInstructionAt(a);
                if(ins.isFallThroughOverridden() && !a.add(4).equals(ins.getFallThrough()))
                    throw new IllegalArgumentException("Existing user flow override at "+site);
                int bank=p.getMemory().getByte(a.add(1))&255;
                int cpu=(p.getMemory().getByte(a.add(2))&255)|((p.getMemory().getByte(a.add(3))&255)<<8);
                var c=ProgramMapping.cartridge(p);
                var resolved=ProgramMapping.cpuToStatic(p,MapperState.reset().write(c,0x2000,bank),cpu,false);
                if(resolved.addresses().size()!=1) throw new IllegalArgumentException("Far target changed during apply");
                var target=resolved.addresses().get(0);
                boolean preserve=false;
                for(var ref:p.getReferenceManager().getReferencesFrom(a))
                    if(ref.getToAddress().equals(target) || (ref.getOperandIndex()==-1 && !ref.isMemoryReference())) preserve=true;
                if(!preserve) p.getReferenceManager().addMemoryReference(a,target,RefType.UNCONDITIONAL_CALL,SourceType.ANALYSIS,-1);
                ins.setFallThrough(a.add(4));
                p.getBookmarkManager().setBookmark(a,"Analysis","GhidraBoy Far Call","Explicitly verified inline bank:u8,target:u16; return +3. Trampoline p-code remains visible.");
            }
            p.getOptions(ProgramMapping.OPTIONS).setString("farCallConvention",ProgramMapping.JSON.toJson(this));
            success=true;
        } finally { p.endTransaction(tx,success); }
        return findings;
    }

}
