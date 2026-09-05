package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import static fi.gekkio.ghidraboy.PcodeConstants.*;

/** Opt-in bounded analysis of existing instructions. Never decodes through marked data. */
public final class BankAnalysis {
    private BankAnalysis() { }
    public record Finding(String source,String access,List<String> targets,String reason,AnalysisResult.Confidence confidence) {
        public Finding { targets=List.copyOf(targets); }
    }
    private record Work(Address address,MapperKnowledge state,Map<Long,Integer> registers) { }

    public static List<Finding> analyze(Program p,Address start,MapperState assumption,TaskMonitor monitor,boolean apply) throws Exception {
        var result=preview(p,start,assumption,AnalysisResult.Configuration.DEFAULT,monitor);
        if(apply) apply(p,result,monitor);
        return result.findings();
    }
    public static AnalysisResult preview(Program p,Address start,MapperState assumption,AnalysisResult.Configuration configuration,TaskMonitor monitor) throws Exception {
        String fingerprint=ProgramFingerprint.capture(p,monitor);
        var cartridge=ProgramMapping.cartridge(p);
        if(cartridge==null) throw new IllegalArgumentException("Cartridge descriptor required");
        var queue=new ArrayDeque<Work>(); queue.add(new Work(start,MapperKnowledge.from(assumption),Map.of()));
        var seen=new HashSet<Work>();
        var targets=new TreeMap<String,Set<String>>(); var reasons=new TreeMap<String,String>();
        int count=0;
        var completion=AnalysisResult.Completion.COMPLETE;
        monitor.setMessage("Exploring bank states");
        try {
        while(!queue.isEmpty()) {
            monitor.checkCancelled(); var w=queue.removeFirst();
            if(seen.contains(w)) continue;
            if(count==configuration.stateLimit()) { queue.addFirst(w); completion=AnalysisResult.Completion.STATE_LIMIT; break; }
            seen.add(w); count++;
            var ins=p.getListing().getInstructionAt(w.address);
            if(ins==null) { reasons.put(w.address+"|flow","No defined instruction; data/undefined bytes left intact"); continue; }
            if(!fetchEstablished(p,cartridge,w.state,ins)) {
                reasons.put(w.address+"|flow","Instruction fetch crosses an unestablished physical execution view"); continue;
            }
            var state=w.state; var regs=new HashMap<>(w.registers); var unique=new HashMap<Long,Integer>();
            boolean changedMapper=false;
            // Internal p-code branches are not path interpreted by this finite evaluator.
            boolean internal=Arrays.stream(ins.getPcode()).anyMatch(op->op.getOpcode()==PcodeOp.CBRANCH ||
                (op.getOpcode()==PcodeOp.BRANCH && op.getInput(0).isConstant()));
            for(var op:ins.getPcode()) {
                if(op.getOpcode()!=PcodeOp.BRANCH && op.getOpcode()!=PcodeOp.CBRANCH && op.getOpcode()!=PcodeOp.CALL && op.getOpcode()!=PcodeOp.RETURN)
                    for(var input:op.getInputs()) if(input.isAddress()) readAccess(p,cartridge,state,(int)(input.getOffset()&65535),input.getSize(),w.address,targets,reasons);
                if(op.getOpcode()==PcodeOp.STORE) {
                    Long ptr=value(op.getInput(1),regs,unique), val=value(op.getInput(2),regs,unique);
                    if(internal || ptr==null) {
                        state=MapperKnowledge.unknown(); changedMapper=true;
                        reasons.put(w.address+"|write","Unknown store may affect mapper state");
                    } else {
                        int cpu=(int)(ptr & 65535);
                        int width=op.getInput(2).getSize();
                        state=writeAccess(p,cartridge,state,cpu,width,val,w.address,targets,reasons);
                        changedMapper |= touchesMapper(cartridge,cpu,width);
                    }
                } else if(op.getOpcode()==PcodeOp.LOAD) {
                    Long ptr=value(op.getInput(1),regs,unique);
                    if(ptr!=null) readAccess(p,cartridge,state,(int)(ptr&65535),op.getOutput().getSize(),w.address,targets,reasons);
                }
                var output=op.getOutput();
                if(output!=null) {
                    Long result=internal?null:evaluate(op,regs,unique);
                    if(output.isAddress()) {
                        int cpu=(int)(output.getOffset() & 65535);
                        state=writeAccess(p,cartridge,state,cpu,output.getSize(),result,w.address,targets,reasons);
                        changedMapper |= touchesMapper(cartridge,cpu,output.getSize());
                    }
                    put(output,result,regs,unique);
                }
            }
            var successors=new ArrayList<Work>();
            var flow=ins.getFlowType();
            for(var dest:ins.getFlows()) {
                var resolved=resolveWithContext(p,cartridge,state,(int)dest.getOffset(),changedMapper?null:w.address);
                String key=w.address+"|"+(flow.isCall()?"call":"jump");
                if(resolved.isEmpty()) reasons.put(key,"Unknown bank or missing static execution view");
                for(var a:resolved) {
                    targets.computeIfAbsent(key,k->new TreeSet<>()).add(a.toString());
                    // No interprocedural return summary: do not propagate assumed state into callees.
                    if(!flow.isCall()) successors.add(new Work(a,state,Map.copyOf(regs)));
                }
            }
            Address next=ins.getFallThrough();
            if(next!=null) {
                if(flow.isCall()) { state=MapperKnowledge.unknown(); regs.clear(); changedMapper=true; }
                int nextCpu=(int)((ins.getAddress().getOffset()+ins.getLength())&65535);
                if(ins.isFallThroughOverridden()) nextCpu=(int)next.getOffset();
                var nextViews=resolveWithContext(p,cartridge,state,nextCpu,changedMapper?null:w.address);
                if(nextViews.isEmpty()) reasons.put(w.address+"|flow","Fallthrough execution view unresolved after call, mapper write or window transition");
                for(var a:nextViews) successors.add(new Work(a,state,Map.copyOf(regs)));
            }
            if(configuration.reverseBranches()) Collections.reverse(successors);
            queue.addAll(successors);
            if(flow.isComputed()) reasons.put(w.address+"|flow","Indirect flow requires a validated per-program convention");
        }
        } catch(ghidra.util.exception.CancelledException cancelled) {
            completion=AnalysisResult.Completion.CANCELLED;
        }
        if(completion==AnalysisResult.Completion.STATE_LIMIT) reasons.put(start+"|limit",configuration.stateLimit()+"-state worklist bound reached");
        if(completion==AnalysisResult.Completion.CANCELLED) reasons.put(start+"|cancelled","Exploration cancelled");
        if(completion!=AnalysisResult.Completion.CANCELLED && !fingerprint.equals(ProgramFingerprint.capture(p,monitor)))
            completion=AnalysisResult.Completion.INPUT_CHANGED;
        Set<String> keys=new TreeSet<>(targets.keySet()); keys.addAll(reasons.keySet());
        List<Finding> findings=new ArrayList<>();
        for(String key:keys) {
            String[] parts=key.split("\\|",2); var values=List.copyOf(targets.getOrDefault(key,Set.of()));
            var confidence=values.isEmpty()?AnalysisResult.Confidence.UNKNOWN:
                completion!=AnalysisResult.Completion.COMPLETE || reasons.containsKey(key)?AnalysisResult.Confidence.CANDIDATE:
                values.size()>1?AnalysisResult.Confidence.AMBIGUOUS:AnalysisResult.Confidence.PROVEN;
            findings.add(new Finding(parts[0],parts[1],values,reasons.getOrDefault(key,values.size()>1?"Ambiguous finite candidate set":"Explicit state or same-window execution context with constant p-code propagation"),confidence));
        }
        return new AnalysisResult(2,List.of(start.toString()),assumption,configuration,completion,count,queue.size(),fingerprint,findings,
            completion==AnalysisResult.Completion.COMPLETE?List.of():List.of("Exploration stopped: "+completion+"; candidates are not proof"));
    }
    public static void apply(Program p,AnalysisResult result,TaskMonitor monitor) throws Exception {
        AnalysisApplication.apply(p,result,monitor);
    }
    private static boolean fetchEstablished(Program p,Cartridge c,MapperKnowledge state,ghidra.program.model.listing.Instruction ins) throws Exception {
        // Ordinary same-window instructions are already supplied by the listing. A
        // boundary-spanning decode must have physical backing for every fetched byte.
        long start=ins.getAddress().getOffset(), end=start+ins.getLength()-1;
        if(start/0x4000==end/0x4000 && end<=65535) return true;
        byte[] bytes=ins.getBytes();
        for(int i=0;i<bytes.length;i++) {
            int cpu=(int)((start+i)&65535);
            var views=resolveWithContext(p,c,state,cpu,ins.getAddress());
            if(views.isEmpty()) return false;
            var actual=ProgramMapping.staticToPhysical(p,ins.getAddress().addWrap(i));
            if(actual.size()!=1) return false;
            for(var view:views) {
                if(!ProgramMapping.staticToPhysical(p,view).equals(actual) || p.getMemory().getByte(view)!=bytes[i]) return false;
            }
        }
        return true;
    }
    private static boolean mapperControl(Cartridge c,int address) {
        return (address<0x8000 && c.mapper()!=Cartridge.Mapper.ROM_ONLY) || (c.color() && (address==0xff4f || address==0xff70));
    }
    private static boolean touchesMapper(Cartridge c,int address,int width) {
        for(int i=0;i<width;i++) if(mapperControl(c,(address+i)&65535)) return true;
        return false;
    }
    private static MapperKnowledge writeAccess(Program p,Cartridge c,MapperKnowledge state,int address,int width,Long value,Address from,
            Map<String,Set<String>> targets,Map<String,String> reasons) throws Exception {
        // P-code operations are ordered. Within a remaining little-endian wide store,
        // bytes use increasing 16-bit addresses. SM83 stack stores explicitly encode
        // their distinct high-byte-first architectural order in SLEIGH.
        for(int i=0;i<width;i++) {
            int cpu=(address+i)&65535;
            record(p,c,state,cpu,true,from,targets,reasons);
            if(mapperControl(c,cpu)) state=state.write(c,cpu,value==null?null:(int)(value>>>(i*8))&255);
        }
        return state;
    }
    private static void readAccess(Program p,Cartridge c,MapperKnowledge state,int address,int width,Address from,
            Map<String,Set<String>> targets,Map<String,String> reasons) throws Exception {
        for(int i=0;i<width;i++) record(p,c,state,(address+i)&65535,false,from,targets,reasons);
    }
    private static List<Address> resolveWithContext(Program p,Cartridge c,MapperKnowledge s,int cpu,Address context) throws Exception {
        var result=resolve(p,c,s,cpu);
        if(!result.isEmpty() || context==null || c.mapper()==Cartridge.Mapper.RAW || cpu>=0x8000 || context.getOffset()>=0x8000
            || cpu/0x4000!=context.getOffset()/0x4000) return result;
        var identities=ProgramMapping.staticToPhysical(p,context);
        if(identities.size()!=1 || !identities.get(0).region().equals("ROM") || !s.allowsExecution(c,cpu,identities.get(0).bank())) return result;
        var physical=new MapperState.Physical("ROM",identities.get(0).bank(),cpu%0x4000);
        return ProgramMapping.physicalToStatic(p,physical).stream().filter(a->a.getOffset()==cpu).toList();
    }
    private static List<Address> resolve(Program p,Cartridge c,MapperKnowledge s,int cpu) throws Exception {
        var physical=s.translate(c,cpu,false).physical();
        if(physical==null) return List.of();
        return ProgramMapping.physicalToStatic(p,physical).stream().filter(a->a.getOffset()==cpu).toList();
    }
    private static void record(Program p,Cartridge c,MapperKnowledge s,int cpu,boolean write,Address from,
                               Map<String,Set<String>> targets,Map<String,String> reasons) throws Exception {
        String key=from+"|"+(write?"write":"read");
        var result=s.translate(c,cpu,write);
        if(result.physical()==null) { reasons.put(key,result.status()+": "+result.reason()); return; }
        var addresses=ProgramMapping.physicalToStatic(p,result.physical()).stream().filter(a->a.getOffset()==cpu).toList();
        if(addresses.isEmpty()) reasons.put(key,"Physical destination has no static mapping");
        for(var a:addresses) targets.computeIfAbsent(key,k->new TreeSet<>()).add(a.toString());
    }
}
