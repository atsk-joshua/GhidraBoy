package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Conditional instruction-site adapter over the maintained predicate transfer engine. */
public final class ConditionalCallSites {
  private ConditionalCallSites() {}
  public static final String VERSION="conditional-call-site-3";
  public record Request(long programId,String imageSha256,String site,MapperKnowledge mapper,
      int shadowCpu,int shadowValue,List<Integer> memoryInputs,SymbolicMemory.Footprint footprint,
      List<Integer> incomingStackBytes,int continuationSteps,boolean bootInactive,
      boolean synchronous,String provenance) {
    public Request {
      Objects.requireNonNull(site);Objects.requireNonNull(imageSha256);Objects.requireNonNull(mapper);Objects.requireNonNull(footprint);
      memoryInputs=List.copyOf(memoryInputs);incomingStackBytes=List.copyOf(incomingStackBytes);
      if(!bootInactive||!synchronous||provenance==null||provenance.isBlank())throw new IllegalArgumentException("Explicit boot/access/interference provenance required");
      if(shadowValue<0||shadowValue>255||mapper.low()==null||mapper.high()==null||mapper.high()!=0||shadowValue!=mapper.low()||shadowCpu<0xff80||shadowCpu>0xfffe)
        throw new IllegalArgumentException("Coherent low-bank shadow and explicit zero high-bank premise required");
      if(memoryInputs.contains(shadowCpu))throw new IllegalArgumentException("Shadow cannot also be an unconstrained input");
      if(continuationSteps<0||continuationSteps>1||incomingStackBytes.size()>16)throw new IllegalArgumentException("Conditional continuation/input budget");
    }
  }
  public static Request readRequest(String text) {
    var root=com.google.gson.JsonParser.parseString(text).getAsJsonObject();
    for(String name:List.of("programId","imageSha256","site","mapper","shadowCpu","shadowValue","memoryInputs","footprint","incomingStackBytes","continuationSteps","bootInactive","synchronous","provenance"))
      if(!root.has(name)||root.get(name).isJsonNull())throw new IllegalArgumentException("Missing required conditional premise: "+name);
    for(String name:List.of("imageSha256","site","provenance"))if(!root.get(name).isJsonPrimitive()||!root.get(name).getAsJsonPrimitive().isString())throw new IllegalArgumentException("Explicit conditional string required: "+name);
    for(String name:List.of("bootInactive","synchronous"))if(!root.get(name).isJsonPrimitive()||!root.get(name).getAsJsonPrimitive().isBoolean())throw new IllegalArgumentException("Explicit conditional boolean required: "+name);
    for(String name:List.of("programId","shadowCpu","shadowValue","continuationSteps"))integer(root,name);
    for(String name:List.of("low","high"))integer(root.getAsJsonObject("mapper"),name);
    for(String name:List.of("stackMin","stackMax","minDelta","maxDelta"))integer(root.getAsJsonObject("footprint"),name);
    for(String name:List.of("memoryInputs","incomingStackBytes"))for(var v:root.getAsJsonArray(name)){if(!v.isJsonPrimitive()||!v.getAsJsonPrimitive().isNumber())throw new IllegalArgumentException("Explicit integer list required: "+name);v.getAsBigDecimal().intValueExact();}
    return ProgramMapping.JSON.fromJson(root,Request.class);
  }
  private static void integer(com.google.gson.JsonObject object,String name) {
    if(!object.has(name)||object.get(name).isJsonNull()||!object.get(name).isJsonPrimitive()||!object.get(name).getAsJsonPrimitive().isNumber())throw new IllegalArgumentException("Explicit conditional integer required: "+name);
    if(name.equals("programId"))object.get(name).getAsBigDecimal().longValueExact();else object.get(name).getAsBigDecimal().intValueExact();
  }
  public record Boundary(String kind,String node,String physical,Integer cpu,int spDelta,
      MapperKnowledge mapper,List<PredicatedCallGraph.Binding> registers,
      List<PredicatedCallGraph.StackByte> stack,List<SymbolicMemory.Fact> memory,AbstractValues.Condition predicate) {}
  public static PredicatedCallGraph.Proof preview(Program p,Request request,TaskMonitor monitor) throws Exception {
    return PredicatedCallGraph.previewSite(p,request,new PredicatedCallGraph.Limits(256,262144,2),monitor);
  }
  public record Interpretation(String source,String kind,String saved) {}
  public static List<Interpretation> interpretations(Program p,PredicatedCallGraph.Proof proof) {
    var result=new LinkedHashMap<String,Interpretation>();
    for(var node:proof.nodes()) {
      var at=ProgramMapping.staticAddress(p,node.source());var instruction=p.getListing().getInstructionAt(at);
      if(instruction!=null&&instruction.getFlowOverride()!=ghidra.program.model.listing.FlowOverride.NONE)
        result.put("instruction:"+at,new Interpretation(at.toString(),"preserved flow override",instruction.getFlowOverride().toString()));
      if(instruction!=null&&instruction.isFallThroughOverridden())result.put("fallthrough:"+at,new Interpretation(at.toString(),"preserved fallthrough",String.valueOf(instruction.getFallThrough())));
      var f=p.getFunctionManager().getFunctionContaining(at);
      if(f!=null&&(f.hasNoReturn()||f.isThunk()))result.put("function:"+f.getEntryPoint(),new Interpretation(f.getEntryPoint().toString(),"preserved Function interpretation","noReturn="+f.hasNoReturn()+"; thunk="+f.isThunk()));
    }
    return List.copyOf(result.values());
  }
  private static String value(Program p,AbstractValues.Origin origin,Boundary initial,int depth) {
    if(origin.kind()==AbstractValues.OriginKind.CONSTANT)return "0x"+Long.toHexString(origin.constant());
    for(var b:initial.registers())if(b.origin().equals(origin)){var r=p.getRegister(p.getRegister("A").getAddress().getAddressSpace().getAddress(b.offset()),1);return r==null?"entry-byte@"+b.offset():"entry_"+r.getName();}
    for(var fact:initial.memory())if(fact.value().equals(origin))return "entry-memory["+fact.physical().region()+fact.physical().bank()+"+0x"+Long.toHexString(fact.physical().offset())+"]";
    if(depth==0)return "source-expression";
    return (origin.opcode()==-1?"immutable-read":ghidra.program.model.pcode.PcodeOp.getMnemonic(origin.opcode()))+"("+String.join(",",origin.inputs().stream().map(o->value(p,o,initial,depth-1)).toList())+")";
  }
  static String conditions(Request request) {
    return VERSION+"\nConditional analysis view of "+request.site()+". Raw semantics; canonical annotations are not repaired.\n"
        +"Assumed incoming bank "+request.mapper().low()+", high=0; shadow 0x"+Integer.toHexString(request.shadowCpu())+"=0x"+Integer.toHexString(request.shadowValue())+".\n"
        +"SP=S in 0x"+Integer.toHexString(request.footprint().stackMin())+"..0x"+Integer.toHexString(request.footprint().stackMax())+"; physical frame footprint "+request.footprint().minDelta()+".."+request.footprint().maxDelta()+".\n"
        +"Execution at this site is conditional; preceding code is outside the proof. Boot inactive; synchronous/no interference.\n"
        +(request.continuationSteps()>0?"The native view ends at the real cleanup RET; the following instruction is explained by linked state. The remaining tail is unanalysed.":"The continuation is included through its genuine incoming-word RET.")
        +"\nUse conditional-call-explain for current validated boundary facts and preserved interpretation records.\nPremise provenance: "+request.provenance();
  }
  static String describe(Program p,PredicatedCallGraph.Proof proof) {
    var request=proof.callSite();var initial=proof.boundaries().getFirst();var text=new StringBuilder(VERSION+"\nConditional source "+request.site()+"; raw architectural semantics; canonical annotations preserved.\n");
    text.append("Assumed bank ").append(request.mapper().low()).append(", high=0; shadow ").append(Integer.toHexString(request.shadowCpu())).append("=").append(request.shadowValue()).append("; boot inactive; synchronous/no interference.\n");
    text.append("SP=S in ").append(Integer.toHexString(request.footprint().stackMin())).append("..").append(Integer.toHexString(request.footprint().stackMax())).append("; checked physical frame footprint ").append(request.footprint().minDelta()).append("..").append(request.footprint().maxDelta()).append(".\n");
    for(var boundary:proof.boundaries())if(Set.of("MATCHED_CALL_COMPLETION","ANALYSIS_BOUNDARY","SOURCE_RETURN").contains(boundary.kind())) {
      if(!boundary.predicate().terms().isEmpty())text.append("When ").append(String.join(" AND ",boundary.predicate().terms().stream().map(t->value(p,t.origin(),initial,3)+"="+t.value()).toList())).append("\n");
      text.append(boundary.kind()).append(" ").append(boundary.physical()==null?"unknown incoming-word destination":boundary.physical()).append("; SP=S").append(boundary.spDelta()>=0?"+":"").append(boundary.spDelta()).append("\n");
      for(String name:List.of("A","F","BC","DE","HL")) {
        var r=p.getRegister(name);text.append(name).append("=");
        var values=new ArrayList<String>();for(int i=r.getMinimumByteSize()-1;i>=0;i--){long offset=r.getAddress().getOffset()+i;var b=boundary.registers().stream().filter(v->v.offset()==offset).findFirst().orElse(null);values.add(b==null?"unknown":value(p,b.origin(),initial,3));}
        text.append(String.join(":",values)).append("; ");
      }
      text.append("\n");
    }
    text.append("Native endpoint is a real source RET. ").append(request.continuationSteps()>0?"The subsequent load/state is linked; the remaining tail is unanalysed.":"Continuation is included through its proved incoming-word RET.");
    text.append("\nPreserved interpretation records: ").append(interpretations(p,proof));return text.toString();
  }
  public static String explainText(Program p,ghidra.program.model.address.Address entry,TaskMonitor monitor) throws Exception {
    explain(p,entry,monitor);return describe(p,PredicatedCalls.registeredProof(p,entry));
  }
  public static List<Boundary> explain(Program p,ghidra.program.model.address.Address entry,TaskMonitor monitor) throws Exception {
    PredicatedCalls.emit(p,entry,0x200000,monitor);
    var proof=PredicatedCalls.registeredProof(p,entry);if(proof.callSite()==null)throw new IllegalArgumentException("Not conditional call-site authority");
    return proof.boundaries();
  }
  static void validate(Program p,Request request,TaskMonitor monitor) throws Exception {
    if(request.programId()!=p.getUniqueProgramID()||!request.imageSha256().equals(ProgramMapping.inspect(p).originalSha256()))throw new IllegalArgumentException("Foreign conditional Program/image authority");
    var c=ProgramMapping.cartridge(p);if(c==null||c.mapper()!=Cartridge.Mapper.MBC5||c.actualRomBanks()>256)throw new IllegalArgumentException("Conditional site requires ordinary mapped MBC5");
    var f=request.footprint();int lo=f.stackMin()+f.minDelta(),hi=f.stackMax()+f.maxDelta();
    var covering=ProgramMapping.inspect(p).ranges().stream().filter(r->r.region().equals("WRAM")&&r.bank()==0&&r.space().equals(p.getAddressFactory().getDefaultAddressSpace().getName())&&r.start()<=lo&&r.start()+r.length()>hi&&r.offset()+lo-r.start()==lo-0xc000&&r.read()&&r.write()&&r.alias()==null).toList();
    if(covering.size()!=1)throw new IllegalArgumentException("Full affine frame domain lacks one canonical physical backing");
    for(int delta=request.footprint().minDelta();delta<=request.footprint().maxDelta();delta++)frame(p,request.footprint(),delta,monitor);
  }
  static void frame(Program p,SymbolicMemory.Footprint f,int delta,TaskMonitor monitor) throws Exception {
    if(delta<f.minDelta()||delta>f.maxDelta())throw new IllegalArgumentException("Frame access escapes declared affine footprint");
    for(int cpu:List.of(f.stackMin()+delta,f.stackMax()+delta)) {
      monitor.checkCancelled();var at=p.getAddressFactory().getDefaultAddressSpace().getAddress(cpu);var block=p.getMemory().getBlock(at);
      if(block==null||block.isMapped()||!block.isRead()||!block.isWrite()||block.isVolatile()
          ||!ProgramMapping.staticToPhysical(p,at).equals(List.of(new MapperState.Physical("WRAM",0,cpu-0xc000))))throw new IllegalArgumentException("Affine frame lacks canonical writable WRAM0 binding");
    }
  }
}
