package fi.gekkio.ghidraboy;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.disassemble.Disassembler;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Multiple exact incoming domains at one configured physical transfer. No selected context is executable authority. */
public final class SoftwareCallDomains {
  private SoftwareCallDomains() {}
  public static final String VERSION="software-call-domains-1", OPTIONS="GhidraBoySoftwareCallDomains";
  private static final String RECORD="registration", DISPLAY="selected-display";
  public record Domain(String id,String physicalSite,SoftwareCallValidation.Configuration configuration,
      SoftwareCallModel.Frame frame,SoftwareCallEffects.Summary effects,SoftwareCallEffects.ContinuationSummary callee,
      SoftwareCallEffects.ContinuationSummary continuation) {}
  public record Proof(String version,long programId,String dependencies,List<Domain> domains,SoftwareCallInstructionDiscovery.Plan discovery) {
    public Proof {domains=List.copyOf(domains);}
  }
  public record View(String domain,String kind,String entry,List<SoftwareCallExecutionView.Segment> segments) {
    public View {segments=List.copyOf(segments);}
  }
  private record Registration(String version,long programId,List<SoftwareCallValidation.Configuration> configurations,String semantics,List<View> views,String dependencies,String nativeIdentity) {
    Registration {configurations=List.copyOf(configurations);views=List.copyOf(views);}
  }
  private static void require(boolean ok,String reason){if(!ok)throw new IllegalArgumentException(reason);}
  private static String fingerprint(Program p,TaskMonitor monitor)throws Exception{return FarCallEvidence.capture(p,monitor);}
  private static String domainId(Program p,SoftwareCallValidation.Configuration config,Address site) throws Exception {
    return PredicatedCallGraph.hash(List.of(VERSION,p.getUniqueProgramID(),site.toString(),ProgramMapping.staticToPhysical(p,site),config));
  }
  public static Proof preview(Program p,List<SoftwareCallValidation.Configuration> configurations,TaskMonitor monitor)throws Exception {
    require(configurations.size()>=2&&configurations.size()<=8,"Bounded configured invocation group needs 2..8 domains");
    require(SoftwareCallRegistry.configurationIdentity(p).equals("absent"),"Domain group requires no overlapping ordinary software registry");
    long revision=p.getModificationNumber();String dependencies=fingerprint(p,monitor);
    try(var discovery=SoftwareCallInstructionDiscovery.begin(p,monitor)) {
      var result=new ArrayList<Domain>();String physicalSite=null;var ids=new HashSet<String>();
      for(var config:configurations) {
        require(config.transfer()==SoftwareCallModel.EntryTransfer.HARDWARE_RST||config.transfer()==SoftwareCallModel.EntryTransfer.HARDWARE_CALL,
            "Scoped domain group requires actual CALL/RST hardware transfer");
        var site=SoftwareCallValidation.executionAddress(p,config.mapper(),config.callCpu());
        require(physicalSite==null||physicalSite.equals(site.toString()),"Incoming domains must share the SAME configured physical site");physicalSite=site.toString();
        var instruction=SoftwareCallInstructionDiscovery.instructionAt(p,site,"domain-qualified configured transfer",monitor);
        require(instruction!=null&&InstructionInterpretation.architecturalUnresolved(instruction)==null,"Unvalidated domain transfer instruction");
        var validated=SoftwareCallValidation.preview(p,config,monitor);
        var effects=SoftwareCallEffects.derive(p,validated.frame(),monitor,List.of(config));
        require(effects.complete()&&effects.paths().size()==1&&effects.paths().getFirst().returned().exit()==SoftwareCallModel.Exit.MAY_RETURN,"Unresolved configured invocation effects");
        var callee=SoftwareCallEffects.deriveCalleeGraph(p,validated.frame(),List.of(config),monitor);
        var continuation=SoftwareCallEffects.deriveContinuation(p,validated.frame(),effects.paths().getFirst(),List.of(config),monitor);
        SoftwareCallContinuationView.requireTransport(p,callee,monitor);SoftwareCallContinuationView.requireTransport(p,continuation,monitor);
        require(SoftwareCallEffects.calleeInvocations(callee).isEmpty()&&SoftwareCallEffects.calleeInvocations(continuation).isEmpty(),"Nested domain invocation remains outside this bounded group");
        require(callee.exit().equals("RETURN")&&continuation.exit().equals("RETURN"),"Domain group requires real callee and outer returns");
        String id=domainId(p,config,site);require(ids.add(id),"Duplicate incoming software-call domain");
        result.add(new Domain(id,physicalSite,config,validated.frame(),effects,callee,continuation));
      }
      result.sort(Comparator.comparing(Domain::id));
      require(revision==p.getModificationNumber()&&dependencies.equals(fingerprint(p,monitor)),"Program changed during software domain proof");
      return new Proof(VERSION,p.getUniqueProgramID(),dependencies,result,discovery.plan(monitor));
    }
  }
  private static com.google.gson.JsonElement canonical(com.google.gson.JsonElement value,String field) {
    if(value.isJsonObject()) {
      var result=new com.google.gson.JsonObject();var entries=new TreeMap<String,com.google.gson.JsonElement>();value.getAsJsonObject().entrySet().forEach(e->entries.put(e.getKey(),e.getValue()));
      entries.forEach((key,child)->{if(!key.equals("dependencies"))result.add(key,canonical(child,key));});return result;
    }
    if(value.isJsonArray()) {
      var children=new ArrayList<com.google.gson.JsonElement>();for(var child:value.getAsJsonArray())children.add(canonical(child,""));
      if(field.equals("changedRegisters"))children.sort(Comparator.comparing(Object::toString));
      var result=new com.google.gson.JsonArray();children.forEach(result::add);return result;
    }
    return value.deepCopy();
  }
  static String semanticJson(com.google.gson.JsonElement value){return canonical(value,"").toString();}
  private static String semantics(List<Domain> domains){return semanticJson(ProgramMapping.JSON.toJsonTree(domains));}
  private static Proof current(Program p,Proof proof,TaskMonitor monitor,boolean initial)throws Exception {
    require(VERSION.equals(proof.version())&&proof.programId()==p.getUniqueProgramID(),"Foreign or incompatible software domain proof");
    if(initial)require(proof.dependencies().equals(fingerprint(p,monitor)),"Stale software domain preview");
    var actual=preview(p,proof.domains().stream().map(Domain::configuration).toList(),monitor);
    require(semantics(actual.domains()).equals(semantics(proof.domains())),"Wrong software invocation domain/physical/frame proof");
    if(initial)require(actual.discovery().equals(proof.discovery()),"Domain discovery differs from rooted proof");return actual;
  }
  private static List<SoftwareCallExecutionView.Segment> segments(Program p,Domain domain,String kind) {
    var body=new AddressSet();
    if(kind.equals("root")) {
      var site=ProgramMapping.staticAddress(p,domain.physicalSite());int length=domain.configuration().transfer()==SoftwareCallModel.EntryTransfer.HARDWARE_RST?1:3;
      body.add(site,site.add(length-1));
    }
    var graph=kind.equals("callee")?domain.callee():domain.continuation();
    for(var step:graph.steps()){var at=ProgramMapping.staticAddress(p,step.address());body.add(at,at.add(step.length()-1));}
    var result=new ArrayList<SoftwareCallExecutionView.Segment>();for(var range:body.getAddressRanges())result.add(new SoftwareCallExecutionView.Segment((int)range.getMinAddress().getOffset(),(int)range.getLength(),range.getMinAddress().toString()));return result;
  }
  private static String name(Domain domain,String kind){return SoftwareCallExecutionView.PREFIX+"domain_"+domain.id().substring(0,16)+"_"+kind;}
  public static List<View> install(Program p,Proof proof,TaskMonitor monitor)throws Exception {
    current(p,proof,monitor,true);require(!p.getOptionsNames().contains(OPTIONS)||!p.getOptions(OPTIONS).contains(RECORD),"Software domain group already installed");
    String nativeIdentity=SoftwareCallStateEntryInjection.nativeIdentity();int tx=p.startTransaction("Install reviewed same-site software invocation domains");boolean success=false;
    try {
      SoftwareCallInstructionDiscovery.apply(p,proof.discovery(),monitor);var views=new ArrayList<View>();
      for(var domain:proof.domains())for(String kind:List.of("root","callee")) {
        var pieces=segments(p,domain,kind);var made=SoftwareCallExecutionView.create(p,SoftwareCallExecutionView.preview(p,name(domain,kind),pieces,monitor),monitor);
        int cpu=kind.equals("root")?domain.configuration().callCpu():domain.frame().targetCpu();
        var entry=made.body().getMinAddress().getAddressSpace().getAddress(cpu);
        Disassembler.getDisassembler(p,monitor,null).disassemble(entry,made.body());
        var function=p.getFunctionManager().createFunction(name(domain,kind),entry,made.body(),SourceType.ANALYSIS);
        require(function!=null,"Domain Function creation failed");function.setCallingConvention(SoftwareCallStateEntryInjection.CONVENTION);
        function.setComment(VERSION+"\nExact incoming domain "+domain.id()+"\n"+ProgramMapping.JSON.toJson(domain.configuration()));
        views.add(new View(domain.id(),kind,entry.toString(),pieces));
      }
      var registration=new Registration(VERSION,p.getUniqueProgramID(),proof.domains().stream().map(Domain::configuration).toList(),semantics(proof.domains()),views,fingerprint(p,monitor),nativeIdentity);
      p.getOptions(OPTIONS).setString(RECORD,ProgramMapping.JSON.toJson(registration));validateViews(p,registration,proof);success=true;return views;
    }finally{p.endTransaction(tx,success);}
  }
  private static Registration read(Program p) {
    require(p.getOptionsNames().contains(OPTIONS)&&p.getOptions(OPTIONS).contains(RECORD),"Missing software domain group");
    var json=com.google.gson.JsonParser.parseString(p.getOptions(OPTIONS).getString(RECORD,null)).getAsJsonObject();
    require(json.has("version")&&VERSION.equals(json.get("version").getAsString()),"Unsupported software domain record version");
    var record=ProgramMapping.JSON.fromJson(json,Registration.class);require(record.programId()==p.getUniqueProgramID(),"Foreign software domain Program");return record;
  }
  public static boolean registered(Program p,Address entry) {
    return entry!=null&&p.getOptionsNames().contains(OPTIONS)&&p.getOptions(OPTIONS).contains(RECORD)
        &&read(p).views().stream().anyMatch(view->view.entry().equals(entry.toString()));
  }
  public static List<View> views(Program p){return read(p).views();}
  public static Proof proof(Program p)throws Exception{return currentRecord(p,read(p),TaskMonitor.DUMMY);}
  private static Proof currentRecord(Program p,Registration record,TaskMonitor monitor)throws Exception {
    require(record.dependencies().equals(fingerprint(p,monitor)),"Stale software domain registration");
    var actual=preview(p,record.configurations(),monitor);
    require(record.semantics().equals(semantics(actual.domains())),"Wrong software invocation domain/physical/frame proof");return actual;
  }
  /** A selection for navigation only. Callback domain identity always comes from its explicit entry. */
  public static void selectDisplay(Program p,String domain) {
    require(read(p).views().stream().anyMatch(d->d.domain().equals(domain)),"Foreign display domain");
    int tx=p.startTransaction("Select software domain display");try{p.getOptions(OPTIONS).setString(DISPLAY,domain);}finally{p.endTransaction(tx,true);}
  }
  private static void validateViews(Program p,Registration record,Proof proof) {
    require(record.views().size()==proof.domains().size()*2,"Changed software domain view inventory");var seen=new HashSet<String>();
    for(var view:record.views()) {
      var domain=proof.domains().stream().filter(d->d.id().equals(view.domain())).findFirst().orElseThrow();
      require(Set.of("root","callee").contains(view.kind())&&seen.add(view.domain()+":"+view.kind()),"Duplicate/unknown software domain view");
      var entry=ProgramMapping.staticAddress(p,view.entry());var f=p.getFunctionManager().getFunctionAt(entry);
      int expectedCpu=view.kind().equals("root")?domain.configuration().callCpu():domain.frame().targetCpu();
      require(entry.getAddressSpace().getName().equals(name(domain,view.kind()))&&entry.getOffset()==expectedCpu,"Wrong alias incoming-domain identity");
      require(view.segments().equals(segments(p,domain,view.kind())),"Changed physical software domain mapping");var body=new AddressSet();
      for(var piece:view.segments()) {
        var at=entry.getAddressSpace().getAddress(piece.cpu());var block=p.getMemory().getBlock(at);
        require(block!=null&&block.getType()==ghidra.program.model.mem.MemoryBlockType.BYTE_MAPPED&&block.getStart().equals(at)&&block.getSize()==piece.length()
            &&block.isRead()&&block.isExecute()&&!block.isWrite()&&!block.isVolatile(),"Changed domain byte mapping permissions");
        var mapped=block.getSourceInfos().getFirst().getMappedRange().orElseThrow();var source=ProgramMapping.staticAddress(p,piece.source());
        require(mapped.getMinAddress().equals(source)&&mapped.getMaxAddress().equals(source.add(piece.length()-1)),"Wrong domain physical source");body.add(at,at.add(piece.length()-1));
      }
      require(f!=null&&f.getBody().equals(body)&&SoftwareCallStateEntryInjection.CONVENTION.equals(f.getCallingConventionName())&&!f.hasNoReturn()
          &&!f.isInline()&&!f.isThunk()&&!f.hasVarArgs()&&f.getCallFixup()==null&&f.getParameterCount()==0&&!f.hasCustomVariableStorage()
          &&f.getReturnType().getName().equals("undefined"),"Changed exact software domain native contract");
    }
  }
  /** Explicit invocation requests cannot consume a site-only cache hit belonging to another domain. */
  public static PcodeOp[] emit(Program p,Address entry,Domain expected,long uniqueBase,TaskMonitor monitor)throws Exception {
    var record=read(p);var view=record.views().stream().filter(v->v.entry().equals(entry.toString())).findFirst().orElseThrow();
    require(view.domain().equals(expected.id()),"Wrong requested software invocation domain");
    var actual=proof(p).domains().stream().filter(d->d.id().equals(view.domain())).findFirst().orElseThrow();
    require(semantics(List.of(actual)).equals(semantics(List.of(expected))),"Foreign software invocation proof");
    return emit(p,entry,uniqueBase,monitor);
  }
  public static PcodeOp[] emit(Program p,Address entry,long uniqueBase,TaskMonitor monitor)throws Exception {
    long revision=p.getModificationNumber();var record=read(p);
    require(record.dependencies().equals(fingerprint(p,monitor)),"Stale software domain registration; explicit refresh required");
    require(record.nativeIdentity().equals(SoftwareCallStateEntryInjection.nativeIdentity()),"Changed domain native companion");var proof=currentRecord(p,record,monitor);validateViews(p,record,proof);
    var view=record.views().stream().filter(v->v.entry().equals(entry.toString())).findFirst().orElseThrow();
    var domain=proof.domains().stream().filter(d->d.id().equals(view.domain())).findFirst().orElseThrow();
    PcodeOp[] result;
    if(view.kind().equals("callee"))result=SoftwareCallContinuationView.emit(p,entry,domain.callee(),List.of(domain.configuration()),uniqueBase);
    else {
      var ops=new ArrayList<PcodeOp>();var config=domain.configuration();var r=config.registers();
      for(var value:new TreeMap<>(Map.of("A",r.a(),"F",r.f(),"BC",r.bc(),"DE",r.de(),"HL",r.hl(),"SP",config.callerSp(),"PC",config.callCpu())).entrySet()) {
        var register=p.getRegister(value.getKey());ops.add(new PcodeOp(entry,ops.size(),PcodeOp.COPY,new Varnode[]{constant(p,value.getValue(),register.getMinimumByteSize())},new Varnode(register.getAddress(),register.getMinimumByteSize())));
      }
      var instruction=p.getListing().getInstructionAt(ProgramMapping.staticAddress(p,domain.physicalSite()));var raw=instruction.getPcode(false);
      require(raw.length>0&&raw[raw.length-1].getOpcode()==PcodeOp.CALL,"Configured transfer lost its real hardware CALL/RST");
      // Keep the original instruction's hardware push. expand intentionally starts at helper entry.
      for(int i=0;i<raw.length-1;i++)append(ops,entry,new PcodeOp[]{raw[i]});
      var target=record.views().stream().filter(v->v.domain().equals(domain.id())&&v.kind().equals("callee")).findFirst().orElseThrow();
      var validated=SoftwareCallValidation.preview(p,config,monitor);
      append(ops,entry,SoftwareCallInjection.expand(p,validated,entry,uniqueBase+0x1000000,true,false,ProgramMapping.staticAddress(p,target.entry())));
      SoftwareCallInjection.returnedRegisters(p,domain.effects(),entry,ops);
      append(ops,entry,SoftwareCallContinuationView.emit(p,entry,domain.continuation(),List.of(config),uniqueBase+0x20000000));result=ops.toArray(PcodeOp[]::new);
    }
    require(revision==p.getModificationNumber(),"Program changed during domain callback");return result;
  }
  private static Varnode constant(Program p,long value,int size){return new Varnode(p.getAddressFactory().getConstantSpace().getAddress(value),size);}
  private static void append(List<PcodeOp> into,Address site,PcodeOp[] operations){for(var op:operations)into.add(new PcodeOp(site,into.size(),op.getOpcode(),op.getInputs(),op.getOutput()));}
}
