package fi.gekkio.ghidraboy;

import ghidra.program.model.address.*;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.disassemble.Disassembler;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Segregated experimental graph records, using the existing ordinary views and native entry protocol. */
public final class PredicatedCalls {
  private PredicatedCalls() {}
  public static final String VERSION="predicated-ordinary-calls-5";
  public static final String OPTIONS="GhidraBoyPredicatedCalls";
  public static final String STOCK_OPTIONS="GhidraBoyStockPredicatedCalls";
  public static final String STOCK_VERSION="stock-predicated-ordinary-calls-3";
  public record Premises(String root,List<Integer> inputs,Integer entryHL) { public Premises {inputs=List.copyOf(inputs);} }
  public static PredicatedCallGraph.Proof preview(Program p,Premises premises,TaskMonitor monitor) throws Exception {
    return PredicatedCallGraph.preview(p,p.getFunctionManager().getFunctionAt(ProgramMapping.staticAddress(p,premises.root())),PredicatedCallGraph.Limits.PRIMARY,SymbolicMemory.declare(p,premises.inputs(),List.of(),null,premises.entryHL()),monitor);
  }
  public record View(String invocation,String entry,List<SoftwareCallExecutionView.Segment> segments,boolean byteAContract,List<Long> inputBytes) {
    public View {segments=List.copyOf(segments);inputBytes=List.copyOf(inputBytes);}
  }
  private record Registration(String version,long programId,String root,PredicatedCallGraph.Proof proof,
      List<View> views,String dependencies,String nativeIdentity,String transport,AnalysisOwnership.Group ownership) {Registration{views=List.copyOf(views);}}
  public static PredicatedCallGraph.Proof preview(Program p,Function root,PredicatedCallGraph.Limits limits,TaskMonitor monitor) throws Exception {
    return PredicatedCallGraph.preview(p,root,limits,monitor);
  }
  public static boolean registered(Program p,Address entry) {
    return entry!=null&&((p.getOptionsNames().contains(OPTIONS)&&p.getOptions(OPTIONS).contains(entry.toString()))
        ||(p.getOptionsNames().contains(STOCK_OPTIONS)&&p.getOptions(STOCK_OPTIONS).contains(entry.toString())));
  }
  private static Registration read(Program p,Address entry) {
    if(!registered(p,entry))throw new IllegalArgumentException("Missing predicated graph registration");
    require(!(p.getOptionsNames().contains(STOCK_OPTIONS) && p.getOptions(STOCK_OPTIONS).contains(entry.toString())
        && p.getOptionsNames().contains(OPTIONS) && p.getOptions(OPTIONS).contains(entry.toString())),
        "Conflicting stock and companion authority; records retained");
    boolean stock=p.getOptionsNames().contains(STOCK_OPTIONS)&&p.getOptions(STOCK_OPTIONS).contains(entry.toString());
    var json=com.google.gson.JsonParser.parseString(p.getOptions(stock?STOCK_OPTIONS:OPTIONS).getString(entry.toString(),null)).getAsJsonObject();
    if(!json.has("version")||!(stock?STOCK_VERSION:VERSION).equals(json.get("version").getAsString()))
      throw new IllegalArgumentException("Unsupported predicated graph version; record retained without migration");
    var record=ProgramMapping.JSON.fromJson(json,Registration.class);
    require(stock?StockEntryInjection.VERSION.equals(record.transport())&&record.nativeIdentity()==null:record.transport()==null,"Incompatible transport authority");
    require(record.ownership()!=null,"Missing current predicate ownership; record retained without conversion");
    return record;
  }
  public static PredicatedCallGraph.Proof registeredProof(Program p,Address entry){return read(p,entry).proof();}
  public static List<View> views(Program p,Address entry){return read(p,entry).views();}
  static boolean sameGraph(PredicatedCallGraph.Proof a,PredicatedCallGraph.Proof b) {
    return a.version().equals(b.version())&&a.programId()==b.programId()&&a.entry().equals(b.entry())&&a.end().equals(b.end())
        &&Objects.equals(a.result(),b.result())&&Objects.equals(a.memory(),b.memory())&&a.domain().equals(b.domain())&&a.limits().equals(b.limits())&&Objects.equals(a.root(),b.root())
        &&a.nodes().equals(b.nodes())&&a.invocations().equals(b.invocations())&&a.frontier().equals(b.frontier())
        &&a.coverageComplete()==b.coverageComplete()&&a.joins().equals(b.joins())&&Objects.equals(a.convergence(),b.convergence())&&a.origins().equals(b.origins())&&a.joinDomains().equals(b.joinDomains());
  }
  private static void currentPreview(Program p,PredicatedCallGraph.Proof proof,TaskMonitor monitor) throws Exception {
    SymbolicMemory.validate(p,proof.memory());
    require(proof.complete()&&PredicatedCallGraph.VERSION.equals(proof.version())&&proof.programId()==p.getUniqueProgramID(),"Incomplete or foreign predicated graph");
    require(proof.dependencies().equals(OrdinaryProofDependencies.fingerprint(p,monitor)),"Stale predicated graph preview");
    var actual=PredicatedCallGraph.preview(p,p.getFunctionManager().getFunctionAt(ProgramMapping.staticAddress(p,proof.entry())),proof.limits(),proof.memory(),monitor);
    require(sameGraph(actual,proof),"Changed predicated graph/guards/frame proof");
    require(actual.discovery().equals(proof.discovery()), "Discovery inventory is not rooted in this graph");
  }
  private static void require(boolean ok,String message){if(!ok)throw new IllegalArgumentException(message);}
  private static List<SoftwareCallExecutionView.Segment> segments(Program p,PredicatedCallGraph.Proof proof,String invocation) {
    if(proof.memory()!=null&&proof.memory().image()!=null) {
      try{var image=ExecutableImages.resolve(p,proof.memory().image());return List.of(new SoftwareCallExecutionView.Segment(image.cpu(),image.length(),SymbolicMemory.address(p,MapperKnowledge.unknown(),image.cpu(),ScalarAccess.Kind.FETCH).toString()));}catch(Exception e){throw new IllegalArgumentException(e);}
    }
    var body=new AddressSet();
    for(var node:proof.nodes())if(node.invocation().equals(invocation)) {
      var at=ProgramMapping.staticAddress(p,node.source());body.add(at,at.add(node.bytes().length()/2-1));
    }
    var result=new ArrayList<SoftwareCallExecutionView.Segment>();
    for(var range:body.getAddressRanges())result.add(new SoftwareCallExecutionView.Segment((int)range.getMinAddress().getOffset(),(int)range.getLength(),range.getMinAddress().toString()));
    return result;
  }
  public static Address install(Program p,PredicatedCallGraph.Proof proof,TaskMonitor monitor) throws Exception {
    return install(p,proof,monitor,true);
  }
  public static Address installLegacyComparison(Program p,PredicatedCallGraph.Proof proof,TaskMonitor monitor) throws Exception {
    return install(p,proof,monitor,false);
  }
  public static Address installStock(Program p,PredicatedCallGraph.Proof proof,TaskMonitor monitor) throws Exception {
    return install(p,proof,monitor,true);
  }
  private static Address install(Program p,PredicatedCallGraph.Proof proof,TaskMonitor monitor,boolean stock) throws Exception {
    currentPreview(p,proof,monitor);
    String nativeIdentity=stock?null:SoftwareCallStateEntryInjection.nativeIdentity();
    String convention=stock?StockEntryInjection.CONVENTION:SoftwareCallStateEntryInjection.CONVENTION;
    int tx=p.startTransaction("Install reviewed predicate-qualified ordinary call graph");boolean success=false;
    try {
      SoftwareCallInstructionDiscovery.apply(p,proof.discovery(),monitor);
      var invocations=new ArrayList<String>();invocations.add("root");invocations.addAll(proof.invocations().stream().map(PredicatedCallGraph.Invocation::id).toList());
      var views=new ArrayList<View>();Address root=null;var ownership=new AnalysisOwnership.Group();
      for(var invocation:invocations) {
        String name=OrdinaryEntryAccess.PREFIX+"pred_"+proof.entry().replace(':','_')+"_"+(invocation.equals("root")?"root":invocation.substring(0,12));
        var pieces=segments(p,proof,invocation);
        boolean image=proof.memory()!=null&&proof.memory().image()!=null;
        var imageEntry=image?ProgramMapping.staticAddress(p,ExecutableImages.resolve(p,proof.memory().image()).entry()):null;
        String node=invocation.equals("root")?proof.root():proof.invocations().stream().filter(i->i.id().equals(invocation)).findFirst().orElseThrow().entry();
        int cpu=proof.nodes().stream().filter(n->n.id().equals(node)).findFirst().orElseThrow().cpu();
        var made=stock?StockEntryInjection.carrier(p,name,cpu,pieces,monitor):image?new SoftwareCallExecutionView.Created(ExecutableImages.VERSION,imageEntry.getAddressSpace().getName(),pieces,new AddressSet(imageEntry,imageEntry.add(pieces.get(0).length()-1))):SoftwareCallExecutionView.createOrdinary(p,SoftwareCallExecutionView.previewOrdinary(p,name,pieces,monitor),monitor);
        var entry=made.body().getMinAddress().getAddressSpace().getAddress(cpu);
        if(stock)StockEntryInjection.prepare(p,entry);
        Disassembler.getDisassembler(p,monitor,null).disassemble(entry,made.body());
        var function=image&&!stock?p.getFunctionManager().getFunctionAt(entry):p.getFunctionManager().createFunction(name,entry,made.body(),SourceType.ANALYSIS);
        require(function!=null,"Predicate view Function creation failed");
        function.setCallingConvention(convention);
        boolean contract=!invocation.equals("root");List<Long> inputBytes=List.of();
        var sourceFunction=p.getFunctionManager().getFunctionAt(ProgramMapping.staticAddress(p,proof.entry()));
        if(!contract&&sourceFunction.hasCustomVariableStorage()) {
          require(sourceFunction.getParameterCount()==0,"Root custom parameters require separate effect admission");
          function.updateFunction(convention,new ReturnParameterImpl(sourceFunction.getReturnType(),sourceFunction.getReturn().getVariableStorage(),p),
              Function.FunctionUpdateType.CUSTOM_STORAGE,true,SourceType.ANALYSIS);
        }
        if(contract) {
          require(proof.invocations().stream().anyMatch(i->i.id().equals(invocation)&&i.byteAContract()),"Unproved callee byte-A effect contract");
          inputBytes=proof.invocations().stream().filter(i->i.id().equals(invocation)).findFirst().orElseThrow().inputBytes();
          var parameters=new ArrayList<Variable>();
          for(long offset:inputBytes) {
            var address=p.getRegister("A").getAddress().getAddressSpace().getAddress(offset);
            var register=p.getRegister(address,1);
            require(register!=null,"Missing proved byte-register input storage");
            parameters.add(new ParameterImpl("input_"+register.getName(),ByteDataType.dataType,
                new VariableStorage(p,new Varnode(address,1)),p));
          }
          // Locations derive from actual read-before-write byte liveness, not a guessed assembly ABI.
          function.updateFunction(convention,
              new ReturnParameterImpl(ByteDataType.dataType,p.getRegister("A"),p),
              Function.FunctionUpdateType.CUSTOM_STORAGE,true,SourceType.ANALYSIS,parameters.toArray(Variable[]::new));
        }
        function.setComment((stock?STOCK_VERSION:VERSION)+"\nConditional analysis entry; source "+proof.entry()+"\nImage generation: "+(proof.memory()==null?"none":proof.memory().image())+"\n"+ProgramMapping.JSON.toJson(proof.domain())+"\nInvocation: "+invocation
            +(contract?"\nValidated ordinary effects: byte A result; input register bytes "+inputBytes+"; only A/F modified; PC/SP matched RET; BC/DE/HL preserved.":"\nOne unknown-input predicate-qualified root graph."));
        ownership.function(function);ownership.views.add(new AnalysisOwnership.View(entry.getAddressSpace().getName(),AnalysisOwnership.viewStamp(p,entry.getAddressSpace().getName(),monitor)));
        monitor.checkCancelled();
        views.add(new View(invocation,entry.toString(),pieces,contract,inputBytes));if(invocation.equals("root"))root=entry;
      }
      var registration=new Registration(stock?STOCK_VERSION:VERSION,p.getUniqueProgramID(),root.toString(),proof,views,
          OrdinaryProofDependencies.fingerprint(p,monitor),nativeIdentity,stock?StockEntryInjection.VERSION:null,ownership);
      for(var view:views)p.getOptions(stock?STOCK_OPTIONS:OPTIONS).setString(view.entry(),ProgramMapping.JSON.toJson(registration));
      validateViews(p,registration);monitor.checkCancelled();success=true;return root;
    } finally {p.endTransaction(tx,success);}
  }
  private static void validateViews(Program p,Registration registration) throws Exception {
    require(registration.programId()==p.getUniqueProgramID(),"Foreign predicate Program registration");
    var expected=new HashSet<String>();expected.add("root");expected.addAll(registration.proof().invocations().stream().map(PredicatedCallGraph.Invocation::id).toList());
    require(registration.views().size()==expected.size()
        &&new HashSet<>(registration.views().stream().map(View::invocation).toList()).equals(expected)
        &&registration.views().stream().map(View::entry).distinct().count()==expected.size(),"Changed predicate view inventory");
    for(var view:registration.views()) {
      var entry=ProgramMapping.staticAddress(p,view.entry());var f=p.getFunctionManager().getFunctionAt(entry);var body=new AddressSet();
      if(view.invocation().equals("root")) {
        require(!view.byteAContract()&&view.inputBytes().isEmpty()&&view.entry().equals(registration.root()),"Changed root view contract flag");
        var source=p.getFunctionManager().getFunctionAt(ProgramMapping.staticAddress(p,registration.proof().entry()));
        require(f!=null&&source!=null&&Objects.equals(PredicatedCallGraph.rootResult(source),registration.proof().result())
            &&Objects.equals(PredicatedCallGraph.rootResult(f),registration.proof().result()),"Changed source/qualified root result storage");
      } else {
        var authority=registration.proof().invocations().stream().filter(i->i.id().equals(view.invocation())).findFirst().orElseThrow();
        require(view.byteAContract()&&authority.byteAContract()&&view.inputBytes().equals(authority.inputBytes()),"Child view contract not bound to graph authority");
      }
      if(registration.transport()!=null) {
        StockEntryInjection.validate(p,entry);
        String node=view.invocation().equals("root")?registration.proof().root():registration.proof().invocations().stream().filter(i->i.id().equals(view.invocation())).findFirst().orElseThrow().entry();
        var source=registration.proof().nodes().stream().filter(n->n.id().equals(node)).findFirst().orElseThrow();
        String name=OrdinaryEntryAccess.PREFIX+"pred_"+registration.proof().entry().replace(':','_')+"_"+(view.invocation().equals("root")?"root":view.invocation().substring(0,12));
        require(entry.getOffset()==source.cpu()&&entry.getAddressSpace().getName().equals(name),"Changed predicate carrier/source entry identity");
      }
      require(f!=null&&(registration.transport()!=null?StockEntryInjection.CONVENTION:SoftwareCallStateEntryInjection.CONVENTION).equals(f.getCallingConventionName())&&!f.isInline()&&!f.isThunk()
          &&!f.hasNoReturn()&&f.getCallFixup()==null,"Changed predicated native Function contract");
      require(view.segments().equals(segments(p,registration.proof(),view.invocation())),"Changed physical predicate view binding");
      if(registration.transport()!=null) {
        body.add(entry);
        if(registration.proof().memory()!=null&&registration.proof().memory().image()!=null)
          ExecutableImages.resolve(p,registration.proof().memory().image());
      } else for(var segment:view.segments()) {
        var at=entry.getAddressSpace().getAddress(segment.cpu());var block=p.getMemory().getBlock(at);
        boolean image=registration.proof().memory()!=null&&registration.proof().memory().image()!=null;
        require(block!=null&&(image&&registration.transport()==null?!block.isMapped()&&block.isInitialized():block.getType()==ghidra.program.model.mem.MemoryBlockType.BYTE_MAPPED)&&block.isRead()&&block.isExecute()
            &&!block.isWrite()&&!block.isVolatile()&&block.getStart().equals(at)&&block.getSize()==segment.length(),"Changed predicate mapped fragment");
        if(!image||registration.transport()!=null) {
        var mapped=block.getSourceInfos().get(0).getMappedRange().orElseThrow();
        var source=ProgramMapping.staticAddress(p,image?ExecutableImages.resolve(p,registration.proof().memory().image()).entry():segment.source());
        require(mapped.getMinAddress().equals(source)&&mapped.getMaxAddress().equals(source.add(segment.length()-1)),"Foreign predicate physical fragment");
        } else ExecutableImages.resolve(p,registration.proof().memory().image());
        body.add(at,at.add(segment.length()-1));
      }
      require(f.getBody().equals(body),"Changed predicate Function body");
      int purge=f.getStackPurgeSize();
      require((purge==0||purge==Function.UNKNOWN_STACK_DEPTH_CHANGE||purge==Function.INVALID_STACK_DEPTH_CHANGE)
          &&!f.hasVarArgs(),"Changed matched-return stack/varargs contract");
      if(view.byteAContract()) {
        require(f.getParameterCount()==view.inputBytes().size()&&f.hasCustomVariableStorage(),"Changed effect-derived native input contract");
        var proved=registration.proof().invocations().stream().filter(i->i.id().equals(view.invocation())).findFirst().orElseThrow();
        require(proved.inputBytes().equals(view.inputBytes()),"Native parameters not bound to current invocation effects");
        for(int index=0;index<view.inputBytes().size();index++) {
          var input=f.getParameter(index);var location=input.getVariableStorage().getVarnodes();
          require(input.getDataType().getLength()==1&&location.length==1&&location[0].getSize()==1
              &&location[0].isRegister()&&location[0].getOffset()==view.inputBytes().get(index),"Changed native input register slice");
        }
        var storage=f.getReturn().getVariableStorage().getVarnodes();
        require(f.getReturnType().getLength()==1&&storage.length==1&&storage[0].getSize()==1
            &&storage[0].getAddress().equals(p.getRegister("A").getAddress()),"Changed effect-derived byte-A return storage");
      }
    }
  }
  public static void refresh(Program p,Address root,PredicatedCallGraph.Proof proof,TaskMonitor monitor) throws Exception {
    var old=read(p,root);currentPreview(p,proof,monitor);
    require(old.proof().entry().equals(proof.entry())&&old.proof().end().equals(proof.end()),"Refresh changed predicate root extent");
    require(Objects.equals(old.proof().memory(),proof.memory())&&old.proof().domain().equals(proof.domain()),"Refresh changed explicit input/domain authority");
    boolean stock=old.transport()!=null;
    var views=new ArrayList<View>();
    for(var view:old.views()) {
      var pieces=segments(p,proof,view.invocation());
      require(stock||view.segments().equals(pieces),"Refresh changes mapped legacy topology");
      views.add(new View(view.invocation(),view.entry(),pieces,view.byteAContract(),view.inputBytes()));
    }
    var next=new Registration(old.version(),p.getUniqueProgramID(),old.root(),proof,views,OrdinaryProofDependencies.fingerprint(p,monitor),stock?null:SoftwareCallStateEntryInjection.nativeIdentity(),old.transport(),old.ownership());
    validateViews(p,next);int tx=p.startTransaction("Explicit predicate graph refresh");boolean success=false;
    try{for(var view:next.views())p.getOptions(stock?STOCK_OPTIONS:OPTIONS).setString(view.entry(),ProgramMapping.JSON.toJson(next));success=true;}finally{p.endTransaction(tx,success);}
  }
  public static List<String> remove(Program p,Address entry,TaskMonitor monitor) throws Exception {
    var registration=read(p,entry);
    require(registration.ownership()!=null,"Missing current predicate ownership; records retained");
    int tx=p.startTransaction("Remove owned predicate view; preserve edited artifacts and source listing");boolean success=false;
    try {
      var diagnostics=new ArrayList<String>();
      AnalysisOwnership.undo(p,registration.ownership(),monitor,diagnostics);
      for(var view:registration.views())p.getOptions(registration.transport()!=null?STOCK_OPTIONS:OPTIONS).removeOption(view.entry());
      monitor.checkCancelled();success=true;return List.copyOf(diagnostics);
    } finally {p.endTransaction(tx,success);}
  }
  public static PcodeOp[] emit(Program p,Address entry,long uniqueBase,TaskMonitor monitor) throws Exception {
    return emit(p,entry,uniqueBase,monitor,read(p,entry).transport()!=null);
  }
  public static PcodeOp[] emitLegacyComparison(Program p, Address entry, long uniqueBase, TaskMonitor monitor) throws Exception {
    return emit(p, entry, uniqueBase, monitor, false);
  }
  public static PcodeOp[] emitStock(Program p,Address entry,long uniqueBase,TaskMonitor monitor) throws Exception {
    return emit(p,entry,uniqueBase,monitor,true);
  }
  private static PcodeOp[] emit(Program p,Address entry,long uniqueBase,TaskMonitor monitor,boolean stock) throws Exception {
    long revision=p.getModificationNumber();var record=read(p,entry);
    require(stock?StockEntryInjection.VERSION.equals(record.transport()):record.transport()==null,"Entry transport mismatch; no record conversion is implicit");
    SymbolicMemory.validate(p,record.proof().memory());
    if(!stock)require(record.nativeIdentity().equals(SoftwareCallStateEntryInjection.nativeIdentity()),"Predicate native companion changed");
    require(record.dependencies().equals(OrdinaryProofDependencies.fingerprint(p,monitor)),"Stale predicated graph registration; explicit refresh required");
    validateViews(p,record);
    var actual=PredicatedCallGraph.preview(p,p.getFunctionManager().getFunctionAt(ProgramMapping.staticAddress(p,record.proof().entry())),record.proof().limits(),record.proof().memory(),monitor);
    require(actual.complete()&&sameGraph(actual,record.proof()),"Changed/forged predicate graph, feasible edge or frame authority");
    var view=record.views().stream().filter(v->v.entry().equals(entry.toString())).findFirst().orElseThrow();
    require(actual.memory()==null||actual.memory().mayWrites().isEmpty(),"Native transport of declared interference is unresolved");
    var result=lower(p,entry,record.proof(),record.views(),view.invocation(),uniqueBase);
    require(revision==p.getModificationNumber(),"Program changed during predicated native callback");return result;
  }
  public record Placement(String node,String source,int start,int end) {}
  public static List<Placement> inspectEmission(Program p,Address entry,long uniqueBase,TaskMonitor monitor) throws Exception {
    var emitted=emit(p,entry,uniqueBase,monitor);var record=read(p,entry);
    var view=record.views().stream().filter(v->v.entry().equals(entry.toString())).findFirst().orElseThrow();
    var placements=new ArrayList<Placement>();
    var inspected=lower(p,entry,record.proof(),record.views(),view.invocation(),uniqueBase,placements);
    require(Arrays.toString(emitted).equals(Arrays.toString(inspected)),"Emission changed during source-placement inspection");
    return List.copyOf(placements);
  }
  private static PcodeOp[] lower(Program p,Address site,PredicatedCallGraph.Proof proof,List<View> views,String invocation,long uniqueBase) throws Exception {
    return lower(p,site,proof,views,invocation,uniqueBase,null);
  }
  private static PcodeOp[] lower(Program p,Address site,PredicatedCallGraph.Proof proof,List<View> views,String invocation,long uniqueBase,List<Placement> placements) throws Exception {
    String entry=invocation.equals("root")?proof.root():proof.invocations().stream().filter(i->i.id().equals(invocation)).findFirst().orElseThrow().entry();
    var selected=proof.nodes().stream().filter(n->n.invocation().equals(invocation)).sorted(Comparator.comparing(n->n.id().equals(entry)?"":n.id())).toList();
    var ops=new ArrayList<PcodeOp>();var labels=new HashMap<String,Integer>();var edges=new HashMap<Integer,String>();long unique=uniqueBase;
    if(invocation.equals("root")&&proof.memory()!=null&&proof.memory().entryHL()!=null)
      ops.add(new PcodeOp(site,ops.size(),PcodeOp.COPY,new Varnode[]{constant(p,proof.memory().entryHL(),2)},new Varnode(p.getRegister("HL").getAddress(),2)));
    for(var node:selected) {
      labels.put(node.id(),ops.size());var temporaries=new HashMap<Long,Long>();var ins=p.getListing().getInstructionAt(ProgramMapping.staticAddress(p,node.source()));
      require(ins!=null&&node.bytes().equals(HexFormat.of().formatHex(ins.getBytes())),"Changed physical graph instruction");
      // Explicit stable local target follows the existing continuation transport convention.
      ops.add(new PcodeOp(site,ops.size(),PcodeOp.COPY,new Varnode[]{constant(p,0,1)},new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(unique),1)));unique+=0x10000;
      int rawIndex=-1;
      for(var op:ins.getPcode(false)) {
        rawIndex++;
        var inputs=op.getInputs().clone();
        for(int i=0;i<inputs.length;i++)inputs[i]=relocate(p,inputs[i],temporaries,unique);
        var output=op.getOutput()==null?null:relocate(p,op.getOutput(),temporaries,unique);int code=op.getOpcode();
        final int operationIndex=rawIndex;
        var read=node.reads().stream().filter(r->r.operation()==operationIndex).findFirst().orElse(null);
        if(code==PcodeOp.LOAD&&read!=null) {
          var done=new ArrayList<Integer>();
          for(int index=0;index<read.alternatives().size();index++) {
            var alternative=read.alternatives().get(index);
            if(index+1<read.alternatives().size()) {
              var condition=new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(unique+0xe0000+index),1);
              ops.add(new PcodeOp(site,ops.size(),PcodeOp.INT_NOTEQUAL,new Varnode[]{inputs[1],constant(p,alternative.cpu(),2)},condition));
              ops.add(new PcodeOp(site,ops.size(),PcodeOp.CBRANCH,new Varnode[]{constant(p,3,4),condition}));
            }
            var physical=ProgramMapping.staticAddress(p,alternative.sources().get(0).address());
            ops.add(new PcodeOp(site,ops.size(),PcodeOp.LOAD,new Varnode[]{constant(p,physical.getAddressSpace().getSpaceID(),4),constant(p,physical.getOffset(),2)},output));
            if(index+1<read.alternatives().size()) {done.add(ops.size());ops.add(new PcodeOp(site,ops.size(),PcodeOp.BRANCH,new Varnode[]{constant(p,0,4)}));}
          }
          for(int from:done)ops.set(from,new PcodeOp(site,from,PcodeOp.BRANCH,new Varnode[]{constant(p,ops.size()-from,4)}));
        } else if(code==PcodeOp.BRANCHIND) {
          var alternatives=node.edges().stream().filter(e->e.kind().equals("DISPATCH")).toList();
          require(!alternatives.isEmpty(),"Missing finite dispatch alternatives");
          for(int index=0;index<alternatives.size();index++) {
            var edge=alternatives.get(index);
            var target=proof.nodes().stream().filter(n->n.id().equals(edge.target())).findFirst().orElseThrow();
            if(index+1==alternatives.size()) {
              edges.put(ops.size(),edge.target());ops.add(new PcodeOp(site,ops.size(),PcodeOp.BRANCH,new Varnode[]{constant(p,0,4)}));
            } else {
              var condition=new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(unique+0xf0000+index),1);
              ops.add(new PcodeOp(site,ops.size(),PcodeOp.INT_EQUAL,new Varnode[]{inputs[0],constant(p,target.cpu(),2)},condition));
              edges.put(ops.size(),edge.target());ops.add(new PcodeOp(site,ops.size(),PcodeOp.CBRANCH,new Varnode[]{constant(p,0,4),condition}));
            }
          }
        } else if(code==PcodeOp.BRANCH||code==PcodeOp.CBRANCH) {
          var taken=node.edges().stream().filter(e->e.kind().equals(op.getOpcode()==PcodeOp.BRANCH?"BRANCH":"TAKEN")).findFirst().orElse(null);
          var fall=node.edges().stream().filter(e->e.kind().equals("FALLTHROUGH")).findFirst().orElse(null);
          if(code==PcodeOp.CBRANCH&&taken!=null&&fall!=null) {
            edges.put(ops.size(),taken.target());ops.add(new PcodeOp(site,ops.size(),PcodeOp.CBRANCH,new Varnode[]{constant(p,0,4),inputs[1]}));
            edges.put(ops.size(),fall.target());ops.add(new PcodeOp(site,ops.size(),PcodeOp.BRANCH,new Varnode[]{constant(p,0,4)}));
          } else {
            var edge=taken==null?fall:taken;require(edge!=null,"Missing feasible graph successor");
            edges.put(ops.size(),edge.target());ops.add(new PcodeOp(site,ops.size(),PcodeOp.BRANCH,new Varnode[]{constant(p,0,4)}));
          }
        } else if(code==PcodeOp.CALL) {
          var target=views.stream().filter(v->v.invocation().equals(node.callee())).findFirst().orElseThrow();
          ops.add(new PcodeOp(site,ops.size(),PcodeOp.CALL,new Varnode[]{new Varnode(ProgramMapping.staticAddress(p,target.entry()),2)}));
        } else {
          if(proof.memory()!=null) {
            if(code==PcodeOp.CALLOTHER&&CartridgeBus.isDirectWrite(p.getLanguage(),op)&&op.getInput(1).getOffset()>=0x8000) {
              var at=SymbolicMemory.address(p,node.incoming(),(int)op.getInput(1).getOffset(),ScalarAccess.Kind.WRITE);
              code=PcodeOp.STORE;inputs=new Varnode[]{constant(p,at.getAddressSpace().getSpaceID(),4),constant(p,at.getOffset(),2),inputs[2]};
            } else {
              for(int i=0;i<inputs.length;i++)if(inputs[i].isAddress()&&inputs[i].getOffset()>=0x8000)inputs[i]=memoryNode(p,node,inputs[i],ScalarAccess.Kind.READ);
              if(output!=null&&output.isAddress())output=memoryNode(p,node,output,ScalarAccess.Kind.WRITE);
            }
          }
          ops.add(new PcodeOp(site,ops.size(),code,inputs,output));
        }
      }
      if(node.transfer().equals("NEXT")||node.transfer().equals("CALL")) {
        var next=node.edges().stream().filter(e->e.kind().equals(node.transfer().equals("CALL")?"RESUME":"NEXT")).findFirst().orElseThrow();
        edges.put(ops.size(),next.target());ops.add(new PcodeOp(site,ops.size(),PcodeOp.BRANCH,new Varnode[]{constant(p,0,4)}));
      }
      if(placements!=null)placements.add(new Placement(node.id(),node.source(),labels.get(node.id()),ops.size()));
      unique+=0x1000000;
      require(ops.size()<=16384&&unique-uniqueBase<=0x100000000L,"Predicate lowering operation/scratch budget exceeded");
    }
    return SoftwareCallContinuationView.bindPredicateEdges(p,site,ops,labels,edges);
  }
  private static Varnode memoryNode(Program p,PredicatedCallGraph.Node node,Varnode value,ScalarAccess.Kind kind) throws Exception {
    require(value.getSize()==1&&(value.getAddress().getAddressSpace().equals(p.getAddressFactory().getDefaultAddressSpace())||value.getAddress().getAddressSpace().equals(ProgramMapping.staticAddress(p,node.source()).getAddressSpace())),"Unsupported native memory spelling");
    return new Varnode(SymbolicMemory.address(p,node.incoming(),(int)value.getOffset(),kind),1);
  }
  private static Varnode constant(Program p,long value,int size){return new Varnode(p.getAddressFactory().getConstantSpace().getAddress(value),size);}
  private static Varnode relocate(Program p,Varnode value,Map<Long,Long> temporaries,long base){
    if(!value.isUnique())return value;long block=value.getOffset()&~0xffffL;
    long next=temporaries.computeIfAbsent(block,k->base+temporaries.size()*0x10000L);
    return new Varnode(p.getAddressFactory().getUniqueSpace().getAddress(next+(value.getOffset()&0xffff)),value.getSize());
  }
}
