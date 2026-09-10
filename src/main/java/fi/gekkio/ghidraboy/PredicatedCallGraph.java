package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Predicate adapter over the shared value core, production fetch evidence and ordinary frame effects. */
public final class PredicatedCallGraph {
  private PredicatedCallGraph() {}
  public static final String VERSION = "predicated-ordinary-graph-4";
  public record Limits(int nodes, int operations, int calls) {
    public static final Limits PRIMARY = new Limits(256, 262144, 1);
    public Limits { if (nodes < 1 || nodes > 512 || operations < 1 || operations > 1048576 || calls < 1 || calls > 2)
      throw new IllegalArgumentException("Predicated graph limits outside scoped envelope"); }
  }
  public record Domain(int stackMin, int stackMax, String conditions) {}
  public static final Domain DOMAIN = new Domain(0xc082, 0xcffc,
      "Boot bypassed; synchronous ordinary MBC5 immutable-ROM execution; no DMA/async/untracked mutation. "
      + "Unknown incoming CPU registers/mapper; outer return word symbolic in fixed WRAM. Root SP C082..CFFC, "
      + "one internal call depth, bounded relational root CFG and straight-line ordinary callees with effect-derived native byte-register inputs. "
      + "Outputs below C080 are disjoint from live frame bytes C080..CFFD.");
  public static final Domain MEMORY_DOMAIN = new Domain(0xc800, 0xcffc,
      "Explicit unknown fixed WRAM inputs and established executable generation; synchronous MBC5, boot bypassed; no async/untracked writers except declared may-writes. Symbolic outer frame C800..CFFD disjoint from data/code C000..C7FF.");
  public record Binding(long offset, AbstractValues.Origin origin, List<Long> cover) {}
  public record Edge(String kind, String target, AbstractValues.Condition condition) {}
  public record Effect(int operation, int cpu, AbstractValues.Origin value, boolean mapperControl) {}
  public record Frontier(String state, int cpu, String invocation, String reason,int domain,List<JoinedBinding> before,String control,int spDelta,List<SoftwareCallEffects.RelativeFrame> frames,List<SymbolicMemory.Access> memoryAccesses) {
    public Frontier(String state,int cpu,String invocation,String reason){this(state,cpu,invocation,reason,-1,List.of(),state,0,List.of(),List.of());}
    public Frontier {memoryAccesses=List.copyOf(memoryAccesses);before=List.copyOf(before);frames=List.copyOf(frames);}
  }
  public record Node(String id, String invocation, int cpu, String source, String bytes,
      List<BankAnalysis.FetchByte> fetch, List<String> rawPcode, AbstractValues.Condition predicate,
      MapperKnowledge incoming, MapperKnowledge outgoing, List<Binding> before, List<Binding> after,
      int beforeSpDelta, int afterSpDelta, List<AbstractValues.Origin> unavailableNativeFlags, List<SoftwareCallEffects.RelativeFrame> frames,
      List<SoftwareCallEffects.RelativeAccess> frameAccesses, List<Effect> effects,
      String transfer, int transferOperation, List<Edge> edges, String callee, List<SymbolicMemory.Access> memoryAccesses) {
    public Node { fetch=List.copyOf(fetch);rawPcode=List.copyOf(rawPcode);before=List.copyOf(before);after=List.copyOf(after);
      memoryAccesses=List.copyOf(memoryAccesses);unavailableNativeFlags=List.copyOf(unavailableNativeFlags);frames=List.copyOf(frames);frameAccesses=List.copyOf(frameAccesses);effects=List.copyOf(effects);edges=List.copyOf(edges); }
  }
  public record Invocation(String id, String caller, String callNode, String target, String entry,
      String returnNode, String continuation, int returnCpu, boolean byteAContract, List<Long> inputBytes) {
    public Invocation {inputBytes=List.copyOf(inputBytes);}
  }
  public record OriginNode(AbstractValues.OriginKind kind,int width,String input,long constant,int opcode,List<Integer> inputs,List<AbstractValues.TableRow> table) {
    public OriginNode {inputs=List.copyOf(inputs);table=List.copyOf(table);}
  }
  public record JoinedBinding(long offset,int origin,List<Long> cover) {public JoinedBinding {cover=cover==null?null:List.copyOf(cover);}}
  public record JoinedEffect(int operation,int cpu,int value,boolean mapperControl) {}
  public record JoinRow(String id,String node,int domain,List<JoinedBinding> before,List<JoinedBinding> after,List<JoinedEffect> effects,List<String> successors) {
    public JoinRow {before=List.copyOf(before);after=List.copyOf(after);effects=List.copyOf(effects);successors=List.copyOf(successors);}
  }
  public record Convergence(int transfers,int rounds,int worklistMaximum,int rows,int replayTransfers,boolean postFixedPoint,boolean possibleNontermination,int operations) {}
  public record Proof(String version, long programId, String entry, String end, Domain domain, Limits limits,
      String dependencies, String root, List<Node> nodes, List<Invocation> invocations,
      List<Frontier> frontier, boolean coverageComplete, SoftwareCallInstructionDiscovery.Plan discovery, List<JoinRow> joins, Convergence convergence,List<OriginNode> origins,List<PredicatedJoin.Domain> joinDomains,SymbolicMemory.Declaration memory) {
    public Proof { nodes=List.copyOf(nodes);invocations=List.copyOf(invocations);frontier=List.copyOf(frontier);joins=joins==null?List.of():List.copyOf(joins);origins=List.copyOf(origins);joinDomains=List.copyOf(joinDomains); }
    public boolean complete() { return coverageComplete && frontier.isEmpty() && root!=null && !nodes.isEmpty(); }
  }
  static String hash(Object value) { return Sha256.of(ProgramMapping.JSON.toJson(value).getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString(); }
  private static List<Binding> bindings(AbstractValues.Storage storage) {
    return storage.registers.entrySet().stream().sorted(Map.Entry.comparingByKey()).map(e ->
        new Binding(e.getKey(),e.getValue().origin(),e.getValue().values()==null?null:new ArrayList<>(e.getValue().values()))).toList();
  }
  private record Slot(String space,long offset,int size) {
    boolean overlaps(Slot other) {return space.equals(other.space)&&offset<other.offset+other.size&&other.offset<offset+size;}
  }
  private static Slot slot(Varnode v) {return new Slot(v.getAddress().getAddressSpace().getName(),v.getOffset(),v.getSize());}
  private static boolean contains(AbstractValues.Origin origin, AbstractValues.Origin target) {
    return origin.equals(target)||origin.inputs().stream().anyMatch(child->contains(child,target));
  }
  private static boolean untransported(State state, AbstractValues.Value value) {
    return state.unavailableFlags.stream().anyMatch(flag->contains(value.origin(),flag));
  }
  private static Integer exact(AbstractValues.Value value) {
    return value.values()!=null && value.values().size()==1 ? value.values().first().intValue() : null;
  }
  private static AbstractValues.Condition and(AbstractValues.Condition before, AbstractValues.Term term) {
    var terms=new ArrayList<>(before.terms());if(!terms.contains(term))terms.add(term);
    if(terms.size()>8)throw new IllegalArgumentException("Predicate conjunction budget exhausted");
    return new AbstractValues.Condition(terms);
  }
  private static final class State {
    PredicatedJoin.Domain domain=PredicatedJoin.Domain.unknown();
    final Map<Integer,Integer> partition=new TreeMap<>();
    int cpu, calls; String invocation="root"; MapperKnowledge mapper=MapperKnowledge.unknown();
    AbstractValues.Condition predicate=new AbstractValues.Condition(List.of());
    final AbstractValues.Storage storage;
    SymbolicMemory.State memory;
    final Map<Slot,Integer> affine=new HashMap<>();
    final Map<Integer,AbstractValues.Value> stack=new HashMap<>();
    final List<SoftwareCallEffects.RelativeFrame> frames=new ArrayList<>();
    final List<AbstractValues.Origin> unavailableFlags=new ArrayList<>();
    State(String scope) {storage=new AbstractValues.Storage(scope);}
    State copy() {
      var n=new State(storage.scope);n.cpu=cpu;n.calls=calls;n.invocation=invocation;n.mapper=mapper;n.predicate=predicate;
      n.memory=memory==null?null:memory.copy();n.storage.registers.putAll(storage.registers);n.storage.uniques.putAll(storage.uniques);n.storage.site=storage.site;
      n.domain=domain;n.partition.putAll(partition);n.affine.putAll(affine);n.stack.putAll(stack);n.frames.addAll(frames);n.unavailableFlags.addAll(unavailableFlags);return n;
    }
  }
  private static final class PendingInvocation {
    final String id, caller, callNode, target;final int returnCpu;
    String entry, returnNode, continuation;boolean byteAContract;AbstractValues.Origin entryFlags;List<Long> inputBytes=List.of();
    PendingInvocation(String id,String caller,String callNode,String target,int returnCpu) {
      this.id=id;this.caller=caller;this.callNode=callNode;this.target=target;this.returnCpu=returnCpu;
    }
    Invocation freeze(){return new Invocation(id,caller,callNode,target,entry,returnNode,continuation,returnCpu,byteAContract,inputBytes);}
  }
  public static Proof preview(Program p,Function root,Limits limits,TaskMonitor monitor) throws Exception {
    return preview(p,root,limits,null,monitor);
  }
  public static Proof preview(Program p,Function root,Limits limits,SymbolicMemory.Declaration memory,TaskMonitor monitor) throws Exception {
    SymbolicMemory.validate(p,memory);
    boolean image=memory!=null&&memory.image()!=null;
    if(root==null || root.getProgram()!=p || (!image&&(root.getEntryPoint().getOffset()>=0x4000
        || !root.getEntryPoint().getAddressSpace().equals(p.getAddressFactory().getDefaultAddressSpace())
        || root.getBody().getMaxAddress().getOffset()>=0x4000)) || root.getBody().getNumAddressRanges()!=1
        || root.getBody().getNumAddresses()>1024 || root.hasNoReturn() || root.getCallFixup()!=null || root.isThunk())
      throw new IllegalArgumentException("Predicate root requires bounded canonical ROM0 Function");
    if(image&&!root.getEntryPoint().toString().equals(ExecutableImages.resolve(p,memory.image()).entry()))throw new IllegalArgumentException("Root is not requested executable generation");
    var cart=ProgramMapping.cartridge(p);
    if(cart==null || cart.mapper()!=Cartridge.Mapper.MBC5 || cart.actualRomBanks()>256
        || !SoftwareCallRegistry.configurationIdentity(p).equals("absent"))
      throw new IllegalArgumentException("Predicate adapter requires existing ordinary MBC5/no-software-registry domain");
    for(String name:List.of("A","F","BC","DE","HL","SP")) {
      var context=p.getProgramContext().getRegisterValue(p.getRegister(name),root.getEntryPoint());
      if(context!=null&&context.hasAnyValue())throw new IllegalArgumentException("Unknown predicate entry register required: "+name);
    }
    long revision=p.getModificationNumber();String dependencies=OrdinaryProofDependencies.fingerprint(p,monitor);
    try(var discovery=SoftwareCallInstructionDiscovery.begin(p,monitor)) {
      var builder=new Builder(p,root,limits,memory,monitor);var state=new State(p.getUniqueProgramID()+":"+root.getEntryPoint());
      state.memory=SymbolicMemory.initial(p,memory,state.storage.scope);
      state.cpu=(int)root.getEntryPoint().getOffset();state.affine.put(slot(builder.sp),0);
      state.stack.put(0,AbstractValues.input(state.storage.scope,"outer-return-byte",0,1));
      state.stack.put(1,AbstractValues.input(state.storage.scope,"outer-return-byte",1,1));
      builder.findCycles(state);
      if(memory!=null&&!builder.cyclic.isEmpty())throw new IllegalArgumentException("Symbolic memory cyclic joins remain unresolved");
      String entry=builder.visit(state,new HashSet<>());
      builder.converge();
      boolean coverage=builder.coverage();
      if(memory!=null)for(var write:memory.mayWrites())if(builder.nodes.values().stream().noneMatch(n->n.cpu()==write.beforeCpu())&&builder.frontier.stream().noneMatch(n->n.cpu()==write.beforeCpu()))throw new IllegalArgumentException("May-write declaration is not a reached instruction boundary");
      if(revision!=p.getModificationNumber()||!dependencies.equals(OrdinaryProofDependencies.fingerprint(p,monitor)))
        throw new IllegalArgumentException("Program changed during predicate graph proof");
      return new Proof(VERSION,p.getUniqueProgramID(),root.getEntryPoint().toString(),root.getBody().getMaxAddress().toString(),
          memory==null?DOMAIN:MEMORY_DOMAIN,limits,dependencies,entry,new ArrayList<>(builder.nodes.values()),
          builder.invocations.values().stream().map(PendingInvocation::freeze).toList(),builder.frontier,coverage,discovery.plan(monitor),new ArrayList<>(builder.rows.values()),builder.statistics(),builder.origins,builder.domains,memory);
    }
  }
  private static final class Builder {
    final SymbolicMemory.Declaration memory;final Domain executionDomain;
    final Program p;final Function root;final Limits limits;final TaskMonitor monitor;final Cartridge cartridge;
    final Varnode sp;final Map<String,Node> nodes=new TreeMap<>();final Map<String,PendingInvocation> invocations=new TreeMap<>();
    final List<Frontier> frontier=new ArrayList<>();final List<AbstractValues.Condition> exits=new ArrayList<>();
    int attempted,operations,rounds,worklistMaximum,replayTransfers;boolean verifying,postFixedPoint;
    final Set<Integer> cyclic=new HashSet<>();
    final Map<String,State> inputs=new LinkedHashMap<>();final Map<String,JoinRow> rows=new TreeMap<>();
    final ArrayDeque<String> queue=new ArrayDeque<>();
    final Map<AbstractValues.Origin,Integer> originIds=new HashMap<>();final List<OriginNode> origins=new ArrayList<>();
    final Map<PredicatedJoin.Domain,Integer> domainIds=new HashMap<>();final List<PredicatedJoin.Domain> domains=new ArrayList<>();
    int origin(AbstractValues.Origin value) {
      var known=originIds.get(value);if(known!=null)return known;
      var inputs=value.inputs().stream().map(this::origin).toList();int id=origins.size();
      origins.add(new OriginNode(value.kind(),value.width(),value.input(),value.constant(),value.opcode(),inputs,value.table()));originIds.put(value,id);return id;
    }
    int domain(PredicatedJoin.Domain value) {
      var known=domainIds.get(value);if(known!=null)return known;int id=domains.size();domains.add(value);domainIds.put(value,id);return id;
    }
    List<JoinedBinding> intern(List<Binding> values) {return values.stream().map(v->new JoinedBinding(v.offset(),origin(v.origin()),v.cover())).toList();}
    void frontier(State state,String row,String control,String reason) {
      frontier.add(new Frontier(row,state.cpu,state.invocation,reason,domain(state.domain),intern(bindings(state.storage)),control,sp(state),state.frames,List.of()));
    }
    String activeRow;List<String> successors;
    Convergence statistics(){return new Convergence(attempted,rounds,worklistMaximum,rows.size(),replayTransfers,postFixedPoint,recurrent(),operations);}
    boolean recurrent() {
      var indegree=new HashMap<String,Integer>();for(String id:rows.keySet())indegree.put(id,0);
      for(var row:rows.values())for(String target:row.successors())if(indegree.containsKey(target))indegree.merge(target,1,Integer::sum);
      var ready=new ArrayDeque<String>();indegree.forEach((id,count)->{if(count==0)ready.add(id);});int removed=0;
      while(!ready.isEmpty()){var row=rows.get(ready.removeFirst());removed++;for(String target:row.successors())if(indegree.containsKey(target)&&indegree.merge(target,-1,Integer::sum)==0)ready.add(target);}
      return removed<rows.size();
    }
    void findCycles(State initial) throws Exception {
      var flow=new TreeMap<Integer,List<Integer>>();var pending=new ArrayDeque<Integer>();pending.add(initial.cpu);
      while(!pending.isEmpty()) {
        int cpu=pending.removeFirst();if(flow.containsKey(cpu))continue;
        if(!root.getBody().contains(root.getEntryPoint().getAddressSpace().getAddress(cpu)))continue;
        var ins=SoftwareCallInstructionDiscovery.instructionAt(p,root.getEntryPoint().getAddressSpace().getAddress(cpu),"root CFG cycle inventory",monitor);
        if(ins==null)continue;
        var targets=new ArrayList<Integer>();boolean terminal=false;
        for(var op:ins.getPcode(false)) {
          if(op.getOpcode()==PcodeOp.BRANCH||op.getOpcode()==PcodeOp.CBRANCH) {
            if(!op.getInput(0).isConstant())targets.add((int)op.getInput(0).getOffset()&65535);
            if(op.getOpcode()==PcodeOp.BRANCH)terminal=true;
          }
          if(op.getOpcode()==PcodeOp.RETURN||op.getOpcode()==PcodeOp.BRANCHIND)terminal=true;
        }
        if(!terminal&&ins.getDefaultFallThrough()!=null)targets.add((cpu+ins.getLength())&65535);
        flow.put(cpu,targets);pending.addAll(targets);
      }
      for(int start:flow.keySet()) {
        var seen=new HashSet<Integer>();pending.addAll(flow.get(start));
        while(!pending.isEmpty()) {
          int next=pending.removeFirst();if(next==start){cyclic.add(start);pending.clear();break;}
          if(seen.add(next))pending.addAll(flow.getOrDefault(next,List.of()));
        }
      }
    }
    String control(State state) throws Exception {
      var at=address(state);
      return hash(Arrays.asList(state.cpu,at.toString(),ProgramMapping.staticToPhysical(p,at),state.invocation,state.mapper,
          state.partition,sp(state),state.frames,state.unavailableFlags));
    }
    String rowIdentity(State state,String node) {
      return hash(Arrays.asList(node,state.domain,bindings(state.storage),state.calls,
          state.affine.entrySet().stream().filter(e->!e.getKey().space().equals("unique")).sorted(Comparator.comparing(e->e.getKey().toString())).map(e->List.of(e.getKey(),e.getValue())).toList(),
          state.stack.entrySet().stream().sorted(Map.Entry.comparingByKey()).map(e->List.of(e.getKey(),e.getValue().origin())).toList()));
    }
    String enqueue(State incoming) throws Exception {
      var state=incoming.copy();state.storage.registers.replaceAll((offset,value)->untransported(state,value)?value:PredicatedJoin.restrict(value,state.domain));
      state.predicate=new AbstractValues.Condition(List.of());
      String node;
      try{node=control(state);}catch(IllegalArgumentException failure){frontier(state,rowIdentity(state,"unresolved"),"unresolved",failure.getMessage());return null;}
      String row=rowIdentity(state,node);if(successors!=null)successors.add(row);
      if(verifying) {if(!inputs.containsKey(row)||!rows.containsKey(row))throw new IllegalArgumentException("Premature fixed point: missing reachable successor row");return node;}
      if(!inputs.containsKey(row)) {
        if(inputs.size()>=limits.nodes()*256){frontier(state,row,node,"Join row budget exhausted; successor obligation retained");return null;}
        inputs.put(row,state);queue.addLast(row);worklistMaximum=Math.max(worklistMaximum,queue.size());
      }
      return node;
    }
    void converge() throws Exception {
      if(cyclic.isEmpty())return;
      while(!queue.isEmpty()&&operations<=limits.operations()) {
        int count=queue.size();rounds++;
        for(int i=0;i<count;i++) {activeRow=queue.removeFirst();successors=new ArrayList<>();attempted++;transfer(inputs.get(activeRow),new HashSet<>());}
      }
      successors=null;
      for(String pending:queue){var state=inputs.get(pending);frontier(state,pending,control(state),"Unexplored reachable join worklist frontier");}
      if(!frontier.isEmpty())return;
      verifying=true;
      for(var e:inputs.entrySet()) {
        activeRow=e.getKey();successors=new ArrayList<>();var expected=rows.get(activeRow);replayTransfers++;
        transfer(e.getValue(),new HashSet<>());
        if(!Objects.equals(expected,rows.get(activeRow)))throw new IllegalArgumentException("Join transfer is not post-fixed under actual instruction semantics");
      }
      successors=null;verifying=false;postFixedPoint=frontier.isEmpty();
      // CALL continuation is established by matched RET transfer, independent of worklist/serialization order.
      for(var e:new ArrayList<>(nodes.entrySet())) {
        var node=e.getValue();if(node.callee()==null)continue;var call=invocations.get(node.callee());
        if(call.continuation==null)continue;
        var edges=new ArrayList<>(node.edges());edges.add(new Edge("RESUME",call.continuation,node.predicate()));
        nodes.put(e.getKey(),replace(node,edges));
      }
    }
    Node replace(Node n,List<Edge> edges) {
      return new Node(n.id(),n.invocation(),n.cpu(),n.source(),n.bytes(),n.fetch(),n.rawPcode(),n.predicate(),n.incoming(),n.outgoing(),
          List.of(),List.of(),n.beforeSpDelta(),n.afterSpDelta(),n.unavailableNativeFlags(),n.frames(),n.frameAccesses(),List.of(),n.transfer(),n.transferOperation(),edges,n.callee(),n.memoryAccesses());
    }

    Builder(Program p,Function root,Limits limits,SymbolicMemory.Declaration memory,TaskMonitor monitor){this.memory=memory;this.executionDomain=memory==null?DOMAIN:MEMORY_DOMAIN;this.p=p;this.root=root;this.limits=limits;this.monitor=monitor;
      cartridge=ProgramMapping.cartridge(p);sp=new Varnode(p.getRegister("SP").getAddress(),2);}
    int sp(State s){var result=s.affine.get(slot(sp));if(result==null)throw new IllegalArgumentException("Unproved symbolic SP delta");return result;}
    Address address(State s) throws Exception {
      if(memory!=null&&memory.image()!=null) {
        var image=ExecutableImages.resolve(p,memory.image());
        ExecutableImages.validateFetch(p,memory.image(),s.memory,image.cpu(),image.length());
        return ProgramMapping.staticAddress(p,ExecutableImages.resolve(p,memory.image()).entry()).getAddressSpace().getAddress(s.cpu);
      }
      var physical=ScalarAccess.resolve(cartridge,s.mapper,new ScalarAccess.Request(s.cpu,ScalarAccess.Kind.FETCH,1,0,
          "predicate root/justified edge",-1,-1,null)).resolution().orElseThrow().physical();
      if(physical==null||!physical.region().equals("ROM"))throw new IllegalArgumentException("Unresolved/non-ROM instruction target");
      return ProgramMapping.physicalToStatic(p,physical).stream().filter(a -> a.getOffset()==s.cpu && SoftwareCallExecutionView.canonical(p,a)
              && !p.getMemory().getBlock(a).getName().startsWith(OrdinaryEntryAccess.PREFIX))
          .findFirst().orElseThrow(()->new IllegalArgumentException("Missing canonical physical fetch target"));
    }
    String visit(State incoming,Set<String> path) throws Exception {
      return cyclic.isEmpty()?transfer(incoming,path):enqueue(incoming);
    }
    String transfer(State incoming,Set<String> path) throws Exception {
      monitor.checkCancelled();var s=incoming.copy();String source="unresolved";
      String id=hash(Arrays.asList(s.cpu,s.invocation,s.mapper,s.predicate,bindings(s.storage),sp(s),s.frames,s.unavailableFlags));
      var memoryAccesses=new ArrayList<SymbolicMemory.Access>();
      try {
        if(cyclic.isEmpty()&&++attempted>limits.nodes())throw new IllegalArgumentException("Predicate node work budget exhausted");
        if(memory!=null)for(var write:memory.mayWrites())if(write.beforeCpu()==s.cpu)
          s.memory.write(p,s.mapper,write.cpu(),AbstractValues.input(s.storage.scope,"declared-interference",0,1),write.reason()+":"+s.invocation+":"+s.cpu,-1,true,memoryAccesses);
        Address at=address(s);source=at.toString();
        id=hash(Arrays.asList(s.cpu,source,ProgramMapping.staticToPhysical(p,at),s.invocation,s.mapper,s.predicate,bindings(s.storage),sp(s),s.frames,s.unavailableFlags));
        if(memory!=null)id=hash(List.of(id,s.memory.identity(),s.memory.killed.stream().map(Object::toString).sorted().toList()));
        if(!cyclic.isEmpty()){id=control(s);if(!nodes.containsKey(id)&&nodes.size()>=limits.nodes())throw new IllegalArgumentException("Predicate control-node budget exhausted");}
        if(cyclic.isEmpty()&&nodes.containsKey(id))return id;
        String cycle=s.invocation+":"+source;
        if(cyclic.isEmpty()&&!path.add(cycle))throw new IllegalArgumentException("Acyclic predicate scope: backedge retained as frontier");
        if(s.invocation.equals("root")&&!root.getBody().contains(at))throw new IllegalArgumentException("Root flow escaped declared body");
        var ins=SoftwareCallInstructionDiscovery.instructionAt(p,at,"predicate-qualified graph edge "+id,monitor);
        if(ins==null)throw new IllegalArgumentException("Missing justified instruction");
        var fetch=memory!=null&&memory.image()!=null?ExecutableImages.fetch(p,memory.image(),s.memory,ins):BankAnalysis.predicatedFetch(p,s.mapper,ins);
        if(InstructionInterpretation.architecturalUnresolved(ins)!=null||!Arrays.toString(ins.getPcode(false)).equals(Arrays.toString(ins.getPcode(true))))
          throw new IllegalArgumentException("Unvalidated instruction override in predicate graph");
        var before=bindings(s.storage);var beforeMapper=s.mapper;int beforeSp=sp(s);
        var frameBefore=List.copyOf(s.frames);var frameAccesses=new ArrayList<SoftwareCallEffects.RelativeAccess>();var effects=new ArrayList<Effect>();
        s.storage.instruction(source);s.affine.keySet().removeIf(k->k.space().equals("unique"));
        var raw=ins.getPcode(false);String transfer="NEXT",callee=null;int transferOperation=-1;var edges=new ArrayList<Edge>();
        for(int index=0;index<raw.length;index++) {
          if(!verifying&&++operations>limits.operations())throw new IllegalArgumentException("Predicate operation work budget exhausted");
          var op=raw[index];int code=op.getOpcode();
          if(code==PcodeOp.CBRANCH||code==PcodeOp.BRANCH||code==PcodeOp.CALL||code==PcodeOp.RETURN) {
            if(index!=raw.length-1)throw new IllegalArgumentException("P-code-local or mid-instruction transfer outside scoped graph fragment");
            transfer=op.getMnemonic();transferOperation=index;
            if(code==PcodeOp.CBRANCH||code==PcodeOp.BRANCH) {
              if(op.getInput(0).isConstant())throw new IllegalArgumentException("P-code-local branch is not a machine-PC edge");
              if(!s.frames.isEmpty())throw new IllegalArgumentException("Conditional callee beyond straight-line invocation scope");
              int target=(int)op.getInput(0).getOffset()&65535;
              if(code==PcodeOp.BRANCH) {
                var next=s.copy();next.cpu=target;edges.add(new Edge("BRANCH",visit(next,new HashSet<>(path)),s.predicate));
              } else {
                var condition=s.storage.get(op.getInput(1));
                if(untransported(s,condition))throw new IllegalArgumentException("Native byte-A call contract cannot carry live returned flags into control");
                if(!cyclic.isEmpty()) {
                  for(var part:PredicatedJoin.split(s.storage,condition,s.domain)) {
                    var next=s.copy();next.domain=part.domain();next.storage.registers.clear();next.storage.registers.putAll(part.registers());
                    for(var binding:s.storage.registers.entrySet())if(untransported(s,binding.getValue()))next.storage.registers.put(binding.getKey(),binding.getValue());
                    next.cpu=part.taken()==1?target:(s.cpu+ins.getLength())&65535;
                    if(!cyclic.contains(s.cpu))next.partition.put(s.cpu,part.taken());
                    var edge=new Edge(part.taken()==1?"TAKEN":"FALLTHROUGH",visit(next,new HashSet<>()),s.predicate);
                    if(!edges.contains(edge))edges.add(edge);
                  }
                } else {
                for(int taken:List.of(0,1)) {
                  var predicate=and(s.predicate,new AbstractValues.Term(condition.origin(),taken));
                  var compatible=AbstractValues.compatible(predicate);
                  if(compatible==AbstractValues.Compatibility.UNKNOWN)throw new IllegalArgumentException("Unknown predicate compatibility retained as frontier");
                  if(compatible==AbstractValues.Compatibility.UNSAT)continue;
                  var next=s.copy();next.predicate=predicate;next.cpu=taken==1?target:(s.cpu+ins.getLength())&65535;
                  edges.add(new Edge(taken==1?"TAKEN":"FALLTHROUGH",visit(next,new HashSet<>(path)),predicate));
                }
                }
              }
            } else if(code==PcodeOp.CALL) {
              if(!s.frames.isEmpty()||++s.calls>limits.calls())throw new IllegalArgumentException("Ordinary invocation depth/count frontier");
              if(op.getInput(0).isConstant()||ins.getDefaultFlows().length!=1)throw new IllegalArgumentException("Unresolved ordinary CALL target");
              int returnCpu=(s.cpu+ins.getLength())&65535;var target=s.copy();target.cpu=(int)op.getInput(0).getOffset()&65535;
              var physical=address(target);callee=hash(List.of(id,physical.toString(),returnCpu));
              var frame=SoftwareCallEffects.ordinaryFrame(callee,s.invocation,id,returnCpu,beforeSp,sp(s),frameAccesses);
              var invocation=new PendingInvocation(callee,s.invocation,id,physical.toString(),returnCpu);
              invocation.entryFlags=s.storage.get(new Varnode(p.getRegister("F").getAddress(),1)).origin();if(cyclic.isEmpty())invocations.put(callee,invocation);else {
                var prior=invocations.putIfAbsent(callee,invocation);if(prior!=null)invocation=prior;
              }
              target.invocation=callee;target.frames.add(frame);invocation.entry=visit(target,new HashSet<>(path));
              if(cyclic.isEmpty()&&(invocation.returnNode==null||invocation.continuation==null))throw new IllegalArgumentException("Ordinary call lacks matched return/continuation");
              edges.add(new Edge("CALL",invocation.entry,s.predicate));if(cyclic.isEmpty())edges.add(new Edge("RESUME",invocation.continuation,s.predicate));
            } else {
              if(s.frames.isEmpty()) {
                if(beforeSp!=0||sp(s)!=2||frameAccesses.size()!=2||frameAccesses.get(0).delta()!=0||frameAccesses.get(1).delta()!=1)
                  throw new IllegalArgumentException("Outer symbolic return frame mismatch");
                transfer="EXTERNAL_RETURN";exits.add(s.predicate);
              } else {
                var frame=s.frames.remove(s.frames.size()-1);var destination=exact(s.storage.get(op.getInput(0)));
                if(destination==null)throw new IllegalArgumentException("Unresolved live ordinary return word");
                SoftwareCallEffects.matchedOrdinaryReturn(frame,destination,sp(s),frameAccesses);
                var invocation=invocations.get(s.invocation);
                var resultA=s.storage.get(new Varnode(p.getRegister("A").getAddress(),1));
                if(contains(resultA.origin(),invocation.entryFlags)||untransported(s,resultA))
                  throw new IllegalArgumentException("Byte-A result depends on flags not carried by native contract");
                invocation.returnNode=id;
                // The callee writes only A/F plus its proved PC/SP return effects. This is a byte A result contract.

                var next=s.copy();next.invocation=frame.caller();next.cpu=destination;
                next.unavailableFlags.add(s.storage.get(new Varnode(p.getRegister("F").getAddress(),1)).origin());
                String continuation=visit(next,new HashSet<>(path));
                if(!cyclic.isEmpty()&&invocation.continuation!=null&&!Objects.equals(invocation.continuation,continuation))
                  throw new IllegalArgumentException("Joined call requires multiple qualified return continuations");
                invocation.continuation=continuation;edges.add(new Edge("MATCHED_RETURN",invocation.continuation,s.predicate));
              }
            }
            break;
          }
          if(code==PcodeOp.BRANCHIND||code==PcodeOp.CALLIND)throw new IllegalArgumentException("Unresolved indirect target retained as frontier");
          var readInputs=new ArrayList<AbstractValues.Value>();
          for(var operand:op.getInputs())readInputs.add(memory!=null&&operand.isAddress()?readMemory(s,operand,source,index,memoryAccesses):s.storage.get(operand));
          var inputs=readInputs.stream().map(v->cyclic.isEmpty()||untransported(s,v)?v:PredicatedJoin.restrict(v,s.domain)).toList();
          if(code==PcodeOp.LOAD) {
            var delta=s.affine.get(slot(op.getInput(1)));
            if(delta==null||op.getOutput().getSize()!=1||!ins.getMnemonicString().equals("RET"))
              throw new IllegalArgumentException("Only justified ordinary frame reads in this graph slice");
            frameAddress(delta);var value=s.stack.get(delta);if(value==null)throw new IllegalArgumentException("Unresolved symbolic frame byte");
            s.storage.put(op.getOutput(),value);frameAccesses.add(new SoftwareCallEffects.RelativeAccess(index,delta,false,exact(value)));
          } else if(code==PcodeOp.STORE) {
            var delta=s.affine.get(slot(op.getInput(1)));var value=inputs.get(2);
            if(delta==null||op.getInput(2).getSize()!=1||!ins.getMnemonicString().equals("CALL"))
              throw new IllegalArgumentException("Unproved/non-CALL stack write");
            frameAddress(delta);s.stack.put(delta,value);frameAccesses.add(new SoftwareCallEffects.RelativeAccess(index,delta,true,exact(value)));
          } else if(code==PcodeOp.CALLOTHER) {
            if(!CartridgeBus.isDirectWrite(p.getLanguage(),op)||op.getNumInputs()!=3||!op.getInput(1).isConstant()||op.getInput(2).getSize()!=1)
              throw new IllegalArgumentException("Unsupported graph device effect");
            int cpu=(int)op.getInput(1).getOffset();var value=inputs.get(2);boolean mapper=cpu>=0x2000&&cpu<0x3000;
            if(!mapper&&memory==null&&!(cpu>=0xc000&&cpu<0xc080))throw new IllegalArgumentException("Output intersects frame/device domain");
            if(untransported(s,value))throw new IllegalArgumentException("Native byte-A call contract cannot carry live returned flags into an effect");
            Integer known=exact(value);if(mapper&&known==null)throw new IllegalArgumentException("Mapper selection is not predicate-exact");
            var access=ScalarAccess.resolve(cartridge,s.mapper,new ScalarAccess.Request(cpu,ScalarAccess.Kind.WRITE,1,0,source,index,2,known));
            s.mapper=access.after().orElseThrow();if(!mapper&&memory!=null)s.memory.write(p,s.mapper,cpu,value,source,index,false,memoryAccesses);effects.add(new Effect(index,cpu,value.origin(),mapper));
          } else if(op.getOutput()!=null) {
            if(memory==null&&(op.getOutput().isAddress()||Arrays.stream(op.getInputs()).anyMatch(Varnode::isAddress)))
              throw new IllegalArgumentException("Unmodeled direct memory operation");
            Integer affine=affine(s,op,inputs);
            if(op.getOutput().isRegister()&&op.getOutput().getOffset()==sp.getOffset()&&affine==null)
              throw new IllegalArgumentException("Non-affine SP change");
            var computed=AbstractValues.evaluate(code,op.getOutput().getSize(),inputs,source+":"+index);
            if(memory!=null&&op.getOutput().isAddress())s.memory.write(p,s.mapper,memoryCpu(op.getOutput()),computed,source,index,false,memoryAccesses);
            s.storage.put(op.getOutput(),cyclic.isEmpty()||untransported(s,computed)?computed:PredicatedJoin.fold(computed));
            var outputSlot=slot(op.getOutput());s.affine.keySet().removeIf(k->k.overlaps(outputSlot));
            if(affine!=null)s.affine.put(outputSlot,affine);
          } else throw new IllegalArgumentException("Unmodeled operation "+op.getMnemonic());
        }
        if(transfer.equals("NEXT")) {
          if(ins.getDefaultFallThrough()==null)throw new IllegalArgumentException("Missing architectural successor");
          var next=s.copy();next.cpu=(s.cpu+ins.getLength())&65535;edges.add(new Edge("NEXT",visit(next,new HashSet<>(path)),s.predicate));
        }
        var made=new Node(id,incoming.invocation,incoming.cpu,source,HexFormat.of().formatHex(ins.getBytes()),fetch,
            Arrays.stream(raw).map(Object::toString).toList(),incoming.predicate,beforeMapper,s.mapper,before,bindings(s.storage),beforeSp,sp(s),
            incoming.unavailableFlags,frameBefore,frameAccesses,effects,transfer,transferOperation,edges,callee,memoryAccesses);
        if(!cyclic.isEmpty()) {
          var beforeNode=nodes.get(id);var combined=new ArrayList<Edge>(edges);
          if(beforeNode!=null) {
            if(!beforeNode.outgoing().equals(made.outgoing())||!Objects.equals(beforeNode.callee(),made.callee()))
              throw new IllegalArgumentException("Join needs runtime-qualified mapper/call successor dispatch");
            for(var edge:beforeNode.edges())if(!combined.contains(edge))combined.add(edge);
          }
          combined.sort(Comparator.comparing(Edge::kind).thenComparing(e->Objects.toString(e.target(),"")));
          made=replace(made,combined);
          rows.put(activeRow,new JoinRow(activeRow,id,domain(incoming.domain),intern(before),intern(bindings(s.storage)),effects.stream().map(e->new JoinedEffect(e.operation(),e.cpu(),origin(e.value()),e.mapperControl())).toList(),successors));
        }
        nodes.put(id,made);
        return id;
      } catch(IllegalArgumentException failure) {
        if(cyclic.isEmpty())frontier.add(new Frontier(id,s.cpu,s.invocation,source+": "+failure.getMessage(),-1,List.of(),id,sp(s),s.frames,memoryAccesses));
        else frontier(incoming,activeRow,id,source+": "+failure.getMessage());return null;
      }
    }
    int memoryCpu(Varnode value) {
      if((!value.getAddress().getAddressSpace().equals(p.getAddressFactory().getDefaultAddressSpace())&&!value.getAddress().getAddressSpace().equals(root.getEntryPoint().getAddressSpace()))||value.getSize()!=1)
        throw new IllegalArgumentException("Unsupported actual memory space/width");
      return (int)value.getOffset();
    }
    AbstractValues.Value readMemory(State state,Varnode value,String source,int operation,List<SymbolicMemory.Access> accesses) throws Exception {
      return state.memory.read(p,state.mapper,memoryCpu(value),source,operation,accesses);
    }
    void frameAddress(int delta) {
      if(executionDomain.stackMin()+delta<(memory==null?0xc080:0xc800)||executionDomain.stackMax()+delta>0xcffd)
        throw new IllegalArgumentException("Frame access escapes disjoint fixed WRAM domain");
    }
    Integer affine(State s,PcodeOp op,List<AbstractValues.Value> inputs) {
      if(op.getOutput().getSize()!=2)return null;
      if(op.getOpcode()==PcodeOp.COPY)return s.affine.get(slot(op.getInput(0)));
      if(op.getNumInputs()!=2)return null;
      Integer a=s.affine.get(slot(op.getInput(0))),b=s.affine.get(slot(op.getInput(1)));
      Integer av=exact(inputs.get(0)),bv=exact(inputs.get(1));
      if(op.getOpcode()==PcodeOp.INT_SUB&&a!=null&&bv!=null)return a-bv;
      if(op.getOpcode()==PcodeOp.INT_ADD) {if(a!=null&&bv!=null)return a+bv;if(b!=null&&av!=null)return b+av;}
      return null;
    }
    boolean coverage() throws Exception {
      if(!frontier.isEmpty()||exits.isEmpty()||(!cyclic.isEmpty()&&!postFixedPoint))return false;
      for(var node:nodes.values())for(String kind:node.edges().stream().map(Edge::kind).distinct().toList()) {
        if(node.edges().stream().filter(e->e.kind().equals(kind)).map(Edge::target).distinct().count()>1) {
          frontier.add(new Frontier(node.id(),node.cpu(),node.invocation(),"Joined edge needs explicit runtime successor selection: "+kind));return false;
        }
      }
      for(var invocation:invocations.values()) {
        var ordered=new ArrayList<Instruction>();var seen=new HashSet<String>();String cursor=invocation.entry;
        while(cursor!=null&&seen.add(cursor)) {
          var step=nodes.get(cursor);if(step==null)break;
          ordered.add(SoftwareCallInstructionDiscovery.instructionAt(p,ProgramMapping.staticAddress(p,step.source()),"native result liveness",monitor));
          cursor=step.edges().stream().filter(e->e.kind().equals("NEXT")).map(Edge::target).findFirst().orElse(null);
        }
        invocation.inputBytes=List.copyOf(SoftwareCallEffects.ordinaryResultInputs(p,ordered,"A"));
        if(invocation.inputBytes.stream().anyMatch(offset->offset<1||offset>7)) {
          frontier.add(new Frontier(invocation.callNode,invocation.returnCpu,"root","Native result needs unsupported flag/PC/SP input transport"));return false;
        }
        boolean wroteA=false;
        for(var node:nodes.values()) if(node.invocation().equals(invocation.id)) {
          if(node.callee()!=null||!node.effects().isEmpty()||rows.values().stream().anyMatch(row->row.node().equals(node.id())&&!row.effects().isEmpty())) {frontier.add(new Frontier(node.id(),node.cpu(),node.invocation(),"Callee contract contains nested call/data effect"));return false;}
          var ins=SoftwareCallInstructionDiscovery.instructionAt(p,ProgramMapping.staticAddress(p,node.source()),"validated ordinary callee effect contract",monitor);
          for(var op:ins.getPcode(false)) if(op.getOutput()!=null&&op.getOutput().isRegister()) {
            for(int byteIndex=0;byteIndex<op.getOutput().getSize();byteIndex++) {
              long offset=op.getOutput().getOffset()+byteIndex;boolean allowed=false;
              for(String name:List.of("A","F","PC","SP")) {var reg=p.getRegister(name);if(offset>=reg.getAddress().getOffset()&&offset<reg.getAddress().getOffset()+reg.getMinimumByteSize())allowed=true;}
              if(!allowed){frontier.add(new Frontier(node.id(),node.cpu(),node.invocation(),"Callee changes register outside validated byte-A call contract"));return false;}
              if(offset==p.getRegister("A").getAddress().getOffset())wroteA=true;
            }
          }
        }
        invocation.byteAContract=wroteA&&invocation.returnNode!=null;
        if(!invocation.byteAContract)return false;
      }
      var origins=exits.stream().flatMap(c->c.terms().stream()).map(AbstractValues.Term::origin).distinct().toList();
      var relation=AbstractValues.relation(origins);
      if(!relation.complete()){frontier.add(new Frontier("coverage",(int)root.getEntryPoint().getOffset(),"root",relation.reason()));return false;}
      for(var tuple:relation.reachable()) {
        boolean covered=exits.stream().anyMatch(c->c.terms().stream().allMatch(t->tuple.values().get(origins.indexOf(t.origin()))==t.value()));
        if(!covered){frontier.add(new Frontier("coverage",(int)root.getEntryPoint().getOffset(),"root","Uncovered feasible input predicate"));return false;}
      }
      return true;
    }
  }
}
