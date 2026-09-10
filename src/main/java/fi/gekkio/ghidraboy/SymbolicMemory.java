package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.*;

/** Checked entry-memory premises and path-local physical effects. Never reads loader fill as a fact. */
public final class SymbolicMemory {
  private SymbolicMemory() {}
  public record Input(int cpu, MapperState.Physical physical, String storage, int width) {}
  public record MayWrite(int beforeCpu, int cpu, String reason) {}
  public record Declaration(long programId, List<Input> inputs, List<MayWrite> mayWrites, String image, String imageAuthority) {
    public Declaration { inputs=List.copyOf(inputs);mayWrites=List.copyOf(mayWrites); }
  }
  public record Access(String kind,int cpu,MapperState.Physical physical,String storage,int operation,
      AbstractValues.Origin value,String reason) {}
  public record Fact(MapperState.Physical physical,AbstractValues.Origin value) {}
  public static Declaration declare(Program p,List<Integer> inputs,List<MayWrite> mayWrites,String image) throws Exception {
    if(inputs.size()>64||mayWrites.size()>16||new HashSet<>(inputs).size()!=inputs.size())
      throw new IllegalArgumentException("Memory declaration budget/duplicate input");
    var bindings=new ArrayList<Input>();
    for(int cpu:inputs) {var at=address(p,MapperKnowledge.unknown(),cpu,ScalarAccess.Kind.READ);bindings.add(new Input(cpu,physical(p,MapperKnowledge.unknown(),cpu,ScalarAccess.Kind.READ),at.toString(),1));}
    for(var write:mayWrites) {
      if(write.beforeCpu()<0||write.beforeCpu()>65535||write.reason()==null||write.reason().isBlank())throw new IllegalArgumentException("Unqualified may-write");
      address(p,MapperKnowledge.unknown(),write.cpu(),ScalarAccess.Kind.WRITE);
    }
    return new Declaration(p.getUniqueProgramID(),bindings,mayWrites,image,image==null?null:PredicatedCallGraph.hash(ExecutableImages.resolve(p,image)));
  }
  static void validate(Program p,Declaration d) throws Exception {
    if(d==null)return;
    if(d.image()!=null)ExecutableImages.resolve(p,d.image());
    if(d.programId()!=p.getUniqueProgramID()||!d.equals(declare(p,d.inputs().stream().map(Input::cpu).toList(),d.mayWrites(),d.image())))
      throw new IllegalArgumentException("Changed/foreign symbolic memory declaration");
  }
  static MapperState.Physical physical(Program p,MapperKnowledge mapper,int cpu,ScalarAccess.Kind kind) {
    var result=ScalarAccess.resolve(ProgramMapping.cartridge(p),mapper,new ScalarAccess.Request(cpu,kind,1,0,"physical memory authority",-1,-1,null));
    var physical=result.resolution().orElseThrow().physical();
    if(physical==null||!physical.region().equals("WRAM")||physical.bank()!=0||physical.offset()<0||physical.offset()>=0x800)
      throw new IllegalArgumentException("Memory cell outside fixed WRAM/disjoint frame domain");
    return physical;
  }
  static Address address(Program p,MapperKnowledge mapper,int cpu,ScalarAccess.Kind kind) throws Exception {
    var physical=physical(p,mapper,cpu,kind);
    var at=p.getAddressFactory().getDefaultAddressSpace().getAddress(0xc000+physical.offset());
    var block=p.getMemory().getBlock(at);
    if(block==null||block.isMapped()||!block.isInitialized()||!block.isRead()||!block.isWrite()||block.isVolatile()
        ||block.getSourceInfos().stream().anyMatch(i->i.getFileBytes().isPresent())
        ||!ProgramMapping.staticToPhysical(p,at).equals(List.of(physical)))
      throw new IllegalArgumentException("Missing canonical mutable physical RAM binding");
    return at;
  }
  static final class State {
    final String scope;
    final Map<MapperState.Physical,AbstractValues.Value> facts=new HashMap<>();
    final Set<MapperState.Physical> killed=new HashSet<>();
    State(String scope){this.scope=scope;}
    State copy(){var s=new State(scope);s.facts.putAll(facts);s.killed.addAll(killed);return s;}
    List<Fact> identity(){return facts.entrySet().stream().sorted(Comparator.comparing(e->e.getKey().toString())).map(e->new Fact(e.getKey(),e.getValue().origin())).toList();}
    AbstractValues.Value read(Program p,MapperKnowledge mapper,int cpu,String source,int operation,List<Access> accesses) throws Exception {
      var at=address(p,mapper,cpu,ScalarAccess.Kind.READ);var physical=physical(p,mapper,cpu,ScalarAccess.Kind.READ);
      var value=facts.get(physical);
      if(value==null)throw new IllegalArgumentException("Undeclared unknown memory input at "+at);
      accesses.add(new Access("READ",cpu,physical,at.toString(),operation,value.origin(),source));return value;
    }
    void write(Program p,MapperKnowledge mapper,int cpu,AbstractValues.Value value,String source,int operation,boolean may,List<Access> accesses) throws Exception {
      var at=address(p,mapper,cpu,ScalarAccess.Kind.WRITE);var physical=physical(p,mapper,cpu,ScalarAccess.Kind.WRITE);
      if(value.width()!=1)throw new IllegalArgumentException("Memory effect requires byte width");
      if(may)value=AbstractValues.input(scope,"memory-after-may-write:"+source+":"+operation+":"+physical,0,1);
      facts.put(physical,value);killed.add(physical);
      accesses.add(new Access(may?"MAY_WRITE":"WRITE",cpu,physical,at.toString(),operation,value.origin(),source));
    }
  }
  static State initial(Program p,Declaration declaration,String scope) throws Exception {
    validate(p,declaration);var state=new State(scope);
    if(declaration!=null)for(var input:declaration.inputs())state.facts.put(input.physical(),AbstractValues.input(scope,"entry-memory:"+input.physical()+":"+input.storage(),0,1));
    return state;
  }
}
