package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.*;

/** Checked entry-memory premises and path-local physical effects. Never reads loader fill as a fact. */
public final class SymbolicMemory {
  private SymbolicMemory() {}
  public record Input(int cpu, MapperState.Physical physical, String storage, int width) {}
  public record MayWrite(int beforeCpu, int cpu, String reason) {}
  public record Footprint(int stackMin,int stackMax,int minDelta,int maxDelta) {
    public Footprint {if(stackMin<0xc000||stackMax>0xcfff||stackMin>stackMax||minDelta< -256||minDelta>0||maxDelta>255||maxDelta< -1||minDelta>maxDelta||stackMin+minDelta<0xc000||stackMax+maxDelta>0xcfff)throw new IllegalArgumentException("Invalid nonempty affine WRAM0 footprint");}
  }
  public record Declaration(long programId, List<Input> inputs, List<MayWrite> mayWrites, String image, String imageAuthority, Integer entryHL, Footprint footprint) {
    public Declaration(long programId,List<Input> inputs,List<MayWrite> mayWrites,String image,String imageAuthority,Integer entryHL){this(programId,inputs,mayWrites,image,imageAuthority,entryHL,null);}
    public Declaration(long programId,List<Input> inputs,List<MayWrite> mayWrites,String image,String imageAuthority){this(programId,inputs,mayWrites,image,imageAuthority,null);}
    public Declaration { inputs=List.copyOf(inputs);mayWrites=List.copyOf(mayWrites); }
  }
  public record Access(String kind,int cpu,MapperState.Physical physical,String storage,int operation,
      AbstractValues.Origin value,String reason) {}
  public record Fact(MapperState.Physical physical,AbstractValues.Origin value) {}
  public static Declaration declare(Program p,List<Integer> inputs,List<MayWrite> mayWrites,String image) throws Exception {
    return declare(p,inputs,mayWrites,image,null);
  }
  public static Declaration declare(Program p,List<Integer> inputs,List<MayWrite> mayWrites,String image,Integer entryHL) throws Exception {
    return declare(p,inputs,mayWrites,image,entryHL,null);
  }
  public static Declaration declare(Program p,List<Integer> inputs,List<MayWrite> mayWrites,String image,Integer entryHL,Footprint footprint) throws Exception {
    if(entryHL!=null&&(entryHL<0||entryHL>65535||!inputs.contains(entryHL)))throw new IllegalArgumentException("Entry HL must point to a declared mutable input byte");
    if(inputs.size()>64||mayWrites.size()>16||new HashSet<>(inputs).size()!=inputs.size())
      throw new IllegalArgumentException("Memory declaration budget/duplicate input");
    var bindings=new ArrayList<Input>();
    for(int cpu:inputs) {var at=address(p,MapperKnowledge.unknown(),cpu,ScalarAccess.Kind.READ,footprint);bindings.add(new Input(cpu,physical(p,MapperKnowledge.unknown(),cpu,ScalarAccess.Kind.READ,footprint),at.toString(),1));}
    for(var write:mayWrites) {
      if(write.beforeCpu()<0||write.beforeCpu()>65535||write.reason()==null||write.reason().isBlank())throw new IllegalArgumentException("Unqualified may-write");
      address(p,MapperKnowledge.unknown(),write.cpu(),ScalarAccess.Kind.WRITE);
    }
    return new Declaration(p.getUniqueProgramID(),bindings,mayWrites,image,image==null?null:PredicatedCallGraph.hash(ExecutableImages.resolve(p,image)),entryHL,footprint);
  }
  static void validate(Program p,Declaration d) throws Exception {
    if(d==null)return;
    if(d.image()!=null)ExecutableImages.resolve(p,d.image());
    if(d.programId()!=p.getUniqueProgramID()||!d.equals(declare(p,d.inputs().stream().map(Input::cpu).toList(),d.mayWrites(),d.image(),d.entryHL(),d.footprint())))
      throw new IllegalArgumentException("Changed/foreign symbolic memory declaration");
  }
  static MapperState.Physical physical(Program p,MapperKnowledge mapper,int cpu,ScalarAccess.Kind kind) {
    return physical(p,mapper,cpu,kind,null);
  }
  static MapperState.Physical physical(Program p,MapperKnowledge mapper,int cpu,ScalarAccess.Kind kind,Footprint footprint) {
    var cartridge=ProgramMapping.cartridge(p);
    if(cartridge==null)throw new IllegalArgumentException("Explicit cartridge mapping authority required for symbolic memory; saved bytes alone do not establish it");
    var result=ScalarAccess.resolve(cartridge,mapper,new ScalarAccess.Request(cpu,kind,1,0,"physical memory authority",-1,-1,null));
    var physical=result.resolution().orElseThrow().physical();
    if(physical==null||physical.bank()!=0||physical.offset()<0||!(physical.region().equals("WRAM")&&physical.offset()<(footprint==null?0x800:0x1000)||physical.region().equals("HRAM")&&physical.offset()<0x7f))
      throw new IllegalArgumentException("Memory cell outside fixed WRAM/disjoint frame domain");
    if(footprint!=null&&physical.region().equals("WRAM")) {
      int at=0xc000+(int)physical.offset();
      if(at>=footprint.stackMin()+footprint.minDelta()&&at<=footprint.stackMax()+footprint.maxDelta())throw new IllegalArgumentException("Data aliases declared affine frame footprint");
    }
    return physical;
  }
  static Address address(Program p,MapperKnowledge mapper,int cpu,ScalarAccess.Kind kind) throws Exception {
    return address(p,mapper,cpu,kind,null);
  }
  static Address address(Program p,MapperKnowledge mapper,int cpu,ScalarAccess.Kind kind,Footprint footprint) throws Exception {
    var physical=physical(p,mapper,cpu,kind,footprint);
    var at=p.getAddressFactory().getDefaultAddressSpace().getAddress((physical.region().equals("HRAM")?0xff80:0xc000)+physical.offset());
    var block=p.getMemory().getBlock(at);
    if(block==null||block.isMapped()||(footprint==null&&!block.isInitialized())||!block.isRead()||!block.isWrite()||block.isVolatile()
        ||block.getSourceInfos().stream().anyMatch(i->i.getFileBytes().isPresent())
        ||!ProgramMapping.staticToPhysical(p,at).equals(List.of(physical)))
      throw new IllegalArgumentException("Missing canonical mutable physical RAM binding");
    return at;
  }
  static final class State {
    final String scope;
    Footprint footprint;
    final Map<MapperState.Physical,AbstractValues.Value> facts=new HashMap<>();
    final Set<MapperState.Physical> killed=new HashSet<>();
    State(String scope){this.scope=scope;}
    State copy(){var s=new State(scope);s.footprint=footprint;s.facts.putAll(facts);s.killed.addAll(killed);return s;}
    List<Fact> identity(){return facts.entrySet().stream().sorted(Comparator.comparing(e->e.getKey().toString())).map(e->new Fact(e.getKey(),e.getValue().origin())).toList();}
    AbstractValues.Value read(Program p,MapperKnowledge mapper,int cpu,String source,int operation,List<Access> accesses) throws Exception {
      var at=address(p,mapper,cpu,ScalarAccess.Kind.READ,footprint);var physical=physical(p,mapper,cpu,ScalarAccess.Kind.READ,footprint);
      var value=facts.get(physical);
      if(value==null)throw new IllegalArgumentException("Undeclared unknown memory input at "+at);
      accesses.add(new Access("READ",cpu,physical,at.toString(),operation,value.origin(),source));return value;
    }
    void write(Program p,MapperKnowledge mapper,int cpu,AbstractValues.Value value,String source,int operation,boolean may,List<Access> accesses) throws Exception {
      var at=address(p,mapper,cpu,ScalarAccess.Kind.WRITE,footprint);var physical=physical(p,mapper,cpu,ScalarAccess.Kind.WRITE,footprint);
      if(value.width()!=1)throw new IllegalArgumentException("Memory effect requires byte width");
      if(may)value=AbstractValues.input(scope,"memory-after-may-write:"+source+":"+operation+":"+physical,0,1);
      facts.put(physical,value);killed.add(physical);
      accesses.add(new Access(may?"MAY_WRITE":"WRITE",cpu,physical,at.toString(),operation,value.origin(),source));
    }
  }
  static State initial(Program p,Declaration declaration,String scope) throws Exception {
    validate(p,declaration);var state=new State(scope);state.footprint=declaration==null?null:declaration.footprint();
    if(declaration!=null)for(var input:declaration.inputs())state.facts.put(input.physical(),AbstractValues.input(scope,"entry-memory:"+input.physical()+":"+input.storage(),0,1));
    return state;
  }
}
