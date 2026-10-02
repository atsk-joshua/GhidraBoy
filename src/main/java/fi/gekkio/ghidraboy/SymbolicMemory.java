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
    // Ordinary analysis has no declared entry inputs. Reuse the physical fact store, but
    // accept only exact path-written bytes; loader bytes and W4 symbolic inputs are absent.
    Map<MapperState.Physical,AbstractValues.Value> snapshot(){return Map.copyOf(facts);}
    /** Must-knowledge meet: absent or disagreeing bytes are unknown, never alternatives. */
    static Map<MapperState.Physical,AbstractValues.Value> joinOrdinary(
        Map<MapperState.Physical,AbstractValues.Value> left,
        Map<MapperState.Physical,AbstractValues.Value> right) {
      if(left.equals(right))return left;
      var common=new HashMap<MapperState.Physical,AbstractValues.Value>();
      for(var entry:left.entrySet()) {
        var other=right.get(entry.getKey());var value=entry.getValue();
        if(other!=null&&value.width()==1&&other.width()==1
            &&value.domain() instanceof AbstractValues.Exact a
            &&other.domain() instanceof AbstractValues.Exact b&&a.value()==b.value())
          common.put(entry.getKey(),value);
      }
      return common.size()==left.size()?left:Map.copyOf(common);
    }
    static State ordinary(Map<MapperState.Physical,AbstractValues.Value> snapshot){
      var state=new State("ordinary-bank-analysis");state.facts.putAll(snapshot);return state;
    }
    static boolean ordinaryRegion(MapperState.Physical physical){
      return physical!=null&&(physical.region().equals("WRAM")||physical.region().equals("HRAM"));
    }
    static boolean ordinaryBacking(Program p,MapperState.Physical physical) throws Exception {
      if(!ordinaryRegion(physical))return false;
      for(var at:ProgramMapping.physicalToStatic(p,physical)) {
        var block=p.getMemory().getBlock(at);
        if(block!=null&&!block.isMapped()&&block.isRead()&&block.isWrite()&&!block.isVolatile()
            &&block.getSourceInfos().stream().noneMatch(i->i.getFileBytes().isPresent())
            &&ProgramMapping.staticToPhysical(p,at).equals(List.of(physical)))return true;
      }
      return false;
    }
    Long ordinaryRead(Program p,Cartridge cartridge,MapperKnowledge mapper,Long pointer,int width) throws Exception {
      if(pointer==null||width<1||width>Long.BYTES)return null;
      long result=0;
      for(int i=0;i<width;i++) {
        var request=new ScalarAccess.Request((int)((pointer+i)&65535),ScalarAccess.Kind.READ,width,i,null,-1,-1,null);
        var physical=ScalarAccess.resolve(cartridge,mapper,request).resolution().orElseThrow().physical();
        if(!ordinaryBacking(p,physical))return null;
        var value=facts.get(physical);
        if(value==null||!(value.domain() instanceof AbstractValues.Exact exact))return null;
        result|=exact.value()<<(i*8);
      }
      return result;
    }
    void ordinaryWrite(Program p,ScalarAccess.Outcome outcome,boolean mapperControl) throws Exception {
      var resolution=outcome.resolution().orElseThrow();var physical=resolution.physical();
      if(ordinaryRegion(physical)) {
        // Remove by physical key even when the current backing is ineligible.
        facts.remove(physical);
        var value=outcome.request().writtenValue();
        if(value!=null&&ordinaryBacking(p,physical))facts.put(physical,AbstractValues.constant(value,1));
      } else if(!mapperControl&&!deviceWriteWithoutOrdinaryRamInterference(p,outcome)
          &&(physical==null||resolution.status().equals("device"))) {
        // An unresolved destination/device effect is not established disjoint from RAM.
        facts.clear();
      }
    }
    private static boolean deviceWriteWithoutOrdinaryRamInterference(Program p,ScalarAccess.Outcome outcome) {
      // Exact qualified local writes preserve only WRAM/HRAM contents in the
      // incumbent synchronous domain. No device state/value or timing is modeled.
      var cartridge=ProgramMapping.cartridge(p);
      return cartridge!=null&&cartridge.hardwareKnown()
          &&outcome.request().kind()==ScalarAccess.Kind.WRITE
          &&outcome.request().cpu()!=null
          &&switch(outcome.request().cpu()) {
            case 0xff26,0xff40,0xff42,0xff43,0xff4a,0xff4b -> true;
            default -> false;
          }
          &&outcome.resolution().orElseThrow().status().equals("device");
    }
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
