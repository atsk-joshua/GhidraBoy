package fi.gekkio.ghidraboy;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.disassemble.Disassembler;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Experimental explicit RAM establishment. History, current lifetime and proof freshness are separate. */
public final class ExecutableImages {
  private ExecutableImages() {}
  public static final String OPTIONS="GhidraBoyExecutableImages", VERSION="executable-images-1";
  public record Initializer(String source,List<MapperState.Physical> physical,String bytes,String sha256,String declaration) {
    public Initializer {physical=List.copyOf(physical);}
  }
  public record Image(String generation,long programId,int cpu,int length,MapperState.Physical physical,
      Initializer initializer,String bytes,String entry,long functionId) {}
  private record Envelope(String version,long programId,long sequence,List<Image> history,Map<String,String> current) {
    Envelope {history=List.copyOf(history);current=Map.copyOf(current);}
  }
  private static void require(boolean ok,String reason){if(!ok)throw new IllegalArgumentException(reason);}
  private static Envelope read(Program p) {
    if(!p.getOptionsNames().contains(OPTIONS)||!p.getOptions(OPTIONS).contains("authority"))return new Envelope(VERSION,p.getUniqueProgramID(),0,List.of(),Map.of());
    String saved=p.getOptions(OPTIONS).getString("authority",null);
    // Ghidra may register a queried null default without a persisted authority value.
    if(saved==null)return new Envelope(VERSION,p.getUniqueProgramID(),0,List.of(),Map.of());
    var json=com.google.gson.JsonParser.parseString(saved).getAsJsonObject();
    require(json.has("version")&&VERSION.equals(json.get("version").getAsString()),"Unsupported executable image version; history retained");
    var e=ProgramMapping.JSON.fromJson(json,Envelope.class);require(e.programId()==p.getUniqueProgramID(),"Foreign image Program authority");return e;
  }
  private static String key(MapperState.Physical physical,int length){return physical+":"+length;}
  public static List<Image> history(Program p){return read(p).history();}
  public static String serialized(Program p){return p.getOptions(OPTIONS).getString("authority",null);}
  public static Image resolve(Program p,String generation) throws Exception {
    require(generation!=null&&!generation.isBlank(),"Explicit executable generation required; address-only lookup refused");
    var e=read(p);var image=e.history().stream().filter(i->generation.equals(i.generation())).findFirst().orElseThrow(()->new IllegalArgumentException("Unknown executable generation"));
    require(generation.equals(e.current().get(key(image.physical(),image.length()))),"Noncurrent executable generation "+generation);
    require(image.programId()==p.getUniqueProgramID()&&image.physical().equals(SymbolicMemory.physical(p,MapperKnowledge.unknown(),image.cpu(),ScalarAccess.Kind.FETCH)),"Foreign executable image/physical identity");
    require(image.length()>0&&image.length()<=256&&image.bytes().length()==image.length()*2&&image.bytes().equals(image.initializer().bytes())&&Sha256.of(HexFormat.of().parseHex(image.bytes())).toString().equals(image.initializer().sha256()),"Malformed image/initializer snapshot");
    for(int i=0;i<image.length();i++) {
      var at=SymbolicMemory.address(p,MapperKnowledge.unknown(),image.cpu()+i,ScalarAccess.Kind.FETCH);
      require((p.getMemory().getByte(at)&255)==Integer.parseInt(image.bytes().substring(i*2,i*2+2),16),"Established RAM bytes replaced; explicit establishment required");
    }
    var entry=ProgramMapping.staticAddress(p,image.entry());var f=p.getFunctionManager().getFunctionAt(entry);
    require(f!=null&&f.getID()==image.functionId(),"Changed image Function ownership");
    var block=p.getMemory().getBlock(entry);var source=SymbolicMemory.address(p,MapperKnowledge.unknown(),image.cpu(),ScalarAccess.Kind.FETCH);
    require(block!=null&&!block.isMapped()&&block.isInitialized()&&block.isRead()&&!block.isWrite()&&block.isExecute()&&!block.isVolatile()
        &&block.getSize()==image.length()&&block.getStart().equals(entry),"Changed generation view binding");
    byte[] snapshot=new byte[image.length()];p.getMemory().getBytes(entry,snapshot);
    require(HexFormat.of().formatHex(snapshot).equals(image.bytes()),"Changed generation snapshot");
    require(f.getBody().equals(new AddressSet(entry,entry.add(image.length()-1))),"Changed generation Function body");
    return image;
  }
  /** The caller supplies a reviewed current-ROM snapshot. This operation declares a new lifetime even for identical bytes. */
  public static Image establish(Program p,Address source,int cpu,byte[] snapshot,String declaration,TaskMonitor monitor) throws Exception {
    require(snapshot!=null&&snapshot.length>0&&snapshot.length<=256&&declaration!=null&&!declaration.isBlank(),"Invalid bounded initializer declaration");
    long revision=p.getModificationNumber();
    byte[] expected=snapshot.clone();var sources=new ArrayList<MapperState.Physical>();
    for(int i=0;i<expected.length;i++) {
      monitor.checkCancelled();var at=source.addNoWrap(i);var block=p.getMemory().getBlock(at);var physical=ProgramMapping.staticToPhysical(p,at);
      require(block!=null&&block.isInitialized()&&block.isRead()&&!block.isWrite()&&!block.isVolatile()&&physical.size()==1&&physical.get(0).region().equals("ROM"),"Initializer must be established immutable ROM snapshot");
      require(p.getMemory().getByte(at)==expected[i],"Initializer snapshot changed");sources.add(physical.get(0));
      var destination=SymbolicMemory.address(p,MapperKnowledge.unknown(),cpu+i,ScalarAccess.Kind.WRITE);
      require(p.getListing().getInstructionContaining(destination)==null&&p.getListing().getDefinedDataContaining(destination)==null
          &&p.getFunctionManager().getFunctionContaining(destination)==null,"Image establishment conflicts with canonical code/data ownership");
      for(var symbol:p.getSymbolTable().getSymbols(destination))require(symbol.isDynamic(),"Image establishment conflicts with named canonical byte");
    }
    var before=read(p);var physical=SymbolicMemory.physical(p,MapperKnowledge.unknown(),cpu,ScalarAccess.Kind.WRITE);
    for(var old:before.history())if(old.physical().bank()==physical.bank()&&old.physical().region().equals(physical.region())
        &&physical.offset()<old.physical().offset()+old.length()&&old.physical().offset()<physical.offset()+expected.length)
      require(old.cpu()==cpu&&old.length()==expected.length,"Overlapping image range changes require separate ownership review");
    long sequence=Math.addExact(before.sequence(),1);String generation=p.getUniqueProgramID()+":"+sequence;
    String name=OrdinaryEntryAccess.PREFIX+"image_"+Long.toUnsignedString(p.getUniqueProgramID(),16)+"_"+sequence;
    int tx=p.startTransaction("Explicit executable RAM image establishment");boolean success=false;
    try {
      require(revision==p.getModificationNumber(),"Program changed during image establishment review");
      var destination=SymbolicMemory.address(p,MapperKnowledge.unknown(),cpu,ScalarAccess.Kind.WRITE);
      p.getMemory().setBytes(destination,expected);monitor.checkCancelled();
      var made=SoftwareCallExecutionView.createImage(p,name,cpu,expected.length,monitor);
      var entry=made.body().getMinAddress();
      Disassembler.getDisassembler(p,monitor,null).disassemble(entry,made.body(),false);
      var function=p.getFunctionManager().createFunction(name,entry,made.body(),SourceType.ANALYSIS);
      require(function!=null,"Image Function creation failed");function.setCallingConvention(SoftwareCallStateEntryInjection.CONVENTION);
      function.setComment(VERSION+" generation "+generation+"; explicit initializer: "+declaration);
      var receipt=new Initializer(source.toString(),sources,HexFormat.of().formatHex(expected),Sha256.of(expected).toString(),declaration);
      var image=new Image(generation,p.getUniqueProgramID(),cpu,expected.length,physical,receipt,receipt.bytes(),entry.toString(),function.getID());
      var history=new ArrayList<>(before.history());history.add(image);var current=new TreeMap<>(before.current());current.put(key(physical,expected.length),generation);
      p.getOptions(OPTIONS).setString("authority",ProgramMapping.JSON.toJson(new Envelope(VERSION,p.getUniqueProgramID(),sequence,history,current)));
      monitor.checkCancelled();resolve(p,generation);success=true;return image;
    } finally {p.endTransaction(tx,success);}
  }
  static void validateFetch(Program p,String generation,SymbolicMemory.State memory,int cpu,int length) throws Exception {
    var image=resolve(p,generation);
    require(cpu>=image.cpu()&&cpu+(long)length<=image.cpu()+image.length(),"FETCH outside established generation");
    for(int i=0;i<length;i++) {
      var physical=SymbolicMemory.physical(p,MapperKnowledge.unknown(),cpu+i,ScalarAccess.Kind.FETCH);
      require(memory==null||!memory.killed.contains(physical),"Insufficient executable-byte knowledge after physical write at "+physical);
    }
  }
  static List<BankAnalysis.FetchByte> fetch(Program p,String generation,SymbolicMemory.State memory,ghidra.program.model.listing.Instruction ins) throws Exception {
    int cpu=(int)ins.getAddress().getOffset();validateFetch(p,generation,memory,cpu,ins.getLength());var image=resolve(p,generation);
    require(ins.getAddress().getAddressSpace().equals(ProgramMapping.staticAddress(p,image.entry()).getAddressSpace()),"Wrong generation instruction view");
    var bytes=ins.getBytes();var result=new ArrayList<BankAnalysis.FetchByte>();
    for(int i=0;i<bytes.length;i++) {
      var at=ins.getAddress().add(i);int expected=Integer.parseInt(image.bytes().substring((cpu-image.cpu()+i)*2,(cpu-image.cpu()+i+1)*2),16);
      require((bytes[i]&255)==expected,"Stale decoded image bytes");var physical=SymbolicMemory.physical(p,MapperKnowledge.unknown(),cpu+i,ScalarAccess.Kind.FETCH);
      var backing=SymbolicMemory.address(p,MapperKnowledge.unknown(),cpu+i,ScalarAccess.Kind.FETCH);result.add(new BankAnalysis.FetchByte(cpu+i,backing.toString(),physical,expected));
    }
    return result;
  }
}
