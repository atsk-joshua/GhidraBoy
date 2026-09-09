// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import java.nio.file.*;
import java.util.*;

/** Same physical configured RST, two simultaneous exact domains, ordinary production state-entry requests. */
public class GhidraBoyW3bDomains extends GhidraBoyPredicatedCalls {
  void domainStage(String label,List<SoftwareCallDomains.View> views,DecompInterface owner)throws Exception {
    var proof=SoftwareCallDomains.proof(currentProgram);save(label+"-proof.json",proof);
    Files.writeString(out.resolve(label+"-registration.json"),currentProgram.getOptions(SoftwareCallDomains.OPTIONS).getString("registration",null));
    var raw=new TreeMap<String,Object>();
    for(var domain:proof.domains()) {
      var addresses=new TreeSet<String>();addresses.add(domain.physicalSite());
      for(var node:domain.callee().steps())addresses.add(node.address());for(var node:domain.continuation().steps())addresses.add(node.address());
      for(int offset=0;offset<domain.configuration().template().bodyHex().length()/2;) {
        var instruction=getInstructionAt(toAddr(domain.configuration().template().helperCpu()+offset));if(instruction==null)throw new IllegalStateException("Missing configured helper instruction");addresses.add(instruction.getAddress().toString());offset+=instruction.getLength();
      }
      for(String address:addresses)if(!raw.containsKey(address)) {
        var ins=getInstructionAt(currentProgram.getAddressFactory().getAddress(address));ids.clear();
        raw.put(address,Map.of("address",address,"bytes",HexFormat.of().formatHex(ins.getBytes()),"physical",ProgramMapping.staticToPhysical(currentProgram,ins.getAddress()),"ops",Arrays.stream(ins.getPcode(false)).map(this::operation).toList()));
      }
    }
    save(label+"-raw.json",raw);var mapping=new ArrayList<Object>();
    for(var view:views) {
      var at=currentProgram.getAddressFactory().getAddress(view.entry());String tag=view.domain().substring(0,12)+"-"+view.kind();mapping.add(Map.of("tag",tag,"view",view));
      var payload=currentProgram.getCompilerSpec().getPcodeInjectLibrary().getPayload(InjectPayload.CALLMECHANISM_TYPE,SoftwareCallStateEntryInjection.NAME);
      var context=new InjectContext();context.baseAddr=at;context.nextAddr=at;ids.clear();save(label+"-"+tag+"-requested.json",Arrays.stream(payload.getPcode(currentProgram,context)).map(this::operation).toList());
      request(getFunctionAt(at),owner,label+"-"+tag);
    }
    save(label+"-views.json",mapping);save(label+"-identity.json",Map.of("programId",currentProgram.getUniqueProgramID(),"javaPid",ProcessHandle.current().pid(),"provider",SoftwareCallDomains.class.getProtectionDomain().getCodeSource().getLocation().toString(),"functions",views.stream().map(v->Map.of("entry",v.entry(),"id",getFunctionAt(currentProgram.getAddressFactory().getAddress(v.entry())).getID())).toList()));
  }
  @Override public void run()throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    var helper=new SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP,0x28,0,null);
    var configurations=List.of(0,0x80).stream().map(flags->new SoftwareCallValidation.Configuration(0x200,helper,SoftwareCallModel.EntryTransfer.HARDWARE_RST,0xc100,new SoftwareCallModel.Registers(2,flags,0,0,0x4100),MapperState.reset())).toList();
    var proof=SoftwareCallDomains.preview(currentProgram,configurations,monitor);save("producer-preview.json",proof);var views=SoftwareCallDomains.install(currentProgram,proof,monitor);var owner=owner();
    try {
      SoftwareCallDomains.selectDisplay(currentProgram,proof.domains().getFirst().id());domainStage("forward",views,owner);
      SoftwareCallDomains.selectDisplay(currentProgram,proof.domains().getLast().id());var reversed=new ArrayList<>(views);Collections.reverse(reversed);domainStage("reverse",reversed,owner);
      Files.write(out.resolve("original-image.gb"),ProgramMapping.exportBytes(currentProgram,true,false,monitor));
      var root=views.stream().filter(v->v.kind().equals("root")&&v.domain().equals(proof.domains().getFirst().id())).findFirst().orElseThrow();
      boolean wrong=false;String wrongReason="";try{SoftwareCallDomains.emit(currentProgram,currentProgram.getAddressFactory().getAddress(root.entry()),proof.domains().getLast(),0x200000,monitor);}catch(IllegalArgumentException failure){wrong=true;wrongReason=failure.getMessage();}
      if(!wrong)throw new IllegalStateException("Site-only cache consumed a foreign domain");save("site-only-negative.json",Map.of("rejected",wrong,"reason",wrongReason));
      var mutation=currentProgram.getAddressFactory().getAddress("rom3::4201");var instructions=new ArrayList<ghidra.program.model.listing.Instruction>();
      for(var ins:currentProgram.getListing().getInstructions(true))if(ins.getAddress().getOffset()==0x4200&&ProgramMapping.staticToPhysical(currentProgram,ins.getAddress()).stream().anyMatch(ph->ph.bank()==3))instructions.add(ins);
      for(var ins:instructions)currentProgram.getListing().clearCodeUnits(ins.getMinAddress(),ins.getMaxAddress(),false);currentProgram.getMemory().setByte(mutation,(byte)0x44);
      var refusals=new ArrayList<Object>();for(var view:views)if(view.kind().equals("root")) {
        var at=currentProgram.getAddressFactory().getAddress(view.entry());String reason="";try{SoftwareCallDomains.emit(currentProgram,at,0x200000,monitor);}catch(IllegalArgumentException failure){reason=failure.getMessage();}
        if(!reason.contains("Stale"))throw new IllegalStateException("Stale domain accepted");refusals.add(Map.of("domain",view.domain(),"reason",reason));request(getFunctionAt(at),owner,"stale-"+view.domain().substring(0,12));
      }
      save("stale-domains.json",refusals);
    }finally{owner.dispose();}
    println("W3B_CAPTURE_COMPLETE setup");
  }
}
