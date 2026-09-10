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
  boolean stock(){return Arrays.asList(getScriptArgs()).contains("stock");}
  String domainOptions(){return stock()?SoftwareCallDomains.STOCK_OPTIONS:SoftwareCallDomains.OPTIONS;}
  void domainStage(String label,List<SoftwareCallDomains.View> views,DecompInterface owner)throws Exception {
    var proof=SoftwareCallDomains.proof(currentProgram);save(label+"-proof.json",proof);
    Files.writeString(out.resolve(label+"-registration.json"),currentProgram.getOptions(domainOptions()).getString("registration",null));
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
      var payload=entryPayload(at);
      var context=new InjectContext();context.baseAddr=at;context.nextAddr=at;ids.clear();save(label+"-"+tag+"-requested.json",Arrays.stream(payload.getPcode(currentProgram,context)).map(this::operation).toList());
      request(getFunctionAt(at),owner,label+"-"+tag);
    }
    save(label+"-views.json",mapping);save(label+"-identity.json",Map.of("programId",currentProgram.getUniqueProgramID(),"javaPid",ProcessHandle.current().pid(),"provider",SoftwareCallDomains.class.getProtectionDomain().getCodeSource().getLocation().toString(),"functions",views.stream().map(v->Map.of("entry",v.entry(),"id",getFunctionAt(currentProgram.getAddressFactory().getAddress(v.entry())).getID())).toList()));
  }
  Object domainState()throws Exception {
    var capture=Class.forName("fi.gekkio.ghidraboy.FarCallEvidence").getDeclaredMethod("capture",ghidra.program.model.listing.Program.class,ghidra.util.task.TaskMonitor.class);
    capture.setAccessible(true);
    var state=new LinkedHashMap<String,Object>();state.put("programId",currentProgram.getUniqueProgramID());
    state.put("modification",currentProgram.getModificationNumber());state.put("dependencies",capture.invoke(null,currentProgram,monitor));
    state.put("instructions",currentProgram.getListing().getNumInstructions());state.put("functions",currentProgram.getFunctionManager().getFunctionCount());
    state.put("blocks",Arrays.stream(currentProgram.getMemory().getBlocks()).map(b->List.of(b.getName(),b.getStart().toString(),b.getEnd().toString(),b.getFlags())).toList());
    state.put("optionsNames",new TreeSet<>(currentProgram.getOptionsNames()));state.put("imageSha256",bytesHash(ProgramMapping.exportBytes(currentProgram,true,false,monitor)));
    return state;
  }
  void structuralDiff(String path,com.google.gson.JsonElement before,com.google.gson.JsonElement after,List<Object> differences) {
    if(Objects.equals(before,after))return;
    if(before!=null&&after!=null&&before.isJsonObject()&&after.isJsonObject()) {
      var keys=new TreeSet<String>();before.getAsJsonObject().keySet().forEach(keys::add);after.getAsJsonObject().keySet().forEach(keys::add);
      for(String key:keys)structuralDiff(path+"."+key,before.getAsJsonObject().get(key),after.getAsJsonObject().get(key),differences);
    }else if(before!=null&&after!=null&&before.isJsonArray()&&after.isJsonArray()) {
      var left=before.getAsJsonArray();var right=after.getAsJsonArray();
      for(int i=0;i<Math.max(left.size(),right.size());i++)structuralDiff(path+"["+i+"]",i<left.size()?left.get(i):null,i<right.size()?right.get(i):null,differences);
    }else {
      var difference=new LinkedHashMap<String,Object>();difference.put("field",path);difference.put("original",before);difference.put("rederived",after);differences.add(difference);
    }
  }
  boolean domainSemanticsEqual(SoftwareCallDomains.Proof left,SoftwareCallDomains.Proof right)throws Exception {
    var semantics=SoftwareCallDomains.class.getDeclaredMethod("semantics",List.class);semantics.setAccessible(true);
    return semantics.invoke(null,left.domains()).equals(semantics.invoke(null,right.domains()));
  }
  <T> boolean equalMultiset(List<T> left,List<T> right) {
    var unmatched=new ArrayList<>(right);for(var item:left)if(!unmatched.remove(item))return false;return unmatched.isEmpty();
  }
  SoftwareCallDomains.Proof domainPreview(String mode,List<SoftwareCallValidation.Configuration> configurations)throws Exception {
    var before=domainState();save("preview-state-before.json",before);
    if(currentProgram.getListing().getNumInstructions()!=0)throw new IllegalStateException("Domain capture requires a fresh undisassembled Program");
    var initial=SoftwareCallDomains.preview(currentProgram,configurations,monitor);save("initial-preview.json",initial);
    var afterInitial=domainState();save("preview-state-after-initial.json",afterInitial);
    var canonical=initial.domains().stream().map(SoftwareCallDomains.Domain::configuration).toList();
    var supplied=new ArrayList<>(canonical);if(mode.contains("anti-canonical"))Collections.reverse(supplied);
    var proof=SoftwareCallDomains.preview(currentProgram,supplied,monitor);save("producer-preview.json",proof);
    var afterProducer=domainState();save("preview-state-after-producer.json",afterProducer);
    var rederivation=proof.domains().stream().map(SoftwareCallDomains.Domain::configuration).toList();
    // This is the exact public production preview call made by current(), on verified unchanged state.
    // It preserves the rederived authority before the actual private install/current guard re-executes it below.
    var actual=SoftwareCallDomains.preview(currentProgram,rederivation,monitor);save("rederived-preview.json",actual);
    var afterRederivation=domainState();save("preview-state-after-rederivation.json",afterRederivation);
    boolean readOnly=before.equals(afterInitial)&&before.equals(afterProducer)&&before.equals(afterRederivation);
    save("original-discovery-plan.json",proof.discovery());save("rederived-discovery-plan.json",actual.discovery());
    var differences=new ArrayList<Object>();structuralDiff("discovery",ProgramMapping.JSON.toJsonTree(proof.discovery()),ProgramMapping.JSON.toJsonTree(actual.discovery()),differences);save("discovery-structural-diff.json",differences);
    var evidence=new LinkedHashMap<String,Object>();evidence.put("mode",mode);evidence.put("programId",currentProgram.getUniqueProgramID());evidence.put("initialCallerOrder",configurations);
    evidence.put("canonicalConfigurationOrder",canonical);evidence.put("callerOrder",supplied);evidence.put("domainIdOrder",proof.domains().stream().map(SoftwareCallDomains.Domain::id).toList());evidence.put("rederivationOrder",rederivation);
    evidence.put("domainSemanticsEqual",domainSemanticsEqual(proof,actual));evidence.put("planRecordEquals",proof.discovery().equals(actual.discovery()));
    evidence.put("candidateRecordMultisetEquals",equalMultiset(proof.discovery().candidates(),actual.discovery().candidates()));evidence.put("reservationRecordMultisetEquals",equalMultiset(proof.discovery().reservations(),actual.discovery().reservations()));
    evidence.put("firstDifferingField",differences.isEmpty()?null:differences.getFirst());evidence.put("differenceCount",differences.size());evidence.put("readOnly",readOnly);
    evidence.put("originalCandidateCount",proof.discovery().candidates().size());evidence.put("rederivedCandidateCount",actual.discovery().candidates().size());
    var location=SoftwareCallDomains.class.getProtectionDomain().getCodeSource().getLocation();evidence.put("provider",location.toString());evidence.put("providerSha256",hash(Path.of(location.toURI())));
    save("discovery-comparison.json",evidence);
    if(!readOnly||proof.discovery().candidates().isEmpty()||actual.discovery().candidates().isEmpty())throw new IllegalStateException("Preview mutation or missing real discovery");
    for(var candidate:proof.discovery().candidates())if(getInstructionAt(currentProgram.getAddressFactory().getAddress(candidate.address()))!=null)throw new IllegalStateException("Discovery candidate already materialized");
    return proof;
  }
  void staleDomains(List<SoftwareCallDomains.View> views,DecompInterface owner)throws Exception {
      var mutation=currentProgram.getAddressFactory().getAddress("rom3::4201");var instructions=new ArrayList<ghidra.program.model.listing.Instruction>();
      for(var ins:currentProgram.getListing().getInstructions(true))if(ins.getAddress().getOffset()==0x4200&&ProgramMapping.staticToPhysical(currentProgram,ins.getAddress()).stream().anyMatch(ph->ph.bank()==3))instructions.add(ins);
      for(var ins:instructions)currentProgram.getListing().clearCodeUnits(ins.getMinAddress(),ins.getMaxAddress(),false);currentProgram.getMemory().setByte(mutation,(byte)0x44);
      var refusals=new ArrayList<Object>();for(var view:views)if(view.kind().equals("root")) {
        var at=currentProgram.getAddressFactory().getAddress(view.entry());String reason="";try{SoftwareCallDomains.emit(currentProgram,at,0x200000,monitor);}catch(IllegalArgumentException failure){reason=failure.getMessage();}
        if(!reason.contains("Stale"))throw new IllegalStateException("Stale domain accepted");refusals.add(Map.of("domain",view.domain(),"reason",reason));request(getFunctionAt(at),owner,"stale-"+view.domain().substring(0,12));
      }
      save("stale-domains.json",refusals);
  }
  Object savedDomainIdentity(List<SoftwareCallDomains.View> views)throws Exception {
    var file=currentProgram.getDomainFile();var identity=new LinkedHashMap<String,Object>();
    identity.put("programId",currentProgram.getUniqueProgramID());identity.put("javaPid",ProcessHandle.current().pid());
    identity.put("domainFile",file.getPathname());identity.put("domainFileId",file.getFileID());
    var provider=Path.of(SoftwareCallDomains.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    identity.put("provider",provider.toString());identity.put("providerSha256",hash(provider));
    identity.put("imageSha256",bytesHash(ProgramMapping.exportBytes(currentProgram,true,false,monitor)));
    identity.put("views",views);identity.put("instructions",currentProgram.getListing().getNumInstructions());
    identity.put("functions",views.stream().map(v->Map.of("entry",v.entry(),"id",getFunctionAt(currentProgram.getAddressFactory().getAddress(v.entry())).getID(),"body",getFunctionAt(currentProgram.getAddressFactory().getAddress(v.entry())).getBody().toString())).toList());
    return identity;
  }
  void reopenDomains()throws Exception {
    Path persisted=getScriptArgs().length>3?Path.of(getScriptArgs()[3]):out;
    String registration=currentProgram.getOptions(domainOptions()).getString("registration",null);
    if(!Files.readString(persisted.resolve("persisted-registration.json")).equals(registration))throw new IllegalStateException("Saved domain registration changed on reopen");
    var identity=com.google.gson.JsonParser.parseString(Files.readString(persisted.resolve("persisted-identity.json"))).getAsJsonObject();
    if(identity.get("programId").getAsLong()!=currentProgram.getUniqueProgramID()||identity.get("javaPid").getAsLong()==ProcessHandle.current().pid())throw new IllegalStateException("Expected same Program in a separate JVM");
    long firstRevision=currentProgram.getModificationNumber();
    System.setProperty("ghidraboy.farCallEvidencePhase","first-reopened-proof");
    var proof=SoftwareCallDomains.proof(currentProgram);
    if(firstRevision!=currentProgram.getModificationNumber())throw new IllegalStateException("First reopened proof changed Program revision");
    var before=domainState();save("reopen-state-before.json",before);
    save("reopened-fingerprint-components.json",ProgramFingerprint.components(currentProgram,monitor));save("reopened-proof.json",proof);var views=SoftwareCallDomains.views(currentProgram);
    save("reopened-domain-identity.json",savedDomainIdentity(views));var owner=owner();
    try {
      domainStage("reopened",views,owner);var after=domainState();save("reopen-state-after.json",after);
      boolean unchanged=registration.equals(currentProgram.getOptions(domainOptions()).getString("registration",null));
      save("reopen-compatibility.json",Map.of("registrationUnchanged",unchanged,"readOnly",before.equals(after),"programId",currentProgram.getUniqueProgramID(),"javaPid",ProcessHandle.current().pid(),"version",proof.version(),"views",views.size(),"firstCheckRevision",firstRevision,"finalRevision",currentProgram.getModificationNumber()));
      if(!unchanged||!before.equals(after))throw new IllegalStateException("Reopen revalidation/native requests changed saved authority");
      println("W3B_DOMAIN_REOPEN_COMPLETE");
      // Stale controls run separately on disposable writable state after this read-only process exits.
    }finally{owner.dispose();}
    println("W3B_CAPTURE_COMPLETE setup");
  }
  void legacyDomains()throws Exception {
    String registration=currentProgram.getOptions(domainOptions()).getString("registration",null);
    var json=com.google.gson.JsonParser.parseString(registration).getAsJsonObject();
    if(!json.get("version").getAsString().equals("software-call-domains-1"))throw new IllegalStateException("Expected actual saved v1 authority");
    long revision=currentProgram.getModificationNumber();var refusals=new ArrayList<String>();
    try{SoftwareCallDomains.proof(currentProgram);throw new IllegalStateException("Legacy proof accepted");}
    catch(IllegalArgumentException expected){refusals.add(expected.getMessage());}
    for(var item:json.getAsJsonArray("views")) {
      var at=currentProgram.getAddressFactory().getAddress(item.getAsJsonObject().get("entry").getAsString());
      try{SoftwareCallDomains.emit(currentProgram,at,0x200000,monitor);throw new IllegalStateException("Legacy emission accepted");}
      catch(IllegalArgumentException expected){refusals.add(expected.getMessage());}
    }
    if(refusals.size()!=5||refusals.stream().anyMatch(r->!r.equals("Unsupported software domain record version")))throw new IllegalStateException("Wrong legacy refusal");
    boolean unchanged=registration.equals(currentProgram.getOptions(domainOptions()).getString("registration",null))&&revision==currentProgram.getModificationNumber();
    save("legacy-refusal.json",Map.of("programId",currentProgram.getUniqueProgramID(),"javaPid",ProcessHandle.current().pid(),"registrationUnchanged",unchanged,"refusals",refusals));
    if(!unchanged)throw new IllegalStateException("Legacy authority changed");println("W3B_DOMAIN_LEGACY_REFUSAL_COMPLETE");
  }
  @Override public void run()throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    String mode=getScriptArgs().length>1?getScriptArgs()[1]:"canonical";
    if(mode.equals("setup"))mode="canonical"; // Preserve the existing runner's setup argument.
    if(mode.equals("reopen")){reopenDomains();return;}
    if(mode.equals("legacy")){legacyDomains();return;}
    if(mode.equals("stale")){var owner=owner();try{staleDomains(SoftwareCallDomains.views(currentProgram),owner);}finally{owner.dispose();}println("W3B_DOMAIN_STALE_COMPLETE");return;}
    if(!Set.of("canonical","anti-canonical","repro-anti-canonical","persist-anti-canonical","persist-canonical").contains(mode))throw new IllegalArgumentException("Unknown domain capture mode: "+mode);
    var helper=new SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP,0x28,0,null);
    var configurations=List.of(0,0x80).stream().map(flags->new SoftwareCallValidation.Configuration(0x200,helper,SoftwareCallModel.EntryTransfer.HARDWARE_RST,0xc100,new SoftwareCallModel.Registers(2,flags,0,0,0x4100),MapperState.reset())).toList();
    var proof=domainPreview(mode,configurations);var beforeInstall=domainState();List<SoftwareCallDomains.View> views;
    System.setProperty("ghidraboy.farCallEvidencePhase","installation");
    try{views=(stock()?SoftwareCallDomains.installStock(currentProgram,proof,monitor):SoftwareCallDomains.install(currentProgram,proof,monitor));save("install-result.json",Map.of("installed",true,"views",views.size()));}
    catch(Exception failure){
      var after=domainState();save("install-result.json",Map.of("installed",false,"exception",failure.getClass().getName(),"reason",String.valueOf(failure.getMessage()),"readOnly",beforeInstall.equals(after)));save("install-state-after-refusal.json",after);
      if(mode.equals("repro-anti-canonical")&&"Domain discovery differs from rooted proof".equals(failure.getMessage())&&beforeInstall.equals(after)){println("W3B_DOMAIN_REPRO_COMPLETE expected discovery guard refusal");return;}throw failure;
    }
    if(mode.equals("repro-anti-canonical"))throw new IllegalStateException("Uncorrected anti-canonical reproduction unexpectedly installed");
    var owner=owner();
    try {
      SoftwareCallDomains.selectDisplay(currentProgram,proof.domains().getFirst().id());domainStage("forward",views,owner);
      SoftwareCallDomains.selectDisplay(currentProgram,proof.domains().getLast().id());var reversed=new ArrayList<>(views);Collections.reverse(reversed);domainStage("reverse",reversed,owner);
      Files.write(out.resolve("original-image.gb"),ProgramMapping.exportBytes(currentProgram,true,false,monitor));
      var root=views.stream().filter(v->v.kind().equals("root")&&v.domain().equals(proof.domains().getFirst().id())).findFirst().orElseThrow();
      boolean wrong=false;String wrongReason="";try{SoftwareCallDomains.emit(currentProgram,currentProgram.getAddressFactory().getAddress(root.entry()),proof.domains().getLast(),0x200000,monitor);}catch(IllegalArgumentException failure){wrong=true;wrongReason=failure.getMessage();}
      if(!wrong)throw new IllegalStateException("Site-only cache consumed a foreign domain");save("site-only-negative.json",Map.of("rejected",wrong,"reason",wrongReason));
      if(mode.startsWith("persist-")) {
        System.setProperty("ghidraboy.farCallEvidencePhase","immediately-before-save");
        save("persisted-state.json",domainState());
        save("persisted-fingerprint-components.json",ProgramFingerprint.components(currentProgram,monitor));
        Files.writeString(out.resolve("persisted-registration.json"),currentProgram.getOptions(domainOptions()).getString("registration",null));
        save("persisted-identity.json",savedDomainIdentity(views));
        println("W3B_DOMAIN_PERSIST_COMPLETE save required by headless project lifecycle");return;
      }
      staleDomains(views,owner);
    }finally{owner.dispose();}
    println("W3B_CAPTURE_COMPLETE setup");
  }
}
