// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.disassemble.Disassembler;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** One unknown root graph; actual requested child functions, current bytes and stored authority. */
public class GhidraBoyPredicatedCalls extends GhidraBoyW2eFinite {
  // This runner owns its enclosing script transaction and accepts whole-owner rollback.
  void publicPredicateAction(String[] args) throws Exception {
    var script=new GhidraBoyTools();script.setScriptArgs(args);
    boolean callerManaged=currentProgram.getCurrentTransactionInfo()!=null;
    if(callerManaged)try(var caller=PredicateOperations.participate(currentProgram)){script.execute(state,monitor,new java.io.PrintWriter(System.out,true));}
    else script.execute(state,monitor,new java.io.PrintWriter(System.out,true));
    if(!callerManaged && script.lastOperation!=null) {
      var result=script.lastOperation.completion().get(60,java.util.concurrent.TimeUnit.SECONDS);
      script.lastPresentation.get(60,java.util.concurrent.TimeUnit.SECONDS);
      if(!result.current())throw new IllegalStateException("Public operation unavailable: "+result);
    }
  }
  @Override Object varnode(Varnode node) {
    if(node==null)return null;
    @SuppressWarnings("unchecked") var result=new LinkedHashMap<String,Object>((Map<String,Object>)super.varnode(node));
    if(node instanceof VarnodeAST ast && ast.getHigh() instanceof HighGlobal global) {
      var symbol=global.getSymbol();var storage=symbol.getStorage().getVarnodes();
      if(storage.length==1)result.put("high_global",Map.of("name",symbol.getName(),"space",storage[0].getAddress().getAddressSpace().getName(),"offset",storage[0].getOffset(),"size",storage[0].getSize()));
    }
    return result;
  }
  @Override Object operation(PcodeOp op) {
    @SuppressWarnings("unchecked") var record=(Map<String,Object>)super.operation(op);
    record.put("opcode",op.getOpcode());return record;
  }
  String bytesHash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
  DecompInterface owner()throws Exception{
    var owner=new DecompInterface();owner.setOptions(new DecompileOptions());owner.setSimplificationStyle("decompile");
    owner.toggleSyntaxTree(true);owner.toggleCCode(true);if(!owner.openProgram(currentProgram))throw new IllegalStateException("Native open failed");return owner;
  }
  void request(Function function,DecompInterface owner,String label)throws Exception{
    var request=new LinkedHashMap<String,Object>();request.put("entry",function.getEntryPoint().toString());request.put("function_name",function.getName());
    request.put("function_id",function.getID());request.put("native_interface_identity",System.identityHashCode(owner));request.put("owner_java_pid",ProcessHandle.current().pid());request.put("revision",currentProgram.getModificationNumber());
    Path debug=out.resolve(label+"-debug.xml");owner.enableDebug(debug.toFile());long nativeStart=System.nanoTime();var result=owner.decompileFunction(function,90,monitor);request.put("decompile_ns",System.nanoTime()-nativeStart);
    request.put("completed",result.decompileCompleted());request.put("error",result.getErrorMessage());request.put("highfunction_available",result.getHighFunction()!=null);
    request.put("processes_after",processes());if(Files.exists(debug))request.put("debug",Map.of("sha256",hash(debug),"path",debug.toString()));
    if(result.getHighFunction()!=null){
      ids.clear();var blocks=new ArrayList<Object>();
      for(var block:result.getHighFunction().getBasicBlocks()){
        var ins=new ArrayList<Integer>();var outs=new ArrayList<Integer>();for(int i=0;i<block.getInSize();i++)ins.add(block.getIn(i).getIndex());for(int i=0;i<block.getOutSize();i++)outs.add(block.getOut(i).getIndex());
        var ops=new ArrayList<Object>();var iterator=block.getIterator();while(iterator.hasNext())ops.add(operation(iterator.next()));
        blocks.add(Map.of("index",block.getIndex(),"in",ins,"out",outs,"ops",ops));
      }
      request.put("jump_tables",Arrays.stream(result.getHighFunction().getJumpTables()).map(t->Map.of("at",t.getSwitchAddress().toString(),"cases",Arrays.stream(t.getCases()).map(Object::toString).toList())).toList());
      save(label+"-high.json",blocks);var proto=result.getHighFunction().getFunctionPrototype();var params=new ArrayList<Object>();
      for(int i=0;i<proto.getNumParams();i++){var param=proto.getParam(i);params.add(Map.of("name",param.getName(),"storage",Arrays.stream(param.getStorage().getVarnodes()).map(this::varnode).toList()));}
      request.put("parameters",params);request.put("return_type",proto.getReturnType().getName());
      if(proto.getReturnStorage()!=null)request.put("return_storage",Arrays.stream(proto.getReturnStorage().getVarnodes()).map(this::varnode).toList());
    }
    if(result.getDecompiledFunction()!=null)Files.writeString(out.resolve(label+".c"),result.getDecompiledFunction().getC());save(label+"-request.json",request);
  }
  void identity(String label,Address root)throws Exception{
    var record=new LinkedHashMap<String,Object>();record.put("program_id",currentProgram.getUniqueProgramID());
    var spaces=new TreeMap<String,Integer>();for(var space:currentProgram.getAddressFactory().getAddressSpaces())spaces.put(space.getName(),space.getSpaceID());record.put("spaces",spaces);
    record.put("domain_file",currentProgram.getDomainFile().getPathname());record.put("domain_file_id",currentProgram.getDomainFile().getFileID());
    record.put("java_pid",ProcessHandle.current().pid());record.put("java_start",ProcessHandle.current().info().startInstant().map(Object::toString).orElse("unknown"));
    record.put("live_modification_number",currentProgram.getModificationNumber());record.put("live_object_identity",System.identityHashCode(currentProgram));
    record.put("original_image_sha256",currentProgram.getExecutableSHA256());record.put("current_image_sha256",bytesHash(ProgramMapping.exportBytes(currentProgram,true,false,monitor)));
    var location=PredicatedCalls.class.getProtectionDomain().getCodeSource().getLocation();record.put("provider_location",location.toString());record.put("provider_jar_sha256",hash(Path.of(location.toURI())));
    var views=new ArrayList<Object>();for(var view:PredicatedCalls.views(currentProgram,root)){
      var at=currentProgram.getAddressFactory().getAddress(view.entry());var function=getFunctionAt(at);
      views.add(Map.of("view",view,"function_name",function.getName(),"function_id",function.getID(),"physical",ProgramMapping.staticToPhysical(currentProgram,at)));
    }
    record.put("views",views);save(label+"-identity.json",record);
  }
  String predicateOptions(Address entry) {
    return StockEntryInjection.CONVENTION.equals(getFunctionAt(entry).getCallingConventionName())?PredicatedCalls.STOCK_OPTIONS:PredicatedCalls.OPTIONS;
  }
  InjectPayload entryPayload(Address entry) {
    boolean stock=StockEntryInjection.CONVENTION.equals(getFunctionAt(entry).getCallingConventionName());
    return currentProgram.getCompilerSpec().getPcodeInjectLibrary().getPayload(stock?InjectPayload.CALLOTHERFIXUP_TYPE:InjectPayload.CALLMECHANISM_TYPE,stock?StockEntryInjection.NAME:SoftwareCallStateEntryInjection.NAME);
  }
  void stage(String label,Address root,DecompInterface owner)throws Exception{
    String registration=currentProgram.getOptions(predicateOptions(root)).getString(root.toString(),null);
    Files.writeString(out.resolve(label+"-registration.json"),registration);identity(label+"-before",root);
    var proof=PredicatedCalls.registeredProof(currentProgram,root);save(label+"-proof.json",proof);
    if(proof.callSite()!=null)save(label+"-cost.json",PredicatedCalls.measure(currentProgram,root,monitor));
    var raw=new TreeMap<String,Object>();for(var node:proof.nodes())if(!raw.containsKey(node.source())){
      var instruction=currentProgram.getListing().getInstructionAt(currentProgram.getAddressFactory().getAddress(node.source()));ids.clear();
      raw.put(node.source(),Map.of("address",node.source(),"bytes",HexFormat.of().formatHex(instruction.getBytes()),"physical",ProgramMapping.staticToPhysical(currentProgram,instruction.getAddress()),"ops",Arrays.stream(instruction.getPcode(false)).map(this::operation).toList()));
    }
    save(label+"-raw.json",raw);var mapping=new ArrayList<Object>();
    for(var view:PredicatedCalls.views(currentProgram,root)){
      var at=currentProgram.getAddressFactory().getAddress(view.entry());String name=view.invocation().equals("root")?"root":view.invocation().substring(0,12);mapping.add(Map.of("tag",name,"view",view));
      var payload=entryPayload(at);
      var context=new InjectContext();context.baseAddr=at;context.nextAddr=at;ids.clear();save(label+"-"+name+"-requested.json",Arrays.stream(payload.getPcode(currentProgram,context)).map(this::operation).toList());
      request(getFunctionAt(at),owner,label+"-"+name);
    }
    save(label+"-placements.json",PredicatedCalls.inspectEmission(currentProgram,root,0x200000,monitor));
    ids.clear();save(label+"-carrier-raw.json",Arrays.stream(currentProgram.getListing().getInstructionAt(root).getPcode(false)).map(this::operation).toList());
    save(label+"-views.json",mapping);identity(label+"-after",root);
    String after=currentProgram.getOptions(predicateOptions(root)).getString(root.toString(),null);Files.writeString(out.resolve(label+"-registration-after.json"),after);
    if(!registration.equals(after))throw new IllegalStateException("Native read mutated graph registration");
  }
  @Override public void run()throws Exception{
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);String mode=getScriptArgs()[1];
    boolean reuse=mode.equals("setup-reuse");
    if(!mode.startsWith("setup")){
      var roots=currentProgram.getOptions(PredicatedCalls.OPTIONS).getOptionNames().stream().filter(n->n.contains("_root::")).toList();
      if(roots.size()!=1)throw new IllegalStateException("Missing unique saved root");var root=currentProgram.getAddressFactory().getAddress(roots.get(0));var owner=owner();
      try{stage(mode.equals("recaptured")?"original":mode,root,owner);}finally{owner.dispose();}println("W3_PREDICATED_CAPTURE_COMPLETE "+mode);return;
    }
    var body=new AddressSet(toAddr(0x150),toAddr(reuse?0x162:0x164));Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(toAddr(0x150),body);
    var function=getFunctionAt(toAddr(0x150));if(function==null)function=currentProgram.getFunctionManager().createFunction("predicated_root",toAddr(0x150),body,ghidra.program.model.symbol.SourceType.USER_DEFINED);
    save("canonical-before.json",canonical(function));var limits=reuse?new PredicatedCallGraph.Limits(256,8192,2):PredicatedCallGraph.Limits.PRIMARY;
    var proof=PredicatedCalls.preview(currentProgram,function,limits,monitor);save("producer-preview.json",proof);
    if(!proof.complete())throw new IllegalStateException("Incomplete graph: "+proof.frontier());var root=PredicatedCalls.install(currentProgram,proof,monitor);save("canonical-after-install.json",canonical(function));
    var owner=owner();try{
      stage("original",root,owner);
      if(reuse){println("W3_PREDICATED_CAPTURE_COMPLETE "+mode);return;}
      String stored=currentProgram.getOptions(predicateOptions(root)).getString(root.toString(),null);
      var canonical=currentProgram.getAddressFactory().getAddress("rom2::4000");
      if((currentProgram.getMemory().getByte(canonical.add(1))&255)!=0xa6)throw new IllegalStateException("Wrong callee mutation source");
      var sites=new ArrayList<Address>();sites.add(canonical);
      for(var view:PredicatedCalls.views(currentProgram,root)){var at=currentProgram.getAddressFactory().getAddress(view.entry());if(ProgramMapping.staticToPhysical(currentProgram,at).equals(ProgramMapping.staticToPhysical(currentProgram,canonical)))sites.add(at);}
      for(var at:sites)currentProgram.getListing().clearCodeUnits(at,at.add(1),false);
      byte[] before=ProgramMapping.exportBytes(currentProgram,true,false,monitor);currentProgram.getMemory().setByte(canonical.add(1),(byte)0xb6);
      for(var at:sites)Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(at,new AddressSet(at,at.add(1)),false);
      byte[] after=ProgramMapping.exportBytes(currentProgram,true,false,monitor);var changed=new ArrayList<Integer>();for(int i=0;i<before.length;i++)if(before[i]!=after[i])changed.add(i);
      save("mutation.json",Map.of("file_offsets",changed,"old",0xa6,"new",0xb6,"source",canonical.add(1).toString(),"registration_retained",stored.equals(currentProgram.getOptions(predicateOptions(root)).getString(root.toString(),null))));
      request(getFunctionAt(root),owner,"stale-root");
      var stale=com.google.gson.JsonParser.parseString(Files.readString(out.resolve("stale-root-request.json"))).getAsJsonObject();
      if(stale.get("completed").getAsBoolean()||stale.get("highfunction_available").getAsBoolean()||!stale.get("error").getAsString().contains("Stale predicated graph"))throw new IllegalStateException("Stale graph accepted");
      var fresh=PredicatedCalls.preview(currentProgram,function,PredicatedCallGraph.Limits.PRIMARY,monitor);PredicatedCalls.refresh(currentProgram,root,fresh,monitor);save("refresh.json",Map.of("explicit",true,"flush",owner.flushCache()));stage("refreshed",root,owner);
    }finally{owner.dispose();}
    println("W3_PREDICATED_CAPTURE_COMPLETE setup");
  }
}
