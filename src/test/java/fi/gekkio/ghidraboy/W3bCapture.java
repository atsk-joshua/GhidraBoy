package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitor;
import java.nio.file.*;
import java.util.*;

/** Raw and emitted operations for the independent checker before the final installed native run. */
public final class W3bCapture {
  private final Program p;private final Path out;private final IdentityHashMap<Varnode,Integer> ids=new IdentityHashMap<>();
  private W3bCapture(Program p,String name)throws Exception{this.p=p;out=Path.of("build","w3b",name);Files.createDirectories(out);}
  private Object node(Varnode v){if(v==null)return null;return Map.of("id",ids.computeIfAbsent(v,k->ids.size()),"space",v.getAddress().getAddressSpace().getName(),"offset",v.getOffset(),"size",v.getSize(),"constant",v.isConstant(),"address",v.isAddress(),"register",v.isRegister());}
  private Object op(PcodeOp op){var value=new LinkedHashMap<String,Object>();value.put("mnemonic",op.getMnemonic());value.put("inputs",Arrays.stream(op.getInputs()).map(this::node).toList());value.put("output",node(op.getOutput()));if(op.getOpcode()==PcodeOp.CALLOTHER)value.put("userop_name",p.getLanguage().getUserDefinedOpName((int)op.getInput(0).getOffset()));return value;}
  private void save(String file,Object data)throws Exception{Files.writeString(out.resolve(file),ProgramMapping.JSON.toJson(data));}
  private void raw(Set<String> sources)throws Exception {
    var data=new TreeMap<String,Object>();for(String source:sources){var at=ProgramMapping.staticAddress(p,source);var ins=p.getListing().getInstructionAt(at);ids.clear();data.put(source,Map.of("address",source,"bytes",HexFormat.of().formatHex(ins.getBytes()),"ops",Arrays.stream(ins.getPcode(false)).map(this::op).toList()));}save("original-raw.json",data);
    Files.write(out.resolve("image.gb"),ProgramMapping.exportBytes(p,true,false,TaskMonitor.DUMMY));
  }
  public static void loop(Program p,Address root)throws Exception {
    var c=new W3bCapture(p,"pre-native-loops");var proof=PredicatedCalls.registeredProof(p,root);c.save("original-proof.json",proof);
    var sources=new TreeSet<String>();proof.nodes().forEach(n->sources.add(n.source()));c.raw(sources);var views=new ArrayList<Object>();
    for(var view:PredicatedCalls.views(p,root)){String tag=view.invocation().equals("root")?"root":view.invocation().substring(0,12);views.add(Map.of("tag",tag,"view",view));c.ids.clear();c.save("original-"+tag+"-requested.json",Arrays.stream(PredicatedCalls.emit(p,ProgramMapping.staticAddress(p,view.entry()),0x200000,TaskMonitor.DUMMY)).map(c::op).toList());}
    c.save("original-views.json",views);
  }
  public static void domains(Program p)throws Exception {
    var c=new W3bCapture(p,"pre-native-domains");var proof=SoftwareCallDomains.proof(p);c.save("original-proof.json",proof);var sources=new TreeSet<String>();
    for(var domain:proof.domains()){sources.add(domain.physicalSite());domain.callee().steps().forEach(n->sources.add(n.address()));domain.continuation().steps().forEach(n->sources.add(n.address()));for(int offset=0;offset<domain.configuration().template().bodyHex().length()/2;){var ins=p.getListing().getInstructionAt(p.getAddressFactory().getDefaultAddressSpace().getAddress(domain.configuration().template().helperCpu()+offset));sources.add(ins.getAddress().toString());offset+=ins.getLength();}}
    c.raw(sources);var views=new ArrayList<Object>();for(var view:SoftwareCallDomains.views(p)){String tag=view.domain().substring(0,12)+"-"+view.kind();views.add(Map.of("tag",tag,"view",view));c.ids.clear();c.save("original-"+tag+"-requested.json",Arrays.stream(SoftwareCallDomains.emit(p,ProgramMapping.staticAddress(p,view.entry()),0x200000,TaskMonitor.DUMMY)).map(c::op).toList());}c.save("original-views.json",views);
  }
}
