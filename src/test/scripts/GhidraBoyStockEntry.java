// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.disassemble.Disassembler;
import java.nio.file.*;
import java.util.*;

/** Real production proof and normal DecompInterface; no callback or compiler replacement. */
public class GhidraBoyStockEntry extends GhidraBoyPredicatedCalls {
  @Override public void run() throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    boolean loop=getScriptArgs().length>1&&getScriptArgs()[1].equals("loop");
    var body=new AddressSet(toAddr(0x150),toAddr(loop?0x174:0x164));
    Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(toAddr(0x150),body);
    var function=currentProgram.getFunctionManager().createFunction("stock_source",toAddr(0x150),body,ghidra.program.model.symbol.SourceType.USER_DEFINED);
    save("canonical-before.json",canonical(function));
    var proof=PredicatedCalls.preview(currentProgram,function,PredicatedCallGraph.Limits.PRIMARY,monitor);
    save("producer-preview.json",proof);
    if(!proof.complete())throw new IllegalStateException("Incomplete graph: "+proof.frontier());
    var root=PredicatedCalls.installStock(currentProgram,proof,monitor);
    save("canonical-after-install.json",canonical(function));
    Files.writeString(out.resolve("original-registration.json"),currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(root.toString(),null));
    save("original-proof.json",proof);identity("original-before",root);
    var raw=new TreeMap<String,Object>();
    for(var node:proof.nodes())if(!raw.containsKey(node.source())) {
      var ins=getInstructionAt(currentProgram.getAddressFactory().getAddress(node.source()));ids.clear();
      raw.put(node.source(),Map.of("address",node.source(),"bytes",HexFormat.of().formatHex(ins.getBytes()),"physical",ProgramMapping.staticToPhysical(currentProgram,ins.getAddress()),"ops",Arrays.stream(ins.getPcode(false)).map(this::operation).toList()));
    }
    save("original-raw.json",raw);var mapping=new ArrayList<Object>();
    var owner=owner();try {
      for(var view:PredicatedCalls.views(currentProgram,root)) {
        var at=currentProgram.getAddressFactory().getAddress(view.entry());String tag=view.invocation().equals("root")?"root":view.invocation().substring(0,12);
        mapping.add(Map.of("tag",tag,"view",view));ids.clear();save("original-"+tag+"-carrier.json",Arrays.stream(getInstructionAt(at).getPcode(false)).map(this::operation).toList());
        var payload=currentProgram.getCompilerSpec().getPcodeInjectLibrary().getPayload(InjectPayload.CALLOTHERFIXUP_TYPE,StockEntryInjection.NAME);
        var context=new InjectContext();context.baseAddr=at;context.nextAddr=at.add(1);ids.clear();
        save("original-"+tag+"-requested.json",Arrays.stream(payload.getPcode(currentProgram,context)).map(this::operation).toList());
        request(getFunctionAt(at),owner,"original-"+tag);
      }
      save("original-views.json",mapping);
      // Observe actual native result after corruption on the same interface, not just a Java throw.
      String saved=currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(root.toString(),null);
      currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).removeOption(root.toString());
      request(getFunctionAt(root),owner,"missing-authority-root");
      currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).setString(root.toString(),saved);
      PredicatedCalls.refresh(currentProgram,root,PredicatedCalls.preview(currentProgram,function,PredicatedCallGraph.Limits.PRIMARY,monitor),monitor);
      request(getFunctionAt(root),owner,"restored-authority-root");
    } finally {owner.dispose();}
    println("STOCK_ENTRY_CAPTURE_COMPLETE");
  }
}
