// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import java.nio.file.*;
import java.util.*;

/** The legacy exact production continuation route, naturally lower-ID successor after a real CALL/RET. */
public class GhidraBoyW3bOrder extends GhidraBoyPredicatedCalls {
  @Override public void run()throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    var helper=new SoftwareCallModel.Template(SoftwareCallModel.Family.REGISTER_JP,0x28,0,null);
    var config=new SoftwareCallValidation.Configuration(0x180,helper,SoftwareCallModel.EntryTransfer.HARDWARE_CALL,0xc100,new SoftwareCallModel.Registers(2,0,2,0x1234,0x4000),MapperState.reset());
    boolean stock=Arrays.asList(getScriptArgs()).contains("stock");
    var review=stock?SoftwareCallApplication.previewStock(currentProgram,List.of(config),monitor):SoftwareCallApplication.preview(currentProgram,List.of(config),monitor);save("producer-continuations.json",review.stateContinuations());
    var graph=review.stateContinuations().get("0180");if(graph==null)throw new IllegalStateException("Missing actual production exact continuation");
    var lower=new ArrayList<Object>();for(var step:graph.steps())if(step.afterCall()!=null) {
      var candidates=graph.steps().stream().filter(n->n.callDepth()==step.callDepth()&&n.before().equals(step.afterCall())).toList();
      if(candidates.stream().anyMatch(n->n.index()<step.index()))lower.add(Map.of("call",step.index(),"candidates",candidates.stream().map(SoftwareCallEffects.ContinuationStep::index).toList(),"afterCall",step.afterCall()));
    }
    if(lower.isEmpty())throw new IllegalStateException("Production did not generate lower-ID continuation");save("lower-id.json",lower);
    SoftwareCallApplication.apply(currentProgram,review,monitor);
    String encoded=currentProgram.getOptions(ProgramMapping.OPTIONS).getString(stock?SoftwareCallRegistry.STOCK_KEY:SoftwareCallRegistry.KEY,null);Files.writeString(out.resolve("registry.json"),encoded);
    var registry=com.google.gson.JsonParser.parseString(encoded).getAsJsonObject();String alias=null;
    for(var item:registry.getAsJsonArray("sites")){var site=item.getAsJsonObject();if(site.get("canonicalAddress").getAsString().equals("0180")&&site.has("executionAlias")){alias=site.get("executionAlias").getAsString();break;}}
    if(alias==null)throw new IllegalStateException("Missing production caller execution alias");var root=currentProgram.getAddressFactory().getAddress(alias);
    var payload=currentProgram.getCompilerSpec().getPcodeInjectLibrary().getPayload(InjectPayload.CALLFIXUP_TYPE,SoftwareCallInjection.NAME);
    var context=new InjectContext();context.baseAddr=root;context.nextAddr=root.add(3);context.callAddr=toAddr(0x28);ids.clear();save("root-requested.json",Arrays.stream(payload.getPcode(currentProgram,context)).map(this::operation).toList());
    save("active-route.json",Map.of("root",root.toString(),"route","SoftwareCallInjection -> SoftwareCallContinuationView -> postCallSuccessor","configuredSite","0180","helper","0028"));
    var owner=owner();try {
      request(getFunctionAt(root),owner,"root");
      for(var function:currentProgram.getFunctionManager().getFunctions(true))if(function.getEntryPoint().getOffset()==0x240)request(function,owner,"callee-"+function.getID());
    }finally{owner.dispose();}
    Files.writeString(out.resolve("registry.json"),currentProgram.getOptions(ProgramMapping.OPTIONS).getString(stock?SoftwareCallRegistry.STOCK_KEY:SoftwareCallRegistry.KEY,null));
    println("W3B_CAPTURE_COMPLETE setup");
  }
}
