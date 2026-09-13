// @category Game Boy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.services.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Attended normal-provider workflow. Uses inherited passive captures; no test-only reset. */
public class GhidraBoyPublicLifecycleWindow extends GhidraBoyStockWindow {
  GhidraBoyTools action(String... args)throws Exception {
    var script=new GhidraBoyTools();script.setScriptArgs(args);
    script.setPropertiesFileLocation(getScriptArgs()[1],"GhidraBoyTools");
    script.execute(new ghidra.app.script.GhidraState(state.getTool(),state.getProject(),currentProgram,
        new ghidra.program.util.ProgramLocation(currentProgram,target.getEntryPoint()),null,null),monitor,new java.io.PrintWriter(System.out,true));
    if(script.lastOperation!=null) {
      var result=script.lastOperation.completion().get(60,TimeUnit.SECONDS);
      save("operation-"+script.lastOperation.id()+".json",result);
      script.lastPresentation.get(60,TimeUnit.SECONDS);
      if(!result.current())throw new IllegalStateException("Public action did not produce current outcome: "+result);
    }
    return script;
  }
  Path preview(ConditionalCallSites.Request request,String label)throws Exception {
    Path in=out.resolve(label+"-request.json"),proof=out.resolve(label+"-proof.json");save(label+"-request.json",request);
    action("conditional-call-preview",in.toString(),proof.toString());return proof;
  }
  @Override public void run()throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    // The launcher starts this script with no current Program, so no enclosing wrapper transaction is held.
    currentProgram=state.getTool().getService(ProgramManager.class).getCurrentProgram();
    var p=currentProgram;window=(DecompilerProvider)state.getTool().getComponentProvider("Decompiler");
    var entry=StockEntries.entries(p).stream().filter(e->e.generation()==null).findFirst().orElseThrow();
    Address at=ProgramMapping.staticAddress(p,entry.carrier());target=getFunctionAt(at);listen(p);
    try {
      String authorityBefore=authority(p);save("before-inventory.json",Sm83PreservationInventory.inventory(p));
      Files.write(out.resolve("before-original.gb"),ProgramMapping.exportBytes(p,false,false,monitor));
      Files.write(out.resolve("before-current.gb"),ProgramMapping.exportBytes(p,true,false,monitor));
      navigate(target,"public-initial");observe(target,"public-initial");
      var proof=PredicatedCalls.registeredProof(p,at);var request=proof.callSite();
      action("conditional-call-explain",at.toString());action("conditional-call-target",at.toString());action("conditional-call-continuation",at.toString());
      navigate(target,"back-to-owned-before-source-edit");
      var callee=proof.boundaries().stream().filter(b->b.kind().equals("RET_DISPATCH")).findFirst().orElseThrow();
      var changed=ProgramMapping.staticAddress(p,callee.physical()).add(2);
      var mutation=new Mutation(p,"consumed-source-edit");boolean committed=false;
      try {p.getListing().clearCodeUnits(changed,changed,false);p.getMemory().setByte(changed,(byte)0x3d);committed=true;}
      finally{mutation.end(committed);}
      drain();observe(target,"public-passive-stale");
      var data=window.getController().getDecompileData();
      if(data.getHighFunction()!=null || !String.valueOf(data.getErrorMessage()).contains("Stale"))throw new IllegalStateException("Passive stale refusal missing");
      action("stock-predicate-refresh",preview(request,"explicit-fresh").toString(),at.toString());
      drain();observe(target,"public-event-recovery");ordinaryRefresh("public-enabled-refresh",false);observe(target,"public-toolbar-refresh");
      var second=new ConditionalCallSites.Request(request.programId(),request.imageSha256(),request.site(),request.mapper(),request.shadowCpu(),request.shadowValue(),request.memoryInputs(),new SymbolicMemory.Footprint(0xc200,0xc500,-16,1),request.incomingStackBytes(),request.continuationSteps(),true,true,request.provenance());
      var applied=action("stock-predicate-apply",preview(second,"second-domain").toString());
      var other=applied.lastOperation.entry();
      action("stock-predicate-refresh",preview(request,"first-after-topology").toString(),at.toString());
      navigate(getFunctionAt(other),"public-domain-two");observe(target,"public-domain-two");
      navigate(getFunctionAt(at),"public-domain-one");observe(target,"public-domain-one");
      save("after-inventory.json",Sm83PreservationInventory.inventory(p));
      Files.write(out.resolve("after-original.gb"),ProgramMapping.exportBytes(p,false,false,monitor));
      Files.write(out.resolve("after-current.gb"),ProgramMapping.exportBytes(p,true,false,monitor));
      p.save("Public lifecycle positive candidate",monitor);save("saved-authority.json",authority(p));
      save("public-window-complete.json",Map.of("program",identity(p),"saved",true,"visible_confirmation_only",true,
          "outstanding_request_service_probe_required",true,"immutable_second_session_required",true,"initial_authority_hash",Sha256.of(authorityBefore.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
    }finally{unlisten(p);}
  }
}
