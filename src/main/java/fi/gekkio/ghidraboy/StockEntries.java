package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.List;

/** Thin normal-tool navigation and authority inspection; never owns a decompiler or display cache. */
public final class StockEntries {
  private StockEntries() {}
  public record Entry(String carrier, String source, String domain, String generation) {}
  public static List<Entry> entries(Program p) {
    var result=new ArrayList<Entry>();
    for(var function:p.getFunctionManager().getFunctions(true)) {
      if(!StockEntryInjection.CONVENTION.equals(function.getCallingConventionName()))continue;
      var at=function.getEntryPoint();
      if(PredicatedCalls.stockRegistered(p,at)) {
        var proof=PredicatedCalls.registeredProof(p,at);
        var view=PredicatedCalls.views(p,at).stream().filter(v->v.entry().equals(at.toString())).findFirst().orElseThrow();
        String source=view.invocation().equals("root")?proof.entry():proof.invocations().stream().filter(i->i.id().equals(view.invocation())).findFirst().orElseThrow().target();
        result.add(new Entry(at.toString(),source,view.invocation(),proof.memory()==null?null:proof.memory().image()));
      } else if(OrdinaryEntryAccess.stockRegistered(p,at)) {
        var proof=OrdinaryEntryAccess.registeredProof(p,at);result.add(new Entry(at.toString(),proof.entry(),ProgramMapping.JSON.toJson(proof.domain()),null));
      } else if(SoftwareCallDomains.stockRegistered(p,at)) {
        var view=SoftwareCallDomains.views(p).stream().filter(v->v.entry().equals(at.toString())).findFirst().orElseThrow();
        result.add(new Entry(at.toString(),SoftwareCallDomains.source(p,at).toString(),view.domain(),null));
      } else if(SoftwareCallRegistry.stockCarrier(p,at)) {
        var state=SoftwareCallRegistry.stockEntry(p,at);
        result.add(new Entry(at.toString(),state.canonical(),state.site()+":"+state.kind()+":"+state.graphEntry()+":"+state.entryStep(),null));
      }
    }
    return List.copyOf(result);
  }
  /** Source identity from recorded authority; the carrier itself is not physical game storage. */
  public static Address source(Program p, Address entry) {
    StockEntryInjection.validateStorage(p, entry);
    return ProgramMapping.staticAddress(p, entries(p).stream().filter(e -> e.carrier().equals(entry.toString()))
        .findFirst().orElseThrow(() -> new IllegalArgumentException("Missing stock source authority")).source());
  }
  public static String current(Program p, Address entry, TaskMonitor monitor) throws Exception {
    monitor.checkCancelled();StockEntryInjection.validate(p,entry);
    if(PredicatedCalls.stockRegistered(p,entry))PredicatedCalls.emitStock(p,entry,0x200000,monitor);
    else if(OrdinaryEntryAccess.stockRegistered(p,entry))OrdinaryEntryAccess.emitStock(p,entry,0x200000,monitor);
    else if(SoftwareCallDomains.stockRegistered(p,entry))SoftwareCallDomains.emitStock(p,entry,0x200000,monitor);
    else if(SoftwareCallRegistry.stockCarrier(p,entry)) {
      long revision=p.getModificationNumber();
      var input=SoftwareCallRegistry.resolveStateEntry(p,entry);
      var graph=SoftwareCallRegistry.entryGraph(p,entry,input);
      SoftwareCallContinuationView.emit(p,entry,graph,SoftwareCallRegistry.configurations(p),0x200000,SoftwareCallRegistry.entryStep(p,entry));
      if(revision!=p.getModificationNumber())throw new IllegalArgumentException("Program changed during currentness check");
    }
    else throw new IllegalArgumentException("Missing stock authority");
    return "Current conditional authority. The normal Decompiler window reports native recovery separately.";
  }
}
