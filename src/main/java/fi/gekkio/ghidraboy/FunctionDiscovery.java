package fi.gekkio.ghidraboy;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Seeds only: entry points, explicitly declared code, and proven direct-call conclusions. */
public final class FunctionDiscovery {
    private FunctionDiscovery() { }
    public static List<String> discover(Program p,List<Address> declaredCode,List<BankAnalysis.Finding> findings,TaskMonitor monitor) throws Exception {
        // Legacy lists carry neither completeness nor dependency evidence. Only explicit seeds are accepted.
        return discoverSeeds(p,declaredCode,List.of(),monitor);
    }
    public static List<String> discover(Program p,List<Address> declaredCode,AnalysisResult result,TaskMonitor monitor) throws Exception {
        ProgramFingerprint.requireCurrent(p,result,monitor);
        String saved=p.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest",null);
        if(saved!=null) {
            var active=AnalysisResult.read(saved);
            if(!Objects.equals(active.assumption(),result.assumption()) || !active.configuration().equals(result.configuration()) || !active.starts().equals(result.starts()))
                throw new IllegalStateException("Analysis assumptions changed; apply the current preview before function discovery");
        }
        if(!result.complete()) return List.of("Incomplete analysis: function discovery suppressed");
        return discoverSeeds(p,declaredCode,result.findings(),monitor);
    }
    private static List<String> discoverSeeds(Program p,List<Address> declaredCode,List<BankAnalysis.Finding> findings,TaskMonitor monitor) throws Exception {
        Set<Address> seeds=new TreeSet<>(declaredCode);
        var entries=p.getSymbolTable().getExternalEntryPointIterator(); while(entries.hasNext()) seeds.add(entries.next());
        for(var f:findings) if(f.access().equals("call") && f.targets().size()==1 && f.confidence()==AnalysisResult.Confidence.PROVEN) {
            var a=p.getAddressFactory().getAddress(f.targets().get(0)); if(a!=null) seeds.add(a);
        }
        List<String> result=new ArrayList<>();
        int tx=p.startTransaction("Discover functions from validated seeds"); boolean success=false;
        try {
            AnalysisOwnership.remove(p,"functions",monitor);
            var owned=new AnalysisOwnership.Group();
            for(var a:seeds) {
                monitor.checkCancelled();
                if(p.getFunctionManager().getFunctionContaining(a)!=null) continue;
                if(p.getListing().getInstructionAt(a)==null || p.getListing().getDefinedDataContaining(a)!=null) {
                    result.add(a+": no defined instruction; data/undefined bytes preserved"); continue;
                }
                boolean userLabel=false;
                for(var symbol:p.getSymbolTable().getSymbols(a)) if(symbol.getSource()!=SourceType.DEFAULT) userLabel=true;
                if(userLabel) { result.add(a+": user symbol preserved; use explicit function editing to promote it"); continue; }
                var cmd=new CreateFunctionCmd(null,a,null,SourceType.ANALYSIS,false,false);
                if(!cmd.applyTo(p,monitor)) result.add(a+": "+cmd.getStatusMsg());
                else {
                    var function=p.getFunctionManager().getFunctionAt(a);
                    owned.function(function);
                    result.add(a+": function created from validated seed");
                }
            }
            AnalysisOwnership.save(p,"functions",owned);
            success=true;
        } finally { p.endTransaction(tx,success); }
        return List.copyOf(result);
    }
}
