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
        Set<Address> seeds=new TreeSet<>(declaredCode);
        var entries=p.getSymbolTable().getExternalEntryPointIterator(); while(entries.hasNext()) seeds.add(entries.next());
        for(var f:findings) if(f.access().equals("call") && f.targets().size()==1 && f.reason().equals("Explicit state or same-window execution context with constant p-code propagation")) {
            var a=p.getAddressFactory().getAddress(f.targets().get(0)); if(a!=null) seeds.add(a);
        }
        List<String> result=new ArrayList<>();
        int tx=p.startTransaction("Discover functions from validated seeds"); boolean success=false;
        try {
            for(var a:seeds) {
                monitor.checkCancelled();
                if(p.getFunctionManager().getFunctionContaining(a)!=null) continue;
                if(p.getListing().getInstructionAt(a)==null || p.getListing().getDefinedDataContaining(a)!=null) {
                    result.add(a+": no defined instruction; data/undefined bytes preserved"); continue;
                }
                var cmd=new CreateFunctionCmd(null,a,null,SourceType.ANALYSIS,false,false);
                if(!cmd.applyTo(p,monitor)) result.add(a+": "+cmd.getStatusMsg());
                else result.add(a+": function created from validated seed");
            }
            success=true;
        } finally { p.endTransaction(tx,success); }
        return List.copyOf(result);
    }
}
