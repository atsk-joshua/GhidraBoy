package ghigbc;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
/** Generic execution stays in GhiGBC. Consumers supply immutable selection context. */
public interface GbcActionService {
    void watch(Trace trace,long selectedSnapshot,String region,int bank,long offset,int length);
    void goWriter(TraceObject event,boolean bookmark);
}
