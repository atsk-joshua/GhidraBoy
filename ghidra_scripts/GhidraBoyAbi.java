// Preview/apply a pinned convention or explicit storage to one existing function.
// @category Game Boy
import ghidra.app.script.GhidraScript;
import fi.gekkio.ghidraboy.*;
import java.nio.file.*;
public class GhidraBoyAbi extends GhidraScript {
    @Override public void run() throws Exception {
        var args=getScriptArgs();
        Path input=args.length>0?Path.of(args[0]):askFile("Per-function ABI request JSON","Preview").toPath();
        var at=args.length>1?currentProgram.getAddressFactory().getAddress(args[1]):currentAddress;
        var function=currentProgram.getFunctionManager().getFunctionContaining(at);
        var request=ProgramMapping.JSON.fromJson(Files.readString(input),CompilerAbi.Request.class);
        println(ProgramMapping.JSON.toJson(CompilerAbi.preview(currentProgram,request)));
        boolean apply=isRunningHeadless()?args.length>2 && args[2].equals("apply"):askYesNo("Apply ABI","Apply this storage and cleanup to the selected function only?");
        if(apply) CompilerAbi.apply(currentProgram,function,request);
    }
}
