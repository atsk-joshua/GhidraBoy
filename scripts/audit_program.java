// Read-only audit of the copied program and its retained annotations.
//@category GBC
import ghidra.app.script.GhidraScript;
import java.nio.file.*;
public class audit_program extends GhidraScript {
    public void run() throws Exception {
        String report="language="+currentProgram.getLanguageID()+"\nblocks="+currentProgram.getMemory().getBlocks().length+"\nfunctions="+currentProgram.getFunctionManager().getFunctionCount()+"\nsymbols="+currentProgram.getSymbolTable().getNumSymbols()+"\n";
        println(report);
        for(var block:currentProgram.getMemory().getBlocks())println(block.getName()+" "+block.getStart()+" size="+block.getSize());
    }
}
