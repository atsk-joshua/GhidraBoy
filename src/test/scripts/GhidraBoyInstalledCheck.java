// Verify loader discovery, persisted checksum data, mapping and symbol ownership.
// @category Game Boy Tests
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.data.EndianSettingsDefinition;
import fi.gekkio.ghidraboy.*;
import java.nio.file.*;
public class GhidraBoyInstalledCheck extends GhidraScript {
    @Override public void run() throws Exception {
        var p=currentProgram;
        if(!p.getExecutableFormat().equals("Game Boy")) throw new AssertionError("Loader discovery: "+p.getExecutableFormat());
        var header=p.getListing().getDataAt(toAddr(0x134));
        var checksum=header.getComponentContaining(0x1a);
        if(((Scalar)checksum.getValue()).getUnsignedValue()!=0x1234 || EndianSettingsDefinition.DEF.getChoice(checksum)!=EndianSettingsDefinition.BIG)
            throw new AssertionError("Persisted checksum data/endian");
        var original=ProgramMapping.exportBytes(p,false,false,monitor);
        var current=ProgramMapping.exportBytes(p,true,false,monitor);
        if(!java.util.Arrays.equals(original,current)) throw new AssertionError("Untouched round trip");
        var parsed=SymbolFile.parse("2:4010 Label\n2:4010 Label\n2:4011 Label.local\n4002 AnyBank\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        SymbolService.importSymbols(p,parsed,"synthetic.sym",monitor);
        long count=p.getSymbolTable().getNumSymbols();
        SymbolService.importSymbols(p,parsed,"synthetic.sym",monitor);
        if(count!=p.getSymbolTable().getNumSymbols()) throw new AssertionError("Symbol idempotence");
        if(!SymbolService.exportRetained(p,"synthetic.sym").contains("Label.local")) throw new AssertionError("Retained symbols");
        println("INSTALLED_LOADER_CHECKSUM_SYMBOLS_PASS");
    }
}
