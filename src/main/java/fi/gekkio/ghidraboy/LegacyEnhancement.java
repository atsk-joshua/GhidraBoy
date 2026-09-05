package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** Explicit metadata-only reconstruction: never changes an annotated program's topology. */
public final class LegacyEnhancement {
    private LegacyEnhancement() { }
    public static ProgramMapping.Snapshot enhance(Program p,String mapperOverride,TaskMonitor monitor) throws Exception {
        if(!p.getLanguageID().toString().equals("SM83:LE:16:default")) throw new IllegalArgumentException("Not an SM83 program");
        if(ProgramMapping.cartridge(p)!=null) return ProgramMapping.inspect(p);
        var source=ProgramMapping.originalFile(p);
        byte[] bytes=new byte[Math.toIntExact(source.getSize())]; source.getOriginalBytes(0,bytes);
        var descriptor=Cartridge.parse(bytes,mapperOverride);
        monitor.checkCancelled();
        int tx=p.startTransaction("Explicit GhidraBoy metadata enhancement"); boolean success=false;
        try {
            var opts=p.getOptions(ProgramMapping.OPTIONS);
            opts.setInt("schemaVersion",ProgramMapping.SCHEMA_VERSION);
            opts.setString("cartridge",ProgramMapping.JSON.toJson(descriptor));
            opts.setString("inputMode","CARTRIDGE");
            opts.setString("mappingProvenance","Explicit legacy reconstruction from original FileBytes; RAM remains unresolved without anchors");
            opts.setString("mapperOverride",mapperOverride);
            monitor.checkCancelled(); success=true;
        } finally { p.endTransaction(tx,success); }
        return ProgramMapping.inspect(p);
    }
}
