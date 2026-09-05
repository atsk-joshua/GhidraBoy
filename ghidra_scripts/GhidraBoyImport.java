// Deliberately import a nonstandard cartridge or synthetic boot image into a NEW program.
// @category Game Boy
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import fi.gekkio.ghidraboy.*;
import java.nio.file.*;
import java.util.*;
public class GhidraBoyImport extends GhidraScript {
    @Override public void run() throws Exception {
        var args=getScriptArgs();
        Path input=args.length>0?Path.of(args[0]):askFile("Manual Game Boy input", "Import").toPath();
        String mode=args.length>1?args[1]:askChoice("Input mode","Explicit layout",List.of("CARTRIDGE","DMG_BOOT","CGB_BOOT"),"CARTRIDGE");
        String override=args.length>2?args[2]:"AUTO";
        var lang=getLanguage(new LanguageID("SM83:LE:16:default"));
        if(Files.size(input)>0x800000) throw new IllegalArgumentException("Input exceeds 8 MiB limit");
        var p=new ProgramDB(input.getFileName().toString(),lang,lang.getDefaultCompilerSpec(),this);
        try(var provider=new ByteArrayProvider(Files.readAllBytes(input))) {
            var kind=args.length>3?GameBoyKind.valueOf(args[3]):GameBoyKind.CGB;
            var log=new MessageLog();
            CartridgeLayout.load(p,provider,mode,override,kind,true,true,monitor,log);
            println(log.toString());
            state.getProject().getProjectData().getRootFolder().createFile(p.getName(),p,monitor);
            if(!isRunningHeadless()) openProgram(p);
        } finally { p.release(this); }
    }
}
