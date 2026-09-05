// Inspect, navigate, import symbols, and export a Game Boy program.
// @category Game Boy
import ghidra.app.script.GhidraScript;
import fi.gekkio.ghidraboy.*;
import java.nio.file.*;
import java.util.*;

public class GhidraBoyTools extends GhidraScript {
    @Override public void run() throws Exception {
        if(currentProgram==null) throw new IllegalStateException("Open a Game Boy program first");
        String[] args=getScriptArgs();
        String action=args.length>0?args[0]:askChoice("GhidraBoy", "Action", List.of("inspect","mapping-json","navigate-file","navigate-physical","navigate-cpu","import-sym","export-retained-sym","export-sym","export-original","export-current","export-repair","enhance-legacy","analyze","discover-functions","far-call-convention"),"inspect");
        String value=args.length>1?args[1]:null;
        switch(action) {
            case "discover-functions" -> {
                String json=currentProgram.getOptions(ProgramMapping.OPTIONS).getString("analysis.latest","null");
                var findings=ProgramMapping.JSON.fromJson(json,AnalysisResult.class);
                FunctionDiscovery.discover(currentProgram,List.of(),findings,monitor).forEach(this::println);
            }
            case "far-call-convention" -> {
                Path file=value==null?askFile("Explicit verified far-call JSON", "Apply").toPath():Path.of(value);
                var convention=ProgramMapping.JSON.fromJson(Files.readString(file),FarCallConvention.class);
                convention.apply(currentProgram,monitor).forEach(this::println);
            }
            case "enhance-legacy" -> println(ProgramMapping.JSON.toJson(LegacyEnhancement.enhance(currentProgram,value==null?"AUTO":value,monitor)));
            case "analyze" -> {
                String json=value==null?askString("Explicit assumption", "MapperState JSON at current address (or null for unknown)"):value;
                var assumption=ProgramMapping.JSON.fromJson(json,MapperState.class);
                var start=args.length>2?currentProgram.getAddressFactory().getAddress(args[2]):currentAddress;
                println(ProgramMapping.JSON.toJson(BankAnalysis.analyze(currentProgram,start,assumption,monitor,true)));
            }
            case "inspect" -> println(ProgramMapping.JSON.toJson(ProgramMapping.inspect(currentProgram)));
            case "mapping-json" -> {
                Path output=value==null?askFile("New mapping JSON", "Export").toPath():Path.of(value);
                Files.writeString(output,ProgramMapping.JSON.toJson(ProgramMapping.inspect(currentProgram)),StandardOpenOption.CREATE_NEW);
                println(output.toString());
            }
            case "navigate-file" -> {
                String off=value==null?askString("ROM file offset", "Hexadecimal offset"):value;
                choose(ProgramMapping.fileToStatic(currentProgram,Long.parseLong(off,16)));
            }
            case "navigate-physical" -> {
                String spec=value==null?askString("Physical address", "REGION:hexBank:hexOffset (e.g. WRAM:3:34)"):value;
                String[] parts=spec.split(":");
                choose(ProgramMapping.physicalToStatic(currentProgram,new MapperState.Physical(parts[0],Integer.parseInt(parts[1],16),Integer.parseInt(parts[2],16))));
            }
            case "navigate-cpu" -> {
                String spec=value==null?askString("CPU address", "Hex CPU address"):value;
                String json=args.length>2?args[2]:askString("Explicit mapper state", "MapperState JSON (inspect documentation for fields)");
                var c=ProgramMapping.cartridge(currentProgram);
                if(c==null) throw new IllegalStateException("No cartridge descriptor");
                var state=ProgramMapping.JSON.fromJson(json,MapperState.class);
                var result=MapperState.translate(c,state,Integer.parseInt(spec,16),false);
                println(ProgramMapping.JSON.toJson(result));
                if(result.physical()!=null) choose(ProgramMapping.cpuToStatic(currentProgram,state,Integer.parseInt(spec,16),false).addresses());
            }
            case "import-sym" -> {
                Path file=value==null?askFile("RGBDS .sym file", "Preview").toPath():Path.of(value);
                var parsed=SymbolFile.parse(Files.readAllBytes(file));
                parsed.diagnostics().forEach(this::println);
                SymbolService.preview(currentProgram,parsed).forEach(p->println(p.toString()));
                if(isRunningHeadless() || askYesNo("Import symbols", "Apply the displayed preview?"))
                    SymbolService.importSymbols(currentProgram,parsed,file.toAbsolutePath().toString(),monitor);
            }
            case "export-sym" -> {
                Path output=value==null?askFile("New .sym output", "Export").toPath():Path.of(value);
                var exported=SymbolService.exportSymbols(currentProgram,monitor);
                exported.diagnostics().forEach(this::println);
                Files.writeString(output,exported.text(),StandardOpenOption.CREATE_NEW);
            }
            case "export-retained-sym" -> {
                String source=value==null?askString("Original symbol source", "Absolute source file path"):value;
                Path output=args.length>2?Path.of(args[2]):askFile("New .sym output", "Export").toPath();
                Files.writeString(output,SymbolService.exportRetained(currentProgram,source),StandardOpenOption.CREATE_NEW);
            }
            case "export-original", "export-current", "export-repair" -> {
                Path output=value==null?askFile("New ROM output", "Export").toPath():Path.of(value);
                boolean current=!action.equals("export-original"), repair=action.equals("export-repair");
                byte[] bytes=ProgramMapping.exportBytes(currentProgram,current,repair,monitor);
                if(repair) {
                    byte[] before=ProgramMapping.exportBytes(currentProgram,true,false,monitor);
                    for(int i=0;i<bytes.length;i++) if(bytes[i]!=before[i]) println(String.format("Checksum repair %04x: %02x -> %02x",i,before[i]&255,bytes[i]&255));
                }
                monitor.checkCancelled(); Files.write(output,bytes,StandardOpenOption.CREATE_NEW);
                println("SHA256 "+Sha256.of(bytes)+"  "+output);
            }
            default -> throw new IllegalArgumentException("Unknown action "+action);
        }
    }
    private void choose(List<ghidra.program.model.address.Address> addresses) throws Exception {
        if(addresses.isEmpty()) { println("Unmapped or no static execution view"); return; }
        addresses.forEach(a->println(a.toString()));
        if(isRunningHeadless()) return;
        goTo(addresses.size()==1?addresses.get(0):askChoice("Static execution views","Choose address",addresses,addresses.get(0)));
    }
}
