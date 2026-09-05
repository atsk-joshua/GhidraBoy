// Export the opened program's authoritative knowledge without modifying it.
//@category GBC
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.CodeUnit;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;
public class ExportGbcKnowledge extends GhidraScript {
    public void run() throws Exception {
        if(currentProgram==null)throw new IllegalStateException("Open the copied program first");
        var result=new LinkedHashMap<String,Object>();result.put("schema","ghigbc-knowledge-v1");result.put("language",currentProgram.getLanguageID().toString());result.put("compiler",currentProgram.getCompilerSpec().getCompilerSpecID().toString());result.put("program",currentProgram.getDomainFile().getPathname());
        var blocks=new ArrayList<Object>();
        for(var b:currentProgram.getMemory().getBlocks()){
            var row=new LinkedHashMap<String,Object>();row.put("name",b.getName());row.put("space",b.getStart().getAddressSpace().getName());row.put("start",b.getStart().getOffset());row.put("length",b.getSize());row.put("comment",b.getComment());
            var sources=new ArrayList<Object>();for(var info:b.getSourceInfos()){
                var source=new LinkedHashMap<String,Object>();source.put("start",info.getMinAddress().toString());source.put("length",info.getLength());source.put("description",info.getDescription());
                if(info.getFileBytes().isPresent()){source.put("file_offset",info.getFileBytesOffset());source.put("file_name",info.getFileBytes().get().getFilename());}
                sources.add(source);
            }row.put("sources",sources);blocks.add(row);
        }result.put("blocks",blocks);
        var symbols=new ArrayList<Object>();var si=currentProgram.getSymbolTable().getAllSymbols(true);
        while(si.hasNext()){var s=si.next();symbols.add(Map.of("name",s.getName(),"namespace",s.getParentNamespace().getName(true),"address",s.getAddress().toString(),"type",s.getSymbolType().toString(),"source",s.getSource().toString()));}result.put("symbols",symbols);
        var functions=new ArrayList<Object>();var fi=currentProgram.getFunctionManager().getFunctions(true);
        while(fi.hasNext()){var f=fi.next();functions.add(Map.of("name",f.getName(true),"entry",f.getEntryPoint().toString(),"signature",f.getSignature().toString()));}result.put("functions",functions);
        var structures=new ArrayList<Object>();var di=currentProgram.getDataTypeManager().getAllDataTypes();
        while(di.hasNext()){var type=di.next();if(!(type instanceof Structure structure))continue;var components=new ArrayList<Object>();for(var c:structure.getDefinedComponents()){var row=new LinkedHashMap<String,Object>();row.put("name",c.getFieldName());row.put("offset",c.getOffset());row.put("length",c.getLength());row.put("type",c.getDataType().getPathName());row.put("comment",c.getComment());components.add(row);}structures.add(Map.of("name",structure.getPathName(),"length",structure.getLength(),"components",components));}result.put("structures",structures);
        var comments=new ArrayList<Object>();var units=currentProgram.getListing().getCodeUnits(true);
        while(units.hasNext()){var unit=units.next();for(int kind:new int[]{CodeUnit.EOL_COMMENT,CodeUnit.PRE_COMMENT,CodeUnit.POST_COMMENT,CodeUnit.PLATE_COMMENT,CodeUnit.REPEATABLE_COMMENT}){String comment=unit.getComment(kind);if(comment!=null)comments.add(Map.of("address",unit.getAddress().toString(),"kind",kind,"text",comment));}}result.put("comments",comments);
        String[] args=getScriptArgs();Path out=args.length>0?Path.of(args[0]):askFile("Export knowledge to a NEW .knowledge.json file","Export").toPath();
        Files.writeString(out,new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(result),StandardOpenOption.CREATE_NEW);
        println("Exported "+symbols.size()+" symbols, "+functions.size()+" functions, "+structures.size()+" structures, "+comments.size()+" comments to "+out);
    }
}
