// Self-authored guarded 6-case fixture: catches native operation/common-varnode index confusion.
//@category Game Boy.Tests
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.ByteDataType;
import fi.gekkio.ghidraboy.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;

public class NormalizedSwitchRegression extends GhidraScript {
    static final Gson JSON=new GsonBuilder().serializeNulls().setPrettyPrinting().create();
    ProgramDB fixture;
    Address a(int offset){return fixture.getAddressFactory().getDefaultAddressSpace().getAddress(offset);}
    void assemble(AddressSet body,int start,String...code)throws Exception {
        for(var instruction:Assemblers.getAssembler(fixture).assemble(a(start),code))body.add(instruction.getMinAddress(),instruction.getMaxAddress());
    }
    public void run()throws Exception {
        Path out=Path.of(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("New output directory required");Files.createDirectories(out);
        var language=currentProgram==null?DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("SM83:LE:16:default")):currentProgram.getLanguage();Object consumer=new Object();fixture=new ProgramDB("guarded-phase-switch",language,language.getDefaultCompilerSpec(),consumer);
        try {
            int tx=fixture.startTransaction("Construct self-authored switch fixture");Function function;
            var targets=new ArrayList<Address>();
            try {
                fixture.getMemory().createInitializedBlock("code_and_tables",a(0),0x400,(byte)0xd3,monitor,false);
                GameBoyUtils.addHardwareBlocks(fixture,GameBoyKind.CGB,new MessageLog());
                var body=new AddressSet();
                assemble(body,0x100,"LD A, (0xff80)","CP 6","JR C, 0x010a","XOR A","RET");
                assemble(body,0x10a,"LD B, 0","CP 3","JR C, 0x0116","LD B, 3","SUB 3","JR 0x0116",
                    "LD HL, 0x0200","ADD L","LD L, A","LD A, H","ADC 0","LD H, A","LD A, (HL)","DEC A","ADD B",
                    "LD HL, 0x0203","ADD A","ADD L","LD L, A","LD A, H","ADC 0","LD H, A","LD A, (HL+)","LD H, (HL)","LD L, A","JP HL");
                fixture.getMemory().setBytes(a(0x200),new byte[]{1,2,3});
                for(int index=0;index<6;index++) {
                    Address target=a(0x300+3*index);targets.add(target);
                    fixture.getMemory().setShort(a(0x203+2*index),(short)target.getOffset());
                    assemble(body,(int)target.getOffset(),"LD A, "+(10*(index+1)),"RET");
                }
                function=fixture.getFunctionManager().createFunction("guarded_phase_switch",a(0x100),body,SourceType.USER_DEFINED);
                function.updateFunction("default",new ReturnParameterImpl(ByteDataType.dataType,fixture.getRegister("A"),fixture),Function.FunctionUpdateType.CUSTOM_STORAGE,true,SourceType.USER_DEFINED);
            }finally{fixture.endTransaction(tx,true);}
            byte[] fixtureBytes=new byte[0x400];fixture.getMemory().getBytes(a(0),fixtureBytes);Files.write(out.resolve("fixture.bin"),fixtureBytes);
            var probe=new DecompInterface();probe.setSimplificationStyle("normalize");probe.openProgram(fixture);
            NormalizedSwitchDecompiler.Norm norm=null;String definition=null;
            try {
                var result=probe.decompileFunction(function,30,monitor);if(!result.decompileCompleted())throw new IllegalStateException(result.getErrorMessage());
                var high=result.getHighFunction();var iterator=high.getPcodeOps(a(0x121));
                while(iterator.hasNext()) {
                    var op=iterator.next();if(op.getOpcode()!=PcodeOp.INT_ADD||op.getOutput()==null||op.getOutput().getSize()!=1)continue;
                    if(norm!=null)throw new IllegalStateException("Ambiguous index");var hash=new DynamicHash(op.getOutput(),high);
                    if(DynamicHash.findVarnode(high,hash.getAddress(),hash.getHash())!=op.getOutput())throw new IllegalStateException("Hash roundtrip failed");
                    norm=new NormalizedSwitchDecompiler.Norm(hash.getAddress(),hash.getHash());definition=op.toString();
                }
            }finally{probe.dispose();}
            if(norm==null)throw new IllegalStateException("Missing source index at0121");
            var report=new TreeMap<String,Object>();report.put("sourceIndex",definition);report.put("normHash",Long.toUnsignedString(norm.hash(),16));report.put("normAddress",norm.address().toString());
            var decompiler=new NormalizedSwitchDecompiler(a(0x100),a(0x12f),targets,norm);decompiler.openProgram(fixture);
            boolean valid=false;
            try {
                var result=decompiler.decompileFunction(function,30,monitor);report.put("completed",result.decompileCompleted());report.put("error",result.getErrorMessage());report.put("injections",decompiler.getInjections());
                if(result.getDecompiledFunction()!=null)Files.writeString(out.resolve("fixture.c"),result.getDecompiledFunction().getC());
                var branches=new ArrayList<Object>();var high=result.getHighFunction();
                if(high!=null) {
                    for(var table:high.getJumpTables()) {
                        report.put("table",Map.of("cases",Arrays.stream(table.getCases()).map(Object::toString).toList(),"labels",Arrays.asList(table.getLabelValues())));
                        if(!Arrays.asList(table.getCases()).equals(targets)||!Arrays.asList(table.getLabelValues()).equals(List.of(0,1,2,3,4,5)))
                            throw new IllegalStateException("Native case labels/targets differ from guarded fixture mapping");
                    }
                    var ops=high.getPcodeOps();while(ops.hasNext()) {
                        var op=ops.next();if(op.getOpcode()!=PcodeOp.BRANCHIND)continue;
                        var def=op.getInput(0).getDef();branches.add(Map.of("operation",op.toString(),"definition",def==null?"input":def.toString()));
                        // The full index must survive: the ADD at0121 combines lookup-1 with phase B.
                        valid=def!=null&&def.getSeqnum().getTarget().equals(a(0x121))&&def.getOpcode()==PcodeOp.INT_ADD&&Arrays.stream(def.getInputs()).noneMatch(Varnode::isConstant);
                    }
                }
                report.put("branches",branches);report.put("status",valid&&result.decompileCompleted()?"PASS":"FAIL");
            }finally{decompiler.dispose();}
            Files.writeString(out.resolve("result.json"),JSON.toJson(report));
            if(!valid)throw new IllegalStateException("Full phase+lookup switch index was not retained");
            println("NORMALIZED_SWITCH_REGRESSION_FINISHED PASS");
        }finally{fixture.release(consumer);}
    }
}
