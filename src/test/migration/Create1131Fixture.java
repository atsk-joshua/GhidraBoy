// Creates a self-authored annotated database using actual Ghidra 11.3.1 only.
// @category Game Boy Tests
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.disassemble.Disassembler;
import ghidra.app.emulator.EmulatorHelper;
import fi.gekkio.ghidraboy.GameBoyUtils;
import fi.gekkio.ghidraboy.GameBoyKind;

public class Create1131Fixture extends GhidraScript {
    @Override public void run() throws Exception {
        if(!ghidra.framework.Application.getApplicationVersion().equals("11.3.1")) throw new AssertionError("Actual 11.3.1 required");
        var lang=getLanguage(new LanguageID("SM83:LE:16:default"));
        var p=new ProgramDB("preserved1131",lang,lang.getDefaultCompilerSpec(),this);
        int tx=p.startTransaction("Original 11.3.1 annotations");
        try {
            byte[] bytes=new byte[0x10000]; bytes[0x143]=(byte)0x80; bytes[0x147]=3; bytes[0x148]=1;
            bytes[0x150]=(byte)0xce; bytes[0x151]=0; bytes[0x152]=(byte)0xc9;
            var as=p.getAddressFactory().getDefaultAddressSpace();
            try(var provider=new ByteArrayProvider(bytes)) {
                var file=MemoryBlockUtils.createFileBytes(p,provider,monitor);
                p.getMemory().createInitializedBlock("rom0",as.getAddress(0),file,0,0x4000,false);
                for(int bank=1;bank<4;bank++) p.getMemory().createInitializedBlock("rom"+bank,as.getAddress(0x4000),file,bank*0x4000,0x4000,true);
            }
            GameBoyUtils.addHardwareBlocks(p,GameBoyKind.GB,new MessageLog());
            // A known historical manual hardware choice contradicts the header on purpose.
            p.getOptions("GhidraBoy").setString("hardware","GB");
            var a=as.getAddress(0x150);
            var ns=p.getSymbolTable().createNameSpace(p.getGlobalNamespace(),"UserNamespace",SourceType.USER_DEFINED);
            p.getSymbolTable().createLabel(a,"user_label",ns,SourceType.USER_DEFINED);
            p.getListing().setComment(a,CodeUnit.EOL_COMMENT,"keep comment 1131");
            p.getBookmarkManager().setBookmark(a,"Note","student","keep bookmark 1131");
            Disassembler.getDisassembler(p,monitor,null).disassemble(a,new AddressSet(a,a.add(2)));
            var f=p.getFunctionManager().createFunction("user_function",a,new AddressSet(a,a.add(2)),SourceType.USER_DEFINED);
            f.setCustomVariableStorage(true);
            f.setReturn(ByteDataType.dataType,new VariableStorage(p,p.getRegister("A")),SourceType.USER_DEFINED);
            p.getListing().getInstructionAt(a).setFallThrough(a.add(3));
            var type=new StructureDataType("UserType1131",0); type.add(ByteDataType.dataType,"owned",null);
            p.getDataTypeManager().addDataType(type,DataTypeConflictHandler.KEEP_HANDLER);
            var bank=p.getMemory().getBlock("rom2"); bank.setName("student bank 1131");
            p.getMemory().setByte(bank.getStart().add(0x12),(byte)0x5a);
            var emu=new EmulatorHelper(p);
            try {
                emu.writeRegister("PC",0x150); emu.writeRegister("A",255); emu.writeRegister("F",16);
                if(!emu.step(monitor)) throw new AssertionError(emu.getLastError());
                if(emu.readRegister("A").intValue()!=0 || (emu.readRegister("F").intValue()&16)!=0) throw new AssertionError("Expected original ADC defect on historical language");
            } finally { emu.dispose(); }
            p.endTransaction(tx,true); tx=-1;
            state.getProject().getProjectData().getRootFolder().createFile("preserved1131",p,monitor);
            println("ACTUAL_1131_CREATED_WITH_OLD_ADC");
        } finally { if(tx!=-1) p.endTransaction(tx,false); p.release(this); }
    }
}
