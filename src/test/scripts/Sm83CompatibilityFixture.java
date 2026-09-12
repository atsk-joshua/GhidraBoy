// Additional self-authored preservation discriminators, applied only to task-owned fixtures.
// @category Game Boy Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.math.BigInteger;

public class Sm83CompatibilityFixture extends GhidraScript {
  @Override public void run() throws Exception {
    var p=currentProgram;var a=toAddr(0x150);
    if(p.getLanguage().getVersion()!=1)throw new AssertionError("Old language required");
    for(var block:p.getMemory().getBlocks())if(block.getName().startsWith("rom")||block.getName().equals("student bank")){block.setWrite(false);block.setExecute(true);}
    var ns=p.getSymbolTable().createNameSpace(p.getGlobalNamespace(),"Research",SourceType.USER_DEFINED);
    var f=p.getFunctionManager().getFunctionAt(a);f.setParentNamespace(ns);f.setComment("preserve Function comment");f.setRepeatableComment("preserve repeatable Function comment");f.setCallingConvention("__asm");
    f.addParameter(new ParameterImpl("input",WordDataType.dataType,new VariableStorage(p,p.getRegister("BC")),p),SourceType.USER_DEFINED);
    f.addLocalVariable(new LocalVariableImpl("saved_local",WordDataType.dataType,4,p),SourceType.USER_DEFINED);
    var t=new StructureDataType("PreservationPair",0);t.add(ByteDataType.dataType,"tag","tag comment");t.add(WordDataType.dataType,"payload","payload comment");
    var d=p.getListing().createData(toAddr(0x300),t);d.setLong("format",1);
    for(int type=0;type<=4;type++)p.getListing().setComment(toAddr(0x300),type,"preserve comment type "+type);
    var secondary=p.getSymbolTable().createLabel(toAddr(0x300),"explicit_target",ns,SourceType.USER_DEFINED);secondary.setPinned(true);
    var ref=p.getReferenceManager().addMemoryReference(a,toAddr(0x300),RefType.DATA,SourceType.USER_DEFINED,0);p.getReferenceManager().setPrimary(ref,true);p.getReferenceManager().setAssociation(secondary,ref);
    p.getOptions("GhidraBoy").setString("hardware","GB");p.getOptions("GhidraBoy").setString("student.assumption","retained manual assumption");
    p.getProgramContext().setValue(p.getRegister("BC"),a,a.add(2),new BigInteger("1234",16));
    for(var name:new String[]{"rom1","student bank"}) {
      var b=p.getMemory().getBlock(name);var start=b.getStart();p.getMemory().setBytes(start,new byte[]{0x3e,0x22,(byte)0xc9});disassemble(start);
      p.getProgramContext().setValue(p.getRegister("DE"),start,start.add(2),BigInteger.valueOf(name.equals("rom1")?0x2345:0x4567));
      b.setComment("preserve overlay "+name);b.setExecute(true);
    }
    p.getMemory().setBytes(toAddr(0x180),new byte[]{(byte)0xc3,0x50,1});disassemble(toAddr(0x180));
    var thunk=p.getFunctionManager().createFunction("user_thunk",toAddr(0x180),new AddressSet(toAddr(0x180),toAddr(0x182)),SourceType.USER_DEFINED);thunk.setThunkedFunction(f);
    println("SM83_ANNOTATED_FIXTURE_PASS");
  }
}
