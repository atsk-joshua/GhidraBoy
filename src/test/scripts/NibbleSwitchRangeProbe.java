// Self-authored mask/SWAP switch range proof; no stored switch references/overrides.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.GsonBuilder;
import java.nio.file.*;
import java.util.*;
public class NibbleSwitchRangeProbe extends GhidraScript {
  @Override public void run() throws Exception {
    if (currentProgram == null || getScriptArgs().length != 1)
      throw new IllegalArgumentException("Fresh zero-filled 32 KiB RAW Program and new output path required");
    Path output = Path.of(getScriptArgs()[0]);
    if (Files.exists(output)) throw new IllegalArgumentException("Output already exists");
    if (!currentProgram.getLanguageID().toString().equals("SM83:LE:16:default")
        || !currentProgram.getExecutableFormat().equals("Raw Binary")
        || currentProgram.getFunctionManager().getFunctionCount() != 0
        || currentProgram.getListing().getInstructions(true).hasNext()
        || currentProgram.getMemory().getSize() != 0x8000
        || currentProgram.getMemory().getMinAddress().getOffset() != 0
        || currentProgram.getMemory().getMaxAddress().getOffset() != 0x7fff)
      throw new IllegalArgumentException("Use a fresh empty SM83 RAW fixture only");
    byte[] initial = new byte[0x8000];
    currentProgram.getMemory().getBytes(toAddr(0),initial);
    String inputHash = HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(initial));
    if (!inputHash.equals("c35020473aed1b4642cd726cad727b63fff2824ad68cedd7ffb73c7cbd890479"))
      throw new IllegalArgumentException("Input must be the generated zero-filled fixture");
    var body=new AddressSet();var assembler=Assemblers.getAssembler(currentProgram);
    currentProgram.getMemory().createInitializedBlock("work",toAddr(0xc000),0x1000,(byte)0,monitor,false).setWrite(true);
    for(int i=0;i<128;i++) {
      int target=0x1000+i*8;
      currentProgram.getMemory().setShort(toAddr(0x200+i*2),(short)target);
      for(Instruction instruction:assembler.assemble(toAddr(target),"POP HL","LD A, "+i,"LD (0xc000), A","RET"))
        if(i<16)body.add(instruction.getMinAddress(),instruction.getMaxAddress());
    }
    for(Instruction instruction:assembler.assemble(toAddr(0x100),"LD A, (HL)","AND 0xf0","SWAP A","ADD A","LD E, A","LD D, 0","LD A, (HL+)","PUSH HL","AND 0x0f","LD HL, 0x0200","ADD HL, DE","LD E, (HL)","INC HL","LD D, (HL)","LD H, D","LD L, E","JP HL"))
      body.add(instruction.getMinAddress(),instruction.getMaxAddress());
    currentProgram.getMemory().getBlock(toAddr(0)).setWrite(false);
    var f=currentProgram.getFunctionManager().createFunction("nibble_switch",toAddr(0x100),body,SourceType.USER_DEFINED);
    var d=new DecompInterface();d.setOptions(new DecompileOptions());
    var report=new LinkedHashMap<String,Object>();
    byte[] routine = new byte[23];
    currentProgram.getMemory().getBytes(toAddr(0x100),routine);
    report.put("routineHex",HexFormat.of().formatHex(routine));
    report.put("inputSha256",inputHash);
    try {
      if(!d.openProgram(currentProgram))throw new AssertionError(d.getLastMessage());
      var result=d.decompileFunction(f,30,monitor);
      report.put("completed",result.decompileCompleted());report.put("error",result.getErrorMessage());
      report.put("c",result.getDecompiledFunction()==null?null:result.getDecompiledFunction().getC());
      var tables=new ArrayList<Object>();
      if(result.getHighFunction()!=null)for(var table:result.getHighFunction().getJumpTables()) {
        var row=new LinkedHashMap<String,Object>();row.put("at",table.getSwitchAddress().toString());row.put("labels",table.getLabelValues());row.put("cases",Arrays.stream(table.getCases()).map(Object::toString).toList());tables.add(row);
      }
      report.put("tables",tables);
    } finally {d.dispose();}
    Files.writeString(output,new GsonBuilder().setPrettyPrinting().create().toJson(report));
    println("NIBBLE_SWITCH_RANGE_PROBE_COMPLETE");
  }
}
