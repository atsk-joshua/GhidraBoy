// Self-authored diagnostic; use a disposable raw 32 KiB Program only.
// Records the current bus-model gap; successful execution is not mapper acceptance.
// @category Game Boy Tests
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.Files;
import java.nio.file.Path;
public class MapperStoreDiagnostics extends GhidraScript {
  void fixture(int at, String name, String... code) throws Exception {
    AddressSet body = new AddressSet();
    for (Instruction i: Assemblers.getAssembler(currentProgram).assemble(toAddr(at), code)) body.add(i.getMinAddress(),i.getMaxAddress());
    currentProgram.getFunctionManager().createFunction(name,toAddr(at),body,SourceType.USER_DEFINED);
  }
  public void run() throws Exception {
    if (getScriptArgs().length != 1) throw new IllegalArgumentException("Expected output path");
    if (currentProgram.getFunctionManager().getFunctionCount() != 0
        || currentProgram.getMemory().getSize() != 0x8000
        || currentProgram.getMemory().getMinAddress().getOffset() != 0
        || currentProgram.getMemory().getMaxAddress().getOffset() != 0x7fff)
      throw new IllegalArgumentException("Use a fresh zero-filled 32 KiB raw Program");
    byte[] source = new byte[0x8000];
    currentProgram.getMemory().getBytes(toAddr(0), source);
    for (byte value : source) if (value != 0)
      throw new IllegalArgumentException("Diagnostic accepts only the self-authored zero-filled fixture");
    currentProgram.getMemory().setByte(toAddr(0x2000),(byte)0x5a);
    currentProgram.getMemory().setByte(toAddr(0x2100),(byte)0x5a);
    currentProgram.getMemory().createInitializedBlock("workram",toAddr(0xc000),0x2000,(byte)0,monitor,false);
    fixture(0x100,"control_write_then_rom_read","LD A, 2","LD (0x2000), A","LD A, (0x2000)","LD (0xc000), A","RET");
    fixture(0x120,"ordinary_ram_write_read","LD A, 2","LD (0xc001), A","LD A, (0xc001)","LD (0xc000), A","RET");
    fixture(0x140,"indirect_control_write_then_rom_read","LD HL, 0x2100","LD A, 2","LD (HL), A","LD A, (0x2100)","LD (0xc002), A","RET");
    currentProgram.getMemory().getBlock(toAddr(0)).setWrite(false);
    DecompInterface d=new DecompInterface();
    var options = new ghidra.app.decompiler.DecompileOptions();
    options.setRespectReadOnly(true);
    d.setOptions(options);
    if(!d.openProgram(currentProgram)) throw new Exception(d.getLastMessage());
    StringBuilder out=new StringBuilder();
    try {
      for(var it=currentProgram.getFunctionManager().getFunctions(true);it.hasNext();) {
        var f=it.next();var r=d.decompileFunction(f,10,monitor);
        out.append("\n=== ").append(f.getName()).append(" completed=").append(r.decompileCompleted()).append(" errors=").append(r.getErrorMessage()).append(" ===\n");
        if(r.getDecompiledFunction()!=null)out.append(r.getDecompiledFunction().getC());
      }
    } finally {d.dispose();}
    out.append("\nSTATIC_SOURCE_BYTE_2000=").append(currentProgram.getMemory().getByte(toAddr(0x2000)) & 255).append("\n");
    Files.writeString(Path.of(getScriptArgs()[0]),out.toString());
    println("MAPPER_STORE_DIAGNOSTICS_COMPLETE");
  }
}
