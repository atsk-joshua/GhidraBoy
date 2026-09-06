// Persist with the old provider; reopen and check with the candidate provider.
// Self-authored opcode corpus. Never run seed against an existing student Program.
// @category Game Boy Tests
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class GhidraBoyInstructionCompatibility extends GhidraScript {
  private static final Set<Integer> INVALID = Set.of(0xd3,0xdb,0xdd,0xe3,0xe4,0xeb,0xec,0xed,0xf4,0xfc,0xfd);
  private void decode(int at, byte... bytes) throws Exception {
    currentProgram.getMemory().setBytes(toAddr(at),bytes);
    var decoded = new PseudoDisassembler(currentProgram).disassemble(toAddr(at));
    if (decoded == null) throw new AssertionError("Invalid fixture opcode at " + toAddr(at));
    var range = new AddressSet(toAddr(at),toAddr(at).add(decoded.getLength()-1));
    var command = new DisassembleCommand(toAddr(at),range,false);
    if (!command.applyTo(currentProgram,monitor) || getInstructionAt(toAddr(at)) == null)
      throw new AssertionError("Cannot decode self-authored opcode at " + toAddr(at));
  }
  private void seed() throws Exception {
    if (currentProgram.getListing().getNumInstructions() != 0
        || currentProgram.getFunctionManager().getFunctionCount() != 0
        || currentProgram.getMemory().getSize() != 0x8000)
      throw new IllegalArgumentException("Seed requires fresh zero-filled 32 KiB raw Program");
    byte[] source = new byte[0x8000];
    currentProgram.getMemory().getBytes(toAddr(0),source);
    for (byte value:source) if(value != 0) throw new IllegalArgumentException("Seed requires zero-filled source");
    for (int op=0;op<256;op++) if(!INVALID.contains(op))
      decode(0x100+op*16,(byte)op,(byte)0x34,(byte)0x12);
    for (int op=0;op<256;op++) decode(0x2000+op*16,(byte)0xcb,(byte)op);
  }
  private List<String> pcode(Instruction instruction) {
    List<String> result = new ArrayList<>();
    for(PcodeOp op:instruction.getPcode(false)) result.add(op.toString());
    return result;
  }
  @Override public void run() throws Exception {
    String[] args=getScriptArgs();
    if(args.length!=2 || (!args[0].equals("seed") && !args[0].equals("check")))
      throw new IllegalArgumentException("Expected seed|check output-path");
    if(args[0].equals("seed")) seed();
    var fresh=new PseudoDisassembler(currentProgram);
    List<String> mismatches=new ArrayList<>();
    int count=0;
    for(var iterator=currentProgram.getListing().getInstructions(true);iterator.hasNext();) {
      var saved=iterator.next();
      String savedDisplay=saved.toString();int savedLength=saved.getLength();var savedPcode=pcode(saved);
      var decoded=fresh.disassemble(saved.getAddress());count++;
      if(decoded==null || savedLength!=decoded.getLength() || !savedDisplay.equals(decoded.toString())
          || !savedPcode.equals(pcode(decoded)))
        mismatches.add(saved.getAddress()+" saved="+savedDisplay+" fresh="+decoded+" savedPcode="+savedPcode
            +" freshPcode="+(decoded==null?"NONE":pcode(decoded)));
    }
    if(count!=501)mismatches.add("Expected501 instructions, got"+count);
    String report="mode="+args[0]+"\ninstructions="+count+"\nmismatches="+mismatches.size()+"\n"+String.join("\n",mismatches)+"\n";
    Files.writeString(Path.of(args[1]),report);
    if(!mismatches.isEmpty())throw new AssertionError(report);
    println("INSTRUCTION_COMPATIBILITY_PASS instructions="+count);
  }
}
