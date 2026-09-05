// Export the 64 mapped ROM banks from the reviewed student program.
// This reads program memory only. It never modifies the Ghidra program.
//@category GBW3
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import java.nio.file.*;
import java.security.MessageDigest;

public class ExportGBW3ROM extends GhidraScript {
    public void run() throws Exception {
        if (currentProgram == null || !currentProgram.getLanguageID().toString().equals("SM83:LE:16:default"))
            throw new IllegalStateException("Open the reviewed Game Boy Wars 3 program first.");
        byte[] rom = new byte[1048576];
        for (int bank=0; bank<64; bank++) {
            MemoryBlock block=currentProgram.getMemory().getBlock("rom"+bank);
            if (block==null || !block.isInitialized() || block.getSize()!=16384)
                throw new IllegalStateException("Expected initialized rom0..rom63 blocks.");
            currentProgram.getMemory().getBytes(block.getStart(),rom,bank*16384,16384);
        }
        StringBuilder hash=new StringBuilder();
        for (byte b:MessageDigest.getInstance("SHA-256").digest(rom))
            hash.append(String.format("%02x",b&255));
        if (!hash.toString().equals("e779a6b56575a2afafb7e1e99411b23d7400a8fddbda8bd52c660b7903c3b451"))
            throw new IllegalStateException("Mapped ROM bytes do not match the reviewed student version.");
        String[] args=getScriptArgs();
        Path output=args.length>0 ? Paths.get(args[0]) : askFile("Export student ROM to a NEW .gbc file", "Export").toPath();
        Files.write(output,rom,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
        println("Exported "+output.toAbsolutePath()+"; SHA256 "+hash);
    }
}
