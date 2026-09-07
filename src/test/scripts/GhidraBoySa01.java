// Self-authored generic SA-01 review/application persistence fixture.
// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CommentType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;

public class GhidraBoySa01 extends GhidraScript {
  private void require(boolean condition, String reason) {
    if (!condition) throw new AssertionError(reason);
  }

  @Override public void run() throws Exception {
    String mode = getScriptArgs()[0];
    Path work = Path.of(getScriptArgs()[1]);
    var c = new FarCallConvention("0028", FarCallConvention.SUPPORTED_BODY, List.of("0200"), 0xc100);
    if (mode.equals("prepare")) {
      int tx = currentProgram.startTransaction("Prepare self-authored call fixture");
      boolean commit = false;
      try {
        currentProgram.getMemory().setBytes(toAddr(0x28), HexFormat.of().parseHex(FarCallConvention.SUPPORTED_BODY));
        currentProgram.getMemory().setBytes(toAddr(0x200), HexFormat.of().parseHex("ef020040c9"));
        currentProgram.getMemory().setByte(ProgramMapping.fileToStatic(currentProgram, 0x8000).get(0), (byte) 0xc9);
        var dis = Disassembler.getDisassembler(currentProgram, monitor, null);
        dis.disassemble(toAddr(0x200), new AddressSet(toAddr(0x200)));
        dis.disassemble(toAddr(0x204), new AddressSet(toAddr(0x204)));
        currentProgram.getListing().setComment(toAddr(0x204), CommentType.EOL, "User continuation annotation");
        commit = true;
      } finally { currentProgram.endTransaction(tx, commit); }
      var reviewed = c.previewReviewed(currentProgram, monitor);
      Files.writeString(work.resolve("review.json"), ProgramMapping.JSON.toJson(reviewed));
      c.apply(currentProgram, reviewed, monitor);
      require(currentProgram.getListing().getInstructionAt(toAddr(0x200)).getFallThrough().equals(toAddr(0x204)), "adjusted continuation");
      println("SA01_PREPARE_PASS");
    } else if (mode.equals("reopen")) {
      var rst = currentProgram.getListing().getInstructionAt(toAddr(0x200));
      require(rst.getFallThrough().equals(toAddr(0x204)), "saved continuation");
      require("User continuation annotation".equals(currentProgram.getListing().getComment(CommentType.EOL, toAddr(0x204))), "saved user comment");
      AnalysisOwnership.remove(currentProgram, "far-call", monitor);
      require(!rst.isFallThroughOverridden(), "remove owned continuation after reopen");
      var reviewed = ProgramMapping.JSON.fromJson(Files.readString(work.resolve("review.json")), FarCallConvention.Preview.class);
      // Removal writes an empty ownership envelope, so exact review state changed; stale input rejects.
      boolean stale = false;
      try { c.apply(currentProgram, reviewed, monitor); } catch (IllegalStateException expected) { stale = true; }
      require(stale, "saved stale review must reject");
      c.apply(currentProgram, c.previewReviewed(currentProgram, monitor), monitor);
      int tx = currentProgram.startTransaction("Later user continuation edit");
      try { currentProgram.getListing().getInstructionAt(toAddr(0x200)).setFallThrough(toAddr(0x205)); }
      finally { currentProgram.endTransaction(tx, true); }
      require(currentProgram.getListing().getInstructionAt(toAddr(0x200)).getFallThrough().equals(toAddr(0x205)), "user edit committed in current listing");
      println("SA01_REOPEN_REAPPLY_PASS");
    } else if (mode.equals("edited")) {
      var rst = currentProgram.getListing().getInstructionAt(toAddr(0x200));
      require(rst.getFallThrough().equals(toAddr(0x205)), "user edit survived reopen");
      AnalysisOwnership.remove(currentProgram, "far-call", monitor);
      require(rst.getFallThrough().equals(toAddr(0x205)), "removal preserves user edit");
      boolean rejected = false;
      try { c.previewReviewed(currentProgram, monitor); } catch (IllegalArgumentException expected) { rejected = true; }
      require(rejected, "reapplication must not overwrite edited continuation");
      require("User continuation annotation".equals(currentProgram.getListing().getComment(CommentType.EOL, toAddr(0x204))), "user annotation preserved");
      println("SA01_EDITED_REOPEN_PASS");
    } else throw new IllegalArgumentException("Unknown phase");
  }
}
