// @category Game Boy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import java.nio.file.*;

/** Explicit cartridge load for retained code occupying the normal logo area. */
public class GhidraBoyFiniteDispatchImport extends GhidraScript {
  @Override public void run() throws Exception {
    var args=getScriptArgs();var input=Path.of(args[0]);var language=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("SM83:LE:16:default"));
    Object consumer=new Object();var program=new ProgramDB(input.getFileName().toString(),language,language.getDefaultCompilerSpec(),consumer);
    try {
      try(var provider=new ByteArrayProvider(Files.readAllBytes(input))) {CartridgeLayout.load(program,provider,"CARTRIDGE","AUTO",GameBoyKind.GB,true,false,monitor,new MessageLog());}
      var file=state.getProject().getProjectData().getRootFolder().createFile(input.getFileName().toString(),program,monitor);
      currentProgram=program;currentAddress=program.getAddressFactory().getDefaultAddressSpace().getAddress(0x100);state.setCurrentProgram(program);state.setCurrentAddress(currentAddress);
      runScript("GhidraBoyFiniteDispatch.java",java.util.Arrays.copyOfRange(args,1,args.length),state);
      program.save("Current finite-dispatch capture",monitor);
      println("FINITE_DISPATCH_SAVED "+file.getPathname());
    } finally {state.setCurrentProgram(null);program.release(consumer);}
  }
}
