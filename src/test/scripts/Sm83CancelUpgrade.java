// Deterministic cancellation AFTER core translation, with no publication of the working copy.
// @category Game Boy Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;
import java.nio.file.*;
import com.google.gson.GsonBuilder;

public class Sm83CancelUpgrade extends GhidraScript {
  @Override public void run() throws Exception {
    var file=state.getProject().getProjectData().getRootFolder().getFile(getScriptArgs()[0]);
    var p=(Program)file.getDomainObject(this,true,false,monitor);
    try {
      if(p.getLanguage().getVersion()!=2)throw new AssertionError("Actual upgrade first");
      var before=Sm83PreservationInventory.inventory(p);int tx=p.startTransaction("Injected cancellable work");
      boolean cancelled=false;var cancel=new TaskMonitorAdapter(true);
      try {p.getListing().setComment(p.getAddressFactory().getDefaultAddressSpace().getAddress(0x150),CodeUnit.EOL_COMMENT,"unpublished partial edit");cancel.cancel();cancel.checkCancelled();}
      catch(CancelledException expected){cancelled=true;}finally{p.endTransaction(tx,false);}
      var after=Sm83PreservationInventory.inventory(p);
      Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(Sm83PreservationInventory.row("pid",ProcessHandle.current().pid(),"coreTranslated",true,"cancelledAfterEdit",cancelled,"saved",false,"before",before,"after",after)));
      // Ghidra invalidates this registered in-memory default on transaction rollback.
      // Preserve the full unnormalized observations above; tolerate only absent-vs-zero here.
      var left=new java.util.TreeMap<>(before);
      var opts=new java.util.TreeMap<>((java.util.Map<String,Object>)before.get("options"));
      var specs=new java.util.TreeMap<>((java.util.Map<String,Object>)opts.get("Specification Extensions"));
      var afterSpecs=(java.util.Map<String,Object>)((java.util.Map<String,Object>)after.get("options")).get("Specification Extensions");
      if(!afterSpecs.containsKey("FormatVersion") && Sm83PreservationInventory.row("type","INT_TYPE","value","0").equals(specs.get("FormatVersion")))specs.remove("FormatVersion");
      opts.put("Specification Extensions",specs);left.put("options",opts);
      if(!cancelled||!left.equals(after))throw new AssertionError("Cancellation rollback changed inventory");
      println("SM83_CANCEL_AFTER_UPGRADE_ROLLBACK_NO_SAVE_PASS");
    } finally {p.release(this);}
  }
}
