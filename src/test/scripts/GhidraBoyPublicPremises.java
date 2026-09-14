// @category Game Boy.Tests
import fi.gekkio.ghidraboy.*;
import java.nio.file.*;
import java.util.*;

/** Uncovered foreign-image control through the actual maintained preview wrapper. */
public class GhidraBoyPublicPremises extends GhidraBoyPredicatedCalls {
  @Override public void run()throws Exception {
    end(true);out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    if(currentProgram.getCurrentTransactionInfo()!=null)throw new IllegalStateException("Finish the capture owner first");
    var name=currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).getOptionNames().getFirst();
    var entry=ProgramMapping.staticAddress(currentProgram,name);String before=currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(name,null);
    var request=PredicatedCalls.registeredProof(currentProgram,entry).callSite();
    save("valid-request.json",request);publicPredicateAction(new String[]{"conditional-call-preview",out.resolve("valid-request.json").toString(),out.resolve("valid-proof.json").toString()});
    if(!PredicatedCalls.readProof(Files.readString(out.resolve("valid-proof.json"))).complete())throw new IllegalStateException("Positive premise base missing");
    var foreign=ProgramMapping.JSON.toJsonTree(request).getAsJsonObject();foreign.addProperty("imageSha256","00".repeat(32));save("foreign-image-request.json",foreign);
    String refusal=null;
    try{publicPredicateAction(new String[]{"conditional-call-preview",out.resolve("foreign-image-request.json").toString(),out.resolve("invalid-proof.json").toString()});}
    catch(Exception expected){
      for(Throwable cause=expected;cause!=null;cause=cause.getCause())if(cause instanceof IllegalArgumentException && String.valueOf(cause.getMessage()).toLowerCase().contains("image")){refusal=cause.getMessage();break;}
      if(refusal==null)throw expected;
    }
    if(refusal==null||!refusal.toLowerCase().contains("image")||Files.exists(out.resolve("invalid-proof.json")))throw new IllegalStateException("Foreign-image refusal not established: "+refusal);
    if(!before.equals(currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(name,null)))throw new IllegalStateException("Premise control changed authority");
    save("result.json",Map.of("positive_complete",true,"same_program_id",currentProgram.getUniqueProgramID(),"only_request_image_changed",true,"foreign_image_refusal",refusal,"authority_unchanged",true));
    println("PUBLIC_FOREIGN_IMAGE_CONTROL_COMPLETE");
  }
}
