// One later edit to a genuinely owned field, using only a copied old-provider project.
// @category Game Boy Tests
import ghidra.app.script.GhidraScript;
public class Sm83LegacyLaterEdit extends GhidraScript {
  @Override public void run() throws Exception {
    var p=currentProgram;var raw=p.getOptions("GhidraBoy").getString("softwareCall.sites.v1","");
    if(!raw.contains("software-call-registry-4")||p.getLanguage().getVersion()!=1)throw new AssertionError("Genuine old record/provider required");
    p.getListing().getInstructionAt(toAddr(0x150)).setFallThrough(toAddr(0x159));
    if(!raw.equals(p.getOptions("GhidraBoy").getString("softwareCall.sites.v1","")))throw new AssertionError("Proof changed");
    println("GENUINE_REGISTRY4_LATER_EDIT_SAVED");
  }
}
