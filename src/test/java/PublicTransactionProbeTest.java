import fi.gekkio.ghidraboy.IntegrationTest;
import ghidra.app.script.*;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.io.PrintWriter;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class PublicTransactionProbeTest extends IntegrationTest {
  @Test public void realScriptWrapperRetainsActualOuterOutcome() throws Exception {
    var p = new ProgramDB("public-route-probe", getLanguage(), getLanguage().getDefaultCompilerSpec(), this);
    try {
      for (boolean commit : new boolean[]{true,false}) {
        int outer = p.startTransaction("deliberate caller owner");
        var actual = p.getCurrentTransactionInfo();
        var script = new GhidraScript() {
          @Override public void run() {
            assertSame(actual, currentProgram.getCurrentTransactionInfo());
            boolean result = runCommand(new BackgroundCommand<Program>("direct script command",true,true,false) {
              @Override public boolean applyTo(Program target, TaskMonitor monitor) {
                assertSame(p,target);
                assertSame(actual,target.getCurrentTransactionInfo());
                target.getOptions("probe").setString("sentinel","write");
                return true;
              }
            });
            assertTrue(result);
            assertEquals(TransactionInfo.Status.NOT_DONE,actual.getStatus());
          }
        };
        script.execute(new GhidraState(null,null,p,null,null,null),TaskMonitor.DUMMY,new PrintWriter(System.out,true));
        assertEquals(TransactionInfo.Status.NOT_DONE, actual.getStatus());
        p.endTransaction(outer,commit);
        assertEquals(commit ? TransactionInfo.Status.COMMITTED : TransactionInfo.Status.ABORTED,actual.getStatus());
        System.out.println("REAL_SCRIPT_OUTER id="+actual.getID()+" status="+actual.getStatus()+" db="+actual.hasCommittedDBTransaction());
        if(commit) p.undo();
        assertNull(p.getOptions("probe").getString("sentinel",null));
      }
    } finally { p.release(this); }
  }
}
