// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.program.model.address.*;
import ghidra.program.disassemble.Disassembler;
import java.nio.file.*;
import java.math.BigInteger;
import java.util.*;

/** Minimized actual-consumer test: remove only owned carrier mode, retaining its authority. */
public class GhidraBoyStockDamage extends GhidraBoyPredicatedCalls {
  @Override public void run()throws Exception {
    out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
    var entry=StockEntries.entries(currentProgram).stream().filter(e->e.domain().equals("root")).findFirst().orElseThrow();
    var at=currentProgram.getAddressFactory().getAddress(entry.carrier());var function=getFunctionAt(at);
    var owner=owner();try {
      request(function,owner,"valid");
      String record=currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(at.toString(),null);
      currentProgram.getListing().clearCodeUnits(at,at,false);
      currentProgram.getProgramContext().setValue(currentProgram.getRegister("gb_analysis_entry"),at,at,BigInteger.ZERO);
      Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(at,function.getBody(),false);
      ids.clear();save("changed-entry-raw.json",Arrays.stream(getInstructionAt(at).getPcode(false)).map(this::operation).toList());
      String reason="";try{StockEntries.current(currentProgram,at,monitor);}catch(Exception e){reason=e.getMessage();}
      save("mutation.json",Map.of("entry",at.toString(),"contextBefore",1,"contextAfter",0,"registrationRetained",record.equals(currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(at.toString(),null)),"providerRefusal",reason));
      request(function,owner,"damaged");
    }finally{owner.dispose();}
    println("STOCK_BOUND_DAMAGE_CAPTURE_COMPLETE");
  }
}
