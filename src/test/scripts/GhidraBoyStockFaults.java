// @category GhidraBoy.Tests
import fi.gekkio.ghidraboy.*;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

/** Actual installed native requests on one owned interface, including paired selector loss. */
public class GhidraBoyStockFaults extends GhidraBoyStockEntry {
  @Override public void run() throws Exception {
    super.run();
    var entry=StockEntries.entries(currentProgram).stream().filter(e->e.domain().equals("root")).findFirst().orElseThrow();
    var at=currentProgram.getAddressFactory().getAddress(entry.carrier());var function=getFunctionAt(at);
    var options=currentProgram.getOptions(PredicatedCalls.STOCK_OPTIONS);String record=options.getString(at.toString(),null);
    var results=new ArrayList<Object>();var owner=owner();
    try {
      for(String fault:List.of("context","convention","paired","missing","malformed","byte","size","flow","backing")) {
        request(function,owner,"matrix-"+fault+"-before");
        var before=com.google.gson.JsonParser.parseString(Files.readString(out.resolve("matrix-"+fault+"-before-request.json"))).getAsJsonObject();
        if(!before.get("completed").getAsBoolean()||!before.get("highfunction_available").getAsBoolean())throw new IllegalStateException("Missing positive baseline: "+fault);
        boolean lost=fault.equals("context")||fault.equals("paired");
        if(lost){currentProgram.getListing().clearCodeUnits(at,at,false);currentProgram.getProgramContext().setValue(currentProgram.getRegister("gb_analysis_entry"),at,at,BigInteger.ZERO);Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(at,new AddressSet(at),false);}
        if(fault.equals("convention")||fault.equals("paired"))function.setCallingConvention("__asm");
        if(fault.equals("missing"))options.removeOption(at.toString());
        if(fault.equals("malformed"))options.setString(at.toString(),"{broken");
        if(fault.equals("byte")){currentProgram.getListing().clearCodeUnits(at,at,false);currentProgram.getMemory().setByte(at,(byte)0);Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(at,new AddressSet(at),false);}
        ghidra.program.model.mem.MemoryBlock extra=null;
        if(fault.equals("size"))extra=currentProgram.getMemory().createInitializedBlock("extra",at.add(1),1,(byte)0,monitor,false);
        if(fault.equals("flow"))getInstructionAt(at).setFlowOverride(FlowOverride.RETURN);
        if(fault.equals("backing"))currentProgram.getMemory().getBlock(at).setComment("foreign storage");
        ids.clear();save("matrix-"+fault+"-raw.json",Arrays.stream(getInstructionAt(at).getPcode(false)).map(this::operation).toList());
        request(function,owner,"matrix-"+fault);
        var invalid=com.google.gson.JsonParser.parseString(Files.readString(out.resolve("matrix-"+fault+"-request.json"))).getAsJsonObject();
        if(invalid.get("completed").getAsBoolean()||invalid.get("highfunction_available").getAsBoolean()||Files.exists(out.resolve("matrix-"+fault+".c")))throw new IllegalStateException("Invalid current game result: "+fault);
        var debug=javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(out.resolve("matrix-"+fault+"-debug.xml").toFile());
        var chunks=debug.getElementsByTagName("bytechunk");
        if(chunks.getLength()!=1)throw new IllegalStateException("Recovery escaped one-byte carrier: "+fault);
        var chunk=(org.w3c.dom.Element)chunks.item(0);
        if(!chunk.getAttribute("space").equals(at.getAddressSpace().getName())||!chunk.getTextContent().replaceAll("\\s+","").equals(fault.equals("byte")?"00":"c9"))throw new IllegalStateException("Unexpected actual recovery footprint: "+fault);
        results.add(Map.of("fault",fault,"result",invalid,"nativeRecoveredBytes",1,"space",chunk.getAttribute("space"),"offset",chunk.getAttribute("offset"),"noC",true));
        if(extra!=null)currentProgram.getMemory().removeBlock(extra,monitor);
        currentProgram.getMemory().getBlock(at).setComment("GhidraBoy stock carrier storage v3");
        options.setString(at.toString(),record);function.setCallingConvention(StockEntryInjection.CONVENTION);
        currentProgram.getListing().clearCodeUnits(at,at,false);currentProgram.getMemory().setByte(at,(byte)0xc9);
        currentProgram.getProgramContext().setValue(currentProgram.getRegister("gb_analysis_entry"),at,at,BigInteger.ONE);
        Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(at,new AddressSet(at),false);
      }
      request(function,owner,"matrix-restored");
      save("carrier-fault-matrix.json",results);
    }finally{owner.dispose();}
    println("STOCK_CARRIER_MATRIX_CAPTURE_COMPLETE");
  }
}
