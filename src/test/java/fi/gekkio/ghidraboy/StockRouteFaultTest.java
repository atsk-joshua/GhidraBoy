package fi.gekkio.ghidraboy;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.util.task.TaskMonitor;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Actual stock native results, including paired loss of the two former callback selectors. */
public class StockRouteFaultTest extends IntegrationTest {
  private void fixture(StockEntryTransportTest.Action action) throws Exception { var helper = new StockEntryTransportTest(); helper.beforeAll(); helper.fixture(action); }
  // Inherited tests remain in their original class only.
  @org.junit.jupiter.params.ParameterizedTest(name="carrier fault {0}")
  @org.junit.jupiter.params.provider.ValueSource(strings={"context", "convention", "paired", "missing", "malformed", "byte", "size", "flow", "backing", "mapped", "paired:__sdcc416", "paired:__sdcc451_call0", "paired:__sdcc451_call1_first8", "paired:__sdcc451_call1_first16", "paired:__sdcc451_call1_first32", "paired:__sdcc451_variadic", "paired:__sdcc451_banked_callee", "paired:__sdcc451_preserves_bc", "paired:__ghidraboy_state_entry_v1", "paired:default", "paired:unknown"})
  void nativeCarrierFaultMatrix(String fault) throws Exception {
    fixture((p,f)->{
      var root=PredicatedCalls.install(p,PredicatedCalls.preview(p,f,PredicatedCallGraph.Limits.PRIMARY,TaskMonitor.DUMMY),TaskMonitor.DUMMY);
      var function=p.getFunctionManager().getFunctionAt(root);
      assertEquals(1,p.getMemory().getBlock(root).getSize());
      assertFalse(p.getMemory().getBlock(root).isMapped());
      assertEquals(List.of(),ProgramMapping.staticToPhysical(p,root));
      var owner=new DecompInterface();owner.setOptions(new ghidra.app.decompiler.DecompileOptions());
      try {
        assertTrue(owner.openProgram(p));
        var baseline=owner.decompileFunction(function,30,TaskMonitor.DUMMY);
        assertTrue(baseline.decompileCompleted(),baseline.getErrorMessage());
        assertNotNull(baseline.getHighFunction());assertNotNull(baseline.getDecompiledFunction());
        if(fault.equals("context")||fault.startsWith("paired")) {
          p.getListing().clearCodeUnits(root,root,false);
          p.getProgramContext().setValue(p.getRegister("gb_analysis_entry"),root,root,BigInteger.ZERO);
          Disassembler.getDisassembler(p,TaskMonitor.DUMMY,null).disassemble(root,new AddressSet(root),false);
          var raw=p.getListing().getInstructionAt(root);
          assertEquals(1,raw.getLength());assertNull(raw.getFallThrough());assertEquals(0,raw.getFlows().length);
        }
        if(fault.equals("convention")||fault.startsWith("paired")) function.setCallingConvention(fault.contains(":")?fault.substring(fault.indexOf(':')+1):"__asm");
        if(fault.equals("missing")) p.getOptions(PredicatedCalls.STOCK_OPTIONS).removeOption(root.toString());
        if(fault.equals("malformed")) p.getOptions(PredicatedCalls.STOCK_OPTIONS).setString(root.toString(),"{broken");
        if(fault.equals("byte")) {
          p.getListing().clearCodeUnits(root,root,false);p.getMemory().setByte(root,(byte)0);
          Disassembler.getDisassembler(p,TaskMonitor.DUMMY,null).disassemble(root,new AddressSet(root),false);
        }
        if(fault.equals("flow"))p.getListing().getInstructionAt(root).setFlowOverride(FlowOverride.RETURN);
        if(fault.equals("size"))p.getMemory().createInitializedBlock("extra",root.add(1),1,(byte)0,TaskMonitor.DUMMY,false);
        if(fault.equals("backing"))p.getMemory().getBlock(root).setComment("foreign storage");
        if(fault.equals("mapped")) {
          var block=p.getMemory().getBlock(root);String name=block.getName();
          var hold=p.getMemory().createInitializedBlock("hold",root.add(4),1,(byte)0,TaskMonitor.DUMMY,false);
          p.getListing().clearCodeUnits(root,root,false);p.getMemory().removeBlock(block,TaskMonitor.DUMMY);
          var mapped=p.getMemory().createByteMappedBlock(name,root,f.getEntryPoint(),1,false);
          mapped.setRead(true);mapped.setWrite(false);mapped.setExecute(true);mapped.setComment(StockEntryInjection.STORAGE);
          p.getMemory().removeBlock(hold,TaskMonitor.DUMMY);
          StockEntryInjection.prepare(p,root);Disassembler.getDisassembler(p,TaskMonitor.DUMMY,null).disassemble(root,new AddressSet(root),false);
          function=p.getFunctionManager().getFunctionAt(root);
          if(function==null)function=p.getFunctionManager().createFunction(name,root,new AddressSet(root),ghidra.program.model.symbol.SourceType.ANALYSIS);
          function.setCallingConvention(StockEntryInjection.CONVENTION);
        }
        var debug=Files.createTempFile("stock-route-"+fault,".xml").toFile();owner.enableDebug(debug);
        var invalid=owner.decompileFunction(function,30,TaskMonitor.DUMMY);
        String recovery=Files.readString(debug.toPath());
        var xml=javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(debug);
        var chunks=xml.getElementsByTagName("bytechunk");assertEquals(1,chunks.getLength(),fault+": recovery escaped carrier");
        var chunk=(org.w3c.dom.Element)chunks.item(0);
        assertEquals(root.getAddressSpace().getName(),chunk.getAttribute("space"),fault);
        assertEquals("0x150",chunk.getAttribute("offset"),fault);
        assertEquals(fault.equals("mapped")?java.util.HexFormat.of().toHexDigits(p.getMemory().getByte(f.getEntryPoint())):fault.equals("byte")?"00":"c9",chunk.getTextContent().replaceAll("\\s+",""),fault);

        System.out.println("STOCK_CARRIER_FAULT "+ProgramMapping.JSON.toJson(Map.of("fault",fault,"completed",invalid.decompileCompleted(),"high",invalid.getHighFunction()!=null,"c",invalid.getDecompiledFunction()!=null,"error",invalid.getErrorMessage(),"debug",recovery)));
        assertFalse(invalid.decompileCompleted(),fault+": "+invalid.getErrorMessage());
        assertNull(invalid.getHighFunction(),fault);assertNull(invalid.getDecompiledFunction(),fault);
        assertFalse(invalid.getErrorMessage().isBlank(),fault);
      }finally{owner.dispose();}
    });
  }
  @Test void earlierStockCarrierRecordRejectsBeforeChangedFieldsAndIsNotRefreshed() throws Exception {
    fixture((p,f)->{
      var root=PredicatedCalls.install(p,PredicatedCalls.preview(p,f,PredicatedCallGraph.Limits.PRIMARY,TaskMonitor.DUMMY),TaskMonitor.DUMMY);
      var options=p.getOptions(PredicatedCalls.STOCK_OPTIONS);
      var old=com.google.gson.JsonParser.parseString(options.getString(root.toString(),null)).getAsJsonObject();
      old.addProperty("version","stock-predicated-ordinary-calls-1");old.addProperty("transport","stock-callother-entry-2");
      old.addProperty("proof","must not decode obsolete fields");String encoded=old.toString();options.setString(root.toString(),encoded);
      var failure=assertThrows(IllegalArgumentException.class,()->PredicatedCalls.emit(p,root,0x200000,TaskMonitor.DUMMY));
      assertTrue(failure.getMessage().contains("version"),failure.getMessage());
      assertThrows(IllegalArgumentException.class,()->PredicatedCalls.refresh(p,root,PredicatedCalls.preview(p,f,PredicatedCallGraph.Limits.PRIMARY,TaskMonitor.DUMMY),TaskMonitor.DUMMY));
      assertEquals(encoded,options.getString(root.toString(),null));
    });
  }

  @Test void competingTransportAuthoritiesAreRejectedWithoutChoosingOne() throws Exception {
    fixture((p,f)->{
      var root=PredicatedCalls.install(p,PredicatedCalls.preview(p,f,PredicatedCallGraph.Limits.PRIMARY,TaskMonitor.DUMMY),TaskMonitor.DUMMY);
      String stock=p.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(root.toString(),null);
      String legacy="{\"version\":\"predicated-ordinary-calls-4\",\"proof\":\"retained synthetic companion authority\"}";
      p.getOptions(PredicatedCalls.OPTIONS).setString(root.toString(),legacy);
      var failure=assertThrows(IllegalArgumentException.class,()->PredicatedCalls.emit(p,root,0x200000,TaskMonitor.DUMMY));
      assertTrue(failure.getMessage().contains("Conflicting"));
      assertEquals(stock,p.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(root.toString(),null));
      assertEquals(legacy,p.getOptions(PredicatedCalls.OPTIONS).getString(root.toString(),null));
    });
  }

  @Test void newApplicationRequestsPreserveCompanionAndIncompatibleStockRecords() throws Exception {
    fixture((p,f)->{
      var options=p.getOptions(ProgramMapping.OPTIONS);
      for(String key:List.of(SoftwareCallRegistry.KEY,SoftwareCallRegistry.STOCK_KEY)) {
        String encoded="{\"version\":\"stock-software-call-registry-1\",\"sites\":[],\"stateEntries\":\"obsolete\"}";
        options.setString(key,encoded);
        assertThrows(IllegalArgumentException.class,()->SoftwareCallApplication.preview(p,List.of(),TaskMonitor.DUMMY));
        assertEquals(encoded,options.getString(key,null));options.removeOption(key);
      }
      p.getOptions(SoftwareCallDomains.STOCK_OPTIONS).setString("registration","{\"version\":\"stock-software-call-domains-1\",\"views\":\"obsolete\"}");
      assertTrue(assertThrows(IllegalArgumentException.class,()->SoftwareCallDomains.views(p)).getMessage().contains("version"));
    });
  }

}
