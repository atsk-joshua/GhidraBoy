package fi.gekkio.ghidraboy;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Transport-specific obligations supplement, rather than replace, the retained semantic cases. */
public class StockEntryTransportTest extends IntegrationTest {
  interface Action { void run(ProgramDB p, Function f) throws Exception; }
  void fixture(Action action) throws Exception {
    var owner=new Object();var p=new ProgramDB("stock-entry",getLanguage(),getLanguage().getDefaultCompilerSpec(),owner);
    try {
      byte[] bytes=getClass().getResourceAsStream("/ordinary/PREDICATED_CALLS.gb").readAllBytes();
      try(var provider=new ByteArrayProvider(bytes)){CartridgeLayout.load(p,provider,"CARTRIDGE","AUTO",GameBoyKind.GB,false,false,TaskMonitor.DUMMY,new MessageLog());}
      int tx=p.startTransaction("self-authored fixture");
      try {
        var body=new AddressSet(address(0x150),address(0x164));
        Disassembler.getDisassembler(p,TaskMonitor.DUMMY,null).disassemble(address(0x150),body);
        var f=p.getFunctionManager().createFunction("source",address(0x150),body,SourceType.USER_DEFINED);
        action.run(p,f);
      } finally {p.endTransaction(tx,true);}
    } finally {p.release(owner);}
  }
  @Test void canonicalBytesEffectsAndContextRemainSeparate() throws Exception {
    fixture((p,f)->{
      var before=p.getListing().getInstructionAt(f.getEntryPoint()).getPcode(false);
      var proof=PredicatedCalls.preview(p,f,PredicatedCallGraph.Limits.PRIMARY,TaskMonitor.DUMMY);
      var root=PredicatedCalls.installStock(p,proof,TaskMonitor.DUMMY);
      StockEntryInjection.validate(p,root);
      assertEquals(java.util.Arrays.toString(before),java.util.Arrays.toString(p.getListing().getInstructionAt(f.getEntryPoint()).getPcode(false)));
      assertEquals(java.math.BigInteger.ZERO,p.getProgramContext().getValue(p.getRegister("gb_analysis_entry"),f.getEntryPoint(),false));
      assertEquals(java.math.BigInteger.ZERO,p.getProgramContext().getValue(p.getRegister("gb_analysis_entry"),root.add(1),false));
      var payload=PredicatedCalls.emitStock(p,root,0x200000,TaskMonitor.DUMMY);
      assertEquals(2,java.util.Arrays.stream(payload).filter(o->o.getOpcode()==PcodeOp.CALL).count());
      assertEquals(4,java.util.Arrays.stream(payload).filter(o->o.getOpcode()==PcodeOp.STORE).count());
      assertThrows(IllegalArgumentException.class,()->PredicatedCalls.emit(p,root,0x200000,TaskMonitor.DUMMY));
    });
  }
  @Test void alteredRawBoundIsRejected() throws Exception {
    fixture((p,f)->{
      var root=PredicatedCalls.installStock(p,PredicatedCalls.preview(p,f,PredicatedCallGraph.Limits.PRIMARY,TaskMonitor.DUMMY),TaskMonitor.DUMMY);
      p.getListing().getInstructionAt(root).setFlowOverride(FlowOverride.RETURN);
      assertThrows(IllegalArgumentException.class,()->PredicatedCalls.emitStock(p,root,0x200000,TaskMonitor.DUMMY));
    });
  }
  @Test void actualNativeMissingAuthorityDoesNotReturnPartialFunction() throws Exception {
    fixture((p,f)->{
      var root=PredicatedCalls.installStock(p,PredicatedCalls.preview(p,f,PredicatedCallGraph.Limits.PRIMARY,TaskMonitor.DUMMY),TaskMonitor.DUMMY);
      var function=p.getFunctionManager().getFunctionAt(root);var nativeOwner=new DecompInterface();
      try {
        assertTrue(nativeOwner.openProgram(p));
        var valid=nativeOwner.decompileFunction(function,60,TaskMonitor.DUMMY);assertTrue(valid.decompileCompleted(),valid.getErrorMessage());assertNotNull(valid.getHighFunction());
        String record=p.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(root.toString(),null);
        p.getOptions(PredicatedCalls.STOCK_OPTIONS).removeOption(root.toString());
        var invalid=nativeOwner.decompileFunction(function,60,TaskMonitor.DUMMY);
        assertFalse(invalid.decompileCompleted());assertNull(invalid.getHighFunction());assertNull(invalid.getDecompiledFunction());
        p.getOptions(PredicatedCalls.STOCK_OPTIONS).setString(root.toString(),record);
        var restored=nativeOwner.decompileFunction(function,60,TaskMonitor.DUMMY);assertTrue(restored.decompileCompleted(),restored.getErrorMessage());
      } finally {nativeOwner.dispose();}
    });
  }
  @Test void rollbackPreservesConventionEditsItNeverOwned() throws Exception {
    for(boolean canonical:new boolean[]{true,false})fixture((p,f)->{
      String original=f.getCallingConventionName();
      if(!canonical)f.setCallingConvention(StockEntryInjection.CONVENTION);
      var group=new AnalysisOwnership.Group();
      group.stateEntries.add(new AnalysisOwnership.StateEntry(AnalysisOwnership.Point.of(f.getEntryPoint()),f.getID(),original,
          null,null,false,false,AnalysisOwnership.helperMetadataStamp(f),f.getCallingConventionName()));
      AnalysisOwnership.save(p,SoftwareCallApplication.FEATURE,group);
      String edited=canonical?StockEntryInjection.CONVENTION:SoftwareCallStateEntryInjection.CONVENTION;
      f.setCallingConvention(edited);
      AnalysisOwnership.remove(p,SoftwareCallApplication.FEATURE,TaskMonitor.DUMMY);
      assertEquals(edited,f.getCallingConventionName());
    });
  }
  @Test void rollbackRestoresOnlyTheAppliedStockConvention() throws Exception {
    fixture((p,f)->{
      String original=f.getCallingConventionName();f.setCallingConvention(StockEntryInjection.CONVENTION);
      var group=new AnalysisOwnership.Group();
      group.stateEntries.add(new AnalysisOwnership.StateEntry(AnalysisOwnership.Point.of(f.getEntryPoint()),f.getID(),original,
          null,null,false,false,AnalysisOwnership.helperMetadataStamp(f),StockEntryInjection.CONVENTION));
      AnalysisOwnership.save(p,SoftwareCallApplication.FEATURE,group);
      AnalysisOwnership.remove(p,SoftwareCallApplication.FEATURE,TaskMonitor.DUMMY);
      assertEquals(original,f.getCallingConventionName());
    });
  }

  @Test void missingCarrierModeIsRejectedByActualNativeIntegrityGuard() throws Exception {
    fixture((p,f)->{
      var root=PredicatedCalls.installStock(p,PredicatedCalls.preview(p,f,PredicatedCallGraph.Limits.PRIMARY,TaskMonitor.DUMMY),TaskMonitor.DUMMY);
      var function=p.getFunctionManager().getFunctionAt(root);var nativeOwner=new DecompInterface();
      try {
        assertTrue(nativeOwner.openProgram(p));
        var valid=nativeOwner.decompileFunction(function,60,TaskMonitor.DUMMY);assertTrue(valid.decompileCompleted(),valid.getErrorMessage());
        p.getListing().clearCodeUnits(root,root,false);
        p.getProgramContext().setValue(p.getRegister("gb_analysis_entry"),root,root,java.math.BigInteger.ZERO);
        Disassembler.getDisassembler(p,TaskMonitor.DUMMY,null).disassemble(root,function.getBody(),false);
        var invalid=nativeOwner.decompileFunction(function,60,TaskMonitor.DUMMY);
        assertFalse(invalid.decompileCompleted());assertNull(invalid.getHighFunction());assertNull(invalid.getDecompiledFunction());
        assertTrue(invalid.getErrorMessage().contains("stock entry integrity"),invalid.getErrorMessage());
      } finally {nativeOwner.dispose();}
    });
  }

}
