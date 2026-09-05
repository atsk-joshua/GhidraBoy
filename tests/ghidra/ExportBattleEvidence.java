import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.model.*;
import ghidra.framework.project.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.*;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.util.task.TaskMonitor;
import ghigbc.BankMappings;
public class ExportBattleEvidence {
 static class Manager extends DefaultProjectManager{Manager(){super();}}
 static Object value(TraceObject o,long snap,String name){var v=o.getValue(snap,name);return v==null?null:v.getValue();}
 static int memory(Trace t,long snap,String space,int offset){ByteBuffer b=ByteBuffer.allocate(1);t.getMemoryManager().getBytes(snap,t.getBaseAddressFactory().getAddressSpace(space).getAddress(offset),b);return b.array()[0]&255;}
 static void require(boolean ok,String message){if(!ok)throw new AssertionError(message);System.out.println("PASS "+message);}
 public static void main(String[] args)throws Exception{
  Path root=Path.of(args[0]);
  Application.initializeApplication(new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),new HeadlessGhidraApplicationConfiguration());
  Project project=new Manager().openProject(new ProjectLocator(root.resolve("build/projects").toString(),args[1]),false,false);
  var trace=(Trace)project.getProjectData().getFile("/New Traces/GBC/student12").getReadOnlyDomainObject(ExportBattleEvidence.class,-1,TaskMonitor.DUMMY);
  var program=(Program)project.getProjectData().getFile("/student-copy").getReadOnlyDomainObject(ExportBattleEvidence.class,-1,TaskMonitor.DUMMY);
  try{
   var mappings=new BankMappings(program);require(mappings.hash().equals("e779a6b56575a2afafb7e1e99411b23d7400a8fddbda8bd52c660b7903c3b451"),"annotated-program ROM fingerprint");
   var m=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));long last=trace.getTimeManager().getMaxSnap();
   var report=new LinkedHashMap<String,Object>();report.put("scope","Real GBW3 CLASS 2 tutorial map battle, normal SDL inputs, actual Ghidra 12.1.2 Trace RMI; development Mac, not Steam Deck");report.put("rom_sha256",mappings.hash());report.put("session",value(m,last,"Session"));report.put("project",project.getProjectLocator().toString());report.put("trace","/New Traces/GBC/student12");
   var records=new ArrayList<Map<String,Object>>();
   for(int id=1;id<=2;id++){
    var e=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine.Events["+id+"]"));require(e!=null,"watch event "+id+" persisted");long snap=((Number)value(e,last,"Snapshot")).longValue();
    Address writer=(Address)value(e,snap,"Writer");var mapping=trace.getStaticMappingManager().findContaining(writer,snap);require(mapping!=null,"writer mapping persisted for event "+id);
    var staticWriter=program.getAddressFactory().getAddress(mapping.getStaticAddress()).add(writer.subtract(mapping.getMinTraceAddress()));var physical=mappings.reverse(staticWriter);
    int before=((Number)value(e,snap,"Before")).intValue(),after=((Number)value(e,snap,"After")).intValue();
    var breakpoint=trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine.Breakpoints[1]"));var range=(AddressRange)value(breakpoint,snap,"_range");
    require(before==10&&after==3,"actual APC HP 10 -> 3 for event "+id);
    String studyDetails=ghigbc.StudyProvider.eventDescription(e,last);
    require(studyDetails.contains("slot 50 HP")&&studyDetails.contains("Origin: cpu")&&studyDetails.contains("snapshot "+snap),"study detail uses fingerprinted HP field and original event snapshot "+id);
    System.out.println("STUDY_EVENT_DETAILS "+studyDetails.replace('\n',' '));
    require(range.getMinAddress().getAddressSpace().getName().equals("wram3")&&range.getMinAddress().getOffset()==0xd324&&range.getLength()==1,"watch qualifies slot 50 HP in WRAM bank 3");
    require(physical.region().equals("rom")&&physical.bank()==18&&physical.offset()==0xb5,"writer physical ROM bank 18 + 0xB5");
    require((program.getMemory().getByte(staticWriter)&255)==0x70,"writer opcode 0x70 = LD (HL),B");require(memory(trace,snap,"wram3",0xd324)==3,"captured physical HP byte agrees");
    var instruction=program.getListing().getInstructionAt(staticWriter);var function=program.getFunctionManager().getFunctionContaining(staticWriter);
    var row=new LinkedHashMap<String,Object>();row.put("event",id);row.put("snapshot",snap);row.put("epoch",value(e,snap,"Epoch"));row.put("target",Map.of("region","wram","bank",3,"offset",0x324,"cpu_address",0xd324,"unit_slot",50,"field","hp"));row.put("before",before);row.put("final_after",after);row.put("attempt",value(e,snap,"Attempt"));row.put("origin",value(e,snap,"Origin"));row.put("precision",value(e,snap,"Precision"));row.put("writer",Map.of("region",physical.region(),"bank",physical.bank(),"offset",physical.offset(),"cpu_address",value(e,snap,"WriterPC"),"static_address",staticWriter.toString(),"opcode",112,"instruction",String.valueOf(instruction),"function",function==null?"unknown":function.getName(true)));row.put("caller","unknown; not inferred");Object combat=value(m,snap,"CombatData");if(combat==null)combat=value(m,snap,"Combat");row.put("combat",JsonParser.parseString(combat instanceof byte[] data?new String(data,java.nio.charset.StandardCharsets.UTF_8):(String)combat));
    Object unitData=value(m,snap,"UnitsData");
    if(unitData instanceof byte[] data){var units=JsonParser.parseString(new String(data,java.nio.charset.StandardCharsets.UTF_8));require(units.getAsJsonArray().size()==100,"all 100 unit records survive binary-attribute persistence");row.put("units",units);row.put("unit_data_storage","UTF-8 binary attribute");}
    else{var units=new JsonArray();for(int slot:new int[]{0,1,50,51}){int base=0xd000+slot*16;var unit=new JsonObject();unit.addProperty("slot",slot);unit.addProperty("template_index",memory(trace,snap,"wram3",base)>>1);unit.addProperty("map_x",memory(trace,snap,"wram3",base+1));unit.addProperty("map_y",memory(trace,snap,"wram3",base+2));unit.addProperty("hp",memory(trace,snap,"wram3",base+4));units.add(unit);}row.put("units",units);row.put("unit_data_storage","reconstructed directly from persisted physical WRAM; legacy string attribute was truncated");}records.add(row);
   }
   require(((Number)records.get(1).get("epoch")).longValue()>((Number)records.get(0).get("epoch")).longValue(),"checkpoint restore starts a new epoch");
   long first=((Number)records.get(0).get("snapshot")).longValue(),second=((Number)records.get(1).get("snapshot")).longValue();
   require(memory(trace,first,"wram3",0xd324)==3&&memory(trace,second-1,"wram3",0xd324)==10&&memory(trace,second,"wram3",0xd324)==3,"history preserves original hit, restored HP, and repeated hit");
   report.put("events",records);report.put("history_assertion","first hit HP3; pre-repeat restored HP10; second hit HP3");report.put("passed",true);
   // Only relevant identified units, not all empty/unclassified WRAM slots.
   for(var row:records){var filtered=new JsonArray();for(var u:((JsonElement)row.get("units")).getAsJsonArray()){int slot=u.getAsJsonObject().get("slot").getAsInt();if(slot==0||slot==1||slot==50||slot==51)filtered.add(u);}row.put("units",filtered);}
   Files.writeString(root.resolve("docs/evidence/actual-battle.json"),new GsonBuilder().setPrettyPrinting().create().toJson(report));System.out.println("ACTUAL_GHIDRA_MAP_BATTLE_PASSED");
  }finally{trace.release(ExportBattleEvidence.class);program.release(ExportBattleEvidence.class);project.close();}
  System.exit(0);
 }
}
