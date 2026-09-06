import java.io.File;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.util.*;
import fi.gekkio.ghidraboy.*;
import ghigbc.BankMappings;
import ghidra.GhidraApplicationLayout;
import ghidra.app.util.importer.*;
import ghidra.framework.*;
import ghidra.framework.model.*;
import ghidra.framework.project.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.*;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.XmlSchemaContext;
import ghidra.util.task.TaskMonitor;

/** Real imported MBC2 Program and DBTrace: isolated from frozen performance harnesses. */
public final class M7MappingContractTest {
    static class Manager extends DefaultProjectManager { Manager(){super();} }
    static void require(boolean ok,String reason){if(!ok)throw new AssertionError(reason);System.out.println("PASS M7 mapping: "+reason);}
    static Address address(DBTrace trace,String space,int offset){return trace.getBaseAddressFactory().getAddressSpace(space).getAddress(offset);}
    static boolean mapped(DBTrace trace,long snap,int cpu){return trace.getStaticMappingManager().findContaining(address(trace,"ram",cpu),snap)!=null;}
    static int read(DBTrace trace,long snap,String space,int offset){var bytes=ByteBuffer.allocate(1);trace.getMemoryManager().getBytes(snap,address(trace,space,offset),bytes);return Byte.toUnsignedInt(bytes.array()[0]);}
    static void capture(DBTrace trace,TraceObject machine,BankMappings mappings,long snap,boolean boot,String ranges,boolean enabled,boolean rtc)throws Exception {
        try(var tx=trace.openTransaction("M7 captured mapper fixture")) {
            trace.getTimeManager().getSnapshot(snap,true);
            for(var entry:Map.<String,Object>of("ROMHash",mappings.hash(),"ROM0",0,"ROMX",1,"WRAM",1,"VRAM",0,"CartBank",0,"CartEnabled",enabled,"RTCSelected",rtc,"Boot",boot).entrySet())machine.setValue(Lifespan.at(snap),entry.getKey(),entry.getValue());
            machine.setValue(Lifespan.at(snap),"Mapper","MBC2");
            machine.setValue(Lifespan.at(snap),"BootRanges",ranges);
            machine.setValue(Lifespan.at(snap),"CaptureSnapshot",snap);
            trace.getMemoryManager().putBytes(snap,address(trace,"cart0",0xa023),ByteBuffer.wrap(new byte[]{0x0b}));
            for(int base=0xa000;base<0xc000;base+=0x200)trace.getMemoryManager().putBytes(snap,address(trace,"ram",base+0x23),ByteBuffer.wrap(new byte[]{(byte)0xfb}));
        }
        mappings.apply(trace,snap);
        require(BankMappings.isReady(machine,snap),"capture "+snap+" mapping published");
    }
    static void check(Program program,Path schema)throws Exception {
        require(ProgramMapping.cartridge(program).mapper()==Cartridge.Mapper.MBC2,"actual loader imports an MBC2 cartridge");
        var mappings=new BankMappings(program);
        require(mappings.banks().stream().anyMatch(b->b.region().equals("cart")&&b.length()==512),"static MBC2_RAM maps to 512-byte live cart storage");
        var canonical=program.getMemory().getBlock("xram").getStart().add(0x23);
        require(mappings.reverse(canonical).equals(new BankMappings.Physical("cart",0,0x23)),"MBC2 static identity reverses to existing cart vocabulary");
        require(mappings.candidates("cart",0,0x23).size()==16,"all 16 static CPU mirrors retain candidate identity");
        var trace=new DBTrace("M7 mapping contract",program.getCompilerSpec(),M7MappingContractTest.class);
        try {
            TraceObject machine;
            try(var tx=trace.openTransaction("M7 trace schema")) {
                var context=XmlSchemaContext.deserialize(schema.toFile());
                trace.getObjectManager().createRootObject(context.getSchema(context.name("Session")));
                machine=trace.getObjectManager().createObject(KeyPath.parse("Machine"));
                machine.insert(Lifespan.nowOn(0),TraceObject.ConflictResolution.DENY);
                trace.getMemoryManager().createOverlayAddressSpace("cart0",trace.getBaseAddressFactory().getDefaultAddressSpace());
                trace.getMemoryManager().createOverlayAddressSpace("rom0",trace.getBaseAddressFactory().getDefaultAddressSpace());
            }
            capture(trace,machine,mappings,0,true,"[[0,256]]",true,false);
            require(!mapped(trace,0,0xff)&&mapped(trace,0,0x100)&&mapped(trace,0,0x200)&&mapped(trace,0,0x8ff),"DMG boot hides only 0000-00ff, leaving 0200-08ff as cartridge ROM");
            for(int base=0xa000;base<0xc000;base+=0x200) {
                var mapping=trace.getStaticMappingManager().findContaining(address(trace,"ram",base+0x23),0);
                require(mapping!=null,"CPU MBC2 mirror mapped at "+Integer.toHexString(base));
                var staticStart=ProgramMapping.staticAddress(program,mapping.getStaticAddress());
                var target=staticStart.add(address(trace,"ram",base+0x23).subtract(mapping.getMinTraceAddress()));
                require(mappings.reverse(target).equals(new BankMappings.Physical("cart",0,0x23)),"CPU mirror resolves to same low-nibble cell");
                require(read(trace,0,"ram",base+0x23)==0xfb,"CPU mirror retains read-high-nibble semantics");
            }
            require(read(trace,0,"cart0",0xa023)==0x0b,"physical trace retains normalized low nibble");
            require(trace.getStaticMappingManager().findContaining(address(trace,"cart0",0xa023),0)!=null,"physical cart0 maps to static MBC2 storage");
            capture(trace,machine,mappings,1,true,"[[0,256],[512,2304]]",true,false);
            require(mapped(trace,1,0x100)&&!mapped(trace,1,0x200)&&!mapped(trace,1,0x8ff)&&mapped(trace,1,0x900),"CGB captures retain both exact boot windows");
            capture(trace,machine,mappings,2,true,null,true,false);
            require(!mapped(trace,2,0x200)&&mapped(trace,2,0x900),"legacy captures conservatively reserve CGB boot windows");
            capture(trace,machine,mappings,3,false,"[]",false,false);
            require(mapped(trace,3,0)&&mapped(trace,3,0x200)&&!mapped(trace,3,0xa023),"boot unmap restores ROM and disabled cart has no CPU mapping");
            capture(trace,machine,mappings,4,false,"[]",true,true);
            require(!mapped(trace,4,0xa023),"RTC selection does not claim SRAM CPU coordinates");
            capture(trace,machine,mappings,5,true,"[[512,256]]",true,false);
            require(!mapped(trace,5,0)&&!mapped(trace,5,0x900)&&mapped(trace,5,0x4000),"malformed boot metadata withholds ROM0 only");
            require(new String((byte[])machine.getValue(5,"MappingIssues").getValue(),java.nio.charset.StandardCharsets.UTF_8).contains("Invalid BootRanges"),"malformed metadata is reported");
            try(var tx=trace.openTransaction("Legacy mapper metadata fixture")) {
                trace.getTimeManager().getSnapshot(6,true);
                for(var entry:Map.<String,Object>of("ROMHash",mappings.hash(),"CartBank",0,"CartEnabled",true,"RTCSelected",false,"Boot",false,"CaptureSnapshot",6L).entrySet())machine.setValue(Lifespan.at(6),entry.getKey(),entry.getValue());
            }
            mappings.apply(trace,6);
            require(mapped(trace,6,0xbe23),"legacy mapper metadata recovers MBC2 identity from static provider");
            require(mapped(trace,0,0x200)&&!mapped(trace,1,0x200),"later captures preserve historical DMG/CGB distinction");
            capture(trace,machine,mappings,7,true,"[]",true,false);
            require(!mapped(trace,7,0)&&!mapped(trace,7,0x900)&&mapped(trace,7,0x4000),"active boot with empty ranges cannot falsely expose ROM0");
        }finally{trace.release(M7MappingContractTest.class);}
    }
    public static void main(String[] args)throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),new HeadlessGhidraApplicationConfiguration());
        Path root=Path.of(args[0]);Path work=Files.createTempDirectory(root.resolve("build"),"m7-mapping-");
        // Reuse the self-authored teaching ROM logo/header; describe a true 32 KiB DMG MBC2 cartridge.
        byte[] rom=Arrays.copyOf(Files.readAllBytes(root.resolve("build/teaching.gbc")),0x8000);
        rom[0x143]=0;rom[0x147]=5;rom[0x148]=0;rom[0x149]=0;
        int checksum=0;for(int i=0x134;i<0x14d;i++)checksum=checksum-Byte.toUnsignedInt(rom[i])-1;rom[0x14d]=(byte)checksum;
        int global=0;for(int i=0;i<rom.length;i++)if(i!=0x14e&&i!=0x14f)global+=Byte.toUnsignedInt(rom[i]);rom[0x14e]=(byte)(global>>8);rom[0x14f]=(byte)global;
        Path image=work.resolve("mbc2.gb");Files.write(image,rom);
        var project=new Manager().createProject(new ProjectLocator(work.toString(),"M7Mappings"),null,false);
        try(var imported=AutoImporter.importByUsingBestGuess(image.toFile(),project,"/",M7MappingContractTest.class,new MessageLog(),TaskMonitor.DUMMY)) {
            imported.save(TaskMonitor.DUMMY);check(imported.getPrimaryDomainObject(),root.resolve("python/ghigbc/schema.xml"));
        }finally{project.close();}
        System.out.println("M7_MAPPING_CONTRACT_PASSED");
    }
}
