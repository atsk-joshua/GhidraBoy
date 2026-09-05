package fi.gekkio.ghidraboy;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;

/** Plans/validates input first, then applies one cancellable transaction. */
public final class CartridgeLayout {
    private CartridgeLayout() { }
    public static void load(Program p,ByteProvider provider,String mode,String mapperOverride,GameBoyKind hardware,
                            boolean hardwareBlocks,boolean types,TaskMonitor monitor,MessageLog log) throws Exception {
        if(p.getMemory().getBlocks().length!=0) throw new IOException("Import requires an empty program; use inspection for legacy programs");
        if(provider.length()>0x800000) throw new IOException("Input exceeds 8 MiB safety limit");
        monitor.checkCancelled();
        String selected=mode;
        if(mode.equals("AUTO")) {
            var boot=BootRomUtils.detectBootRom(provider);
            if(boot.isPresent()) selected=boot.get()==GameBoyKind.CGB?"CGB_BOOT":"DMG_BOOT";
            else if(RomUtils.detectRom(provider).isPresent()) selected="CARTRIDGE";
            else throw new IOException("Unrecognized input: select explicit CARTRIDGE, DMG_BOOT or CGB_BOOT mode");
        }
        if(!java.util.Set.of("CARTRIDGE","DMG_BOOT","CGB_BOOT").contains(selected)) throw new IOException("Unknown input mode: "+selected);
        boolean boot=!selected.equals("CARTRIDGE");
        if(boot && provider.length()!=(selected.equals("CGB_BOOT")?0x900:0x100)) throw new IOException("Boot image size must be DMG 0x100 or CGB 0x900 (including hole)");
        byte[] input=provider.readBytes(0,provider.length());
        Cartridge cartridge=boot?null:Cartridge.parse(input,mapperOverride).withHardware(hardware);
        GameBoyKind kind=boot?(selected.equals("CGB_BOOT")?GameBoyKind.CGB:GameBoyKind.GB):hardware;
        int tx=p.startTransaction("Import GhidraBoy cartridge"); boolean success=false;
        try {
            var memory=p.getMemory(); var as=p.getAddressFactory().getDefaultAddressSpace();
            var file=MemoryBlockUtils.createFileBytes(p,provider,monitor);
            var opts=p.getOptions(ProgramMapping.OPTIONS);
            opts.setInt("schemaVersion",ProgramMapping.SCHEMA_VERSION);
            opts.setString("inputMode",selected); opts.setString("requestedMode",mode);
            opts.setString("hardware",kind.name()); opts.setString("mapperOverride",mapperOverride);
            opts.setString("originalSha256",Sha256.of(input).toString()); opts.setLong("originalLength",input.length);
            if(cartridge!=null) { opts.setString("cartridge",ProgramMapping.JSON.toJson(cartridge)); cartridge.warnings().forEach(log::appendMsg); }
            if(types) DataTypes.addAll(p.getDataTypeManager());
            if(boot) {
                permissions(memory.createInitializedBlock("boot",as.getAddress(0),file,0,0x100,false),true,false,true);
                if(kind==GameBoyKind.CGB) permissions(memory.createInitializedBlock("boot1",as.getAddress(0x200),file,0x200,0x700,false),true,false,true);
                p.getSymbolTable().addExternalEntryPoint(as.getAddress(0));
                p.getSymbolTable().createLabel(as.getAddress(0),"boot_entry",SourceType.IMPORTED);
            } else {
                int banks=cartridge.actualRomBanks();
                if(banks==2 && cartridge.mapper()==Cartridge.Mapper.ROM_ONLY)
                    permissions(memory.createInitializedBlock("rom",as.getAddress(0),file,0,0x8000,false),true,false,true);
                else {
                    var canonical=new MemoryBlock[banks];
                    for(int bank=0;bank<banks;bank++) {
                        monitor.checkCancelled();
                        canonical[bank]=memory.createInitializedBlock("rom"+bank,as.getAddress(bank==0?0:0x4000),file,bank*0x4000L,0x4000,bank!=0);
                        permissions(canonical[bank],true,false,true);
                    }
                    for(var view:MapperTopology.romViews(cartridge)) {
                        monitor.checkCancelled();
                        var source=canonical[view.bank()];
                        if(source.getStart().getOffset()==view.cpuWindow()) continue;
                        String suffix=view.cpuWindow()==0?"_low":"_high";
                        permissions(memory.createByteMappedBlock("rom"+view.bank()+suffix,
                            as.getAddress(view.cpuWindow()),source.getStart(),0x4000,true),true,false,true);
                    }
                }
                int ram=cartridge.ramBytes();
                if(ram>0) {
                    int length=Math.min(ram,0x2000), count=Math.max(1,ram/0x2000);
                    for(int bank=0;bank<count;bank++) {
                        monitor.checkCancelled();
                        var b=memory.createUninitializedBlock(count==1?"xram":"xram"+bank,as.getAddress(0xa000),length,bank>0);
                        permissions(b,true,true,false);
                        ProgramMapping.anchor(p,b,cartridge.mapper()==Cartridge.Mapper.MBC2?"MBC2_RAM":"SRAM",bank);
                        // MBC2 stores low nibbles only; static bytes do not enforce read-high-nibble behavior.
                        if(length<0x2000) for(int off=length;off<0x2000;off+=length)
                            permissions(memory.createByteMappedBlock("xram_mirror"+off,as.getAddress(0xa000+off),b.getStart(),length,false),true,true,false);
                    }
                }
                for(int vector=0;vector<=0x38;vector+=8)
                    p.getSymbolTable().createLabel(as.getAddress(vector),String.format("rst%02x",vector),SourceType.IMPORTED);
                String[] interrupts={"vblank","stat","timer","serial","joypad"};
                for(int vector=0;vector<interrupts.length;vector++)
                    p.getSymbolTable().createLabel(as.getAddress(0x40+vector*8),"intr_"+interrupts[vector],SourceType.IMPORTED);
                p.getSymbolTable().addExternalEntryPoint(as.getAddress(0x100));
                p.getSymbolTable().createLabel(as.getAddress(0x100),"entry",SourceType.IMPORTED);
                if(types) {
                    DataUtilities.createData(p,as.getAddress(0x104),DataTypes.LOGO,-1,false,DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
                    var header=DataUtilities.createData(p,as.getAddress(0x134),DataTypes.HEADER,-1,false,DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
                    EndianSettingsDefinition.DEF.setBigEndian(header.getComponentContaining(0x1a),true);
                }
            }
            if(hardwareBlocks) hardware(p,kind,monitor,log);
            monitor.checkCancelled(); success=true;
        } finally { p.endTransaction(tx,success); }
    }
    private static void hardware(Program p,GameBoyKind kind,TaskMonitor monitor,MessageLog log) throws Exception {
        GameBoyUtils.addHardwareBlocks(p,kind,log);
        var m=p.getMemory(); var as=p.getAddressFactory().getDefaultAddressSpace();
        String[] required=kind==GameBoyKind.CGB?new String[]{"vram0","vram1","wram0","wram1","wram2","wram3","wram4","wram5","wram6","wram7","oam","io","hram","ie"}:new String[]{"vram","wram","oam","io","hram","ie"};
        for(String name:required) {
            monitor.checkCancelled();
            var b=m.getBlock(name); if(b==null) throw new IOException("Required hardware block creation failed: "+name);
            String region=name.startsWith("wram")?"WRAM":name.startsWith("vram")?"VRAM":name.toUpperCase();
            int bank=Character.isDigit(name.charAt(name.length()-1))?name.charAt(name.length()-1)-'0':0;
            ProgramMapping.anchor(p,b,region,bank);
        }
        if(kind==GameBoyKind.CGB) {
            permissions(m.createByteMappedBlock("echo0",as.getAddress(0xe000),m.getBlock("wram0").getStart(),0x1000,false),true,true,false);
            for(int bank=1;bank<=7;bank++) permissions(m.createByteMappedBlock("echo"+bank,as.getAddress(0xf000),m.getBlock("wram"+bank).getStart(),0xe00,true),true,true,false);
        } else {
            // Split physical identity at D000 while retaining familiar historical wram block name.
            m.split(m.getBlock("wram"),as.getAddress(0xd000));
            ProgramMapping.anchor(p,m.getBlock(as.getAddress(0xc000)),"WRAM",0);
            ProgramMapping.anchor(p,m.getBlock(as.getAddress(0xd000)),"WRAM",1);
            permissions(m.createByteMappedBlock("echo",as.getAddress(0xe000),as.getAddress(0xc000),0x1e00,false),true,true,false);
        }
        GameBoyUtils.populateHardwareBlocks(p,kind);
        HardwareReference.apply(p,kind);
    }
    private static void permissions(MemoryBlock b,boolean read,boolean write,boolean execute) {
        b.setRead(read); b.setWrite(write); b.setExecute(execute);
    }
}
