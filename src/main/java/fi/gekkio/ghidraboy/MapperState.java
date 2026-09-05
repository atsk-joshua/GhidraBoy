package fi.gekkio.ghidraboy;

/** Explicit immutable static register state. Null state means unknown, never bank 1. */
public record MapperState(int romLow, int romHigh, int mode, int ramSelect, boolean ramEnabled,
                          int vbk, int svbk, int latch) {
    public MapperState {
        if(romLow<0 || romLow>255 || romHigh<0 || romHigh>3 || mode<0 || mode>1 ||
            ramSelect<0 || ramSelect>255 || vbk<0 || vbk>1 || svbk<0 || svbk>7 || latch<0 || latch>255)
            throw new IllegalArgumentException("Mapper state register out of range");
        if(svbk==0) svbk=1;
    }
    public static MapperState reset() { return new MapperState(1,0,0,0,false,0,1,0); }

    public MapperState write(Cartridge c, int address, int value) {
        if (address < 0 || address > 65535 || value < 0 || value > 255)
            throw new IllegalArgumentException("CPU address/value out of range");
        int low=romLow, high=romHigh, m=mode, ram=ramSelect, v=vbk, s=svbk, l=latch;
        boolean enabled=ramEnabled;
        if (address==0xff4f) v=value & 1;
        if (address==0xff70) s=(value & 7)==0 ? 1 : value & 7;
        switch(c.mapper()) {
            case MBC1 -> {
                if(address<0x2000) enabled=(value & 15)==10;
                else if(address<0x4000) low=value & 31;
                else if(address<0x6000) { high=value & 3; ram=high; }
                else if(address<0x8000) m=value & 1;
            }
            case MBC2 -> {
                if(address<0x4000) {
                    if((address & 0x100)==0) enabled=(value & 15)==10;
                    else low=value & 15;
                }
            }
            case MBC3 -> {
                if(address<0x2000) enabled=(value & 15)==10;
                else if(address<0x4000) low=value & 127;
                else if(address<0x6000) ram=value;
                else if(address<0x8000) l=value; // 0 -> 1 requests RTC latch, no clock evolution.
            }
            case MBC5 -> {
                if(address<0x2000) enabled=(value & 15)==10;
                else if(address<0x3000) low=value;
                else if(address<0x4000) high=value & 1;
                else if(address<0x6000) ram=value & (c.rumble()?7:15);
            }
            default -> { }
        }
        return new MapperState(low,high,m,ram,enabled,v,s,l);
    }

    /** True for the documented MBC3 0 -> 1 latch request, without clock evolution. */
    public boolean rtcLatchRequested(Cartridge c,int address,int value) {
        return c.mapper()==Cartridge.Mapper.MBC3 && c.rtc() && address>=0x6000 && address<0x8000 && latch==0 && value==1;
    }

    /** MBC2 stores only the low nibble and returns ones in the upper nibble. */
    public static int ramWriteValue(Cartridge c,int value) {
        if(value<0 || value>255) throw new IllegalArgumentException("RAM byte out of range");
        return c.mapper()==Cartridge.Mapper.MBC2?value & 15:value;
    }
    public static int ramReadValue(Cartridge c,int stored) {
        return c.mapper()==Cartridge.Mapper.MBC2?0xf0 | ramWriteValue(c,stored):ramWriteValue(c,stored);
    }

    public record Physical(String region, int bank, int offset) { }
    public record Resolution(String status, Physical physical, String reason) {
        static Resolution mapped(String r,int b,int o) { return new Resolution("mapped",new Physical(r,b,o),""); }
        static Resolution other(String s,String why) { return new Resolution(s,null,why); }
    }
    public static Resolution translate(Cartridge c, MapperState s, int cpu, boolean write) {
        if(cpu<0 || cpu>65535) throw new IllegalArgumentException("CPU address out of range");
        if(cpu<0x8000) {
            if(write) return Resolution.other(c.mapper()==Cartridge.Mapper.ROM_ONLY ? "unmapped" : "device", "ROM is read-only; mapper control write");
            if(c.mapper()==Cartridge.Mapper.RAW) return Resolution.other("unknown","Unsupported mapper");
            if(s==null && cpu<0x4000 && (c.mapper()==Cartridge.Mapper.MBC2 || c.mapper()==Cartridge.Mapper.MBC3 || c.mapper()==Cartridge.Mapper.MBC5))
                return Resolution.mapped("ROM",0,cpu);
            if(c.mapper()!=Cartridge.Mapper.ROM_ONLY && s==null) return Resolution.other("unknown","Explicit mapper state required");
            int bank=cpu/0x4000;
            switch(c.mapper()) {
                case MBC1 -> bank=cpu<0x4000 ? (s.mode==0?0:s.romHigh<<5) : (s.romHigh<<5)|(s.romLow==0?1:s.romLow);
                case MBC2,MBC3 -> bank=cpu<0x4000?0:(s.romLow==0?1:s.romLow);
                case MBC5 -> bank=cpu<0x4000?0:(s.romHigh<<8)|s.romLow;
                default -> { }
            }
            int banks=c.actualRomBanks();
            if((banks & (banks-1))!=0) return Resolution.other("unknown","Non-power-of-two ROM wiring is not inferred");
            bank &= banks-1; // zero-register substitution precedes masking disconnected address lines.
            return Resolution.mapped("ROM",bank,cpu & 0x3fff);
        }
        if(cpu<0xa000) {
            if(c.color() && s==null) return Resolution.other("unknown","VBK required");
            return Resolution.mapped("VRAM",c.color()?s.vbk:0,cpu-0x8000);
        }
        if(cpu<0xc000) {
            if(c.mapper()==Cartridge.Mapper.RAW) return Resolution.other("unknown","Unsupported external device");
            if(c.mapper()!=Cartridge.Mapper.ROM_ONLY && s==null) return Resolution.other("unknown","RAM selection required");
            if(c.mapper()!=Cartridge.Mapper.ROM_ONLY && !s.ramEnabled) return Resolution.other("unmapped","RAM/RTC disabled");
            if(c.mapper()==Cartridge.Mapper.MBC3 && s.ramSelect>=8 && s.ramSelect<=12)
                return Resolution.other(c.rtc()?"device":"unmapped","MBC3 RTC register selection (no clock model)");
            if(c.mapper()==Cartridge.Mapper.MBC3 && s.ramSelect>3) return Resolution.other("unmapped","Invalid RAM/RTC selection");
            if(c.ramBytes()==0) return Resolution.other("unmapped","No cartridge RAM");
            if(c.mapper()==Cartridge.Mapper.MBC2) return Resolution.mapped("MBC2_RAM",0,cpu & 511);
            int bank=s==null?0:s.ramSelect;
            if(c.mapper()==Cartridge.Mapper.MBC1) bank=s.mode==0?0:s.romHigh;
            if(c.mapper()==Cartridge.Mapper.ROM_ONLY) bank=0;
            bank &= Math.max(1,c.ramBytes()/8192)-1;
            return Resolution.mapped("SRAM",bank,(cpu-0xa000)%Math.min(c.ramBytes(),8192));
        }
        if(cpu<0xfe00) {
            int base=cpu>=0xe000?cpu-0x2000:cpu;
            if(base<0xd000) return Resolution.mapped("WRAM",0,base-0xc000);
            if(c.color() && s==null) return Resolution.other("unknown","SVBK required");
            return Resolution.mapped("WRAM",c.color()?s.svbk:1,base-0xd000);
        }
        if(cpu<0xfea0) return Resolution.mapped("OAM",0,cpu-0xfe00);
        if(cpu<0xff00) return Resolution.other("unmapped","Unusable hardware interval");
        if(cpu<0xff80 || cpu==0xffff) return Resolution.other("device","Volatile hardware register");
        return Resolution.mapped("HRAM",0,cpu-0xff80);
    }
}
