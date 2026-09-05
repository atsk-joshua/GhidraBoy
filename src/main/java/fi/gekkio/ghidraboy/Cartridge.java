package fi.gekkio.ghidraboy;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/** Immutable, Ghidra-independent header validation. No byte repair or database mutation. */
public record Cartridge(String rawHeader, String title, String manufacturer, int cgb, int sgb,
        int type, int romSizeCode, int ramSizeCode, int declaredRomBanks, int ramBytes,
        long inputLength, String inputSha256, int headerChecksum, int computedHeaderChecksum,
        int globalChecksum, int computedGlobalChecksum, Mapper mapper, String hardware, List<String> warnings, Geometry geometry, HeaderStatus headerStatus) {
    public enum InputPolicy { STRICT, SALVAGE }
    public enum HeaderStatus { COMPLETE, TRUNCATED, UNKNOWN_SIZE }
    public record Geometry(long actualLength, Long declaredLength, long addressableLength,
                           long trailingOffset, long trailingLength, InputPolicy policy) { }
    public enum Mapper { ROM_ONLY, MBC1, MBC2, MBC3, MBC5, RAW }

    public Cartridge { warnings = List.copyOf(warnings); }

    public static Cartridge parse(byte[] data, String mapperOverride) { return parse(data,mapperOverride,InputPolicy.STRICT); }
    public static Cartridge parse(byte[] data, String mapperOverride, InputPolicy policy) {
        boolean salvage=policy==InputPolicy.SALVAGE;
        if(data.length==0 || data.length>(salvage?0x1000000:0x800000)) throw new IllegalArgumentException("Input outside policy size limits");
        if(salvage && data.length<0x150) return new Cartridge(HexFormat.of().formatHex(data),"","",-1,-1,-1,-1,-1,-1,0,
            data.length,Sha256.of(data).toString(),-1,-1,-1,-1,Mapper.RAW,"UNKNOWN",List.of("Incomplete header: all original bytes retained unmapped"),
            new Geometry(data.length,null,0,0,data.length,policy),HeaderStatus.TRUNCATED);
        if (data.length < 0x150) throw new IllegalArgumentException("Cartridge header truncated: need at least 0x150 bytes");
        if (!salvage && (data.length < 0x8000 || data.length > 0x800000 || data.length % 0x4000 != 0))
            throw new IllegalArgumentException("Cartridge must contain 2..512 complete 16 KiB banks; partial/trailing bytes are rejected");
        int type = u(data, 0x147), rc = u(data, 0x148), ac = u(data, 0x149);
        int banks = switch (rc) {
            case 0,1,2,3,4,5,6,7,8 -> 2 << rc;
            case 0x52 -> 72;
            case 0x53 -> 80;
            case 0x54 -> 96;
            default -> { if(!salvage) throw new IllegalArgumentException("Unknown ROM size code: " + rc); yield -1; }
        };
        int ram = switch (ac) {
            case 0 -> 0; case 1 -> 2048; case 2 -> 8192; case 3 -> 32768;
            case 4 -> 131072; case 5 -> 65536;
            default -> { if(!salvage) throw new IllegalArgumentException("Unknown RAM size code: " + ac); yield 0; }
        };
        Mapper mapper = switch (type) {
            case 0,8,9 -> Mapper.ROM_ONLY;
            case 1,2,3 -> Mapper.MBC1;
            case 5,6 -> Mapper.MBC2;
            case 0x0f,0x10,0x11,0x12,0x13 -> Mapper.MBC3;
            case 0x19,0x1a,0x1b,0x1c,0x1d,0x1e -> Mapper.MBC5;
            default -> Mapper.RAW;
        };
        var warnings = new ArrayList<String>();
        long fullBytes=Math.min(data.length/0x4000,512)*0x4000L;
        long addressable=salvage && banks>=0?Math.min(fullBytes,banks*0x4000L):fullBytes;
        var geometry=new Geometry(data.length,banks<0?null:banks*0x4000L,addressable,addressable,data.length-addressable,policy);
        if(salvage) warnings.add("Explicit salvage policy: incomplete or trailing bytes retained without executable padding");
        if (mapperOverride != null && !mapperOverride.equals("AUTO")) {
            mapper = Mapper.valueOf(mapperOverride);
            warnings.add("Explicit mapper override: " + mapperOverride);
        }
        if(salvage && (banks<0 || ac>5 || addressable<banks*0x4000L)) {
            mapper=Mapper.RAW; warnings.add("Incomplete/unknown geometry: mapper certainty disabled even with a requested override");
        }
        if (banks * 0x4000 != data.length) warnings.add("Declared ROM size differs from actual complete banks; actual geometry used");
        if (rc >= 0x52 || ac == 1) warnings.add("Historical uncertain size convention; no verified hardware claim");
        if (mapper == Mapper.MBC2) ram = 512;
        boolean hasRam = switch (type) {
            case 2,3,8,9,0x10,0x12,0x13,0x1a,0x1b,0x1d,0x1e -> true;
            default -> false;
        };
        if (mapper != Mapper.MBC2 && mapper != Mapper.RAW && !hasRam && ram != 0) {
            warnings.add("RAM size contradicts cartridge type; no external RAM allocated");
            ram = 0;
        }
        int max = switch (mapper) {
            case ROM_ONLY -> 2; case MBC1,MBC3 -> 128; case MBC2 -> 16; case MBC5,RAW -> 512;
        };
        if (data.length / 0x4000 > max || ((mapper == Mapper.MBC1 || mapper == Mapper.MBC3) && ram > 32768) || (mapper == Mapper.ROM_ONLY && ram > 8192) || (mapper == Mapper.MBC5 && type>=0x1c && type<=0x1e && ram>65536)) {
            warnings.add("Geometry exceeds ordinary mapper capabilities; static translation disabled (MBC30/other subtype not inferred)");
            mapper = Mapper.RAW;
        }
        if (mapper == Mapper.RAW) { ram=0; warnings.add("Raw physical-bank import only; unsupported mapper translation and external RAM topology"); }
        if (mapper == Mapper.MBC1) warnings.add("Ordinary MBC1 assumed; MBC1M is not auto-detected or modeled");
        int hc = 0, gc = 0;
        for (int i = 0x134; i <= 0x14c; i++) hc = (hc - u(data,i) - 1) & 255;
        for (int i = 0; i < addressable; i++) if (i != 0x14e && i != 0x14f) gc = (gc + u(data,i)) & 65535;
        int header = u(data,0x14d), global = u(data,0x14e) * 256 + u(data,0x14f);
        if (hc != header) warnings.add("Header checksum mismatch (bytes preserved)");
        if (gc != global) warnings.add("Global checksum mismatch (bytes preserved)");
        int cgb = u(data,0x143);
        return new Cartridge(HexFormat.of().formatHex(data,0x100,0x150),
            text(data,0x134,(cgb & 128) != 0 ? 15 : 16), text(data,0x13f,4), cgb,
            u(data,0x146),type,rc,ac,banks,ram,data.length,Sha256.of(data).toString(),
            header,hc,global,gc,mapper,(cgb & 128)!=0?"CGB":"GB",warnings,geometry,banks<0 || ac>5?HeaderStatus.UNKNOWN_SIZE:HeaderStatus.COMPLETE);
    }

    public enum SupportLevel { SUPPORTED, RAW_ONLY, ASSUMPTION_REQUIRED, UNSUPPORTED }
    public record Support(SupportLevel rawLoading,SupportLevel physicalBanks,SupportLevel translation,SupportLevel inference,List<String> limitations) { }
    public Support support() {
        return new Support(SupportLevel.SUPPORTED,mapper==Mapper.RAW?SupportLevel.RAW_ONLY:SupportLevel.SUPPORTED,
            mapper==Mapper.RAW?SupportLevel.UNSUPPORTED:mapper==Mapper.MBC1?SupportLevel.ASSUMPTION_REQUIRED:SupportLevel.SUPPORTED,
            mapper==Mapper.RAW?SupportLevel.UNSUPPORTED:SupportLevel.ASSUMPTION_REQUIRED,List.copyOf(warnings));
    }
    public long addressableLength() { return geometry==null?inputLength:geometry.addressableLength(); }
    public int actualRomBanks() { return (int)(addressableLength() / 0x4000); }
    public Cartridge withHardware(GameBoyKind kind) { return withHardwareChoice(kind.name()); }
    public Cartridge withHardwareChoice(String choice) {
        if(!List.of("GB","CGB","UNKNOWN").contains(choice)) throw new IllegalArgumentException("Unknown hardware choice");
        var notes=new ArrayList<>(warnings);
        if(!choice.equals(hardware)) notes.add("Hardware choice: "+choice);
        return new Cartridge(rawHeader,title,manufacturer,cgb,sgb,type,romSizeCode,ramSizeCode,declaredRomBanks,ramBytes,
            inputLength,inputSha256,headerChecksum,computedHeaderChecksum,globalChecksum,computedGlobalChecksum,mapper,choice,notes,geometry,headerStatus);
    }
    public boolean hardwareKnown() { return "GB".equals(hardware) || "CGB".equals(hardware); }
    public boolean color() { return "CGB".equals(hardware); }
    public boolean rumble() { return type >= 0x1c && type <= 0x1e; }
    public boolean rtc() { return type == 0x0f || type == 0x10; }
    private static int u(byte[] b,int i) { return b[i] & 255; }
    private static String text(byte[] b,int off,int len) {
        int n=0; while(n<len && b[off+n]!=0) n++;
        return new String(b,off,n,StandardCharsets.ISO_8859_1);
    }
}
