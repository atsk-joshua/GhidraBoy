package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import java.io.IOException;

/** Preview before mutation; only imported labels with recorded ownership are removable. */
public final class SymbolService {
    public record Placement(SymbolFile.Symbol symbol,List<Address> addresses,String diagnostic) { }
    private record Owned(long id,String name,String address) { }
    private SymbolService() { }
    public static List<Placement> preview(Program p,SymbolFile.Result parsed) throws IOException {
        List<Placement> out=new ArrayList<>();
        var snapshot=ProgramMapping.inspect(p);
        for(var symbol:parsed.symbols()) {
            var l=symbol.location(); var found=new LinkedHashSet<Address>();
            String reason="";
            if(l.address()==0x8000 || l.address()==0xa000 || l.address()==0xc000 || l.address()==0xd000 || l.address()==0xe000)
                reason="Region boundary or one-past-end marker requires explicit placement";
            else for(var r:snapshot.ranges()) {
                if(l.address()<r.start() || l.address()>=r.start()+r.length()) continue;
                if(r.alias()!=null) {
                    var a=p.getAddressFactory().getAddressSpace(r.space()).getAddress(l.address());
                    for(var physical:ProgramMapping.staticToPhysical(p,a,snapshot)) {
                        boolean boot=physical.region().equals("BOOT");
                        if((l.form().equals("BOOT") && boot) || (!boot && (l.form().equals("ANY") || l.bank()==physical.bank()))) found.add(a);
                    }
                    continue;
                }
                boolean match;
                if(l.form().equals("BOOT")) match=r.region().equals("BOOT");
                else if(r.region().equals("BOOT")) match=false;
                else if(l.form().equals("ANY")) match=true;
                else {
                    long bank=r.bank();
                    // RGBDS's unbanked 32 KiB ROM convention uses bank 0 for both windows.
                    if(snapshot.cartridge()!=null && snapshot.cartridge().mapper()==Cartridge.Mapper.ROM_ONLY && r.region().equals("ROM")) bank=0;
                    match=bank==l.bank();
                }
                if(match) found.add(p.getAddressFactory().getAddressSpace(r.space()).getAddress(l.address()));
            }
            if(found.isEmpty() && reason.isEmpty()) reason="Unmapped or unsupported symbol location; source retained";
            out.add(new Placement(symbol,List.copyOf(found),reason));
        }
        return List.copyOf(out);
    }
    public static List<Placement> importSymbols(Program p,SymbolFile.Result parsed,String source,TaskMonitor monitor) throws Exception {
        var placements=preview(p,parsed);
        int tx=p.startTransaction("Import Game Boy symbols"); boolean success=false;
        try {
            var st=p.getSymbolTable(); var owned=new ArrayList<Owned>();
            var opts=p.getOptions(ProgramMapping.OPTIONS);
            String key="symbols."+Sha256.of(source.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String existing=opts.getString(key+".owned","[]");
            owned.addAll(Arrays.asList(ProgramMapping.JSON.fromJson(existing,Owned[].class)));
            var desired=new HashSet<String>();
            for(var placement:placements) for(var a:placement.addresses) desired.add(a+"\n"+placement.symbol.name());
            for(var prior:List.copyOf(owned)) {
                if(desired.contains(prior.address+"\n"+prior.name)) continue;
                var sym=st.getSymbol(prior.id);
                if(sym!=null && sym.getSource()==SourceType.IMPORTED && sym.getName().equals(prior.name) && sym.getAddress().toString().equals(prior.address)
                    && sym.getSymbolType()==ghidra.program.model.symbol.SymbolType.LABEL) sym.delete();
                owned.remove(prior);
            }
            for(var placement:placements) {
                monitor.checkCancelled();
                for(var a:placement.addresses) {
                    String name=placement.symbol.name();
                    boolean present=false;
                    for(var sym:st.getSymbols(a)) if(sym.getName().equals(name)) present=true;
                    if(!present) {
                        var sym=st.createLabel(a,name,SourceType.IMPORTED);
                        owned.add(new Owned(sym.getID(),name,a.toString()));
                    }
                }
            }
            opts.setString(key+".owned",ProgramMapping.JSON.toJson(owned));
            opts.setString(key+".source",source);
            opts.setString(key+".text",SymbolFile.format(parsed.symbols()));
            success=true;
        } finally { p.endTransaction(tx,success); }
        return placements;
    }
    public static void removeOwned(Program p,String source,TaskMonitor monitor) throws Exception {
        var opts=p.getOptions(ProgramMapping.OPTIONS);
        String key="symbols."+Sha256.of(source.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        var owned=ProgramMapping.JSON.fromJson(opts.getString(key+".owned","[]"),Owned[].class);
        int tx=p.startTransaction("Remove owned Game Boy symbols"); boolean success=false;
        try {
            for(var o:owned) {
                monitor.checkCancelled();
                var s=p.getSymbolTable().getSymbol(o.id);
                if(s!=null && s.getSource()==SourceType.IMPORTED && s.getName().equals(o.name) && s.getAddress().toString().equals(o.address)
                    && s.getSymbolType()==ghidra.program.model.symbol.SymbolType.LABEL) s.delete();
            }
            opts.removeOption(key+".owned"); success=true;
        } finally { p.endTransaction(tx,success); }
    }
    public record Export(String text,List<String> diagnostics) { }
    public static Export exportSymbols(Program p,TaskMonitor monitor) throws Exception {
        var out=new ArrayList<SymbolFile.Symbol>(); var diagnostics=new ArrayList<String>();
        var seen=new HashSet<String>(); var c=ProgramMapping.cartridge(p);
        var snapshot=ProgramMapping.inspect(p);
        var symbols=p.getSymbolTable().getAllSymbols(true);
        while(symbols.hasNext()) {
            monitor.checkCancelled(); var symbol=symbols.next();
            if(symbol.getSource()==SourceType.DEFAULT || (!symbol.getSymbolType().equals(ghidra.program.model.symbol.SymbolType.LABEL)
                && !symbol.getSymbolType().equals(ghidra.program.model.symbol.SymbolType.FUNCTION))) continue;
            var identities=ProgramMapping.staticToPhysical(p,symbol.getAddress(),snapshot);
            if(identities.size()!=1) { diagnostics.add(symbol.getName()+": physical identity unresolved"); continue; }
            var physical=identities.get(0); int bank=physical.bank();
            if(c!=null && c.mapper()==Cartridge.Mapper.ROM_ONLY && physical.region().equals("ROM")) bank=0;
            var location=new SymbolFile.Location(physical.region().equals("BOOT")?"BOOT":"BANK",bank,(int)symbol.getAddress().getOffset());
            var entry=new SymbolFile.Symbol(location,symbol.getName(),0);
            String line=SymbolFile.format(List.of(entry));
            var validated=SymbolFile.parse(line.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            if(validated.symbols().size()!=1) { diagnostics.add(symbol.getName()+": name not representable by RGBDS grammar"); continue; }
            if(seen.add(line)) out.add(entry);
        }
        out.sort(Comparator.comparing((SymbolFile.Symbol x)->x.location().form()).thenComparingLong(x->x.location().bank())
            .thenComparingInt(x->x.location().address()).thenComparing(SymbolFile.Symbol::name));
        return new Export(SymbolFile.format(out),List.copyOf(diagnostics));
    }
    public static String exportRetained(Program p,String source) {
        String key="symbols."+Sha256.of(source.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return p.getOptions(ProgramMapping.OPTIONS).getString(key+".text","");
    }
}
