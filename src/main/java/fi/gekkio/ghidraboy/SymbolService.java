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
                var address=p.getAddressFactory().getAddressSpace(r.space()).getAddress(l.address());
                for(var physical:ProgramMapping.staticToPhysical(p,address,snapshot))
                    if(matches(l,physical,snapshot.cartridge())) found.add(address);
            }
            if(found.isEmpty() && reason.isEmpty()) reason="Unmapped or unsupported symbol location; source retained";
            out.add(new Placement(symbol,List.copyOf(found),reason));
        }
        return List.copyOf(out);
    }
    public static String entryKey(SymbolFile.Symbol symbol) { return SymbolFile.format(List.of(symbol)).strip(); }
    public static List<Address> boundaryCandidates(Program p,SymbolFile.Symbol symbol) throws IOException {
        var snapshot=ProgramMapping.inspect(p); var out=new TreeSet<Address>(); int cpu=symbol.location().address();
        for(var range:snapshot.ranges()) {
            var space=p.getAddressFactory().getAddressSpace(range.space());
            if(range.start()==cpu || range.start()+range.length()==cpu) {
                long probe=range.start()==cpu?cpu:cpu-1;
                for(var physical:ProgramMapping.staticToPhysical(p,space.getAddress(probe),snapshot))
                    if(matches(symbol.location(),physical,snapshot.cartridge())) out.add(space.getAddressInThisSpaceOnly(cpu));
            }
        }
        return List.copyOf(out);
    }
    public static Optional<java.nio.file.Path> companion(Program p) {
        String executable=p.getExecutablePath();
        if(executable==null || executable.isBlank()) return Optional.empty();
        try {
            var input=java.nio.file.Path.of(executable).toAbsolutePath().normalize();
            if(!java.nio.file.Files.isRegularFile(input)) return Optional.empty();
            String name=input.getFileName().toString(); int dot=name.lastIndexOf('.');
            var candidate=input.resolveSibling((dot<0?name:name.substring(0,dot))+".sym");
            return java.nio.file.Files.isRegularFile(candidate)?Optional.of(candidate):Optional.empty();
        } catch(java.nio.file.InvalidPathException e) { return Optional.empty(); }
    }
    private static boolean matches(SymbolFile.Location location,MapperState.Physical physical,Cartridge cartridge) {
        boolean boot=physical.region().equals("BOOT");
        long bank=physical.bank();
        if(cartridge!=null && cartridge.mapper()==Cartridge.Mapper.ROM_ONLY && physical.region().equals("ROM")) bank=0;
        return switch(location.form()) {
            case "BOOT" -> boot;
            case "ANY" -> !boot;
            case "BANK" -> !boot && location.bank()==bank;
            default -> false;
        };
    }
    private static final String REGISTRY = "symbols.registry.v2";
    private static final class Registry {
        int version = 2;
        Map<String, String> sources = new TreeMap<>();
        Map<String, Map<String, AnalysisOwnership.Point>> placements = new TreeMap<>();
        Map<Long, LabelIdentity> labels = new TreeMap<>();
    }
    private static final class LabelIdentity {
        long id;
        String name;
        String qualifiedName;
        long namespace;
        int space;
        long offset;
        boolean created;
        Set<String> claims = new TreeSet<>();

        LabelIdentity(ghidra.program.model.symbol.Symbol symbol, boolean created) {
            id = symbol.getID(); name = symbol.getName(); qualifiedName = symbol.getName(true);
            namespace = symbol.getParentNamespace().getID();
            space = symbol.getAddress().getAddressSpace().getSpaceID(); offset = symbol.getAddress().getOffset();
            this.created = created;
        }
        boolean unchanged(ghidra.program.model.symbol.Symbol symbol) {
            return symbol != null && symbol.getSource() == SourceType.IMPORTED &&
                symbol.getSymbolType() == ghidra.program.model.symbol.SymbolType.LABEL &&
                symbol.getName().equals(name) && symbol.getName(true).equals(qualifiedName) &&
                symbol.getParentNamespace().getID() == namespace &&
                symbol.getAddress().getAddressSpace().getSpaceID() == space && symbol.getAddress().getOffset() == offset;
        }
    }
    public record Source(String name, String retainedText, int claims) { }

    private static Registry registry(Program p) throws IOException {
        var opts = p.getOptions(ProgramMapping.OPTIONS);
        String json = opts.getString(REGISTRY, null);
        if (json != null) {
            var registry = ProgramMapping.JSON.fromJson(json, Registry.class);
            if (registry.version != 2) throw new IOException("Unsupported symbol registry version");
            return registry;
        }
        // Migrate v1 retained sources as claims, including sources that created no new label.
        var registry = new Registry();
        var previouslyOwned = new HashSet<Long>();
        for (String key : opts.getOptionNames()) if (key.startsWith("symbols.") && key.endsWith(".owned")) {
            for (var old : ProgramMapping.JSON.fromJson(opts.getString(key, "[]"), Owned[].class)) {
                var symbol = p.getSymbolTable().getSymbol(old.id);
                if (symbol != null && symbol.getSource() == SourceType.IMPORTED && symbol.getName().equals(old.name) &&
                    symbol.getAddress().toString().equals(old.address)) previouslyOwned.add(old.id);
            }
        }
        for (String key : opts.getOptionNames()) if (key.startsWith("symbols.") && key.endsWith(".source")) {
            String source = opts.getString(key, "");
            String text = opts.getString(key.substring(0, key.length()-7) + ".text", "");
            registry.sources.put(source, text);
            var parsed = SymbolFile.parse(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            for (var placement : preview(p, parsed)) for (var address : placement.addresses()) {
                var symbol = existing(p, address, placement.symbol().name());
                if (symbol == null) continue;
                var identity = registry.labels.computeIfAbsent(symbol.getID(), id -> new LabelIdentity(symbol, previouslyOwned.contains(id)));
                identity.claims.add(source);
            }
        }
        return registry;
    }
    private static ghidra.program.model.symbol.Symbol existing(Program p, Address address, String name) {
        for (var symbol : p.getSymbolTable().getSymbols(address))
            if (symbol.getName().equals(name) && symbol.getParentNamespace().isGlobal()) return symbol;
        return null;
    }
    private static void collectUnclaimed(Program p, Registry registry, TaskMonitor monitor) throws Exception {
        for (var identity : List.copyOf(registry.labels.values())) {
            monitor.checkCancelled();
            if (!identity.claims.isEmpty()) continue;
            var symbol = p.getSymbolTable().getSymbol(identity.id);
            if (identity.created && identity.unchanged(symbol)) symbol.delete();
            registry.labels.remove(identity.id);
        }
    }
    public static List<Source> sources(Program p) throws IOException {
        var registry = registry(p);
        return registry.sources.entrySet().stream().map(entry -> new Source(entry.getKey(), entry.getValue(),
            (int) registry.labels.values().stream().filter(label -> label.claims.contains(entry.getKey())).count())).toList();
    }
    public static List<Placement> importSymbols(Program p,SymbolFile.Result parsed,String source,TaskMonitor monitor) throws Exception {
        return importSymbols(p,parsed,source,Map.of(),monitor);
    }
    public static List<Placement> importSymbols(Program p,SymbolFile.Result parsed,String source,Map<String,String> overrides,TaskMonitor monitor) throws Exception {
        var registryBefore=registry(p);
        var choices=new TreeMap<String,AnalysisOwnership.Point>(registryBefore.placements.getOrDefault(source,Map.of()));
        for(var entry:overrides.entrySet()) {
            var address=ProgramMapping.staticAddress(p,entry.getValue());
            if(address==null) throw new IllegalArgumentException("Unknown static address "+entry.getValue());
            choices.put(entry.getKey(),AnalysisOwnership.Point.of(address));
        }
        var placements=new ArrayList<Placement>();
        for(var placement:preview(p,parsed)) {
            var selected=choices.get(entryKey(placement.symbol()));
            if(selected!=null) {
                var address=selected.resolve(p);
                if(!boundaryCandidates(p,placement.symbol()).contains(address)) throw new IllegalArgumentException("Stale or invalid boundary placement for "+entryKey(placement.symbol()));
                placement=new Placement(placement.symbol(),List.of(address),"Explicit boundary/end-marker placement");
            }
            placements.add(placement);
        }
        monitor.checkCancelled();
        int tx = p.startTransaction("Import Game Boy symbols"); boolean success = false;
        try {
            var registry = registry(p);
            for (var identity : registry.labels.values()) identity.claims.remove(source);
            for (var placement : placements) for (var address : placement.addresses()) {
                monitor.checkCancelled();
                var symbol = existing(p, address, placement.symbol().name());
                boolean created = symbol == null;
                if (created) symbol = p.getSymbolTable().createLabel(address, placement.symbol().name(), SourceType.IMPORTED);
                var identity = registry.labels.get(symbol.getID());
                if (identity == null) { identity = new LabelIdentity(symbol, created); registry.labels.put(symbol.getID(), identity); }
                identity.claims.add(source);
            }
            collectUnclaimed(p, registry, monitor);
            registry.sources.put(source, SymbolFile.format(parsed.symbols()));
            registry.placements.put(source,choices);
            p.getOptions(ProgramMapping.OPTIONS).setString(REGISTRY, ProgramMapping.JSON.toJson(registry));
            monitor.checkCancelled(); success = true;
        } finally { p.endTransaction(tx, success); }
        return placements;
    }
    public static void removeOwned(Program p,String source,TaskMonitor monitor) throws Exception {
        int tx = p.startTransaction("Remove Game Boy symbol source"); boolean success = false;
        try {
            var registry = registry(p);
            registry.sources.remove(source);
            registry.placements.remove(source);
            for (var identity : registry.labels.values()) identity.claims.remove(source);
            collectUnclaimed(p, registry, monitor);
            p.getOptions(ProgramMapping.OPTIONS).setString(REGISTRY, ProgramMapping.JSON.toJson(registry));
            monitor.checkCancelled(); success = true;
        } finally { p.endTransaction(tx, success); }
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
    public static String exportRetained(Program p,String source) throws IOException {
        return registry(p).sources.getOrDefault(source, "");
    }
}
