package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Persisted explicit site premises. Results are rederived, never used as their own evidence. */
public final class SoftwareCallRegistry {
  private SoftwareCallRegistry() {}
  public static final String KEY = "softwareCall.sites.v1";
  public static final String STOCK_KEY = "softwareCall.stock.sites.v1";
  public static final String STOCK_VERSION = "stock-software-call-registry-1";
  public static boolean stock(Program p) { return p.getOptions(ProgramMapping.OPTIONS).contains(STOCK_KEY); }
  private static String key(Program p) { return stock(p) ? STOCK_KEY : KEY; }
  public static final String VERSION = "software-call-registry-7";
  private record Site(String address, String canonicalAddress, String target, String executionAlias, boolean stateContinuation, SoftwareCallValidation.Configuration configuration) {}
  public static final String EXECUTION_CONDITIONS = "Synchronous SM83 model: results require no asynchronous interrupt/DMA interference or untracked memory changes, in addition to the supplied register, stack and mapper premises. These are explicit conditions, not an all-input ABI or whole-ROM proof.";
  public record StateEntry(String site, int graphEntry, String canonical, String kind, int entryStep, boolean projection) {
    public StateEntry(String site, int graphEntry, String canonical, String kind) {
      this(site, graphEntry, canonical, kind, graphEntry, false);
    }
  }
  private record Registry(String version, String executionConditions, List<Site> sites, List<String> nativeFunctions, Map<String, StateEntry> stateEntries, String dependencies, String transport) {}

  private static Registry read(Program program) {
    var options = program.getOptions(ProgramMapping.OPTIONS);
    if (!options.contains(key(program))) return null;
    var raw = com.google.gson.JsonParser.parseString(options.getString(key(program), "null"));
    if (!raw.isJsonObject() || !raw.getAsJsonObject().has("sites")
        || !raw.getAsJsonObject().get("sites").isJsonArray())
      throw new IllegalArgumentException("Invalid software-call registry");
    if (!raw.getAsJsonObject().has("version") || !(stock(program) ? STOCK_VERSION : VERSION).equals(raw.getAsJsonObject().get("version").getAsString()))
      throw new IllegalArgumentException("Incompatible software-call registry; review and reapply");
    for (var site : raw.getAsJsonObject().getAsJsonArray("sites")) {
      if (!site.isJsonObject()) throw new IllegalArgumentException("Invalid software-call site record");
      SoftwareCallConfiguration.readOne(site.getAsJsonObject().get("configuration"));
      for (String field : List.of("address", "canonicalAddress", "target"))
        if (!site.getAsJsonObject().has(field) || !site.getAsJsonObject().get(field).isJsonPrimitive()
            || !site.getAsJsonObject().get(field).getAsJsonPrimitive().isString()
            || site.getAsJsonObject().get(field).getAsString().isBlank())
          throw new IllegalArgumentException("Missing software-call site identity " + field);
      var state = site.getAsJsonObject().get("stateContinuation");
      if (state == null || !state.isJsonPrimitive() || !state.getAsJsonPrimitive().isBoolean())
        throw new IllegalArgumentException("Missing explicit continuation transport policy");
    }
    var value = ProgramMapping.JSON.fromJson(raw, Registry.class);
    if (value == null || !(stock(program) ? STOCK_VERSION : VERSION).equals(value.version) || !EXECUTION_CONDITIONS.equals(value.executionConditions) || value.sites == null || value.nativeFunctions == null || value.stateEntries == null)
      throw new IllegalArgumentException("Incompatible software-call registry; review and reapply");
    if (stock(program) ? !StockEntryInjection.VERSION.equals(value.transport) : value.transport != null)
      throw new IllegalArgumentException("Incompatible software-call transport authority");
    for (var entry : value.stateEntries.entrySet()) {
      var state = entry.getValue();
      if (entry.getKey().isBlank() || state == null || state.site == null || state.canonical == null
          || state.kind == null || !Set.of("CALLEE", "CONTINUATION").contains(state.kind)
          || state.graphEntry < 0 || state.graphEntry >= 4096 || state.entryStep < 0 || state.entryStep >= 4096)
        throw new IllegalArgumentException("Invalid state-entry context record");
      var encoded = raw.getAsJsonObject().getAsJsonObject("stateEntries").getAsJsonObject(entry.getKey());
      if (!encoded.has("graphEntry") || !encoded.get("graphEntry").isJsonPrimitive()
          || !encoded.get("graphEntry").getAsJsonPrimitive().isNumber()
          || !encoded.get("graphEntry").getAsString().matches("[0-9]+"))
        throw new IllegalArgumentException("Missing explicit state-entry graph index");
      if (!encoded.has("entryStep") || !encoded.get("entryStep").isJsonPrimitive()
          || !encoded.get("entryStep").getAsJsonPrimitive().isNumber()
          || !encoded.get("entryStep").getAsString().matches("[0-9]+"))
        throw new IllegalArgumentException("Missing explicit selected graph step");
      if (!encoded.has("projection") || !encoded.get("projection").isJsonPrimitive()
          || !encoded.get("projection").getAsJsonPrimitive().isBoolean())
        throw new IllegalArgumentException("Missing explicit projection policy");
    }
    return value;
  }

  /** Called last inside the reviewed application transaction. */
  public static void install(Program p, List<SoftwareCallValidation.Configuration> configurations)
      throws Exception {
    install(p, configurations, Map.of());
  }

  public static void install(Program p, List<SoftwareCallValidation.Configuration> configurations,
      Map<String, String> executionSites) throws Exception {
    install(p, configurations, executionSites, Set.of());
  }

  public static void install(Program p, List<SoftwareCallValidation.Configuration> configurations,
      Map<String, String> executionSites, Set<String> stateContinuations) throws Exception {
    install(p, configurations, executionSites, stateContinuations, Map.of());
  }

  public static void install(Program p, List<SoftwareCallValidation.Configuration> configurations,
      Map<String, String> executionSites, Set<String> stateContinuations, Map<String, StateEntry> stateEntries) throws Exception {
    install(p, configurations, executionSites, stateContinuations, stateEntries, false);
  }
  static void install(Program p, List<SoftwareCallValidation.Configuration> configurations,
      Map<String, String> executionSites, Set<String> stateContinuations, Map<String, StateEntry> stateEntries, boolean stock) throws Exception {
    if (p.getOptions(ProgramMapping.OPTIONS).contains(stock ? KEY : STOCK_KEY))
      throw new IllegalArgumentException("Other transport authority retained; no implicit conversion");
    var sites = new ArrayList<Site>();
    var nativeFunctions = new TreeSet<String>();
    var seen = new HashSet<String>();
    for (var config : configurations) {
      int transferCpu = config.callCpu() + (config.transfer() == SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION ? 4 : 0);
      var physical = MapperState.translate(ProgramMapping.cartridge(p), config.mapper(), transferCpu, false).physical();
      var views = ProgramMapping.physicalToStatic(p, physical).stream()
          .filter(a -> a.getOffset() == transferCpu && SoftwareCallExecutionView.canonical(p, a)).toList();
      if (views.size() != 1 || !seen.add(views.get(0).toString()))
        throw new IllegalArgumentException("Ambiguous or duplicate software-call site");
      var frame = SoftwareCallValidation.preview(p, config, TaskMonitor.DUMMY).frame();
      var effects = SoftwareCallEffects.deriveForInstallation(p, frame, TaskMonitor.DUMMY, configurations);
      for (var fetch : effects.fetches()) nativeFunctions.add(fetch.nativeFunctionEntry());
      for (var path : effects.paths()) {
        var exit = path.returned();
        if (exit.exit() == SoftwareCallModel.Exit.NONLOCAL && exit.physical() != null)
          for (var destination : ProgramMapping.physicalToStatic(p, exit.physical()))
            if (destination.getOffset() == exit.cpu() && SoftwareCallExecutionView.canonical(p, destination))
              nativeFunctions.add(destination.toString());
      }
      var targets = ProgramMapping.physicalToStatic(p, frame.target()).stream()
          .filter(a -> a.getOffset() == frame.targetCpu() && SoftwareCallExecutionView.canonical(p, a)).toList();
      if (targets.size() != 1) throw new IllegalArgumentException("Ambiguous target");
      boolean stateful = stateContinuations.contains(views.get(0).toString());
      if (stateful) {
        var graph = SoftwareCallEffects.deriveContinuationForInstallation(p, frame, effects.paths().get(0), configurations, TaskMonitor.DUMMY);
        SoftwareCallContinuationView.requireTransport(p, graph, TaskMonitor.DUMMY);
        for (var step : graph.steps()) if (step.callDepth() > 0) nativeFunctions.add(step.nativeFunctionEntry());
      }
      String alias = executionSites.get(views.get(0).toString());
      sites.add(new Site(views.get(0).toString(), views.get(0).toString(), targets.get(0).toString(), alias, stateful, config));
      if (alias != null) {
        if (!seen.add(alias)) throw new IllegalArgumentException("Duplicate execution site alias");
        sites.add(new Site(alias, views.get(0).toString(), targets.get(0).toString(), alias, stateful, config));
      }
    }
    sites.sort(Comparator.comparing(Site::address));
    var options = p.getOptions(ProgramMapping.OPTIONS);
    options.setString(stock ? STOCK_KEY : KEY, ProgramMapping.JSON.toJson(new Registry(stock ? STOCK_VERSION : VERSION, EXECUTION_CONDITIONS, sites, List.copyOf(nativeFunctions), Map.copyOf(stateEntries), "", stock ? StockEntryInjection.VERSION : null)));
    String dependencies = semanticDependencies(p, TaskMonitor.DUMMY);
    options.setString(stock ? STOCK_KEY : KEY, ProgramMapping.JSON.toJson(new Registry(stock ? STOCK_VERSION : VERSION, EXECUTION_CONDITIONS, sites, List.copyOf(nativeFunctions), Map.copyOf(stateEntries), dependencies, stock ? StockEntryInjection.VERSION : null)));
  }

  public static void remove(Program p) { p.getOptions(ProgramMapping.OPTIONS).removeOption(key(p)); }

  /** Included in bounded-analysis invalidation without recursively hashing the saved digest. */
  static String configurationIdentity(Program p) {
    var registry = read(p);
    return registry == null ? "absent" : registry.version + (registry.transport == null ? "" : registry.transport) + registry.executionConditions + ProgramMapping.JSON.toJson(registry.sites) + ProgramMapping.JSON.toJson(registry.nativeFunctions) + ProgramMapping.JSON.toJson(registry.stateEntries);
  }

  public static SoftwareCallValidation.Preview resolve(Program p, Address address) throws Exception {
    var registry = read(p);
    if (registry == null) return null;
    var match = registry.sites.stream().filter(s -> s.address.equals(address.toString())).toList();
    if (match.isEmpty()) return null;
    if (!current(p, match.get(0)))
      throw new IllegalArgumentException("Software-call annotations changed after review");
    if (match.size() != 1 || !semanticDependencies(p, TaskMonitor.DUMMY).equals(registry.dependencies))
      throw new IllegalArgumentException("Stale software-call dependencies; review and reapply");
    return SoftwareCallValidation.preview(p, match.get(0).configuration, TaskMonitor.DUMMY);
  }

  /** Canonical root uses local continuation lowering; the alias uses mapped native flow. */
  static Address executionAlias(Program p, Address address) {
    var registry = read(p);
    if (registry == null) return null;
    var site = registry.sites.stream().filter(s -> s.address.equals(address.toString())).findFirst().orElse(null);
    return site == null || site.executionAlias == null || !site.address.equals(site.canonicalAddress) ? null : ProgramMapping.staticAddress(p, site.executionAlias);
  }

  static StateEntry stockEntry(Program p, Address entry) {
    if (!stock(p)) throw new IllegalArgumentException("No stock registry");
    var state = read(p).stateEntries.get(entry.toString());
    if (state == null || entry.toString().equals(state.canonical)) throw new IllegalArgumentException("Not an owned stock carrier");
    return state;
  }
  static boolean stockCarrier(Program p, Address entry) {
    var registry = read(p);
    var state = registry == null ? null : registry.stateEntries.get(entry.toString());
    return stock(p) && state != null && !entry.toString().equals(state.canonical);
  }
  static SoftwareCallValidation.Preview resolveStateEntry(Program p, Address entry) throws Exception {
    var registry = read(p);
    if (registry == null || !registry.stateEntries.containsKey(entry.toString()))
      throw new IllegalArgumentException("Missing state-entry registry at " + entry);
    if (!stock(p)) SoftwareCallStateEntryInjection.nativeIdentity();
    for (String address : registry.stateEntries.keySet())
      if (!AnalysisOwnership.stateEntryCurrent(p, ProgramMapping.staticAddress(p, address)))
        throw new IllegalArgumentException("Paired state-entry metadata changed at " + address);
    if (!AnalysisOwnership.softwareCallViewsCurrent(p)) throw new IllegalArgumentException("State-entry view annotations changed");
    return resolve(p, ProgramMapping.staticAddress(p, registry.stateEntries.get(entry.toString()).site()));
  }

  static SoftwareCallEffects.ContinuationSummary entryGraph(Program p, Address entry,
      SoftwareCallValidation.Preview input) throws Exception {
    return entryGraph(p, read(p).stateEntries.get(entry.toString()), input);
  }

  private static SoftwareCallEffects.ContinuationSummary entryGraph(Program p, StateEntry entry,
      SoftwareCallValidation.Preview input) throws Exception {
    var graph = entry.kind.equals("CALLEE")
        ? SoftwareCallEffects.deriveCalleeGraph(p, input.frame(), configurations(p), TaskMonitor.DUMMY)
        : SoftwareCallEffects.deriveContinuation(p, input.frame(), effects(p, input, TaskMonitor.DUMMY).paths().get(0), configurations(p), TaskMonitor.DUMMY);
    int index = entry.graphEntry;
    if (index == graph.entry().index()) return graph;
    return SoftwareCallEffects.calleeInvocations(graph).stream().map(SoftwareCallEffects.CalleeInvocation::graph)
        .filter(candidate -> candidate.entry().index() == index).findFirst()
        .orElseThrow(() -> new IllegalArgumentException("Missing current contextual callee graph at " + entry.canonical));
  }

  static int entryStep(Program p, Address entry) {
    return read(p).stateEntries.get(entry.toString()).entryStep;
  }

  public record StateContext(String canonical, String entry, String site, int graphEntry, String kind,
      boolean selected, SoftwareCallEffects.ContinuationState entryState) {}

  public static List<StateContext> stateContexts(Program p, Address canonical, TaskMonitor monitor) throws Exception {
    resolveStateEntry(p, canonical);
    var registry = read(p); var selected = registry.stateEntries.get(canonical.toString());
    if (!canonical.toString().equals(selected.canonical)) throw new IllegalArgumentException("Expected canonical state entry");
    var result = new ArrayList<StateContext>();
    for (var entry : registry.stateEntries.entrySet()) {
      monitor.checkCancelled();
      var context = entry.getValue();
      if (context.projection || !context.canonical.equals(canonical.toString()) || entry.getKey().equals(context.canonical)) continue;
      var input = resolve(p, ProgramMapping.staticAddress(p, context.site));
      var graph = entryGraph(p, context, input);
      SoftwareCallContinuationView.requireTransport(p, graph, monitor);
      result.add(new StateContext(context.canonical, entry.getKey(), context.site, context.graphEntry, context.kind,
          context.equals(selected), graph.entry().before()));
    }
    result.sort(Comparator.comparing(StateContext::site).thenComparingInt(StateContext::graphEntry));
    return List.copyOf(result);
  }

  public static void selectStateContext(Program p, Address canonical, Address entry, TaskMonitor monitor) throws Exception {
    if (stock(p)) throw new IllegalArgumentException("Stock contexts are separate navigation entries; canonical selection is not executable authority");
    long modification = p.getModificationNumber();
    var initialRegistry = read(p);
    if (initialRegistry == null) throw new IllegalArgumentException("Missing state-entry registry");
    String before = initialRegistry.dependencies;
    var available = stateContexts(p, canonical, monitor);
    var selected = available.stream().filter(context -> context.entry.equals(entry.toString())).findFirst()
        .orElseThrow(() -> new IllegalArgumentException("Context does not belong to canonical entry"));
    if (modification != p.getModificationNumber() || !before.equals(semanticDependencies(p, monitor)))
      throw new IllegalArgumentException("State contexts changed during selection review");
    int transaction = p.startTransaction("Select reviewed GhidraBoy execution context");
    boolean success = false;
    try {
      monitor.checkCancelled();
      if (modification != p.getModificationNumber() || !before.equals(semanticDependencies(p, monitor)))
        throw new IllegalArgumentException("State contexts changed before selection");
      var registry = read(p); var entries = new LinkedHashMap<>(registry.stateEntries);
      entries.put(canonical.toString(), entries.get(entry.toString()));
      AnalysisOwnership.selectStateEntryComment(p, canonical,
          ProgramMapping.JSON.toJson(Map.of("sourceSite", selected.site, "origin", selected.kind, "state", selected.entryState)));
      var options = p.getOptions(ProgramMapping.OPTIONS);
      options.setString(key(p), ProgramMapping.JSON.toJson(new Registry(registry.version, EXECUTION_CONDITIONS,
          registry.sites, registry.nativeFunctions, Map.copyOf(entries), "", registry.transport)));
      options.setString(key(p), ProgramMapping.JSON.toJson(new Registry(registry.version, EXECUTION_CONDITIONS,
          registry.sites, registry.nativeFunctions, Map.copyOf(entries), semanticDependencies(p, monitor), registry.transport)));
      monitor.checkCancelled(); success = true;
    } finally { p.endTransaction(transaction, success); }
  }

  static String graphSourceSite(Program p, Address entry) {
    var registry = read(p);
    if (registry == null) return null;
    var state = registry.stateEntries.get(entry.toString());
    if (state != null) return state.site;
    return registry.sites.stream().filter(site -> site.address.equals(entry.toString())).map(Site::canonicalAddress).findFirst().orElse(null);
  }

  static String graphOrigin(Program p, Address entry, String fallback) {
    var registry = read(p);
    var state = registry == null ? null : registry.stateEntries.get(entry.toString());
    return state == null ? fallback : state.kind;
  }

  static Address stateTarget(Program p, SoftwareCallValidation.Preview input) {
    var registry = read(p);
    if (registry == null) return null;
    String site = registry.sites.stream().filter(value -> value.configuration.equals(input.configuration()))
        .map(Site::canonicalAddress).findFirst().orElse(null);
    return contextualTarget(p, site, "CALLEE", 0);
  }

  static Address contextualTarget(Program p, String site, String kind, int graphEntry) {
    var registry = read(p);
    if (registry == null || site == null) return null;
    for (var entry : registry.stateEntries.entrySet()) {
      var state = entry.getValue();
      if (!state.projection && !entry.getKey().equals(state.canonical) && state.site.equals(site) && state.kind.equals(kind)
          && state.graphEntry == graphEntry && state.entryStep == graphEntry)
        return ProgramMapping.staticAddress(p, entry.getKey());
    }
    return null;
  }

  static void requireCalleeTransport(Program p, SoftwareCallValidation.Preview input, TaskMonitor monitor) throws Exception {
    var registry = read(p);
    var target = SoftwareCallValidation.executionAddress(p, input.frame().targetMapper(), input.frame().targetCpu());
    if (registry == null || !registry.stateEntries.containsKey(target.toString()))
      throw new IllegalArgumentException("Missing state-qualified callee transport at " + target);
    resolveStateEntry(p, target);
    var graph = SoftwareCallEffects.deriveCalleeGraph(p, input.frame(), configurations(p), monitor);
    SoftwareCallContinuationView.requireTransport(p, graph, monitor);
  }

  static boolean stateContinuation(Program p, Address address) {
    var registry = read(p);
    return registry != null && registry.sites.stream().anyMatch(site -> site.address.equals(address.toString()) && site.stateContinuation);
  }

  static List<SoftwareCallValidation.Configuration> configurations(Program p) {
    var registry = read(p);
    return registry == null ? List.of() : registry.sites.stream().map(Site::configuration).distinct().toList();
  }

  private static boolean current(Program p, Site site) throws Exception {
    var address = p.getAddressFactory().getAddress(site.canonicalAddress);
    if (!AnalysisOwnership.softwareCallCurrent(p, address)) return false;
    if (site.stateContinuation && !AnalysisOwnership.softwareCallViewsCurrent(p)) return false;
    if (site.executionAlias == null) return true;
    var alias = p.getAddressFactory().getAddress(site.executionAlias);
    return alias != null && alias.getOffset() == address.getOffset()
        && !SoftwareCallExecutionView.canonical(p, alias)
        && ProgramMapping.staticToPhysical(p, address).equals(ProgramMapping.staticToPhysical(p, alias))
        && AnalysisOwnership.softwareCallCurrent(p, alias);
  }

  public static SoftwareCallEffects.Summary effects(Program p, SoftwareCallValidation.Preview preview,
      TaskMonitor monitor) throws Exception {
    var registry = read(p);
    var candidates = new ArrayList<SoftwareCallValidation.Configuration>();
    if (registry != null)
      for (var site : registry.sites)
        if (current(p, site)
            && !candidates.contains(site.configuration)) candidates.add(site.configuration);
    // A stale nested site is not supplied as an executable convention. If the raw path reaches
    // it, native compatibility rejects that unvalidated helper; unrelated sites remain independent.
    return SoftwareCallEffects.derive(p, preview.frame(), monitor, candidates);
  }

  /** Native capability veto only; this receipt is never substituted for raw return evidence. */
  public static boolean isNeutralReturningTarget(Program p, Address target) {
    try {
      var registry = read(p);
      return registry != null && AnalysisOwnership.returningMarkerCurrent(p, target)
          && semanticDependencies(p, TaskMonitor.DUMMY).equals(registry.dependencies);
    } catch (Exception invalid) { return false; }
  }

  /** Existential may-return proof; the neutral payload never borrows these premises for a caller. */
  public static void requireReturningTarget(Program p, Address target) throws Exception {
    long modification = p.getModificationNumber();
    var registry = read(p);
    if (registry == null || !semanticDependencies(p, TaskMonitor.DUMMY).equals(registry.dependencies))
      throw new IllegalArgumentException("Missing or stale returning-target proof");
    Exception rejectedWitness = null;
    var attempted = new HashSet<String>();
    var ordered = registry.sites.stream().sorted(Comparator.comparing(site -> !site.target.equals(target.toString()))).toList();
    for (var site : ordered) {
      if (modification != p.getModificationNumber())
        throw new IllegalStateException("Program changed during returning-target proof");
      if (!attempted.add(site.canonicalAddress) || !current(p, site)) continue;
      try {
        var preview = resolve(p, p.getAddressFactory().getAddress(site.address));
        if (preview == null) continue;
        var summary = effects(p, preview, TaskMonitor.DUMMY);
        boolean transport = summary.nativeCompatible();
        if (!transport && registry.stateEntries.values().stream().anyMatch(entry -> entry.site().equals(site.canonicalAddress))) {
          requireCalleeTransport(p, preview, TaskMonitor.DUMMY); transport = true;
        }
        boolean witnessed = transport && summary.returningNativeFunctions().contains(target.toString());
        if (!witnessed && site.stateContinuation && summary.nativeCompatible()) {
          var graph = SoftwareCallEffects.deriveContinuation(p, preview.frame(), summary.paths().get(0), configurations(p), TaskMonitor.DUMMY);
          SoftwareCallContinuationView.requireTransport(p, graph, TaskMonitor.DUMMY);
          witnessed = graph.returningNativeFunctions().contains(target.toString());
        }
        if (witnessed) {
          if (modification != p.getModificationNumber())
            throw new IllegalStateException("Program changed during returning-target proof");
          return;
        }
      } catch (IllegalArgumentException | IllegalStateException rejectedSite) {
        if (modification != p.getModificationNumber())
          throw new IllegalStateException("Program changed during returning-target proof", rejectedSite);
        rejectedWitness = rejectedSite;
        // Another still-current site may provide the existential witness. No invalid site is
        // supplied as a nested executable convention, and the final modification guard remains.
      }
    }
    throw new IllegalArgumentException("No current code-derived returning path for " + target
        + (rejectedWitness == null ? "" : "; rejected witness: " + rejectedWitness.getMessage()), rejectedWitness);
  }

  /**
   * The summary consumes raw code, initialized memory, mapper metadata and context, not generated
   * references or repaired bodies. Native calls additionally consume function prototypes. Boundary
   * and ownership checks are repeated by resolve, rather than exempting generated data from checks.
   */
  static String semanticDependencies(Program p, TaskMonitor monitor) throws Exception {
    if (read(p) == null) return "absent";
    var fields = new TreeMap<String, String>();
    var base = ProgramFingerprint.coreComponents(p, monitor);
    fields.put("memory", base.get("memory"));
    fields.put("mapping", base.get("mapping"));
    fields.put("configuration", configurationIdentity(p));
    if (!read(p).stateEntries.isEmpty()) fields.put(stock(p) ? "stateEntryTransport" : "stateEntryNative", stock(p) ? StockEntryInjection.VERSION : SoftwareCallStateEntryInjection.nativeIdentity());
    var permissions = new ArrayList<String>();
    for (var block : p.getMemory().getBlocks()) permissions.add(block.getStart() + ":" + block.getFlags());
    Collections.sort(permissions);
    fields.put("permissions", ProgramMapping.JSON.toJson(permissions));
    fields.put("versions", VERSION + SoftwareCallModel.VERSION + SoftwareCallValidation.VERSION
        + SoftwareCallInjection.VERSION + SoftwareCallEffects.VERSION + SoftwareCallMayReturnInjection.VERSION
        + SoftwareCallContinuationView.VERSION + SoftwareCallInstructionDiscovery.VERSION + SoftwareCallStateEntryInjection.VERSION
        + p.getLanguageID() + p.getLanguage().getVersion() + p.getCompilerSpec().getCompilerSpecID());
    var context = new ArrayList<String>();
    var pc = p.getProgramContext();
    context.add(String.valueOf(pc.getDefaultDisassemblyContext()));
    for (var register : pc.getRegisters()) {
      for (var range : pc.getDefaultRegisterValueAddressRanges(register))
        context.add(register.getName() + ":default:" + range + ":" + pc.getDefaultValue(register, range.getMinAddress()));
      for (var range : pc.getRegisterValueAddressRanges(register))
        context.add(register.getName() + ":" + range + ":" + pc.getRegisterValue(register, range.getMinAddress()));
    }
    Collections.sort(context);
    fields.put("context", ProgramMapping.JSON.toJson(context));
    var prototypes = new ArrayList<String>();
    var consumed = new HashSet<Address>();
    var callerBodies = new ArrayList<String>();
    for (var site : read(p).sites) {
      var caller = p.getFunctionManager().getFunctionContaining(p.getAddressFactory().getAddress(site.address));
      if (caller != null) {
        consumed.add(caller.getEntryPoint());
        callerBodies.add(site.address + ":" + caller.getEntryPoint() + ":" + caller.getBody());
      } else callerBodies.add(site.address + ":no-caller-function");
      consumed.add(p.getAddressFactory().getAddress(site.target));
      consumed.add(p.getAddressFactory().getDefaultAddressSpace().getAddress(site.configuration.template().helperCpu()));
    }
    Collections.sort(callerBodies); fields.put("callerBodies", ProgramMapping.JSON.toJson(callerBodies));
    for (String entry : read(p).nativeFunctions) consumed.add(p.getAddressFactory().getAddress(entry));
    for (String entry : read(p).stateEntries.keySet()) consumed.add(p.getAddressFactory().getAddress(entry));
    for (var entry : consumed) {
      var function = p.getFunctionManager().getFunctionAt(entry);
      if (function == null) { prototypes.add(entry + ":missing"); continue; }
      prototypes.add(function.getEntryPoint() + ":"
          + function.getCallingConventionName() + ":" + function.getSignatureSource() + ":" + function.getStackPurgeSize() + ":"
          + function.getReturn().getVariableStorage().getSerializationString() + ":"
          + function.hasNoReturn() + ":" + function.getCallFixup() + ":" + function.isInline()
          + ":" + function.isThunk() + ":" + (function.isThunk() ? function.getThunkedFunction(false).getEntryPoint() : "none")
          + ":" + function.hasVarArgs() + ":" + function.hasCustomVariableStorage()
          + ":" + nativeTypeIdentity(function.getReturnType()));
      for (var parameter : function.getParameters())
        prototypes.add(function.getEntryPoint() + ":param:" + parameter.getOrdinal() + ":"
            + parameter.getVariableStorage().getSerializationString() + ":"
            + nativeTypeIdentity(parameter.getDataType()));
    }
    Collections.sort(prototypes);
    fields.put("prototypes", ProgramMapping.JSON.toJson(prototypes));
    return Sha256.of(ProgramMapping.JSON.toJson(fields).getBytes(StandardCharsets.UTF_8)).toString();
  }
  /** Native type definitions can change in place without changing their name or byte size. */
  static String nativeTypeIdentity(ghidra.program.model.data.DataType root) {
    var queue = new ArrayList<ghidra.program.model.data.DataType>();
    var seen = new IdentityHashMap<ghidra.program.model.data.DataType, Integer>();
    queue.add(root); seen.put(root, 0);
    var fields = new ArrayList<String>();
    for (int index = 0; index < queue.size(); index++) {
      if (queue.size() > 4096) throw new IllegalArgumentException("Native type dependency bound exceeded");
      var type = queue.get(index);
      fields.add(index + ":" + type.getClass().getName() + ":" + type.getPathName() + ":" + type.getLength() + ":" + type);
      var settings = type.getDefaultSettings();
      var settingNames = settings.getNames(); Arrays.sort(settingNames);
      for (var name : settingNames) fields.add(index + ":setting:" + name + ":" + settings.getValue(name));
      var children = new ArrayList<ghidra.program.model.data.DataType>();
      if (type instanceof ghidra.program.model.data.Composite composite) {
        for (var component : composite.getComponents()) {
          fields.add(index + ":field:" + component.getOrdinal() + ":" + component.getOffset()
              + ":" + component.getLength() + ":" + component.getFieldName());
          children.add(component.getDataType());
        }
      } else if (type instanceof ghidra.program.model.data.Pointer pointer) {
        if (pointer.getDataType() != null) children.add(pointer.getDataType());
      } else if (type instanceof ghidra.program.model.data.Array array) {
        fields.add(index + ":array:" + array.getNumElements() + ":" + array.getElementLength());
        children.add(array.getDataType());
      } else if (type instanceof ghidra.program.model.data.TypeDef definition) {
        children.add(definition.getBaseDataType());
      } else if (type instanceof ghidra.program.model.data.BitFieldDataType bitfield) {
        fields.add(index + ":bitfield:" + bitfield.getBitSize() + ":" + bitfield.getBitOffset());
        children.add(bitfield.getBaseDataType());
      } else if (type instanceof ghidra.program.model.data.Enum enumeration) {
        var names = enumeration.getNames(); Arrays.sort(names);
        for (var name : names) fields.add(index + ":enum:" + name + ":" + enumeration.getValue(name));
      } else if (type instanceof ghidra.program.model.data.FunctionDefinition function) {
        fields.add(index + ":function:" + function.hasVarArgs() + ":" + function.hasNoReturn() + ":" + function.getCallingConventionName());
        children.add(function.getReturnType());
        for (var parameter : function.getArguments()) children.add(parameter.getDataType());
      }
      for (var child : children) {
        Integer childIndex = seen.get(child);
        if (childIndex == null) { childIndex = queue.size(); seen.put(child, childIndex); queue.add(child); }
        fields.add(index + ":child:" + childIndex);
      }
    }
    return Sha256.of(ProgramMapping.JSON.toJson(fields).getBytes(StandardCharsets.UTF_8)).toString();
  }

}
