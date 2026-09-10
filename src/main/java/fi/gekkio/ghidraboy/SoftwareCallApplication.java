package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Reviewed listing changes for validated software calls. Generated annotations are never proof. */
public final class SoftwareCallApplication {
  private SoftwareCallApplication() {}

  public static final String FEATURE = "software-call";
  public record SiteInventory(String site, String helper, String originalFlow,
      String originalContinuation, boolean helperNoReturn, String helperFixup,
      List<PayloadDisposition> payload, List<SoftwareCallValidation.PayloadSegment> physicalPayload, String target, boolean targetNoReturn, String originalThunk,
      List<AnalysisOwnership.Range> originalBody, List<AnalysisOwnership.Range> repairedBody, String canonicalTransport, String appliedCanonicalFlow, String disposition) {
    public SiteInventory { physicalPayload = List.copyOf(physicalPayload); payload = List.copyOf(payload); originalBody = List.copyOf(originalBody); repairedBody = List.copyOf(repairedBody); }
  }
  public record NestedRepair(String site, String target, String originalFlow, String appliedFlow,
      boolean originalNoReturn, String originalFixup, String appliedFixup, String witness) {}
  public static final class Review {
    private final List<SoftwareCallValidation.Configuration> configurations;
    private final List<SiteInventory> inventory;
    private final List<NestedRepair> nestedRepairs;
    private final String dependencies;
    private SoftwareCallInstructionDiscovery.Plan discovery;
    private boolean stock;
    private final Map<String, SoftwareCallEffects.ContinuationSummary> stateContinuations = new LinkedHashMap<>();
    private final Map<String, SoftwareCallEffects.ContinuationSummary> stateCallees = new LinkedHashMap<>();
    private final Map<String, SoftwareCallExecutionView.Preview> views;
    private Review(List<SoftwareCallValidation.Configuration> configurations,
        List<SiteInventory> inventory, List<NestedRepair> nestedRepairs, String dependencies, Map<String, SoftwareCallExecutionView.Preview> views) {
      this.configurations = List.copyOf(configurations);
      this.inventory = List.copyOf(inventory);
      this.nestedRepairs = List.copyOf(nestedRepairs);
      this.dependencies = dependencies;
      this.views = Map.copyOf(views);
    }
    public List<SiteInventory> inventory() { return inventory; }
    public List<NestedRepair> nestedRepairs() { return nestedRepairs; }
    public String dependencies() { return dependencies; }
    public SoftwareCallInstructionDiscovery.Plan instructionDiscovery() { return discovery; }
    public Map<String, SoftwareCallEffects.ContinuationSummary> stateContinuations() { return Map.copyOf(stateContinuations); }
    public Map<String, SoftwareCallEffects.ContinuationSummary> stateCallees() { return Map.copyOf(stateCallees); }
    public Map<String, SoftwareCallExecutionView.Preview> executionViews() { return views; }
  }

  public static Review preview(Program p, List<SoftwareCallValidation.Configuration> configurations,
      TaskMonitor monitor) throws Exception {
    return previewStock(p, configurations, monitor);
  }
  public static Review previewLegacyComparison(Program p, List<SoftwareCallValidation.Configuration> configurations, TaskMonitor monitor) throws Exception {
    return preview(p, configurations, monitor, false);
  }
  public static Review previewStock(Program p, List<SoftwareCallValidation.Configuration> configurations, TaskMonitor monitor) throws Exception {
    if (p.getOptions(ProgramMapping.OPTIONS).contains(SoftwareCallRegistry.KEY))
      throw new IllegalArgumentException("Legacy software-call record retained; stock conversion is not implicit");
    SoftwareCallRegistry.configurationIdentity(p); // Reject incompatible saved stock authority before reapply.
    return preview(p, configurations, monitor, true);
  }
  private static Review preview(Program p, List<SoftwareCallValidation.Configuration> configurations, TaskMonitor monitor, boolean stock) throws Exception {
    try (var session = SoftwareCallInstructionDiscovery.begin(p, monitor)) {
      for (var config : configurations)
        for (var payload : SoftwareCallValidation.payloadSegments(p, config, monitor))
          session.reserve(ProgramMapping.staticAddress(p, payload.address()), payload.length(), "validated software-call payload");
      var result = previewDecoded(p, configurations, monitor, stock);
      result.discovery = session.plan(monitor);
      result.stock = stock;
      return result;
    }
  }

  private static Review previewDecoded(Program p, List<SoftwareCallValidation.Configuration> configurations,
      TaskMonitor monitor, boolean stock) throws Exception {
    if (configurations.isEmpty()) throw new IllegalArgumentException("No software-call sites supplied");
    String before = FarCallEvidence.capture(p, monitor);
    var inventory = new ArrayList<SiteInventory>();
    var sites = new HashSet<Address>();
    var views = new LinkedHashMap<String, SoftwareCallExecutionView.Preview>();
    var validations = new ArrayList<SoftwareCallValidation.Preview>();
    var derived = new ArrayList<SoftwareCallEffects.Summary>();
    var returningTargets = new TreeSet<String>();
    var stateContinuations = new LinkedHashMap<String, SoftwareCallEffects.ContinuationSummary>();
    var stateCallees = new LinkedHashMap<String, SoftwareCallEffects.ContinuationSummary>();
    for (var config : configurations) {
      var validated = SoftwareCallValidation.preview(p, config, monitor);
      var summary = SoftwareCallEffects.deriveForReview(p, validated.frame(), monitor, configurations);
      validations.add(validated); derived.add(summary);
      if (summary.nativeCompatible()) returningTargets.addAll(summary.returningNativeFunctions());
    }
    var stateTargets = new HashSet<String>();
    for (int index = 0; index < configurations.size(); index++) if (!derived.get(index).nativeCompatible()
        || SoftwareCallContinuationView.requiresEntryContext(p, validations.get(index).frame(), configurations, monitor)) {
      var frame = validations.get(index).frame();
      stateTargets.add(SoftwareCallValidation.executionAddress(p, frame.targetMapper(), frame.targetCpu()).toString());
    }
    for (int index = 0; index < configurations.size(); index++) {
      var config = configurations.get(index); var validated = validations.get(index);
      var summary = derived.get(index);
      if (summary.complete() && stateTargets.contains(SoftwareCallValidation.executionAddress(p,
          validated.frame().targetMapper(), validated.frame().targetCpu()).toString())) {
        var graph = SoftwareCallEffects.deriveCalleeGraphForReview(p, validated.frame(), configurations, monitor);
        SoftwareCallContinuationView.requireTransport(p, graph, monitor);
        if (!stock) SoftwareCallStateEntryInjection.nativeIdentity();
        String at = site(p, config).toString();
        String target = SoftwareCallValidation.executionAddress(p, validated.frame().targetMapper(), validated.frame().targetCpu()).toString();
        var existing = p.getFunctionManager().getFunctionAt(ProgramMapping.staticAddress(p, target));
        if (existing != null && !defaultCallerContract(existing)
            && !AnalysisOwnership.stateEntryCurrent(p, existing.getEntryPoint()))
          throw new IllegalArgumentException("State entry requires reviewed bare native contract at " + target);
        for (var invocation : SoftwareCallEffects.calleeInvocations(graph)) {
          var nested = p.getFunctionManager().getFunctionAt(ProgramMapping.staticAddress(p, invocation.graph().entry().address()));
          if (nested != null && !defaultCallerContract(nested)
              && !AnalysisOwnership.stateEntryCurrent(p, nested.getEntryPoint()))
            throw new IllegalArgumentException("Nested state entry requires reviewed bare native contract at " + nested.getEntryPoint());
        }
        stateCallees.put(at, graph); returningTargets.addAll(graph.returningNativeFunctions());
        planEntryViews(p, at, graph, views, monitor, stock);
      }
    }
    for (int configurationIndex = 0; configurationIndex < configurations.size(); configurationIndex++) {
      var config = configurations.get(configurationIndex);
      var validated = validations.get(configurationIndex);
      var effects = derived.get(configurationIndex);
      if (!effects.complete() || effects.paths().stream().map(path -> path.returned().exit()).distinct().count() != 1
          || effects.paths().stream().anyMatch(path -> path.returned().exit() != SoftwareCallModel.Exit.MAY_RETURN
              && path.returned().exit() != SoftwareCallModel.Exit.NONRETURNING
              && path.returned().exit() != SoftwareCallModel.Exit.NONLOCAL))
        throw new IllegalArgumentException("Unresolved or unsupported nonreturning callee effects: " + effects.unresolved());
      if (!effects.nativeCompatible() && !stateCallees.containsKey(site(p, config).toString()))
        throw new IllegalArgumentException("Callee needs an unsupported native execution view: " + effects.nativeIncompatibilities());
      for (var fetch : effects.fetches()) {
        var nativeEntry = ProgramMapping.staticAddress(p, fetch.nativeFunctionEntry());
        if (p.getFunctionManager().getFunctionAt(nativeEntry) != null) continue;
        if (p.getFunctionManager().getFunctionContaining(nativeEntry) != null)
          throw new IllegalArgumentException("Native entry lies inside an existing function: " + nativeEntry);
        validateFunctionLabel(p, nativeEntry);
      }
      var site = site(p, config);
      if (!sites.add(site)) throw new IllegalArgumentException("Duplicate software-call site " + site);
      var ins = SoftwareCallInstructionDiscovery.instructionAt(p, site, "configured software-call transfer", monitor);
      if (ins == null) throw new IllegalArgumentException("Missing transfer instruction " + site);
      if (ins.getFlowOverride() != FlowOverride.NONE && ins.getFlowOverride() != FlowOverride.CALL_RETURN
          && !(config.transfer() == SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION && ins.getFlowOverride() == FlowOverride.CALL))
        throw new IllegalArgumentException("Conflicting flow override " + site);
      var continuation = continuation(p, effects);
      var expectedHelper = p.getAddressFactory().getDefaultAddressSpace().getAddress(config.template().helperCpu());
      for (var reference : ins.getReferencesFrom()) {
        if (!InstructionInterpretation.relevant(reference)) continue;
        if (reference.getReferenceType().isFallthrough() && Objects.equals(reference.getToAddress(), continuation)) continue;
        if ((!reference.getReferenceType().isCall()
                && !(config.transfer() == SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION && reference.getReferenceType().isJump()))
            || !reference.getToAddress().equals(expectedHelper)
            || reference.getReferenceType().isOverride())
          throw new IllegalArgumentException("Initial software-call flow reference requires reviewed migration at " + site);
      }
      var continuationSegments = List.<SoftwareCallExecutionView.Segment>of();
      SoftwareCallEffects.ContinuationSummary stateContinuation = null;
      if (continuation != null) {
        var finiteDiscovery = SoftwareCallInstructionDiscovery.checkpoint(p);
        try {
          continuationSegments = SoftwareCallExecutionView.continuationSegments(p, effects.paths().get(0).returned(), monitor, false);
          if (effects.paths().get(0).returned().exit() == SoftwareCallModel.Exit.NONLOCAL
              || continuationSegments.stream().anyMatch(segment ->
              !site.getAddressSpace().getAddress(segment.cpu()).equals(ProgramMapping.staticAddress(p, segment.source()))))
            SoftwareCallExecutionView.continuationSegments(p, effects.paths().get(0).returned(), monitor);
        } catch (IllegalArgumentException finiteObligation) {
          SoftwareCallInstructionDiscovery.rollback(p, finiteDiscovery);
          try { stateContinuation = SoftwareCallContinuationView.derive(p, validated, effects.paths().get(0), configurations, monitor); }
          catch (IllegalArgumentException stateObligation) {
            stateObligation.addSuppressed(finiteObligation);
            throw new IllegalArgumentException(finiteObligation.getMessage() + "; state graph: " + stateObligation.getMessage(), stateObligation);
          }
          stateContinuations.put(site.toString(), stateContinuation);
          planEntryViews(p, site.toString(), stateContinuation, views, monitor, stock);
        }
      }
      if (ins.isFallThroughOverridden() && ins.getFallThrough() != null
          && !Objects.equals(ins.getFallThrough(), continuation))
        throw new IllegalArgumentException("Conflicting continuation override " + site);
      if (stateContinuation != null || (continuation != null && continuationSegments.stream().anyMatch(segment ->
          !site.getAddressSpace().getAddress(segment.cpu()).equals(ProgramMapping.staticAddress(p, segment.source()))))) {
        var segments = new ArrayList<SoftwareCallExecutionView.Segment>();
        var caller = p.getFunctionManager().getFunctionContaining(site);
        var entry = caller == null ? executionView(p, config.mapper(), config.callCpu()) : caller.getEntryPoint();
        if (caller != null && ((AnalysisOwnership.functionStamp(caller) == null
            && !AnalysisOwnership.sourceRedirectCurrent(p, caller)) || !defaultCallerContract(caller)))
          throw new IllegalArgumentException("Execution view requires reviewed bare caller metadata; custom contracts are preserved");
        if (!entry.getAddressSpace().equals(site.getAddressSpace()) || entry.compareTo(site) > 0)
          throw new IllegalArgumentException("Invalid caller entry for execution view");
        validateViewPrefix(p, entry, site, config, monitor);
        var encoded = payloadStart(p, config);
        segments.add(new SoftwareCallExecutionView.Segment((int) entry.getOffset(), (int) encoded.subtract(entry), entry.toString()));
        for (var payloadSegment : SoftwareCallValidation.payloadSegments(p, config, monitor)) {
          var source = ProgramMapping.staticAddress(p, payloadSegment.address());
          segments.add(new SoftwareCallExecutionView.Segment((int) source.getOffset(), payloadSegment.length(), source.toString()));
        }
        if (stateContinuation == null)
          segments.addAll(SoftwareCallExecutionView.continuationSegments(p, effects.paths().get(0).returned(), monitor));
        String baseName = SoftwareCallExecutionView.PREFIX + Integer.toUnsignedString(site.getAddressSpace().getSpaceID(), 16)
            + "_" + Long.toHexString(site.getOffset());
        String name = baseName;
        int suffix = 0;
        while (p.getAddressFactory().getAddressSpace(name) != null) name = baseName + "_" + ++suffix;
        views.put(site.toString(), SoftwareCallExecutionView.preview(p, name, segments, monitor));
        if (stateContinuation != null) {
          if (!stock) SoftwareCallStateEntryInjection.nativeIdentity();
          int fragment = 0;
          for (var ranges : SoftwareCallContinuationView.fragments(p, stateContinuation)) {
            String key = site + "#state" + fragment;
            views.put(key, SoftwareCallExecutionView.preview(p, name + "_state" + fragment++, ranges, monitor));
          }
        }
      }
      var helper = p.getAddressFactory().getDefaultAddressSpace().getAddress(config.template().helperCpu());
      var function = p.getFunctionManager().getFunctionAt(helper);
      if (function != null && function.getCallFixup() != null
          && !function.getCallFixup().equals(SoftwareCallInjection.NAME))
        throw new IllegalArgumentException("Conflicting helper callfixup " + helper);
      var targetAddress = SoftwareCallValidation.executionAddress(p, validated.frame().targetMapper(), validated.frame().targetCpu());
      var targetFunction = p.getFunctionManager().getFunctionAt(targetAddress);
      if (targetFunction != null && targetFunction.hasNoReturn()
          && effects.paths().get(0).returned().exit() == SoftwareCallModel.Exit.NONLOCAL
          && !returningTargets.contains(targetAddress.toString()))
        throw new IllegalArgumentException("Nonlocal path does not justify clearing target noReturn contract at " + targetAddress);
      if (targetFunction != null && (targetFunction.isInline() || targetFunction.isThunk()))
        throw new IllegalArgumentException("Target inline/thunk contract needs reviewed native integration at " + targetAddress);
      if (targetFunction != null && targetFunction.getCallFixup() != null
          && !targetFunction.getCallFixup().equals(SoftwareCallMayReturnInjection.NAME))
        throw new IllegalArgumentException("Conflicting target callfixup at " + targetAddress);
      if (targetFunction != null && targetFunction.getStackPurgeSize() != 0
          && targetFunction.getStackPurgeSize() != Function.UNKNOWN_STACK_DEPTH_CHANGE)
        throw new IllegalArgumentException("Conflicting target stack-purge contract at " + targetAddress);
      var physicalPayload = SoftwareCallValidation.payloadSegments(p, config, monitor);
      var payload = new ArrayList<PayloadDisposition>();
      for (var segment : physicalPayload)
        payload.addAll(inspectPayload(p, ProgramMapping.staticAddress(p, segment.address()), segment.length(), site, monitor));
      var callerFunction = p.getFunctionManager().getFunctionContaining(site);
      var originalBody = callerFunction == null ? new ghidra.program.model.address.AddressSet()
          : new ghidra.program.model.address.AddressSet(callerFunction.getBody());
      var repairedBody = new ghidra.program.model.address.AddressSet(originalBody);
      for (var segment : physicalPayload) {
        var source = ProgramMapping.staticAddress(p, segment.address());
        repairedBody.delete(source, source.add(segment.length() - 1));
      }
      if (effects.paths().get(0).returned().exit() == SoftwareCallModel.Exit.NONLOCAL && !views.containsKey(site.toString())) {
        for (var segment : SoftwareCallExecutionView.continuationSegments(p, effects.paths().get(0).returned(), monitor)) {
          var begin = ProgramMapping.staticAddress(p, segment.source());
          var addition = new ghidra.program.model.address.AddressSet(begin, begin.add(segment.length() - 1));
          for (var other : p.getFunctionManager().getFunctions(true))
            if ((callerFunction == null || other.getID() != callerFunction.getID()) && other.getBody().intersects(addition))
              throw new IllegalArgumentException("Nonlocal destination conflicts with existing function " + other.getEntryPoint());
          repairedBody.add(addition);
        }
      }
      inventory.add(new SiteInventory(site.toString(), helper.toString(), ins.getFlowOverride().toString(),
          String.valueOf(ins.getFallThrough()), function != null && function.hasNoReturn(),
          function == null ? null : function.getCallFixup(), payload, physicalPayload, targetAddress.toString(),
          targetFunction != null && targetFunction.hasNoReturn(),
          function != null && function.isThunk() ? function.getThunkedFunction(false).getEntryPoint().toString() : null,
          AnalysisOwnership.bodyRanges(originalBody), AnalysisOwnership.bodyRanges(repairedBody),
          views.containsKey(site.toString()) ? "BOUNDED_SELF_FALLTHROUGH_EXPANSION" : "ORDINARY_SITE",
          !views.containsKey(site.toString()) && continuation == null ? FlowOverride.CALL_RETURN.toString()
              : config.transfer() == SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION ? FlowOverride.CALL.toString() : FlowOverride.NONE.toString(),
          "INSTALL_VALIDATED_CALL; exit=" + effects.paths().get(0).returned().exit() + "; continuation=" + continuation + "; repair thunk="
              + (function != null && function.isThunk()) + "; subtract exact payload from caller body"));
    }
    if (!before.equals(FarCallEvidence.capture(p, monitor))) throw new IllegalStateException("Review changed during preview");
    monitor.checkCancelled();
    var nestedRepairs = new ArrayList<NestedRepair>();
    var recordedCalls = new HashSet<SoftwareCallEffects.ReturningCall>();
    for (var graph : stateContinuations.values()) derived.add(continuationFunctions(graph));
    for (var graph : stateCallees.values()) derived.add(continuationFunctions(graph));
    for (var summary : derived) for (var witness : summary.returningCalls()) {
      if (!recordedCalls.add(witness)) continue;
      var instruction = SoftwareCallInstructionDiscovery.instructionAt(p, ProgramMapping.staticAddress(p, witness.site()), "matched ordinary call", monitor);
      var target = p.getFunctionManager().getFunctionAt(ProgramMapping.staticAddress(p, witness.target()));
      nestedRepairs.add(new NestedRepair(witness.site(), witness.target(), instruction.getFlowOverride().toString(),
          FlowOverride.NONE.toString(), target != null && target.hasNoReturn(), target == null ? null : target.getCallFixup(),
          SoftwareCallMayReturnInjection.NAME, "MATCHED_ARCHITECTURAL_RET; CPU continuation and restored SP agree with this call"));
    }
    var result = new Review(configurations, inventory, nestedRepairs, before, views);
    result.stateContinuations.putAll(stateContinuations);
    result.stateCallees.putAll(stateCallees);
    return result;
  }

  public static List<SiteInventory> apply(Program p, Review review, TaskMonitor monitor) throws Exception {
    Objects.requireNonNull(review);
    if (!review.dependencies.equals(FarCallEvidence.capture(p, monitor)))
      throw new IllegalStateException("Stale software-call review; preview again");
    var freshReview = preview(p, review.configurations, monitor, review.stock);
    if (!ProgramMapping.JSON.toJsonTree(freshReview).equals(ProgramMapping.JSON.toJsonTree(review)))
      throw new IllegalArgumentException("Software-call review plan differs from current validated inventory");
    review = freshReview;
    int tx = p.startTransaction("Apply reviewed software-call interpretation");
    boolean success = false;
    try {
      if (!review.dependencies.equals(FarCallEvidence.capture(p, monitor)))
        throw new IllegalStateException("Stale software-call review; preview again");
      SoftwareCallInstructionDiscovery.apply(p, review.discovery, monitor);
      var validated = new ArrayList<SoftwareCallValidation.Preview>();
      var summaries = new ArrayList<SoftwareCallEffects.Summary>();
      for (var config : review.configurations) {
        var v = SoftwareCallValidation.preview(p, config, monitor);
        validated.add(v); summaries.add(SoftwareCallEffects.deriveForReview(p, v.frame(), monitor, review.configurations));
      }
      for (var graph : review.stateContinuations.values()) summaries.add(continuationFunctions(graph));
      for (var graph : review.stateCallees.values()) summaries.add(continuationFunctions(graph));
      AnalysisOwnership.remove(p, FEATURE, monitor);
      // The displayed view plans have already been checked against the complete review digest.
      // Refresh only transaction-local dependency tokens between our own view creations.
      var createdViews = new HashMap<String, SoftwareCallExecutionView.Created>();
      for (var entry : review.views.entrySet()) {
        var plan = entry.getValue();
        if (review.stock && (entry.getKey().contains("#native_") || entry.getKey().contains("#state"))) {
          var graph = carrierGraph(p, plannedGraph(review, entry.getKey()), plan.segments());
          if (graph == null) {
            // Some fragments contain only inlined configured-call effects. They never had
            // an independently admitted entry; retain their listing without inventing one.
            createdViews.put(entry.getKey(), SoftwareCallExecutionView.create(p,
                SoftwareCallExecutionView.preview(p, plan.name(), plan.segments(), monitor), monitor));
          } else {
            var first = carrierStep(p, graph, plan.segments());
            createdViews.put(entry.getKey(), StockEntryInjection.carrier(p, plan.name(), first.before().cpu(), plan.segments(), monitor));
          }
        } else createdViews.put(entry.getKey(), SoftwareCallExecutionView.create(p,
            SoftwareCallExecutionView.preview(p, plan.name(), plan.segments(), monitor), monitor));
      }
      var owned = new AnalysisOwnership.Group();
      var helpers = new HashSet<Address>();
      var executionSites = new LinkedHashMap<String, String>();
      for (int index = 0; index < review.configurations.size(); index++) {
        monitor.checkCancelled();
        var config = review.configurations.get(index);
        var site = site(p, config);
        var helper = p.getAddressFactory().getDefaultAddressSpace().getAddress(config.template().helperCpu());
        if (helpers.add(helper)) {
          var function = p.getFunctionManager().getFunctionAt(helper);
          if (function == null) {
            function = p.getFunctionManager().createFunction(null, helper,
                new ghidra.program.model.address.AddressSet(helper, helper.add(config.template().bodyHex().length() / 2 - 1)),
                ghidra.program.model.symbol.SourceType.ANALYSIS);
            owned.function(function);
          }
          owned.helpers.add(new AnalysisOwnership.Helper(AnalysisOwnership.Point.of(helper), function.getID(),
              function.hasNoReturn(), function.getCallFixup(), SoftwareCallInjection.NAME,
              function.isThunk() ? AnalysisOwnership.Point.of(function.getThunkedFunction(false).getEntryPoint()) : null));
          if (function.isThunk()) function.setThunkedFunction(null);
          function.setNoReturn(false);
          function.setCallFixup(SoftwareCallInjection.NAME);
        }
        var ins = p.getListing().getInstructionAt(site);
        var next = continuation(p, summaries.get(index));
        var appliedFlow = next == null ? FlowOverride.CALL_RETURN : config.transfer() == SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION ? FlowOverride.CALL : FlowOverride.NONE;
        var view = createdViews.get(site.toString());
        if (view == null) {
          repairFlow(ins, appliedFlow, next, owned);
          if (summaries.get(index).paths().get(0).returned().exit() == SoftwareCallModel.Exit.NONLOCAL) {
            var source = p.getFunctionManager().getFunctionContaining(site);
            var segments = SoftwareCallExecutionView.continuationSegments(p, summaries.get(index).paths().get(0).returned(), monitor);
            if (source != null) {
              var body = new ghidra.program.model.address.AddressSet(source.getBody());
              for (var segment : segments) {
                var begin = ProgramMapping.staticAddress(p, segment.source());
                var addition = new ghidra.program.model.address.AddressSet(begin, begin.add(segment.length() - 1));
                for (var other : p.getFunctionManager().getFunctions(true))
                  if (other.getID() != source.getID() && other.getBody().intersects(addition))
                    throw new IllegalArgumentException("Nonlocal destination conflicts with existing function " + other.getEntryPoint());
                body.add(addition);
              }
              var original = AnalysisOwnership.bodyRanges(source.getBody());
              source.setBody(body);
              owned.bodies.add(new AnalysisOwnership.Body(AnalysisOwnership.Point.of(source.getEntryPoint()), source.getID(), original,
                  AnalysisOwnership.bodyRanges(body)));
            }
          }
        }
        for (var segment : SoftwareCallValidation.payloadSegments(p, config, monitor))
          applyPayload(p, ProgramMapping.staticAddress(p, segment.address()), segment.length(), site, owned, monitor);
        if (view != null) {
          // The expansion contains the complete validated tail. Bound initial native decoding
          // with an explicit self fallthrough, keeping CALL nonterminal: stock thunk discovery
          // otherwise mistakes a one-instruction CALL_RETURN for the helper's own contract.
          // The injected graph exits before this transport edge; it is not a CPU loop.
          var boundedCallFlow = config.transfer() == SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION
              ? FlowOverride.CALL : FlowOverride.NONE;
          repairFlow(ins, boundedCallFlow, site, owned);
          var space = p.getAddressFactory().getAddressSpace(view.name());
          var disassembler = ghidra.program.disassemble.Disassembler.getDisassembler(p, monitor, null);
          var codeBody = view.body();
          var payload = space.getAddress(payloadStart(p, config).getOffset());
          if (config.template().payloadLength() != 0)
            codeBody.delete(payload, payload.add(config.template().payloadLength() - 1));
          for (var range : codeBody.getAddressRanges())
            disassembler.disassemble(range.getMinAddress(), codeBody);
          var alias = space.getAddress(site.getOffset());
          var aliasInstruction = p.getListing().getInstructionAt(alias);
          if (aliasInstruction == null) throw new IllegalStateException("Missing view transfer boundary");
          boolean stateful = review.stateContinuations.containsKey(site.toString());
          repairFlow(aliasInstruction, stateful ? boundedCallFlow : appliedFlow,
              stateful ? alias : space.getAddress(next.getOffset()), owned);
          for (var ref : p.getReferenceManager().getReferencesFrom(alias)) {
            if (ref.getReferenceType().isCall() && ref.isPrimary()) {
              owned.primaries.add(new AnalysisOwnership.Primary(AnalysisOwnership.Point.of(alias),
                  AnalysisOwnership.Point.of(ref.getToAddress()), ref.getOperandIndex(), ref.getReferenceType().toString(),
                  ref.getSource().toString(), true, false));
              p.getReferenceManager().setPrimary(ref, false);
            }
          }
          var helperReference = p.getReferenceManager().addMemoryReference(alias, helper,
              ghidra.program.model.symbol.RefType.CALL_OVERRIDE_UNCONDITIONAL,
              ghidra.program.model.symbol.SourceType.ANALYSIS, -1);
          p.getReferenceManager().setPrimary(helperReference, true);
          owned.reference(helperReference);
          applyPayload(p, payload, config.template().payloadLength(), alias, owned, monitor);
          var sourceFunction = p.getFunctionManager().getFunctionContaining(site);
          var rootLabel = p.getSymbolTable().getPrimarySymbol(executionView(p, config.mapper(), config.callCpu()));
          String callerName = sourceFunction != null ? sourceFunction.getName()
              : rootLabel != null && !rootLabel.isDynamic() ? rootLabel.getName() : "software_call_" + Integer.toHexString(config.callCpu());
          var function = p.getFunctionManager().createFunction(
              callerName + "_software_call",
              space.getAddress(sourceFunction == null ? config.callCpu() : sourceFunction.getEntryPoint().getOffset()), codeBody,
              ghidra.program.model.symbol.SourceType.ANALYSIS);
          owned.function(function);
          if (sourceFunction != null) {
            String originalStamp = AnalysisOwnership.functionStamp(sourceFunction);
            if (originalStamp == null) throw new IllegalArgumentException("Caller metadata changed before redirect");
            sourceFunction.setThunkedFunction(function);
            owned.redirects.add(new AnalysisOwnership.Redirect(AnalysisOwnership.Point.of(sourceFunction.getEntryPoint()),
                sourceFunction.getID(), AnalysisOwnership.Point.of(function.getEntryPoint()), originalStamp,
                AnalysisOwnership.functionStamp(sourceFunction, true)));
          }
          executionSites.put(site.toString(), alias.toString());
        }
      }
      for (var entry : createdViews.entrySet()) if (entry.getKey().contains("#state") || entry.getKey().contains("#native_")) {
        var body = entry.getValue().body();
        var disassembler = ghidra.program.disassemble.Disassembler.getDisassembler(p, monitor, null);
        for (var range : body.getAddressRanges()) disassembler.disassemble(range.getMinAddress(), body);
      }
      var repairedNested = new HashSet<String>();
      for (var summary : summaries) for (var witness : summary.returningCalls()) {
        if (!repairedNested.add(witness.site())) continue;
        var nestedInstruction = p.getListing().getInstructionAt(ProgramMapping.staticAddress(p, witness.site()));
        if (nestedInstruction.getFlowOverride() == FlowOverride.CALL_RETURN)
          repairFlow(nestedInstruction, FlowOverride.NONE, nestedInstruction.getAddress().add(nestedInstruction.getLength()), owned);
      }
      var stateEntries = new LinkedHashMap<String, SoftwareCallRegistry.StateEntry>();
      var entrySources = new ArrayList<Map.Entry<String, SoftwareCallEffects.ContinuationSummary>>(review.stateCallees.entrySet());
      entrySources.addAll(review.stateContinuations.entrySet());
      for (var entry : entrySources) for (var graph : nativeEntryGraphs(entry.getValue())) {
        var root = ProgramMapping.staticAddress(p, graph.entry().address());
        if (p.getFunctionManager().getFunctionAt(root) == null) {
          var body = new ghidra.program.model.address.AddressSet();
          for (var step : graph.steps()) {
            var at = ProgramMapping.staticAddress(p, step.address());
            if (step.callDepth() == 0 && at.getAddressSpace().equals(root.getAddressSpace())) body.add(at, at.add(step.length() - 1));
          }
          owned.function(createNamedFunction(p, root, body));
        }
        var stateEntry = new SoftwareCallRegistry.StateEntry(entry.getKey(), graph.entry().index(), root.toString(), entry.getValue().kind());
        stateEntries.putIfAbsent(root.toString(), stateEntry);
        String key = nativeViewKey(entry.getKey(), entry.getValue().kind(), graph.entry().index());
        for (var fragment : createdViews.entrySet()) if (fragment.getKey().startsWith(key)) {
          var space = p.getAddressFactory().getAddressSpace(fragment.getValue().name());
          var alias = space.getAddress(root.getOffset());
          if (review.stock ? !fragment.getValue().body().contains(alias) || !containsSource(p, fragment.getValue().segments(), root)
              : !ProgramMapping.staticToPhysical(p, alias).equals(ProgramMapping.staticToPhysical(p, root))) continue;
          var body = new ghidra.program.model.address.AddressSet();
          if (!review.stock) for (var step : graph.steps()) {
            var at = ProgramMapping.staticAddress(p, step.address());
            if (step.callDepth() == 0 && at.getAddressSpace().equals(root.getAddressSpace()))
              body.add(space.getAddress(at.getOffset()), space.getAddress(at.getOffset() + step.length() - 1));
          }
          if (review.stock) body = new ghidra.program.model.address.AddressSet(alias, alias);
          var function = p.getFunctionManager().createFunction(p.getFunctionManager().getFunctionAt(root).getName() + "_state_" + graph.entry().index(),
              alias, body, ghidra.program.model.symbol.SourceType.ANALYSIS);
          owned.function(function); stateEntries.put(alias.toString(), stateEntry);
        }
      }
      createMissingNativeFunctions(p, summaries, owned, monitor);
      for (var config : review.configurations) {
        var root = executionView(p, config.mapper(), config.callCpu());
        String configuredSite = site(p, config).toString();
        boolean continuationSite = review.stateContinuations.entrySet().stream()
            .filter(entry -> !entry.getKey().equals(configuredSite))
            .anyMatch(entry -> entry.getValue().steps().stream().anyMatch(step -> step.address().equals(root.toString())));
        if (!continuationSite && p.getFunctionManager().getFunctionContaining(root) == null) {
          var body = ghidra.app.cmd.function.CreateFunctionCmd.getFunctionBody(p, root, false, monitor);
          if (body == null || body.isEmpty()) throw new IllegalArgumentException("Missing justified caller body at " + root);
          var caller = createNamedFunction(p, root, body);
          owned.function(caller);
          String aliasSite = executionSites.get(configuredSite);
          if (aliasSite != null) {
            var aliasFunction = p.getFunctionManager().getFunctionContaining(ProgramMapping.staticAddress(p, aliasSite));
            String originalStamp = AnalysisOwnership.functionStamp(caller);
            if (aliasFunction == null || originalStamp == null) throw new IllegalArgumentException("Missing reviewed caller execution alias");
            caller.setThunkedFunction(aliasFunction);
            owned.redirects.add(new AnalysisOwnership.Redirect(AnalysisOwnership.Point.of(root), caller.getID(),
                AnalysisOwnership.Point.of(aliasFunction.getEntryPoint()), originalStamp, AnalysisOwnership.functionStamp(caller, true)));
          }
          owned.nativeFunctionInventories.add(new AnalysisOwnership.NativeFunctionInventory(
              AnalysisOwnership.Point.of(root), AnalysisOwnership.bodyRanges(body), "CREATE_FROM_CONFIGURED_ROOT; original=absent"));
        }
      }
      installProjectedEntries(p, review, createdViews, stateEntries, owned, monitor);
      installReturningMarkers(p, summaries, owned, monitor);
      for (var entry : stateEntries.entrySet()) {
        var function = p.getFunctionManager().getFunctionAt(ProgramMapping.staticAddress(p, entry.getKey()));
        String original = function.getCallingConventionName();
        String originalComment = function.getComment();
        boolean originalNoReturn = function.hasNoReturn();
        var context = entry.getValue();
        var source = context.kind().equals("CALLEE") ? review.stateCallees.get(context.site()) : review.stateContinuations.get(context.site());
        var state = source.steps().stream().filter(step -> step.index() == context.entryStep()).findFirst().orElseThrow().before();
        String appliedComment = AnalysisOwnership.stateEntryComment(originalComment,
            ProgramMapping.JSON.toJson(Map.of("sourceSite", context.site(), "origin", context.kind(), "state", state)));
        boolean carrier = review.stock && !entry.getKey().equals(context.canonical());
        if (carrier) {
          var at = function.getEntryPoint();
          p.getListing().clearCodeUnits(at, at, false);
          StockEntryInjection.prepare(p, at);
          ghidra.program.disassemble.Disassembler.getDisassembler(p, monitor, null).disassemble(at, new ghidra.program.model.address.AddressSet(at, at), false);
          function.setCallingConvention(StockEntryInjection.CONVENTION);
        } else if (!review.stock) function.setCallingConvention(SoftwareCallStateEntryInjection.CONVENTION);
        if (review.stock && !carrier) appliedComment = originalComment;
        var selectedGraph = projectionGraphs(source).stream().filter(graph -> graph.entry().index() == context.graphEntry()).findFirst().orElseThrow();
        if (!entry.getKey().equals(context.canonical()) && selectedGraph.exit().equals("LOOP")) function.setNoReturn(true);
        function.setComment(appliedComment);
        owned.stateEntries.add(new AnalysisOwnership.StateEntry(AnalysisOwnership.Point.of(function.getEntryPoint()),
            function.getID(), original, originalComment, appliedComment, originalNoReturn, function.hasNoReturn(), AnalysisOwnership.helperMetadataStamp(function), review.stock ? function.getCallingConventionName() : null));
      }
      for (int index = 0; index < owned.helpers.size(); index++) {
        var receipt = owned.helpers.get(index);
        var function = p.getFunctionManager().getFunctionAt(receipt.address().resolve(p));
        owned.helpers.set(index, new AnalysisOwnership.Helper(receipt.address(), receipt.id(), receipt.originalNoReturn(),
            receipt.originalFixup(), receipt.appliedFixup(), receipt.originalThunk(), AnalysisOwnership.helperMetadataStamp(function)));
      }
      for (var receipt : owned.repairs) {
        var address = receipt.address().resolve(p);
        owned.siteReferences.add(new AnalysisOwnership.SiteReferences(receipt.address(), AnalysisOwnership.referenceStamp(p, address)));
      }
      AnalysisOwnership.save(p, FEATURE, owned);
      p.getOptions(ProgramMapping.OPTIONS).setString("softwareCall.review.inventory.v1", ProgramMapping.JSON.toJson(Map.of("sites", review.inventory, "nestedRepairs", review.nestedRepairs, "instructionDiscovery", review.discovery, "stateContinuations", review.stateContinuations, "stateCallees", review.stateCallees)));
      SoftwareCallRegistry.install(p, review.configurations, executionSites, review.stateContinuations.keySet(), stateEntries, review.stock);
      for (var view : createdViews.values())
        owned.views.add(new AnalysisOwnership.View(view.name(), AnalysisOwnership.viewStamp(p, view.name(), monitor)));
      AnalysisOwnership.save(p, FEATURE, owned);
      monitor.checkCancelled();
      success = true;
    } finally { p.endTransaction(tx, success); }
    return review.inventory;
  }

  private static String nativeViewKey(String site, String kind, int index) {
    return site + "#native_" + kind + "_" + index + "_";
  }

  private static List<SoftwareCallEffects.ContinuationSummary> projectionGraphs(SoftwareCallEffects.ContinuationSummary source) {
    var graphs = new ArrayList<SoftwareCallEffects.ContinuationSummary>();
    graphs.add(source);
    for (var invocation : SoftwareCallEffects.calleeInvocations(source)) graphs.add(invocation.graph());
    return graphs;
  }

  /** Give every supplementary listing fragment an actual proved native entry, including the
   * temporary-function entry paths used by stock switch analysis. No mapped byte or instruction
   * is removed; a projection selects a state inside its complete original invocation graph. */
  private static void installProjectedEntries(Program p, Review review,
      Map<String, SoftwareCallExecutionView.Created> views, Map<String, SoftwareCallRegistry.StateEntry> entries,
      AnalysisOwnership.Group owned, TaskMonitor monitor) throws Exception {
    for (var view : views.entrySet()) {
      if (!view.getKey().contains("#state") && !view.getKey().contains("#native_")) continue;
      String site = view.getKey().substring(0, view.getKey().indexOf('#'));
      var source = view.getKey().contains("#native_CALLEE") ? review.stateCallees.get(site) : review.stateContinuations.get(site);
      if (source == null) throw new IllegalArgumentException("Missing fragment source graph");
      if (!review.stock) SoftwareCallStateEntryInjection.nativeIdentity();
      var space = p.getAddressFactory().getAddressSpace(view.getValue().name());
      var fragmentGraph = source;
      if (view.getKey().contains("#native_")) {
        String[] identity = view.getKey().substring(view.getKey().indexOf('#') + 1).split("_");
        int graphEntry = Integer.parseInt(identity[2]);
        fragmentGraph = projectionGraphs(source).stream().filter(graph -> graph.entry().index() == graphEntry)
            .findFirst().orElseThrow(() -> new IllegalArgumentException("Missing planned fragment invocation"));
      }
      if (review.stock) {
        var selectedGraph = carrierGraph(p, fragmentGraph, view.getValue().segments());
        if (selectedGraph == null) continue;
        var first = carrierStep(p, selectedGraph, view.getValue().segments());
        var alias = view.getValue().body().getMinAddress();
        if (p.getFunctionManager().getFunctionAt(alias) == null) {
          var function = p.getFunctionManager().createFunction("projection_" + Integer.toHexString(first.before().cpu()),
              alias, view.getValue().body(), ghidra.program.model.symbol.SourceType.ANALYSIS);
          owned.function(function);
          entries.put(alias.toString(), new SoftwareCallRegistry.StateEntry(site, selectedGraph.entry().index(),
              first.address(), source.kind(), first.index(), true));
        }
        continue;
      }
      for (var graph : projectionGraphs(fragmentGraph)) {
        monitor.checkCancelled();
        var body = new ghidra.program.model.address.AddressSet();
        SoftwareCallEffects.ContinuationStep first = null;
        for (var step : graph.steps()) {
          if (step.callDepth() != 0) continue;
          var alias = space.getAddress(step.before().cpu());
          if (!view.getValue().body().contains(alias, alias.add(step.length() - 1))
              || !ProgramMapping.staticToPhysical(p, alias).equals(List.of(step.before().physical()))
              || p.getFunctionManager().getFunctionContaining(alias) != null) continue;
          if (first == null) first = step;
          body.add(alias, alias.add(step.length() - 1));
        }
        if (first == null) continue;
        var alias = space.getAddress(first.before().cpu());
        var function = p.getFunctionManager().createFunction("projection_" + Integer.toHexString(first.before().cpu()),
            alias, body, ghidra.program.model.symbol.SourceType.ANALYSIS);
        owned.function(function);
        entries.put(alias.toString(), new SoftwareCallRegistry.StateEntry(site, graph.entry().index(),
            first.address(), source.kind(), first.index(), true));
      }
    }
  }

  private static boolean containsSource(Program p, List<SoftwareCallExecutionView.Segment> segments, Address source) {
    return segments.stream().anyMatch(segment -> {
      var at = ProgramMapping.staticAddress(p, segment.source());
      return at.getAddressSpace().equals(source.getAddressSpace()) && at.getOffset() <= source.getOffset()
          && at.getOffset() + segment.length() > source.getOffset();
    });
  }

  private static SoftwareCallEffects.ContinuationSummary carrierGraph(Program p,
      SoftwareCallEffects.ContinuationSummary graph, List<SoftwareCallExecutionView.Segment> segments) {
    return projectionGraphs(graph).stream().filter(candidate -> candidate.steps().stream().anyMatch(step -> step.callDepth() == 0
        && containsSource(p, segments, ProgramMapping.staticAddress(p, step.address())))).findFirst()
        .orElse(null);
  }

  private static SoftwareCallEffects.ContinuationStep carrierStep(Program p,
      SoftwareCallEffects.ContinuationSummary graph, List<SoftwareCallExecutionView.Segment> segments) {
    return graph.steps().stream().filter(step -> step.callDepth() == 0
        && containsSource(p, segments, ProgramMapping.staticAddress(p, step.address()))).findFirst()
        .orElseThrow(() -> new IllegalArgumentException("No proved entry in presentation fragment"));
  }

  private static SoftwareCallEffects.ContinuationSummary plannedGraph(Review review, String key) {
    String site = key.substring(0, key.indexOf('#'));
    var source = key.contains("#native_CALLEE") ? review.stateCallees.get(site) : review.stateContinuations.get(site);
    if (!key.contains("#native_")) return source;
    String[] identity = key.substring(key.indexOf('#') + 1).split("_");
    return projectionGraphs(source).stream().filter(graph -> graph.entry().index() == Integer.parseInt(identity[2])).findFirst().orElseThrow();
  }

  private static List<SoftwareCallEffects.ContinuationSummary> nativeEntryGraphs(SoftwareCallEffects.ContinuationSummary graph) {
    var result = new ArrayList<SoftwareCallEffects.ContinuationSummary>();
    if (graph.kind().equals("CALLEE")) result.add(graph);
    for (var invocation : SoftwareCallEffects.calleeInvocations(graph))
      if (graph.kind().equals("CALLEE") || !invocation.graph().transportVetoes().isEmpty()
          || !invocation.graph().exit().equals("RETURN")) result.add(invocation.graph());
    return result;
  }

  private static void planEntryViews(Program p, String site, SoftwareCallEffects.ContinuationSummary source,
      Map<String, SoftwareCallExecutionView.Preview> views, TaskMonitor monitor, boolean stock) throws Exception {
    for (var graph : nativeEntryGraphs(source)) {
      if (!stock) SoftwareCallStateEntryInjection.nativeIdentity();
      var root = ProgramMapping.staticAddress(p, graph.entry().address());
      var function = p.getFunctionManager().getFunctionAt(root);
      if (function != null && !defaultCallerContract(function) && !AnalysisOwnership.stateEntryCurrent(p, root))
        throw new IllegalArgumentException("State entry requires reviewed bare native contract at " + root);
      int node = graph.entry().index(), fragment = 0;
      var sourceSite = ProgramMapping.staticAddress(p, site);
      String base = SoftwareCallExecutionView.PREFIX + "entry_" + Integer.toUnsignedString(sourceSite.getAddressSpace().getSpaceID(), 16)
          + "_" + Long.toHexString(sourceSite.getOffset()) + "_" + source.kind().toLowerCase(java.util.Locale.ROOT) + "_" + node;
      while (p.getAddressFactory().getAddressSpace(base + "_0") != null) base += "_next";
      for (var ranges : SoftwareCallContinuationView.fragments(p, graph)) {
        views.put(nativeViewKey(site, source.kind(), node) + fragment,
            SoftwareCallExecutionView.preview(p, base + "_" + fragment++, ranges, monitor));
      }
    }
  }

  private static SoftwareCallEffects.Summary continuationFunctions(SoftwareCallEffects.ContinuationSummary graph) {
    var entries = new HashSet<String>();
    for (var invocation : SoftwareCallEffects.calleeInvocations(graph)) entries.add(invocation.target());
    var fetches = graph.steps().stream().filter(step -> step.callDepth() > 0 && entries.contains(step.nativeFunctionEntry()))
        .map(step -> new SoftwareCallEffects.Fetch(step.address(), step.before().physical(), step.nativeFunctionEntry(), step.callDepth())).toList();
    return new SoftwareCallEffects.Summary(SoftwareCallEffects.VERSION, graph.dependencies(), List.of(), List.of(),
        fetches, graph.nativeIncompatibilities(), graph.returningNativeFunctions(), graph.returningCalls());
  }

  private static void validateFunctionLabel(Program p, Address entry) {
    for (var symbol : p.getSymbolTable().getSymbols(entry))
      if (!symbol.isDynamic() && symbol.getSymbolType() != ghidra.program.model.symbol.SymbolType.LABEL)
        throw new IllegalArgumentException("Native function root conflicts with existing symbol at " + entry);
  }

  private static Function createNamedFunction(Program p, Address entry,
      ghidra.program.model.address.AddressSetView body) throws Exception {
    validateFunctionLabel(p, entry);
    var primary = p.getSymbolTable().getPrimarySymbol(entry);
    boolean named = primary != null && !primary.isDynamic();
    return p.getFunctionManager().createFunction(named ? primary.getName() : null,
        named ? primary.getParentNamespace() : p.getGlobalNamespace(), entry, body,
        named ? primary.getSource() : ghidra.program.model.symbol.SourceType.ANALYSIS);
  }

  private static void installReturningMarkers(Program p, List<SoftwareCallEffects.Summary> summaries,
      AnalysisOwnership.Group owned, TaskMonitor monitor) throws Exception {
    var targets = new TreeSet<String>();
    for (var summary : summaries) targets.addAll(summary.returningNativeFunctions());
    for (String value : targets) {
      monitor.checkCancelled();
      var entry = ProgramMapping.staticAddress(p, value);
      var function = p.getFunctionManager().getFunctionAt(entry);
      if (function == null || function.isThunk() || function.isInline())
        throw new IllegalArgumentException("Returning target lacks compatible native Function at " + entry);
      var originalFixup = function.getCallFixup();
      if (originalFixup != null && !originalFixup.equals(SoftwareCallMayReturnInjection.NAME))
        throw new IllegalArgumentException("Returning target has conflicting fixup at " + entry);
      owned.helpers.add(new AnalysisOwnership.Helper(AnalysisOwnership.Point.of(entry), function.getID(),
          function.hasNoReturn(), originalFixup, SoftwareCallMayReturnInjection.NAME, null));
      function.setNoReturn(false);
      function.setCallFixup(SoftwareCallMayReturnInjection.NAME);
    }
  }

  private static void createMissingNativeFunctions(Program p, List<SoftwareCallEffects.Summary> summaries,
      AnalysisOwnership.Group owned, TaskMonitor monitor) throws Exception {
    var entries = new TreeSet<Address>();
    for (var summary : summaries)
      for (var fetch : summary.fetches()) entries.add(ProgramMapping.staticAddress(p, fetch.nativeFunctionEntry()));
    for (var entry : entries) {
      monitor.checkCancelled();
      if (p.getFunctionManager().getFunctionAt(entry) != null) continue;
      if (p.getFunctionManager().getFunctionContaining(entry) != null
          || p.getListing().getInstructionAt(entry) == null)
        throw new IllegalArgumentException("Native function entry conflicts with existing body/boundary at " + entry);
      validateFunctionLabel(p, entry);
      var body = ghidra.app.cmd.function.CreateFunctionCmd.getFunctionBody(p, entry, false, monitor);
      if (body == null || body.isEmpty() || !body.contains(entry))
        throw new IllegalArgumentException("No ordinary native function body at " + entry);
      for (var function : p.getFunctionManager().getFunctions(true))
        if (function.getBody().intersects(body))
          throw new IllegalArgumentException("Native function body would split existing function " + function.getEntryPoint());
      for (var range : body.getAddressRanges()) {
        if (!range.getMinAddress().getAddressSpace().equals(entry.getAddressSpace()))
          throw new IllegalArgumentException("Native function body spans unsupported spaces at " + entry);
        for (var address = range.getMinAddress(); address.compareTo(range.getMaxAddress()) <= 0;) {
          var instruction = p.getListing().getInstructionAt(address);
          if (instruction == null || instruction.getMaxAddress().compareTo(range.getMaxAddress()) > 0)
            throw new IllegalArgumentException("Native function body has missing/conflicting code at " + address);
          if (instruction.getFlowType().isJump())
            for (var target : instruction.getFlows())
              if (!body.contains(target) && p.getFunctionManager().getFunctionAt(target) == null)
                throw new IllegalArgumentException("Native function body omits a known jump target at " + target);
          address = instruction.getMaxAddress().add(1);
        }
      }
      var created = createNamedFunction(p, entry, body);
      owned.function(created);
      owned.nativeFunctionInventories.add(new AnalysisOwnership.NativeFunctionInventory(
          AnalysisOwnership.Point.of(entry), AnalysisOwnership.bodyRanges(body), "CREATE_FROM_ORDINARY_FLOW; original=absent"));
    }
  }

  private static void repairFlow(Instruction ins, FlowOverride appliedFlow, Address next,
      AnalysisOwnership.Group owned) throws Exception {
    String originalFlow = ins.getFlowOverride().toString();
    boolean originalOverridden = ins.isFallThroughOverridden();
    var original = ins.getFallThrough();
    String bytes = HexFormat.of().formatHex(ins.getBytes());
    ins.setFlowOverride(appliedFlow);
    ins.setFallThrough(next);
    owned.repairs.add(new AnalysisOwnership.Repair(AnalysisOwnership.Point.of(ins.getAddress()), originalFlow,
        appliedFlow.toString(), originalOverridden, original == null ? null : AnalysisOwnership.Point.of(original),
        next == null ? null : AnalysisOwnership.Point.of(next), bytes, ins.isFallThroughOverridden()));
  }

  private static boolean defaultCallerContract(Function function) {
    String convention = function.getCallingConventionName();
    return function.getSignatureSource() == ghidra.program.model.symbol.SourceType.DEFAULT
        && !function.hasCustomVariableStorage() && !function.hasVarArgs() && !function.isInline()
        && function.getCallFixup() == null && function.getStackPurgeSize() == Function.UNKNOWN_STACK_DEPTH_CHANGE
        && (convention == null || convention.equals(Function.DEFAULT_CALLING_CONVENTION_STRING)
            || convention.equals(Function.UNKNOWN_CALLING_CONVENTION_STRING));
  }

  private static void validateViewPrefix(Program p, Address entry, Address site,
      SoftwareCallValidation.Configuration config, TaskMonitor monitor) throws Exception {
    for (var at = entry; at.compareTo(site) < 0;) {
      monitor.checkCancelled();
      var ins = p.getListing().getInstructionAt(at);
      if (ins == null || ins.getMaxAddress().compareTo(site) >= 0)
        throw new IllegalArgumentException("Missing prefix instruction boundary at " + at);
      boolean exactManualPrelude = config.transfer() == SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION
          && at.getOffset() >= config.callCpu();
      for (var op : ins.getPcode(false)) {
        int code = op.getOpcode();
        if (op.getOutput() != null && op.getOutput().isAddress())
          throw new IllegalArgumentException("Execution prefix writes memory without a physical-view proof at " + at);
        if (code != ghidra.program.model.pcode.PcodeOp.BRANCH && code != ghidra.program.model.pcode.PcodeOp.CBRANCH
            && code != ghidra.program.model.pcode.PcodeOp.CALL && code != ghidra.program.model.pcode.PcodeOp.RETURN)
          for (var input : op.getInputs())
            if (input.isAddress()) validatePrefixSource(p, config.mapper(), input.getOffset(), input.getSize());
        if (code == ghidra.program.model.pcode.PcodeOp.LOAD) {
          var pointer = op.getInput(1);
          if (!pointer.isConstant() || pointer.getOffset() < 0
              || pointer.getOffset() + op.getOutput().getSize() > 0x4000)
            throw new IllegalArgumentException("Execution prefix LOAD requires a proven native physical data view at " + at);
          for (int i = 0; i < op.getOutput().getSize(); i++) {
            var source = SoftwareCallValidation.executionAddress(p, config.mapper(), (int) pointer.getOffset() + i);
            var identity = ProgramMapping.staticToPhysical(p, source);
            var block = p.getMemory().getBlock(source);
            if (identity.size() != 1 || !identity.get(0).region().equals("ROM") || identity.get(0).bank() != 0
                || block == null || !block.isInitialized() || block.isWrite() || block.isVolatile())
              throw new IllegalArgumentException("Execution prefix LOAD source is not immutable fixed ROM0");
          }
        }
        if (code == ghidra.program.model.pcode.PcodeOp.CALL || code == ghidra.program.model.pcode.PcodeOp.CALLIND
            || code == ghidra.program.model.pcode.PcodeOp.BRANCH || code == ghidra.program.model.pcode.PcodeOp.CBRANCH
            || code == ghidra.program.model.pcode.PcodeOp.BRANCHIND || code == ghidra.program.model.pcode.PcodeOp.RETURN
            || code == ghidra.program.model.pcode.PcodeOp.CALLOTHER
            || (code == ghidra.program.model.pcode.PcodeOp.STORE && !exactManualPrelude))
          throw new IllegalArgumentException("Execution prefix requires further mapper/flow proof at " + at);
      }
      at = ins.getMaxAddress().add(1);
    }
  }

  private static void validatePrefixSource(Program p, MapperState mapper, long cpu, int size) throws Exception {
    if (cpu < 0 || cpu + size > 0x4000)
      throw new IllegalArgumentException("Execution prefix read requires immutable fixed ROM0 data");
    for (int i = 0; i < size; i++) {
      var source = SoftwareCallValidation.executionAddress(p, mapper, (int) cpu + i);
      var identity = ProgramMapping.staticToPhysical(p, source);
      var block = p.getMemory().getBlock(source);
      if (identity.size() != 1 || !identity.get(0).region().equals("ROM") || identity.get(0).bank() != 0
          || block == null || !block.isInitialized() || block.isWrite() || block.isVolatile())
        throw new IllegalArgumentException("Execution prefix read source is not immutable fixed ROM0");
    }
  }

  private static Address site(Program p, SoftwareCallValidation.Configuration config) throws Exception {
    int offset = config.callCpu() + (config.transfer() == SoftwareCallModel.EntryTransfer.PUSHED_CONTINUATION ? 4 : 0);
    return executionView(p, config.mapper(), offset);
  }
  private static Address payloadStart(Program p, SoftwareCallValidation.Configuration config) throws Exception {
    int length = switch (config.transfer()) {
      case HARDWARE_CALL -> 3; case HARDWARE_RST -> 1; case PUSHED_CONTINUATION -> 7;
    };
    return executionView(p, config.mapper(), config.callCpu() + length);
  }
  private static Address executionView(Program p, MapperState mapper, int cpu) throws Exception {
    var resolved = ProgramMapping.cpuToStatic(p, mapper, cpu, false).addresses().stream()
        .filter(address -> address.getOffset() == cpu && SoftwareCallExecutionView.canonical(p, address)).toList();
    if (resolved.size() != 1) throw new IllegalArgumentException("Ambiguous execution view at " + cpu);
    return resolved.get(0);
  }
  private static Address continuation(Program p, SoftwareCallEffects.Summary summary) throws Exception {
    var returns = summary.paths().stream().filter(path -> path.returned().exit() == SoftwareCallModel.Exit.MAY_RETURN
        || path.returned().exit() == SoftwareCallModel.Exit.NONLOCAL).toList();
    if (returns.isEmpty()) return null;
    var identities = returns.stream().map(path -> path.returned().physical()).distinct().toList();
    if (identities.size() != 1) throw new IllegalArgumentException("Ambiguous physical continuation");
    var views = ProgramMapping.physicalToStatic(p, identities.get(0)).stream()
        .filter(address -> address.getOffset() == returns.get(0).returned().cpu()
            && SoftwareCallExecutionView.canonical(p, address)).toList();
    if (views.size() != 1) throw new IllegalArgumentException("Ambiguous continuation execution view");
    var result = views.get(0);
    var instruction = p.getListing().getInstructionContaining(result);
    if ((instruction != null && !instruction.getAddress().equals(result))
        || p.getListing().getDefinedDataContaining(result) != null)
      throw new IllegalArgumentException("Derived continuation boundary conflict at " + result);
    return result;
  }

  public record PayloadDisposition(String address, int length, String disposition, String type) {}

  /** Exact, non-destructive ownership inventory. Compatible scalar data is retained verbatim. */
  public static List<PayloadDisposition> inspectPayload(
      Program p, Address start, int length, TaskMonitor monitor) throws Exception {
    var before = p.getListing().getInstructionBefore(start);
    return inspectPayload(p, start, length, before == null ? null : before.getAddress(), monitor);
  }

  public static List<PayloadDisposition> inspectPayload(Program p, Address start, int length,
      Address ownerSite, TaskMonitor monitor) throws Exception {
    if (length < 0 || length > 0x10000) throw new IllegalArgumentException("Invalid payload extent");
    var result = new ArrayList<PayloadDisposition>();
    if (length == 0) return List.of();
    var end = start.addNoWrap(length - 1);
    for (int offset = 0; offset < length;) {
      monitor.checkCancelled();
      var at = start.addNoWrap(offset);
      if (p.getListing().getInstructionContaining(at) != null
          || !compatibleBodyClaim(p, start, at, ownerSite)
          || !compatiblePayloadAnnotations(p, at, ownerSite))
        throw new IllegalArgumentException("Payload ownership/boundary conflict at " + at);
      var data = p.getListing().getDefinedDataContaining(at);
      if (data == null) {
        result.add(new PayloadDisposition(at.toString(), 1, "CREATE_BYTE", "byte"));
        offset++;
      } else {
        if (!data.getAddress().equals(at) || data.getMaxAddress().compareTo(end) > 0
            || !compatible(data.getDataType()))
          throw new IllegalArgumentException("Incompatible payload data extent/type at " + at);
        // Every byte of an existing unit must remain free of competing claims.
        for (int i = 1; i < data.getLength(); i++) {
          var interior = at.add(i);
          if (!compatibleBodyClaim(p, start, interior, ownerSite)
              || !compatiblePayloadAnnotations(p, interior, ownerSite))
            throw new IllegalArgumentException("Payload ownership conflict at " + interior);
        }
        result.add(new PayloadDisposition(at.toString(), data.getLength(), "PRESERVE_DATA", data.getDataType().getPathName()));
        offset += data.getLength();
      }
    }
    return List.copyOf(result);
  }

  private static boolean compatiblePayloadAnnotations(Program p, Address at, Address ownerSite) throws Exception {
    if (p.getReferenceManager().getReferencesFrom(at).length != 0) return false;
    var transfer = ownerSite == null ? null : p.getListing().getInstructionAt(ownerSite);
    boolean adjacentCall = transfer != null && transfer.getFlowType().isCall();
    var references = p.getReferenceManager().getReferencesTo(at);
    while (references.hasNext()) {
      var ref = references.next();
      // Ordinary analysis may materialize the injection's payload LOADs. Such output
      // is compatible annotation, never a premise proving a call or payload extent.
      if (!adjacentCall || !samePhysicalInstruction(p, ref.getFromAddress(), transfer.getAddress())
          || ref.getReferenceType() != ghidra.program.model.symbol.RefType.READ
          || ref.getSource() != ghidra.program.model.symbol.SourceType.ANALYSIS
          || ref.getOperandIndex() != 0) return false;
    }
    for (var symbol : p.getSymbolTable().getSymbols(at))
      if (!symbol.isDynamic() || symbol.getSource() != ghidra.program.model.symbol.SourceType.DEFAULT) return false;
    return true;
  }

  private static boolean samePhysicalInstruction(Program p, Address a, Address b) throws Exception {
    if (a.equals(b)) return true;
    var first = ProgramMapping.staticToPhysical(p, a);
    var second = ProgramMapping.staticToPhysical(p, b);
    return first.size() == 1 && first.equals(second);
  }

  private static boolean compatibleBodyClaim(Program p, Address payloadStart, Address at, Address ownerSite) {
    var function = p.getFunctionManager().getFunctionContaining(at);
    if (function == null) return true;
    var transfer = ownerSite == null ? null : p.getListing().getInstructionAt(ownerSite);
    return transfer != null && transfer.getAddress().getAddressSpace().equals(payloadStart.getAddressSpace())
        && transfer.getFlowType().isCall() && function.getBody().contains(transfer.getAddress())
        && function.getEntryPoint().compareTo(payloadStart) < 0;
  }

  private static boolean compatible(DataType type) {
    if (type instanceof Array array)
      return array.getDataType().getClass() == ByteDataType.class;
    return type.getClass() == ByteDataType.class || type.getClass() == WordDataType.class
        || type.getClass() == Undefined1DataType.class || type.getClass() == Undefined2DataType.class;
  }

  public static void applyPayload(Program p, Address start, int length,
      AnalysisOwnership.Group owned, TaskMonitor monitor) throws Exception {
    var before = p.getListing().getInstructionBefore(start);
    applyPayload(p, start, length, before == null ? null : before.getAddress(), owned, monitor);
  }

  public static void applyPayload(Program p, Address start, int length, Address ownerSite,
      AnalysisOwnership.Group owned, TaskMonitor monitor) throws Exception {
    var inventory = inspectPayload(p, start, length, ownerSite, monitor);
    if (length != 0) {
      var affected = new LinkedHashSet<Function>();
      for (int offset = 0; offset < length; offset++) {
        var function = p.getFunctionManager().getFunctionContaining(start.add(offset));
        if (function != null) affected.add(function);
      }
      for (var function : affected) {
        var original = AnalysisOwnership.bodyRanges(function.getBody());
        var repaired = new ghidra.program.model.address.AddressSet(function.getBody());
        repaired.delete(start, start.add(length - 1));
        function.setBody(repaired);
        owned.bodies.add(new AnalysisOwnership.Body(AnalysisOwnership.Point.of(function.getEntryPoint()),
            function.getID(), original, AnalysisOwnership.bodyRanges(repaired)));
      }
    }
    for (var item : inventory) {
      monitor.checkCancelled();
      if (!item.disposition.equals("CREATE_BYTE")) continue;
      var at = p.getAddressFactory().getAddress(item.address);
      var data = p.getListing().createData(at, ByteDataType.dataType);
      owned.payloads.add(new AnalysisOwnership.Payload(AnalysisOwnership.Point.of(at), AnalysisOwnership.payloadStamp(p, data)));
    }
  }
}
