package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Transactional ownership receipts; removal only undoes unchanged tool additions. */
public final class AnalysisOwnership {
  // Keep the option key so saved v1 projects are found. The envelope and each function
  // receipt carry independent versions: saving another group must not upgrade old proof.
  private static final String KEY = "analysis.ownership.v1";
  private static final int VERSION = 5;
  private static final int FUNCTION_VERSION = 2;

  private AnalysisOwnership() {}

  public record Point(int space, long offset) {
    static Point of(Address a) {
      return new Point(a.getAddressSpace().getSpaceID(), a.getOffset());
    }

    Address resolve(Program p) {
      var as = p.getAddressFactory().getAddressSpace(space);
      return as == null ? null : as.getAddressInThisSpaceOnly(offset);
    }
  }

  // Nullable for old receipts: missing edit evidence must never authorize deletion.
  public record Ref(Point from, Point to, int operand, String type, long symbol, Boolean primary) {}

  public record Mark(long id, Point address, String type, String category, String comment) {}

  public record Func(long id, Point entry, String source, String stamp, int version) {}

  public record Flow(
      Point address,
      String bytes,
      String flowOverride,
      Point applied,
      boolean originalOverridden,
      Point original) {}

  public record Payload(Point address, String stamp) {}

  public record Repair(Point address, String originalFlow, String appliedFlow,
      boolean originalFallthrough, Point originalNext, Point appliedNext, String bytes, boolean appliedFallthrough) {}

  public record Helper(Point address, long id, boolean originalNoReturn, String originalFixup,
      String appliedFixup, Point originalThunk, String appliedMetadata) {
    public Helper(Point address, long id, boolean originalNoReturn, String originalFixup,
        String appliedFixup, Point originalThunk) {
      this(address, id, originalNoReturn, originalFixup, appliedFixup, originalThunk, null);
    }
  }

  public record NativeFunctionInventory(Point entry, List<Range> body, String disposition) {}
  public record Redirect(Point source, long id, Point target, String originalStamp, String appliedStamp) {}
  public record View(String name, String stamp) {}
  public record StateEntry(Point address, long id, String originalConvention,
      String originalComment, String appliedComment, Boolean originalNoReturn, Boolean appliedNoReturn, String appliedMetadata,
      String appliedConvention) {
    public StateEntry(Point address, long id, String originalConvention, String originalComment,
        String appliedComment, Boolean originalNoReturn, Boolean appliedNoReturn, String appliedMetadata) {
      this(address,id,originalConvention,originalComment,appliedComment,originalNoReturn,appliedNoReturn,appliedMetadata,null);
    }
    // Absent only in old companion-owned receipts; their applied convention had one meaning.
    public String appliedConvention() { return appliedConvention == null ? SoftwareCallStateEntryInjection.CONVENTION : appliedConvention; }
  }
  public record SiteReferences(Point address, String stamp) {}
  public record Primary(Point from, Point to, int operand, String type, String source, boolean original, boolean applied) {}
  public record Range(Point min, Point max) {}
  public record Body(Point entry, long id, List<Range> original, List<Range> applied) {}

  public static final class Group {
    public List<StateEntry> stateEntries = new ArrayList<>();
    public List<NativeFunctionInventory> nativeFunctionInventories = new ArrayList<>();
    public List<Redirect> redirects = new ArrayList<>();
    public List<View> views = new ArrayList<>();
    public List<SiteReferences> siteReferences = new ArrayList<>();
    public List<Primary> primaries = new ArrayList<>();
    public List<Body> bodies = new ArrayList<>();
    public List<Payload> payloads = new ArrayList<>();
    public List<Repair> repairs = new ArrayList<>();
    public List<Helper> helpers = new ArrayList<>();
    public List<Ref> references = new ArrayList<>();
    public List<Mark> bookmarks = new ArrayList<>();
    public List<Func> functions = new ArrayList<>();
    public List<Flow> flows = new ArrayList<>();

    public void reference(Reference r) {
      references.add(
          new Ref(
              Point.of(r.getFromAddress()),
              Point.of(r.getToAddress()),
              r.getOperandIndex(),
              r.getReferenceType().toString(),
              r.getSymbolID(),
              r.isPrimary()));
    }

    public void bookmark(Bookmark b) {
      bookmarks.add(
          new Mark(
              b.getId(),
              Point.of(b.getAddress()),
              b.getTypeString(),
              b.getCategory(),
              b.getComment()));
    }

    public void function(Function f) {
      functions.add(
          new Func(
              f.getSymbol().getID(),
              Point.of(f.getEntryPoint()),
              f.getSymbol().getSource().toString(),
              functionStamp(f),
              FUNCTION_VERSION));
    }
  }

  private static final class Registry {
    int version = VERSION;
    Map<String, Group> groups = new TreeMap<>();
  }

  private static Registry registry(Program p) {
    var options = p.getOptions(ProgramMapping.OPTIONS);
    // A default-valued Options read can register an otherwise absent option in its cache.
    // Do not let a read-only ownership check manufacture a review dependency.
    String value = options.contains(KEY) ? options.getString(KEY, null) : "{\"version\":1,\"groups\":{}}";
    var result = ProgramMapping.JSON.fromJson(value, Registry.class);
    if (result.version != 1 && result.version != 2 && result.version != 3 && result.version != 4 && result.version != VERSION)
      throw new IllegalStateException("Unsupported analysis ownership version");
    // Upgrade only the envelope. Missing function versions remain zero (legacy), and
    // their incomplete stamps are never recomputed against the current Program.
    result.version = VERSION;
    return result;
  }

  public static boolean isRetiredSoftwareCallView(Program p, Address address) {
    var block = p.getMemory().getBlock(address);
    return block != null && block.getName().startsWith(SoftwareCallExecutionView.PREFIX) && !block.isExecute();
  }

  /** Ownership consistency only; the independent raw returning witness is checked separately. */
  static boolean returningMarkerCurrent(Program p, Address address) {
    try {
      if (!p.getOptions(ProgramMapping.OPTIONS).contains(KEY)) return false;
      var group = registry(p).groups.get("software-call");
      if (group == null) return false;
      var function = p.getFunctionManager().getFunctionAt(address);
      if (function == null || function.isThunk() || function.isInline() || function.hasNoReturn()
          || !SoftwareCallMayReturnInjection.NAME.equals(function.getCallFixup())) return false;
      return group.helpers.stream().anyMatch(receipt -> receipt.id == function.getID()
          && Objects.equals(receipt.address.resolve(p), address)
          && SoftwareCallMayReturnInjection.NAME.equals(receipt.appliedFixup));
    } catch (Exception failure) { return false; }
  }

  static boolean sourceRedirectCurrent(Program p, Function source) {
    try {
      var group = registry(p).groups.get("software-call");
      if (group == null) return false;
      return group.redirects.stream().anyMatch(r -> r.id == source.getID() && source.isThunk()
          && Objects.equals(r.source.resolve(p), source.getEntryPoint())
          && Objects.equals(r.target.resolve(p), source.getThunkedFunction(false).getEntryPoint())
          && r.appliedStamp != null && r.appliedStamp.equals(functionStamp(source, true)));
    } catch (Exception e) { return false; }
  }

  static boolean stateEntryCurrent(Program p, Address entry) {
    try {
      var group = registry(p).groups.get("software-call");
      var function = p.getFunctionManager().getFunctionAt(entry);
      if (SoftwareCallRegistry.stockCarrier(p, entry)) StockEntryInjection.validate(p, entry);
      return group != null && function != null && (SoftwareCallRegistry.stock(p)
          ? (SoftwareCallRegistry.stockCarrier(p, entry) ? StockEntryInjection.CONVENTION.equals(function.getCallingConventionName()) : !StockEntryInjection.CONVENTION.equals(function.getCallingConventionName()))
          : SoftwareCallStateEntryInjection.CONVENTION.equals(function.getCallingConventionName()))
          && group.stateEntries.stream().anyMatch(receipt -> receipt.id == function.getID()
              && Objects.equals(receipt.address.resolve(p), entry) && receipt.appliedMetadata != null
              && receipt.appliedMetadata.equals(helperMetadataStamp(function)));
    } catch (Exception failure) { return false; }
  }

  static void selectStateEntryComment(Program p, Address entry, String detail) {
    if (!stateEntryCurrent(p, entry)) throw new IllegalArgumentException("State entry metadata changed before context selection");
    var registry = registry(p); var group = registry.groups.get("software-call");
    var function = p.getFunctionManager().getFunctionAt(entry);
    for (int index = 0; index < group.stateEntries.size(); index++) {
      var old = group.stateEntries.get(index);
      if (!Objects.equals(old.address.resolve(p), entry)) continue;
      String applied = stateEntryComment(old.originalComment, detail);
      function.setComment(applied);
      group.stateEntries.set(index, new StateEntry(old.address, old.id, old.originalConvention,
          old.originalComment, applied, old.originalNoReturn, old.appliedNoReturn, helperMetadataStamp(function), old.appliedConvention()));
      for (int helperIndex = 0; helperIndex < group.helpers.size(); helperIndex++) {
        var helper = group.helpers.get(helperIndex);
        if (helper.id == function.getID()) group.helpers.set(helperIndex, new Helper(helper.address, helper.id,
            helper.originalNoReturn, helper.originalFixup, helper.appliedFixup, helper.originalThunk, helperMetadataStamp(function)));
      }
      p.getOptions(ProgramMapping.OPTIONS).setString(KEY, ProgramMapping.JSON.toJson(registry));
      return;
    }
    throw new IllegalArgumentException("Missing state entry receipt");
  }

  static String stateEntryComment(String original, String detail) {
    return (original == null ? "" : original + "\n\n") + "GhidraBoy conditional execution context. "
        + "This decompilation applies only to the following reviewed state; other entry states remain unproved. "
        + "Use GhidraBoy Tools software-call-contexts / software-call-select-context to inspect all contexts.\n" + detail;
  }

  static boolean softwareCallViewsCurrent(Program p) throws Exception {
    var group = registry(p).groups.get("software-call");
    if (group == null) return false;
    for (var view : group.views)
      if (view.stamp == null || !view.stamp.equals(viewStamp(p, view.name, TaskMonitor.DUMMY))) return false;
    return true;
  }

  /** Live receipt consistency is a veto, never evidence establishing the convention itself. */
  public static boolean softwareCallCurrent(Program p, Address address) {
    try {
      var group = registry(p).groups.get("software-call");
      if (group == null) return false;
      var receipt = group.repairs.stream().filter(r -> Objects.equals(address, r.address.resolve(p))).findFirst().orElse(null);
      if (receipt == null) return false;
      var ins = p.getListing().getInstructionAt(address);
      if (ins == null || !HexFormat.of().formatHex(ins.getBytes()).equals(receipt.bytes)
          || !ins.getFlowOverride().toString().equals(receipt.appliedFlow)
          || ins.isFallThroughOverridden() != receipt.appliedFallthrough
          || !Objects.equals(ins.getFallThrough(), receipt.appliedNext == null ? null : receipt.appliedNext.resolve(p))) return false;
      var refs = group.siteReferences.stream().filter(r -> Objects.equals(address, r.address.resolve(p))).findFirst().orElse(null);
      if (refs == null || !Objects.equals(refs.stamp, referenceStamp(p, address))) return false;
      if (address.getAddressSpace().getName().startsWith(SoftwareCallExecutionView.PREFIX)) {
        var view = group.views.stream().filter(v -> v.name.equals(address.getAddressSpace().getName())).findFirst().orElse(null);
        if (view == null || view.stamp == null || !view.stamp.equals(viewStamp(p, view.name, TaskMonitor.DUMMY))) return false;
      }
      for (var helper : group.helpers) {
        var f = p.getFunctionManager().getFunctionAt(helper.address.resolve(p));
        if (f == null || f.getID() != helper.id || f.isThunk() || f.hasNoReturn()
            || !Objects.equals(f.getCallFixup(), helper.appliedFixup)) return false;
      }
      return true;
    } catch (Exception e) { return false; }
  }

  public static void save(Program p, String feature, Group group) {
    SoftwareCallRegistry.requireSupportedRecords(p);
    var registry = registry(p);
    registry.groups.put(feature, group);
    p.getOptions(ProgramMapping.OPTIONS).setString(KEY, ProgramMapping.JSON.toJson(registry));
  }

  public static List<String> remove(Program p, String feature, TaskMonitor monitor)
      throws Exception {
    SoftwareCallRegistry.requireSupportedRecords(p);
    int tx = p.startTransaction("Remove owned " + feature);
    boolean success = false;
    var diagnostics = new ArrayList<String>();
    try {
      var registry = registry(p);
      var group = registry.groups.remove(feature);
      if (group != null) undo(p, group, monitor, diagnostics);
      if (feature.equals("software-call")) SoftwareCallRegistry.remove(p);
      if (feature.equals("far-call"))
        p.getOptions(ProgramMapping.OPTIONS).removeOption("farCallConvention");
      p.getOptions(ProgramMapping.OPTIONS).setString(KEY, ProgramMapping.JSON.toJson(registry));
      monitor.checkCancelled();
      success = true;
    } finally {
      p.endTransaction(tx, success);
    }
    return List.copyOf(diagnostics);
  }

  public static List<String> removeAll(Program p, TaskMonitor monitor) throws Exception {
    SoftwareCallRegistry.requireSupportedRecords(p);
    int tx = p.startTransaction("Remove GhidraBoy analysis additions");
    boolean success = false;
    var diagnostics = new ArrayList<String>();
    try {
      for (String feature : List.copyOf(registry(p).groups.keySet()))
        diagnostics.addAll(remove(p, feature, monitor));
      p.getOptions(ProgramMapping.OPTIONS).removeOption("analysis.latest");
      monitor.checkCancelled();
      success = true;
    } finally {
      p.endTransaction(tx, success);
    }
    return List.copyOf(diagnostics);
  }

  private static void undo(Program p, Group group, TaskMonitor monitor, List<String> diagnostics)
      throws Exception {
    var removableViews = new ArrayList<String>();
    for (var view : group.views) {
      if (view.stamp != null && view.stamp.equals(viewStamp(p, view.name, monitor))) removableViews.add(view.name);
      else diagnostics.add("Preserved edited or uncertain execution view " + view.name);
    }
    var unchangedHelperMetadata = new HashSet<Long>();
    for (var receipt : group.helpers) {
      var entry = receipt.address.resolve(p);
      var function = entry == null ? null : p.getFunctionManager().getFunctionAt(entry);
      if (function != null && function.getID() == receipt.id && receipt.appliedMetadata != null
          && receipt.appliedMetadata.equals(helperMetadataStamp(function))) unchangedHelperMetadata.add(receipt.id);
    }
    for (var receipt : group.stateEntries) {
      var function = p.getFunctionManager().getFunctionAt(receipt.address.resolve(p));
      if (function != null && function.getID() == receipt.id
          && Objects.equals(receipt.appliedConvention(), function.getCallingConventionName())
          && receipt.appliedMetadata != null)
        function.setCallingConvention(receipt.originalConvention);
      else diagnostics.add("Preserved edited state-entry convention at " + receipt.address.resolve(p));
      if (function != null && function.getID() == receipt.id && receipt.appliedNoReturn != null
          && receipt.originalNoReturn != null && function.hasNoReturn() == receipt.appliedNoReturn)
        function.setNoReturn(receipt.originalNoReturn);
      if (function != null && function.getID() == receipt.id && Objects.equals(function.getComment(), receipt.appliedComment))
        function.setComment(receipt.originalComment);
    }
    for (var redirect : group.redirects) {
      var source = p.getFunctionManager().getFunctionAt(redirect.source.resolve(p));
      if (source != null && source.getID() == redirect.id && source.isThunk()
          && Objects.equals(source.getThunkedFunction(false).getEntryPoint(), redirect.target.resolve(p))
          && redirect.appliedStamp != null)
        source.setThunkedFunction(null);
      else diagnostics.add("Preserved edited source redirect at " + redirect.source.resolve(p));
    }
    for (var receipt : group.repairs) {
      monitor.checkCancelled();
      var at = receipt.address.resolve(p);
      var ins = at == null ? null : p.getListing().getInstructionAt(at);
      if (ins != null && HexFormat.of().formatHex(ins.getBytes()).equals(receipt.bytes)
          && ins.getFlowOverride().toString().equals(receipt.appliedFlow)
          && ins.isFallThroughOverridden() == receipt.appliedFallthrough
          && Objects.equals(ins.getFallThrough(), receipt.appliedNext == null ? null : receipt.appliedNext.resolve(p))) {
        ins.setFlowOverride(ghidra.program.model.listing.FlowOverride.valueOf(receipt.originalFlow));
        if (receipt.originalFallthrough)
          ins.setFallThrough(receipt.originalNext == null ? null : receipt.originalNext.resolve(p));
        else ins.clearFallThroughOverride();
      } else diagnostics.add("Preserved edited repair at " + at);
    }
    for (var receipt : group.helpers) {
      monitor.checkCancelled();
      var at = receipt.address.resolve(p);
      var f = at == null ? null : p.getFunctionManager().getFunctionAt(at);
      if (f != null && f.getID() == receipt.id && !f.isThunk()
          && Objects.equals(f.getCallFixup(), receipt.appliedFixup)) {
        // Clear an unchanged tool fixup even if another field was edited. Leaving a neutral
        // marker after registry removal would strand ordinary calls behind a missing proof.
        f.setCallFixup(receipt.originalFixup);
        if (unchangedHelperMetadata.contains(receipt.id)) {
          f.setNoReturn(receipt.originalNoReturn);
          if (receipt.originalThunk != null) {
            var target = p.getFunctionManager().getFunctionAt(receipt.originalThunk.resolve(p));
            if (target != null) f.setThunkedFunction(target);
            else diagnostics.add("Original thunk target absent at " + at);
          }
        } else diagnostics.add("Preserved edited or legacy helper semantic metadata at " + at);
      } else diagnostics.add("Preserved edited helper at " + at);
    }
    for (var receipt : group.payloads) {
      monitor.checkCancelled();
      var at = receipt.address.resolve(p);
      var data = at == null ? null : p.getListing().getDefinedDataAt(at);
      if (data != null && receipt.stamp != null && Objects.equals(receipt.stamp, payloadStamp(p, data)))
        p.getListing().clearCodeUnits(data.getMinAddress(), data.getMaxAddress(), false);
      else diagnostics.add("Preserved edited payload at " + at);
    }
    List<Body> bodyReceipts;
    try { bodyReceipts = mergedBodies(group.bodies); }
    catch (IllegalArgumentException failure) {
      bodyReceipts = List.of(); diagnostics.add("Preserved inconsistent historical body repair chain");
    }
    for (var receipt : bodyReceipts) {
      monitor.checkCancelled();
      var f = p.getFunctionManager().getFunctionAt(receipt.entry.resolve(p));
      if (f != null && f.getID() == receipt.id && bodyRanges(f.getBody()).equals(receipt.applied)) {
        var original = new ghidra.program.model.address.AddressSet();
        for (var range : receipt.original) original.add(range.min.resolve(p), range.max.resolve(p));
        try { f.setBody(original); }
        catch (Exception e) {
          diagnostics.add("Preserved body with new overlap at " + receipt.entry.resolve(p));
        }
      } else diagnostics.add("Preserved edited body at " + receipt.entry.resolve(p));
    }
    for (var receipt : group.references) {
      monitor.checkCancelled();
      if (receipt.primary == null) {
        diagnostics.add("Preserved legacy reference: receipt lacks primary-status edit evidence");
        continue;
      }
      var from = receipt.from.resolve(p);
      var to = receipt.to.resolve(p);
      if (from == null || to == null) continue;
      for (var ref : p.getReferenceManager().getReferencesFrom(from))
        if (ref.getToAddress().equals(to)
            && ref.getOperandIndex() == receipt.operand
            && ref.getSource() == SourceType.ANALYSIS
            && ref.getReferenceType().toString().equals(receipt.type)
            && ref.getSymbolID() == receipt.symbol
            && ref.isPrimary() == receipt.primary) p.getReferenceManager().delete(ref);
    }
    for (var receipt : group.primaries) {
      monitor.checkCancelled();
      for (var ref : p.getReferenceManager().getReferencesFrom(receipt.from.resolve(p))) {
        if (ref.getToAddress().equals(receipt.to.resolve(p)) && ref.getOperandIndex() == receipt.operand
            && ref.getReferenceType().toString().equals(receipt.type)
            && ref.getSource().toString().equals(receipt.source) && ref.isPrimary() == receipt.applied) {
          boolean competing = Arrays.stream(p.getReferenceManager().getReferencesFrom(ref.getFromAddress()))
              .anyMatch(other -> other != ref && other.isPrimary() && other.getReferenceType().isCall());
          if (receipt.original && competing) diagnostics.add("Preserved later primary reference at " + ref.getFromAddress());
          else p.getReferenceManager().setPrimary(ref, receipt.original);
        }
      }
    }
    for (var receipt : group.bookmarks) {
      monitor.checkCancelled();
      var b = p.getBookmarkManager().getBookmark(receipt.id);
      if (b != null
          && Objects.equals(b.getAddress(), receipt.address.resolve(p))
          && b.getTypeString().equals(receipt.type)
          && b.getCategory().equals(receipt.category)
          && b.getComment().equals(receipt.comment)) p.getBookmarkManager().removeBookmark(b);
      else diagnostics.add("Preserved edited or removed bookmark " + receipt.id);
    }
    for (var receipt : group.functions) {
      monitor.checkCancelled();
      var entry = receipt.entry.resolve(p);
      var f = entry == null ? null : p.getFunctionManager().getFunctionAt(entry);
      if (receipt.version != FUNCTION_VERSION) {
        diagnostics.add(
            "Preserved legacy function "
                + receipt.id
                + ": receipt lacks edit evidence; destructive ownership relinquished");
        continue;
      }
      String current = f == null ? null : functionStamp(f);
      if (f != null
          && f.getSymbol().getID() == receipt.id
          && f.getSymbol().getSource().toString().equals(receipt.source)
          && receipt.stamp != null
          && current != null
          && current.equals(receipt.stamp)) p.getFunctionManager().removeFunction(entry);
      else
        diagnostics.add(
            "Preserved edited, uncertain or removed function "
                + receipt.id
                + ": destructive ownership relinquished");
    }
    for (var receipt : group.flows) {
      monitor.checkCancelled();
      var at = receipt.address.resolve(p);
      var ins = at == null ? null : p.getListing().getInstructionAt(at);
      if (ins != null
          && ins.isFallThroughOverridden()
          && Objects.equals(ins.getFallThrough(), receipt.applied.resolve(p))
          && ins.getFlowOverride().toString().equals(receipt.flowOverride)
          && HexFormat.of().formatHex(ins.getBytes()).equals(receipt.bytes)) {
        if (receipt.originalOverridden)
          ins.setFallThrough(receipt.original == null ? null : receipt.original.resolve(p));
        else ins.clearFallThroughOverride();
      } else diagnostics.add("Preserved edited or removed flow at " + at);
    }
    for (String name : removableViews) {
      boolean retainedFunction = false;
      for (var f : p.getFunctionManager().getFunctions(true))
        if (f.getEntryPoint().getAddressSpace().getName().equals(name)
            || (f.isThunk() && f.getThunkedFunction(false).getEntryPoint().getAddressSpace().getName().equals(name)))
          retainedFunction = true;
      if (retainedFunction) {
        diagnostics.add("Preserved execution view referenced by retained function " + name);
        continue;
      }
      for (var block : p.getMemory().getBlocks()) {
        monitor.checkCancelled();
        if (block.getStart().getAddressSpace().getName().equals(name)) {
          // Queued ordinary analysis may still hold addresses in this space. Retain the
          // real shared-byte mapping; retiring its owned listing avoids deleting a live
          // address-space identity or canceling unrelated queued analysis.
          p.getListing().clearCodeUnits(block.getStart(), block.getEnd(), false);
          block.setExecute(false);
          block.setComment("software-call-retired-view-1; retained shared mapping for saved address and analysis-queue identity");
        }
      }
      diagnostics.add("Retired execution view; shared mapping retained " + name);
    }
  }

  static String referenceStamp(Program p, Address address) {
    var fields = new ArrayList<String>();
    for (var ref : p.getReferenceManager().getReferencesFrom(address))
      if (InstructionInterpretation.relevant(ref)) fields.add(ref.getToAddress() + ":" + ref.getOperandIndex() + ":" + ref.getReferenceType()
          + ":" + ref.getSource() + ":" + ref.isPrimary() + ":" + ref.getSymbolID());
    Collections.sort(fields);
    return Sha256.of(ProgramMapping.JSON.toJson(fields).getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString();
  }

  /** Semantic annotation snapshot for field restoration, including non-default signatures. */
  static String helperMetadataStamp(Function function) {
    try {
      var fields = new ArrayList<Object>();
      fields.add("software-call-helper-metadata-1");
      fields.add(function.getID()); fields.add(Point.of(function.getEntryPoint()));
      fields.add(function.getName(true)); fields.add(function.getSymbol().getSource().toString());
      fields.add(function.getSymbol().isPinned());
      fields.add(function.getProgram().getSymbolTable().isExternalEntryPoint(function.getEntryPoint()));
      fields.add(bodyRanges(function.getBody()));
      fields.add(function.getCallingConventionName()); fields.add(function.getSignatureSource().toString());
      fields.add(function.hasCustomVariableStorage()); fields.add(function.hasVarArgs());
      fields.add(function.isInline()); fields.add(function.hasNoReturn()); fields.add(function.getCallFixup());
      fields.add(function.isExternal()); fields.add(function.isThunk());
      fields.add(function.isThunk() ? Point.of(function.getThunkedFunction(false).getEntryPoint()) : null);
      var thunks = function.getFunctionThunkAddresses();
      fields.add(thunks == null ? null : Arrays.stream(thunks).map(Address::toString).sorted().toList());
      fields.add(function.getComment()); fields.add(function.getRepeatableComment());
      fields.add(function.getStackPurgeSize());
      var stack = function.getStackFrame();
      fields.add(stack.getLocalSize()); fields.add(stack.getReturnAddressOffset());
      fields.add(stack.getParameterOffset()); fields.add(stack.getParameterSize()); fields.add(stack.growsNegative());
      var tags = new ArrayList<String>();
      for (var tag : function.getTags()) tags.add(ProgramMapping.JSON.toJson(Arrays.asList(tag.getName(), tag.getComment())));
      Collections.sort(tags); fields.add(tags);
      var variables = new ArrayList<ghidra.program.model.listing.Variable>();
      variables.add(function.getReturn()); variables.addAll(Arrays.asList(function.getParameters()));
      variables.addAll(Arrays.asList(function.getLocalVariables()));
      var descriptions = new ArrayList<String>();
      for (int index = 0; index < variables.size(); index++) {
        var variable = variables.get(index);
        String role = index == 0 ? "return" : index <= function.getParameterCount() ? "parameter:" + (index - 1) : "local";
        var storage = variable.getVariableStorage();
        descriptions.add(ProgramMapping.JSON.toJson(Arrays.asList(role, variable.getName(), variable.getSource().toString(),
            variable.getFirstUseOffset(), variable.getComment(), SoftwareCallRegistry.nativeTypeIdentity(variable.getDataType()),
            storage.getSerializationString(), storage.isForcedIndirect(), storage.isAutoStorage(), storage.getAutoParameterType())));
      }
      Collections.sort(descriptions); fields.add(descriptions);
      fields.add(function.getParameterCount());
      var children = new ArrayList<String>();
      var symbols = function.getProgram().getSymbolTable().getSymbols(function);
      while (symbols.hasNext()) {
        var symbol = symbols.next();
        children.add(ProgramMapping.JSON.toJson(Arrays.asList(symbol.getID(), symbol.getName(true),
            symbol.getAddress().toString(), symbol.getSource().toString(), symbol.getSymbolType().toString(), symbol.isPinned())));
      }
      Collections.sort(children); fields.add(children);
      return Sha256.of(ProgramMapping.JSON.toJson(fields).getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString();
    } catch (Exception uncertain) { return null; }
  }

  static String viewStamp(Program p, String name, TaskMonitor monitor) throws Exception {
    if (!name.startsWith(SoftwareCallExecutionView.PREFIX)) return null;
    var fields = new ArrayList<String>();
    fields.add("software-call-view-3");
    boolean exists = false;
    for (var block : p.getMemory().getBlocks()) {
      if (!block.getStart().getAddressSpace().getName().equals(name)) continue;
      monitor.checkCancelled();
      exists = true;
      fields.add(block.getStart() + ":" + block.getSize() + ":" + block.getName() + ":" + block.getComment() + ":" + block.getFlags());
      for (var source : block.getSourceInfos()) fields.add(source.getMappedRange().toString());
      byte[] bytes = new byte[(int) block.getSize()];
      if (p.getMemory().getBytes(block.getStart(), bytes) != bytes.length) return null;
      fields.add(Sha256.of(bytes).toString());
    }
    if (!exists) return null;
    for (var ins : p.getListing().getInstructions(true)) {
      if (!ins.getAddress().getAddressSpace().getName().equals(name)) continue;
      monitor.checkCancelled();
      fields.add(ins.getAddress() + ":" + ins.getLength() + ":" + ins.isLengthOverridden()
          + ":" + Arrays.toString(ins.getPcode(false)) + ":" + ins.getFlowOverride()
          + ":" + ins.isFallThroughOverridden() + ":" + ins.getFallThrough());
      for (var type : ghidra.program.model.listing.CommentType.values())
        fields.add(ins.getAddress() + ":" + type + ":" + ins.getComment(type));
    }
    for (var data : p.getListing().getDefinedData(true)) {
      if (!data.getAddress().getAddressSpace().getName().equals(name)) continue;
      if (data.getDataType().getClass() != ghidra.program.model.data.ByteDataType.class) return null;
      fields.add("data:" + data.getAddress() + ":" + data.getLength());
      for (String setting : data.getNames()) fields.add(data.getAddress() + ":" + setting + ":" + data.getValue(setting));
      for (var type : ghidra.program.model.listing.CommentType.values())
        fields.add(data.getAddress() + ":" + type + ":" + data.getComment(type));
    }
    for (var f : p.getFunctionManager().getFunctions(true)) {
      if (!f.getEntryPoint().getAddressSpace().getName().equals(name)) continue;
      String stamp = functionStamp(f, true);
      if (stamp == null) return null;
      fields.add(stamp);
    }
    for (var symbol : p.getSymbolTable().getAllSymbols(true)) {
      if (!symbol.getAddress().getAddressSpace().getName().equals(name) || symbol.isDynamic()) continue;
      fields.add("symbol:" + symbol.getID() + ":" + symbol.getAddress() + ":" + symbol.getName(true)
          + ":" + symbol.getSource() + ":" + symbol.isPinned());
    }
    var sources = p.getReferenceManager().getReferenceSourceIterator(p.getMemory(), true);
    while (sources.hasNext()) {
      monitor.checkCancelled();
      for (var ref : p.getReferenceManager().getReferencesFrom(sources.next())) {
        boolean fromView = ref.getFromAddress().getAddressSpace().getName().equals(name);
        boolean toView = ref.getToAddress().getAddressSpace().getName().equals(name);
        if (!fromView && !toView) continue;
        // Ordinary analysis materializes data accesses from unchanged instructions. These
        // generated non-flow references are not user edits or proof for deleting other work.
        if (!InstructionInterpretation.relevant(ref)
            && (ref.getSource() == SourceType.ANALYSIS || decodedDataReference(p, ref))) continue;
        fields.add("ref:" + ref.getFromAddress() + ":" + ref.getToAddress() + ":" + ref.getReferenceType()
            + ":" + ref.getOperandIndex() + ":" + ref.getSource() + ":" + ref.isPrimary() + ":" + ref.getSymbolID());
      }
    }
    var bookmarks = p.getBookmarkManager().getBookmarksIterator();
    while (bookmarks.hasNext()) {
      var bookmark = bookmarks.next();
      if (bookmark.getAddress().getAddressSpace().getName().equals(name))
        fields.add("bookmark:" + bookmark.getId() + ":" + bookmark.getAddress() + ":"
            + bookmark.getTypeString() + ":" + bookmark.getCategory() + ":" + bookmark.getComment());
    }
    for (var register : p.getProgramContext().getRegisters())
      for (var range : p.getProgramContext().getRegisterValueAddressRanges(register))
        if (range.getMinAddress().getAddressSpace().getName().equals(name))
          fields.add("context:" + register.getName() + ":" + range + ":"
              + p.getProgramContext().getRegisterValue(register, range.getMinAddress()));
    Collections.sort(fields);
    return Sha256.of(ProgramMapping.JSON.toJson(fields).getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString();
  }

  /** Ordinary analysis may replace an unedited decoder DATA reference with READ/WRITE. */
  private static boolean decodedDataReference(Program p, Reference ref) {
    if (ref.getSource() != SourceType.DEFAULT || ref.getReferenceType() != ghidra.program.model.symbol.RefType.DATA
        || !ref.isPrimary() || ref.getSymbolID() != -1 || ref.getOperandIndex() < 0) return false;
    var instruction = p.getListing().getInstructionAt(ref.getFromAddress());
    if (instruction == null || ref.getOperandIndex() >= instruction.getNumOperands()) return false;
    for (var object : instruction.getOpObjects(ref.getOperandIndex()))
      if (object instanceof Address address && address.equals(ref.getToAddress())) return true;
    // SM83 absolute store operands are rendered as scalars; the bus operation still identifies
    // the decoder's actual data destination. No flow or arbitrary DEFAULT reference is excluded.
    for (var op : instruction.getPcode(false)) {
      if (ref.getOperandIndex() == 0 && CartridgeBus.isDirectWrite(p.getLanguage(), op) && op.getInput(1).isConstant()
          && p.getAddressFactory().getDefaultAddressSpace().getAddress(op.getInput(1).getOffset()).equals(ref.getToAddress())) return true;
    }
    return false;
  }

  private static List<Body> mergedBodies(List<Body> receipts) {
    var result = new LinkedHashMap<Point, Body>();
    for (var receipt : receipts) {
      var previous = result.get(receipt.entry);
      if (previous == null) result.put(receipt.entry, receipt);
      else {
        if (previous.id != receipt.id || !previous.applied.equals(receipt.original))
          throw new IllegalArgumentException("Inconsistent body repair chain");
        result.put(receipt.entry, new Body(receipt.entry, receipt.id, previous.original, receipt.applied));
      }
    }
    return List.copyOf(result.values());
  }

  static List<Range> bodyRanges(ghidra.program.model.address.AddressSetView body) {
    var ranges = new ArrayList<Range>();
    for (var range : body.getAddressRanges()) ranges.add(new Range(Point.of(range.getMinAddress()), Point.of(range.getMaxAddress())));
    return List.copyOf(ranges);
  }

  static String payloadStamp(Program p, ghidra.program.model.listing.Data data) throws Exception {
    // Only an unadorned built-in byte is ever destructively owned. Type/settings/comments,
    // bytes and newly attached references/symbols all relinquish ownership on later edits.
    if (data.getDataType().getClass() != ghidra.program.model.data.ByteDataType.class
        || data.getLength() != 1 || data.getNames().length != 0
        || p.getSymbolTable().getSymbols(data.getAddress()).length != 0
        || p.getReferenceManager().getReferencesTo(data.getAddress()).hasNext()
        || p.getReferenceManager().getReferencesFrom(data.getAddress()).length != 0
        || p.getFunctionManager().getFunctionContaining(data.getAddress()) != null) return null;
    for (var type : ghidra.program.model.listing.CommentType.values())
      if (data.getComment(type) != null) return null;
    return HexFormat.of().formatHex(data.getBytes());
  }

  /**
   * Destructive ownership is deliberately limited to bare functions. Variables, non-default types
   * (including pointers/typedefs to mutable types), tags and namespace children cannot be certified
   * here. Retain them even when present at receipt creation. In particular, a data type's
   * path/size/timestamp is not proof that its definition is unchanged in place. Null means
   * uncertain, never an equality token. This policy survives save/reopen without event listeners
   * and does not rely on the function symbol's source to detect user edits.
   */
  static String functionStamp(Function f) { return functionStamp(f, false); }

  static String functionStamp(Function f, boolean permitThunk) {
    if (f.getLocalVariables().length != 0
        || f.getParameterCount() != 0
        || !f.getTags().isEmpty()
        || (f.isThunk() && !permitThunk)
        || f.isExternal()
        || f.getProgram().getSymbolTable().getSymbols(f).hasNext()) return null;
    var thunks = f.getFunctionThunkAddresses();
    if (!permitThunk && thunks != null && thunks.length != 0) return null;
    var type = f.getReturnType();
    // Only the immutable, built-in default undefined return is eligible. Everything
    // else is retained, even if it happens to render the same path as that built-in.
    if (type.getClass() != ghidra.program.model.data.DefaultDataType.class
        || type.getDefaultSettings().getNames().length != 0) return null;

    var fields = new ArrayList<Object>();
    if (permitThunk) {
      fields.add(f.isThunk() ? Point.of(f.getThunkedFunction(false).getEntryPoint()) : null);
      fields.add(thunks == null ? null : Arrays.stream(thunks).map(Point::of).toList());
    }
    fields.add(f.getName(true));
    fields.add(f.getSymbol().isPinned());
    fields.add(f.getProgram().getSymbolTable().isExternalEntryPoint(f.getEntryPoint()));
    for (var ns = f.getParentNamespace(); ns != null; ns = ns.getParentNamespace()) {
      fields.add(ns.getID());
      fields.add(ns.getName());
      if (!ns.isGlobal() && ns.getSymbol() != null)
        fields.add(ns.getSymbol().getSource().toString());
    }
    for (var range : f.getBody().getAddressRanges()) {
      fields.add(Point.of(range.getMinAddress()));
      fields.add(Point.of(range.getMaxAddress()));
    }
    fields.add(f.getCallingConventionName());
    fields.add(f.getSignatureSource().toString());
    fields.add(f.hasCustomVariableStorage());
    fields.add(f.getComment());
    fields.add(f.getRepeatableComment());
    fields.add(f.isInline());
    fields.add(f.hasNoReturn());
    fields.add(f.hasVarArgs());
    fields.add(f.getCallFixup());
    fields.add(f.getStackPurgeSize());
    var frame = f.getStackFrame();
    fields.add(frame.getLocalSize());
    fields.add(frame.getReturnAddressOffset());
    fields.add(frame.getParameterOffset());
    fields.add(frame.getParameterSize());
    fields.add(frame.growsNegative());
    var ret = f.getReturn();
    fields.add(ret.getSource().toString());
    fields.add(ret.getName());
    fields.add(ret.getComment());
    fields.add(ret.getFirstUseOffset());
    fields.add(ret.getFormalDataType().getClass().getName());
    fields.add(ret.isForcedIndirect());
    var storage = ret.getVariableStorage();
    fields.add(storage.getSerializationString());
    fields.add(storage.isForcedIndirect());
    fields.add(storage.isAutoStorage());
    fields.add(storage.getAutoParameterType());
    // JSON preserves field boundaries, nulls and escaping; display delimiters do not.
    return Sha256.of(
            ProgramMapping.JSON.toJson(fields).getBytes(java.nio.charset.StandardCharsets.UTF_8))
        .toString();
  }
}
