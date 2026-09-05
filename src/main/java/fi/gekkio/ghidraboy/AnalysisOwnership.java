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
  private static final int VERSION = 2;

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

  public record Ref(Point from, Point to, int operand, String type, long symbol) {}

  public record Mark(long id, Point address, String type, String category, String comment) {}

  public record Func(long id, Point entry, String source, String stamp, int version) {}

  public record Flow(
      Point address,
      String bytes,
      String flowOverride,
      Point applied,
      boolean originalOverridden,
      Point original) {}

  public static final class Group {
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
              r.getSymbolID()));
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
              VERSION));
    }
  }

  private static final class Registry {
    int version = VERSION;
    Map<String, Group> groups = new TreeMap<>();
  }

  private static Registry registry(Program p) {
    var result =
        ProgramMapping.JSON.fromJson(
            p.getOptions(ProgramMapping.OPTIONS).getString(KEY, "{\"version\":1,\"groups\":{}}"),
            Registry.class);
    if (result.version != 1 && result.version != VERSION)
      throw new IllegalStateException("Unsupported analysis ownership version");
    // Upgrade only the envelope. Missing function versions remain zero (legacy), and
    // their incomplete stamps are never recomputed against the current Program.
    result.version = VERSION;
    return result;
  }

  public static void save(Program p, String feature, Group group) {
    var registry = registry(p);
    registry.groups.put(feature, group);
    p.getOptions(ProgramMapping.OPTIONS).setString(KEY, ProgramMapping.JSON.toJson(registry));
  }

  public static List<String> remove(Program p, String feature, TaskMonitor monitor)
      throws Exception {
    int tx = p.startTransaction("Remove owned " + feature);
    boolean success = false;
    var diagnostics = new ArrayList<String>();
    try {
      var registry = registry(p);
      var group = registry.groups.remove(feature);
      if (group != null) undo(p, group, monitor, diagnostics);
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
    for (var receipt : group.references) {
      monitor.checkCancelled();
      var from = receipt.from.resolve(p);
      var to = receipt.to.resolve(p);
      if (from == null || to == null) continue;
      for (var ref : p.getReferenceManager().getReferencesFrom(from))
        if (ref.getToAddress().equals(to)
            && ref.getOperandIndex() == receipt.operand
            && ref.getSource() == SourceType.ANALYSIS
            && ref.getReferenceType().toString().equals(receipt.type)
            && ref.getSymbolID() == receipt.symbol) p.getReferenceManager().delete(ref);
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
      if (receipt.version != VERSION) {
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
  }

  /**
   * Destructive ownership is deliberately limited to bare functions. Variables, non-default types
   * (including pointers/typedefs to mutable types), tags and namespace children cannot be certified
   * here. Retain them even when present at receipt creation. In particular, a data type's
   * path/size/timestamp is not proof that its definition is unchanged in place. Null means
   * uncertain, never an equality token. This policy survives save/reopen without event listeners
   * and does not rely on the function symbol's source to detect user edits.
   */
  private static String functionStamp(Function f) {
    if (f.getLocalVariables().length != 0
        || f.getParameterCount() != 0
        || !f.getTags().isEmpty()
        || f.isThunk()
        || f.isExternal()
        || f.getProgram().getSymbolTable().getSymbols(f).hasNext()) return null;
    var thunks = f.getFunctionThunkAddresses();
    if (thunks != null && thunks.length != 0) return null;
    var type = f.getReturnType();
    // Only the immutable, built-in default undefined return is eligible. Everything
    // else is retained, even if it happens to render the same path as that built-in.
    if (type.getClass() != ghidra.program.model.data.DefaultDataType.class
        || type.getDefaultSettings().getNames().length != 0) return null;

    var fields = new ArrayList<Object>();
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
