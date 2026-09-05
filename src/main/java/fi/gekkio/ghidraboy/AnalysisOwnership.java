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
  private static final String KEY = "analysis.ownership.v1";

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

  public record Func(long id, Point entry, String source, String stamp) {}

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
              functionStamp(f)));
    }
  }

  private static final class Registry {
    int version = 1;
    Map<String, Group> groups = new TreeMap<>();
  }

  private static Registry registry(Program p) {
    var result =
        ProgramMapping.JSON.fromJson(
            p.getOptions(ProgramMapping.OPTIONS).getString(KEY, "{\"version\":1,\"groups\":{}}"),
            Registry.class);
    if (result.version != 1)
      throw new IllegalStateException("Unsupported analysis ownership version");
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
      if (f != null
          && f.getSymbol().getID() == receipt.id
          && f.getSymbol().getSource().toString().equals(receipt.source)
          && functionStamp(f).equals(receipt.stamp)) p.getFunctionManager().removeFunction(entry);
      else diagnostics.add("Preserved edited or removed function " + receipt.id);
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

  private static String functionStamp(Function f) {
    var text =
        new StringBuilder(f.getName(true))
            .append('|')
            .append(f.getBody())
            .append('|')
            .append(f.getCallingConventionName())
            .append('|')
            .append(f.getSignatureSource())
            .append('|')
            .append(f.hasCustomVariableStorage())
            .append('|')
            .append(f.getComment())
            .append('|')
            .append(f.getRepeatableComment())
            .append('|')
            .append(f.getReturnType().getPathName())
            .append('|')
            .append(f.getReturn().getVariableStorage());
    for (var parameter : f.getParameters())
      text.append('|')
          .append(parameter.getName())
          .append(':')
          .append(parameter.getDataType().getPathName())
          .append(':')
          .append(parameter.getVariableStorage());
    return Sha256.of(text.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString();
  }
}
