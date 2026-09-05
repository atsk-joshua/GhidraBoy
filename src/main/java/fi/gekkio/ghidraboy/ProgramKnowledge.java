package fi.gekkio.ghidraboy;

// Extracted from GhiGBC, copyright Joshua Hansen; MIT (see LICENSES/GhiGBC-MIT.txt).
import com.google.gson.*;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.nio.file.*;
import java.util.*;

/** Read-only authoritative knowledge export. Keeps the existing ghigbc-knowledge-v1 schema. */
public final class ProgramKnowledge {
  private ProgramKnowledge() {}

  public static void export(Program program, Path out, TaskMonitor monitor) throws Exception {
    if (program == null) throw new IllegalStateException("Open a copied Program first");
    var result = new LinkedHashMap<String, Object>();
    result.put("schema", "ghigbc-knowledge-v1");
    result.put("language", program.getLanguageID().toString());
    result.put("compiler", program.getCompilerSpec().getCompilerSpecID().toString());
    result.put("program", program.getDomainFile().getPathname());
    var blocks = new ArrayList<Object>();
    for (var b : program.getMemory().getBlocks()) {
      monitor.checkCancelled();
      var row = new LinkedHashMap<String, Object>();
      row.put("name", b.getName());
      row.put("space", b.getStart().getAddressSpace().getName());
      row.put("start", b.getStart().getOffset());
      row.put("length", b.getSize());
      row.put("comment", b.getComment());
      var sources = new ArrayList<Object>();
      for (var info : b.getSourceInfos()) {
        var source = new LinkedHashMap<String, Object>();
        source.put("start", info.getMinAddress().toString());
        source.put("length", info.getLength());
        source.put("description", info.getDescription());
        if (info.getFileBytes().isPresent()) {
          source.put("file_offset", info.getFileBytesOffset());
          source.put("file_name", info.getFileBytes().get().getFilename());
        }
        sources.add(source);
      }
      row.put("sources", sources);
      blocks.add(row);
    }
    result.put("blocks", blocks);
    var symbols = new ArrayList<Object>();
    var si = program.getSymbolTable().getAllSymbols(true);
    while (si.hasNext()) {
      monitor.checkCancelled();
      var s = si.next();
      symbols.add(
          Map.of(
              "name",
              s.getName(),
              "namespace",
              s.getParentNamespace().getName(true),
              "address",
              s.getAddress().toString(),
              "type",
              s.getSymbolType().toString(),
              "source",
              s.getSource().toString()));
    }
    result.put("symbols", symbols);
    var functions = new ArrayList<Object>();
    var fi = program.getFunctionManager().getFunctions(true);
    while (fi.hasNext()) {
      monitor.checkCancelled();
      var f = fi.next();
      functions.add(
          Map.of(
              "name",
              f.getName(true),
              "entry",
              f.getEntryPoint().toString(),
              "signature",
              f.getSignature().toString()));
    }
    result.put("functions", functions);
    var structures = new ArrayList<Object>();
    var di = program.getDataTypeManager().getAllDataTypes();
    while (di.hasNext()) {
      monitor.checkCancelled();
      var type = di.next();
      if (!(type instanceof Structure structure)) continue;
      var components = new ArrayList<Object>();
      for (var c : structure.getDefinedComponents()) {
        var row = new LinkedHashMap<String, Object>();
        row.put("name", c.getFieldName());
        row.put("offset", c.getOffset());
        row.put("length", c.getLength());
        row.put("type", c.getDataType().getPathName());
        row.put("comment", c.getComment());
        components.add(row);
      }
      structures.add(
          Map.of(
              "name",
              structure.getPathName(),
              "length",
              structure.getLength(),
              "components",
              components));
    }
    result.put("structures", structures);
    var comments = new ArrayList<Object>();
    var units = program.getListing().getCodeUnits(true);
    while (units.hasNext()) {
      monitor.checkCancelled();
      var unit = units.next();
      for (int kind :
          new int[] {
            CodeUnit.EOL_COMMENT,
            CodeUnit.PRE_COMMENT,
            CodeUnit.POST_COMMENT,
            CodeUnit.PLATE_COMMENT,
            CodeUnit.REPEATABLE_COMMENT
          }) {
        String comment = unit.getComment(kind);
        if (comment != null)
          comments.add(
              Map.of("address", unit.getAddress().toString(), "kind", kind, "text", comment));
      }
    }
    result.put("comments", comments);
    monitor.checkCancelled();
    Files.writeString(
        out,
        new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(result),
        StandardOpenOption.CREATE_NEW);
  }
}
