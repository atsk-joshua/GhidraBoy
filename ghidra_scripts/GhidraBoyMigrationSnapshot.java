// Capture exact user-reference primacy before the SM83 v1-to-v2 upgrade.
// This script is deliberately self-contained so it runs with the source-compatible old provider.
// @category GhidraBoy Migration

import fi.gekkio.ghidraboy.ProgramMapping;
import fi.gekkio.ghidraboy.Sha256;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class GhidraBoyMigrationSnapshot extends GhidraScript {
  private static ghidra.program.model.listing.Program program;

  private static Map<String, Object> map(Object... fields) {
    var result = new TreeMap<String, Object>();
    for (int index = 0; index < fields.length; index += 2)
      result.put((String) fields[index], fields[index + 1]);
    return result;
  }

  private static Map<String, Object> address(Address address) {
    var space = address.getAddressSpace();
    return map(
        "spaceName", space.getName(),
        "spaceId", space.getSpaceID(),
        "spaceSize", space.getSize(),
        "spaceType", space.getType(),
        "addressableUnitSize", space.getAddressableUnitSize(),
        "overlay", space.isOverlaySpace(),
        "physicalSpaceName", space.getPhysicalSpace().getName(),
        "offsetHex", Long.toUnsignedString(address.getOffset(), 16));
  }

  private static String addressText(Address address) {
    var space = address.getAddressSpace();
    return space.getName()
        + "|" + space.getSpaceID()
        + "|" + space.getSize()
        + "|" + space.getType()
        + "|" + space.getAddressableUnitSize()
        + "|" + space.isOverlaySpace()
        + "|" + space.getPhysicalSpace().getName()
        + "|" + Long.toUnsignedString(address.getOffset(), 16);
  }

  private static String symbol(Reference reference) {
    long id = reference.getSymbolID();
    if (id < 0) return "-";
    var symbol = program.getSymbolTable().getSymbol(id);
    if (symbol == null) throw new IllegalArgumentException("Associated reference symbol is missing");
    return id
        + "|" + symbol.getName(true)
        + "|" + symbol.getSymbolType()
        + "|" + symbol.getSource()
        + "|" + addressText(symbol.getAddress())
        + "|" + symbol.isDynamic()
        + "|" + symbol.isExternal();
  }

  private static String tuple(Reference reference) {
    return addressText(reference.getFromAddress())
        + "\t" + addressText(reference.getToAddress())
        + "\t" + reference.getOperandIndex()
        + "\t" + reference.getReferenceType()
        + "\t" + reference.getSource()
        + "\t" + symbol(reference);
  }

  private static String digest(List<String> rows) {
    return Sha256.of(
            (String.join("\n", rows) + (rows.isEmpty() ? "" : "\n"))
                .getBytes(StandardCharsets.UTF_8))
        .toString();
  }

  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length != 2)
      throw new IllegalArgumentException(
          "Usage: GhidraBoyMigrationSnapshot.java <new-snapshot.json> <target-language-version>");
    if (currentProgram == null) throw new IllegalStateException("A source Program is required");
    int target = Integer.parseInt(args[1]);
    if (target <= currentProgram.getLanguage().getVersion())
      throw new IllegalArgumentException("Target language version must be newer than the source");
    program = currentProgram;
    var unique = new LinkedHashMap<String, Reference>();
    for (var space : currentProgram.getAddressFactory().getAllAddressSpaces()) {
      if (!space.isMemorySpace()) continue;
      var sources =
          currentProgram
              .getReferenceManager()
              .getReferenceSourceIterator(
                  new AddressSet(space.getMinAddress(), space.getMaxAddress()), true);
      while (sources.hasNext()) {
        monitor.checkCancelled();
        var from = sources.next();
        for (var reference : currentProgram.getReferenceManager().getReferencesFrom(from))
          if (reference.getSource() == SourceType.USER_DEFINED
              && unique.putIfAbsent(tuple(reference), reference) != null)
            throw new IllegalArgumentException("Ambiguous duplicate USER_DEFINED reference");
      }
    }
    var ordered = new ArrayList<>(unique.entrySet());
    ordered.sort(Map.Entry.comparingByKey());
    var references = new ArrayList<Object>();
    var tuples = new ArrayList<String>();
    var states = new ArrayList<String>();
    int primary = 0;
    for (var entry : ordered) {
      var reference = entry.getValue();
      tuples.add(entry.getKey());
      states.add(entry.getKey() + "\t" + reference.isPrimary());
      if (reference.isPrimary()) primary++;
      references.add(
          map(
              "from", address(reference.getFromAddress()),
              "to", address(reference.getToAddress()),
              "operand", reference.getOperandIndex(),
              "referenceType", reference.getReferenceType().toString(),
              "sourceType", reference.getSource().toString(),
              "symbol", symbol(reference),
              "primary", reference.isPrimary()));
    }
    var file = currentProgram.getDomainFile();
    var binding =
        map(
            "originalSha256", ProgramMapping.inspect(currentProgram).originalSha256(),
            "executableSha256", currentProgram.getExecutableSHA256(),
            "executableMd5", currentProgram.getExecutableMD5(),
            "programName", currentProgram.getName(),
            "uniqueProgramId", currentProgram.getUniqueProgramID(),
            "domainFileId", file == null ? null : file.getFileID(),
            "domainPath", file == null ? null : file.getPathname(),
            "languageId", currentProgram.getLanguageID().toString(),
            "sourceLanguageVersion", currentProgram.getLanguage().getVersion(),
            "targetLanguageVersion", target,
            "compilerSpecId", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
    var snapshot =
        map(
            "schema", "ghidraboy.user-defined-reference-primacy",
            "schemaVersion", 1,
            "binding", binding,
            "referenceCount", references.size(),
            "primaryReferenceCount", primary,
            "tupleSha256", digest(tuples),
            "stateSha256", digest(states),
            "references", references);
    Files.writeString(
        Path.of(args[0]),
        ProgramMapping.JSON.toJson(snapshot) + "\n",
        StandardOpenOption.CREATE_NEW);
    println(
        "GHIDRABOY_MIGRATION_SNAPSHOT_PASS program="
            + currentProgram.getName()
            + " references="
            + references.size()
            + " primary="
            + primary);
  }
}
