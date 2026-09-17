package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Exact pre-upgrade USER_DEFINED reference-primary snapshot and bounded restoration. */
public final class UserReferencePrimacy {
  public static final String SCHEMA = "ghidraboy.user-defined-reference-primacy";
  public static final int VERSION = 1;

  public record Binding(
      String originalSha256,
      String executableSha256,
      String executableMd5,
      String programName,
      long uniqueProgramId,
      String domainFileId,
      String domainPath,
      String languageId,
      int sourceLanguageVersion,
      int targetLanguageVersion,
      String compilerSpecId) {}

  public record AddressIdentity(
      String spaceName,
      int spaceId,
      int spaceSize,
      int spaceType,
      int addressableUnitSize,
      boolean overlay,
      String physicalSpaceName,
      String offsetHex) {}

  public record ReferenceState(
      AddressIdentity from,
      AddressIdentity to,
      int operand,
      String referenceType,
      String sourceType,
      String symbol,
      boolean primary) {}

  public record Snapshot(
      String schema,
      int schemaVersion,
      Binding binding,
      int referenceCount,
      int primaryReferenceCount,
      String tupleSha256,
      String stateSha256,
      List<ReferenceState> references) {
    public Snapshot {
      references = List.copyOf(references);
    }
  }

  public record RestoreResult(int changedPrimaryStates, int referenceCount, int primaryCount) {}

  private record Match(ReferenceState expected, String tuple, Reference actual) {}

  private UserReferencePrimacy() {}

  public static Snapshot capture(Program program, int targetLanguageVersion, TaskMonitor monitor)
      throws Exception {
    if (targetLanguageVersion <= program.getLanguage().getVersion())
      throw new IllegalArgumentException("Target language version must be newer than the source");
    var references = userReferences(program, monitor);
    var states = new ArrayList<ReferenceState>();
    for (var reference : references) {
      monitor.checkCancelled();
      states.add(state(program, reference));
    }
    states.sort(Comparator.comparing(UserReferencePrimacy::tuple));
    int primary = (int) states.stream().filter(ReferenceState::primary).count();
    var file = program.getDomainFile();
    var binding =
        new Binding(
            ProgramMapping.inspect(program).originalSha256(),
            program.getExecutableSHA256(),
            program.getExecutableMD5(),
            program.getName(),
            program.getUniqueProgramID(),
            file == null ? null : file.getFileID(),
            file == null ? null : file.getPathname(),
            program.getLanguageID().toString(),
            program.getLanguage().getVersion(),
            targetLanguageVersion,
            program.getCompilerSpec().getCompilerSpecID().toString());
    return new Snapshot(
        SCHEMA,
        VERSION,
        binding,
        states.size(),
        primary,
        digest(states.stream().map(UserReferencePrimacy::tuple).toList()),
        digest(states.stream().map(UserReferencePrimacy::stateTuple).toList()),
        states);
  }

  public static RestoreResult restore(Program program, Snapshot snapshot, TaskMonitor monitor)
      throws Exception {
    validateSnapshot(snapshot);
    validateBinding(program, snapshot.binding(), true);
    long modification = program.getModificationNumber();
    String allTuplesBefore = allReferenceTupleDigest(program, monitor);
    var matches = preflight(program, snapshot, monitor);
    var changes = matches.stream().filter(match -> match.actual().isPrimary() != match.expected().primary()).toList();
    boolean markerCurrent =
        program.getOptions(ProgramMapping.OPTIONS).contains("migration.referencePrimacy")
            && "PRESERVED"
                .equals(
                    program
                        .getOptions(ProgramMapping.OPTIONS)
                        .getString("migration.referencePrimacy", null));
    if (changes.isEmpty() && markerCurrent) {
      verify(program, snapshot, matches, allTuplesBefore, monitor);
      return new RestoreResult(0, snapshot.referenceCount(), snapshot.primaryReferenceCount());
    }
    if (program.getModificationNumber() != modification)
      throw new IllegalStateException("Program changed after reference-primary preflight");

    int transaction = program.startTransaction("Restore pre-upgrade USER_DEFINED reference primacy");
    boolean commit = false;
    try {
      var ordered = new ArrayList<>(changes);
      ordered.sort(Comparator.comparing(match -> match.expected().primary()));
      for (var match : ordered) {
        monitor.checkCancelled();
        program.getReferenceManager().setPrimary(match.actual(), match.expected().primary());
      }
      verify(program, snapshot, matches, allTuplesBefore, monitor);
      program
          .getOptions(ProgramMapping.OPTIONS)
          .setString("migration.referencePrimacy", "PRESERVED");
      monitor.checkCancelled();
      commit = true;
    } finally {
      program.endTransaction(transaction, commit);
    }
    verify(program, snapshot, matches, allTuplesBefore, monitor);
    return new RestoreResult(
        changes.size(), snapshot.referenceCount(), snapshot.primaryReferenceCount());
  }

  public static void verify(Program program, Snapshot snapshot, TaskMonitor monitor)
      throws Exception {
    validateSnapshot(snapshot);
    validateBinding(program, snapshot.binding(), false);
    String allTuples = allReferenceTupleDigest(program, monitor);
    var matches = preflight(program, snapshot, monitor);
    verify(program, snapshot, matches, allTuples, monitor);
  }

  private static List<Match> preflight(Program program, Snapshot snapshot, TaskMonitor monitor)
      throws Exception {
    var manager = program.getReferenceManager();
    var matches = new ArrayList<Match>();
    var expectedTuples = new TreeMap<String, ReferenceState>();
    for (var expected : snapshot.references()) {
      monitor.checkCancelled();
      String tuple = tuple(expected);
      if (expectedTuples.put(tuple, expected) != null)
        throw new IllegalArgumentException("Snapshot contains an ambiguous duplicate reference");
      Address from = resolve(program, expected.from());
      Address to = resolve(program, expected.to());
      var candidates = new ArrayList<Reference>();
      for (var candidate : manager.getReferencesFrom(from, expected.operand()))
        if (candidate.getToAddress().equals(to)) candidates.add(candidate);
      if (candidates.size() != 1)
        throw new IllegalArgumentException(
            candidates.isEmpty()
                ? "Expected USER_DEFINED reference is missing: " + tuple
                : "Expected USER_DEFINED reference is ambiguous: " + tuple);
      var actual = candidates.get(0);
      if (actual.getSource() != SourceType.USER_DEFINED
          || !actual.getReferenceType().toString().equals(expected.referenceType())
          || !symbol(program, actual).equals(expected.symbol()))
        throw new IllegalArgumentException("Expected USER_DEFINED reference identity changed: " + tuple);
      matches.add(new Match(expected, tuple, actual));
    }
    var currentTuples =
        userReferences(program, monitor).stream()
            .map(reference -> tuple(state(program, reference)))
            .sorted()
            .toList();
    if (!currentTuples.equals(new ArrayList<>(expectedTuples.keySet())))
      throw new IllegalArgumentException("Complete USER_DEFINED reference set differs from snapshot");

    var baselinePrimary = new TreeMap<String, Match>();
    for (var match : matches)
      if (match.expected().primary()
          && baselinePrimary.put(group(match.expected()), match) != null)
        throw new IllegalArgumentException(
            "Snapshot has multiple primary USER_DEFINED references for one operand");
    for (var match : matches) {
      if (match.actual().isPrimary() == match.expected().primary()) continue;
      if (match.expected().primary()) {
        var competing =
            manager.getPrimaryReferenceFrom(
                match.actual().getFromAddress(), match.actual().getOperandIndex());
        if (competing == null || competing.getSource() != SourceType.DEFAULT)
          throw new IllegalArgumentException(
              "Primary drift is not a generated DEFAULT displacement: " + match.tuple());
      } else if (!baselinePrimary.containsKey(group(match.expected()))) {
        throw new IllegalArgumentException(
            "Unexpected non-primary USER_DEFINED drift: " + match.tuple());
      }
    }
    return matches;
  }

  private static void verify(
      Program program,
      Snapshot snapshot,
      List<Match> matches,
      String allTuplesBefore,
      TaskMonitor monitor)
      throws Exception {
    var current = new ArrayList<ReferenceState>();
    for (var reference : userReferences(program, monitor)) current.add(state(program, reference));
    current.sort(Comparator.comparing(UserReferencePrimacy::tuple));
    requireEqual("USER_DEFINED tuple digest", snapshot.tupleSha256(), digest(current.stream().map(UserReferencePrimacy::tuple).toList()));
    requireEqual("USER_DEFINED state digest", snapshot.stateSha256(), digest(current.stream().map(UserReferencePrimacy::stateTuple).toList()));
    requireEqual("USER_DEFINED count", snapshot.referenceCount(), current.size());
    requireEqual(
        "primary USER_DEFINED count",
        (long) snapshot.primaryReferenceCount(),
        current.stream().filter(ReferenceState::primary).count());
    requireEqual("complete reference tuples", allTuplesBefore, allReferenceTupleDigest(program, monitor));
    for (var match : matches) {
      var actual =
          program
              .getReferenceManager()
              .getReference(
                  match.actual().getFromAddress(),
                  match.actual().getToAddress(),
                  match.actual().getOperandIndex());
      if (actual == null
          || !tuple(state(program, actual)).equals(match.tuple())
          || actual.isPrimary() != match.expected().primary())
        throw new IllegalStateException("Reference-primary restoration verification failed");
    }
  }

  private static void validateSnapshot(Snapshot snapshot) {
    requireEqual("schema", SCHEMA, snapshot.schema());
    requireEqual("schema version", VERSION, snapshot.schemaVersion());
    requireEqual("snapshot reference count", snapshot.referenceCount(), snapshot.references().size());
    requireEqual(
        "snapshot tuple digest",
        snapshot.tupleSha256(),
        digest(snapshot.references().stream().map(UserReferencePrimacy::tuple).sorted().toList()));
    requireEqual(
        "snapshot state digest",
        snapshot.stateSha256(),
        digest(snapshot.references().stream().map(UserReferencePrimacy::stateTuple).sorted().toList()));
  }

  private static void validateBinding(Program program, Binding binding, boolean requireDomain)
      throws Exception {
    requireEqual("original input", binding.originalSha256(), ProgramMapping.inspect(program).originalSha256());
    requireEqual("executable SHA-256", binding.executableSha256(), program.getExecutableSHA256());
    requireEqual("executable MD5", binding.executableMd5(), program.getExecutableMD5());
    requireEqual("Program name", binding.programName(), program.getName());
    requireEqual("unique Program ID", binding.uniqueProgramId(), program.getUniqueProgramID());
    var file = program.getDomainFile();
    if (requireDomain) {
      requireEqual("domain file ID", binding.domainFileId(), file == null ? null : file.getFileID());
      requireEqual("domain path", binding.domainPath(), file == null ? null : file.getPathname());
    }
    requireEqual("language ID", binding.languageId(), program.getLanguageID().toString());
    requireEqual("target language version", binding.targetLanguageVersion(), program.getLanguage().getVersion());
    requireEqual("compiler spec", binding.compilerSpecId(), program.getCompilerSpec().getCompilerSpecID().toString());
    if (binding.sourceLanguageVersion() >= binding.targetLanguageVersion())
      throw new IllegalArgumentException("Snapshot does not describe an upgrade");
  }

  private static List<Reference> userReferences(Program program, TaskMonitor monitor)
      throws Exception {
    var unique = new LinkedHashMap<String, Reference>();
    for (var space : program.getAddressFactory().getAllAddressSpaces()) {
      if (!space.isMemorySpace()) continue;
      var iterator =
          program
              .getReferenceManager()
              .getReferenceSourceIterator(
                  new AddressSet(space.getMinAddress(), space.getMaxAddress()), true);
      while (iterator.hasNext()) {
        monitor.checkCancelled();
        var from = iterator.next();
        for (var reference : program.getReferenceManager().getReferencesFrom(from))
          if (reference.getSource() == SourceType.USER_DEFINED) {
            String key = tuple(state(program, reference));
            if (unique.putIfAbsent(key, reference) != null)
              throw new IllegalArgumentException("Ambiguous duplicate USER_DEFINED reference");
          }
      }
    }
    return new ArrayList<>(unique.values());
  }

  private static String allReferenceTupleDigest(Program program, TaskMonitor monitor)
      throws Exception {
    var rows = new ArrayList<String>();
    for (var space : program.getAddressFactory().getAllAddressSpaces()) {
      if (!space.isMemorySpace()) continue;
      var iterator =
          program
              .getReferenceManager()
              .getReferenceSourceIterator(
                  new AddressSet(space.getMinAddress(), space.getMaxAddress()), true);
      while (iterator.hasNext()) {
        monitor.checkCancelled();
        var from = iterator.next();
        for (var reference : program.getReferenceManager().getReferencesFrom(from))
          rows.add(tuple(state(program, reference)));
      }
    }
    rows.sort(String::compareTo);
    return digest(rows);
  }

  private static ReferenceState state(Program program, Reference reference) {
    return new ReferenceState(
        address(reference.getFromAddress()),
        address(reference.getToAddress()),
        reference.getOperandIndex(),
        reference.getReferenceType().toString(),
        reference.getSource().toString(),
        symbol(program, reference),
        reference.isPrimary());
  }

  private static AddressIdentity address(Address address) {
    var space = address.getAddressSpace();
    return new AddressIdentity(
        space.getName(),
        space.getSpaceID(),
        space.getSize(),
        space.getType(),
        space.getAddressableUnitSize(),
        space.isOverlaySpace(),
        space.getPhysicalSpace().getName(),
        Long.toUnsignedString(address.getOffset(), 16));
  }

  private static Address resolve(Program program, AddressIdentity identity) {
    var space = program.getAddressFactory().getAddressSpace(identity.spaceName());
    if (space == null || !spaceIdentity(space).equals(spaceIdentity(identity)))
      throw new IllegalArgumentException("Address-space identity changed: " + identity.spaceName());
    return space.getAddress(Long.parseUnsignedLong(identity.offsetHex(), 16));
  }

  private static String tuple(ReferenceState state) {
    return address(state.from())
        + "\t"
        + address(state.to())
        + "\t"
        + state.operand()
        + "\t"
        + state.referenceType()
        + "\t"
        + state.sourceType()
        + "\t"
        + state.symbol();
  }

  private static String stateTuple(ReferenceState state) {
    return tuple(state) + "\t" + state.primary();
  }

  private static String group(ReferenceState state) {
    return address(state.from()) + "|" + state.operand();
  }

  private static String address(AddressIdentity identity) {
    return spaceIdentity(identity) + "|" + identity.offsetHex().toLowerCase();
  }

  private static String spaceIdentity(AddressSpace space) {
    return space.getName()
        + "|"
        + space.getSpaceID()
        + "|"
        + space.getSize()
        + "|"
        + space.getType()
        + "|"
        + space.getAddressableUnitSize()
        + "|"
        + space.isOverlaySpace()
        + "|"
        + space.getPhysicalSpace().getName();
  }

  private static String spaceIdentity(AddressIdentity identity) {
    return identity.spaceName()
        + "|"
        + identity.spaceId()
        + "|"
        + identity.spaceSize()
        + "|"
        + identity.spaceType()
        + "|"
        + identity.addressableUnitSize()
        + "|"
        + identity.overlay()
        + "|"
        + identity.physicalSpaceName();
  }

  private static String symbol(Program program, Reference reference) {
    long id = reference.getSymbolID();
    if (id < 0) return "-";
    Symbol symbol = program.getSymbolTable().getSymbol(id);
    if (symbol == null) throw new IllegalArgumentException("Associated reference symbol is missing");
    return id
        + "|"
        + symbol.getName(true)
        + "|"
        + symbol.getSymbolType()
        + "|"
        + symbol.getSource()
        + "|"
        + address(address(symbol.getAddress()))
        + "|"
        + symbol.isDynamic()
        + "|"
        + symbol.isExternal();
  }

  private static String digest(List<String> rows) {
    return Sha256.of(
            (String.join("\n", rows) + (rows.isEmpty() ? "" : "\n"))
                .getBytes(StandardCharsets.UTF_8))
        .toString();
  }

  private static void requireEqual(String label, Object expected, Object actual) {
    if (!Objects.equals(expected, actual))
      throw new IllegalArgumentException(
          label + " mismatch: expected=" + expected + " actual=" + actual);
  }
}
