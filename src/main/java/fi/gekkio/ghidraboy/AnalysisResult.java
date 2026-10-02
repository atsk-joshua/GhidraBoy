package fi.gekkio.ghidraboy;

import java.util.List;
import java.util.Objects;

/** Versioned conclusions: prose is presentation only, never an authorization to mutate. */
public record AnalysisResult(
    int schemaVersion,
    String engineVersion,
    List<String> starts,
    MapperState assumption,
    List<EntryPremise> entryPremises,
    Configuration configuration,
    Completion completion,
    int exploredStates,
    int pendingStates,
    String fingerprint,
    List<BankAnalysis.Finding> findings,
    List<OrdinaryCallProof> ordinaryCallProofs,
    List<String> diagnostics) {
  public static final int SCHEMA_VERSION = 4;
  public static final String ENGINE_VERSION = "20261001-call-stack-liveness-2b-1";

  /** Successful must-proof of an ordinary unconditional CD invocation and its matched return. */
  public record OrdinaryCallProof(
      String source,
      MapperState.Physical sourcePhysical,
      String target,
      MapperState.Physical targetPhysical,
      String continuation,
      MapperState.Physical continuationPhysical) {
    public OrdinaryCallProof {
      Objects.requireNonNull(source);
      Objects.requireNonNull(sourcePhysical);
      Objects.requireNonNull(target);
      Objects.requireNonNull(targetPhysical);
      Objects.requireNonNull(continuation);
      Objects.requireNonNull(continuationPhysical);
    }
  }

  public record EntryPremise(
      String start,
      MapperState.Physical physical,
      MapperKnowledge knowledge,
      String provenance) {}

  public static AnalysisResult read(String json) {
    try {
      var root = com.google.gson.JsonParser.parseString(json);
      if (!root.isJsonObject()) throw new IllegalArgumentException("Not an analysis object");
      var object = root.getAsJsonObject();
      if (!object.has("schemaVersion")
          || !Integer.toString(SCHEMA_VERSION).equals(object.get("schemaVersion").getAsString())
          || !object.has("engineVersion")
          || !ENGINE_VERSION.equals(object.get("engineVersion").getAsString()))
        throw new IllegalArgumentException("Obsolete analysis identity");
      return ProgramMapping.JSON.fromJson(root, AnalysisResult.class);
    } catch (RuntimeException invalid) {
      throw new IllegalArgumentException(
          "Stored analysis is obsolete or invalid; run a new preview", invalid);
    }
  }

  public enum Completion {
    COMPLETE,
    STATE_LIMIT,
    CANCELLED,
    INPUT_CHANGED
  }

  public enum Confidence {
    PROVEN,
    AMBIGUOUS,
    CANDIDATE,
    UNKNOWN
  }

  public record Configuration(int stateLimit, boolean reverseBranches) {
    public static final Configuration DEFAULT = new Configuration(4096, false);

    public Configuration {
      if (stateLimit < 1 || stateLimit > 100000)
        throw new IllegalArgumentException("State limit must be 1..100000");
    }
  }

  public AnalysisResult {
    starts = List.copyOf(starts);
    entryPremises = List.copyOf(entryPremises);
    findings = List.copyOf(findings);
    // Gson invokes this record constructor too: bypassing read() cannot expose old/partial proof.
    ordinaryCallProofs =
        completion == Completion.COMPLETE
                && schemaVersion == SCHEMA_VERSION
                && ENGINE_VERSION.equals(engineVersion)
                && ordinaryCallProofs != null
            ? List.copyOf(ordinaryCallProofs)
            : List.of();
    diagnostics = List.copyOf(diagnostics);
  }

  /** Source compatibility for the preceding result shape; observations cannot infer proofs. */
  public AnalysisResult(
      int schemaVersion,
      String engineVersion,
      List<String> starts,
      MapperState assumption,
      List<EntryPremise> entryPremises,
      Configuration configuration,
      Completion completion,
      int exploredStates,
      int pendingStates,
      String fingerprint,
      List<BankAnalysis.Finding> findings,
      List<String> diagnostics) {
    this(
        schemaVersion,
        engineVersion,
        starts,
        assumption,
        entryPremises,
        configuration,
        completion,
        exploredStates,
        pendingStates,
        fingerprint,
        findings,
        List.of(),
        diagnostics);
  }

  /** Source compatibility for callers constructing the pre-M2 shape in tests/tools. */
  public AnalysisResult(
      int schemaVersion,
      String engineVersion,
      List<String> starts,
      MapperState assumption,
      Configuration configuration,
      Completion completion,
      int exploredStates,
      int pendingStates,
      String fingerprint,
      List<BankAnalysis.Finding> findings,
      List<String> diagnostics) {
    this(
        schemaVersion,
        engineVersion,
        starts,
        assumption,
        List.of(),
        configuration,
        completion,
        exploredStates,
        pendingStates,
        fingerprint,
        findings,
        diagnostics);
  }

  public boolean complete() {
    return completion == Completion.COMPLETE;
  }
}
