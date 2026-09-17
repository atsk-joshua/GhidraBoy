package fi.gekkio.ghidraboy;

import java.util.List;

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
    List<String> diagnostics) {
  public static final String ENGINE_VERSION = "20260916-m2-native-analysis-2";

  public record EntryPremise(
      String start,
      MapperState.Physical physical,
      MapperKnowledge knowledge,
      String provenance) {}

  public static AnalysisResult read(String json) {
    var root = com.google.gson.JsonParser.parseString(json);
    if (!root.isJsonObject()
        || !root.getAsJsonObject().has("engineVersion")
        || !ENGINE_VERSION.equals(root.getAsJsonObject().get("engineVersion").getAsString()))
      throw new IllegalArgumentException("Stored analysis predates this engine; run a new preview");
    return ProgramMapping.JSON.fromJson(root, AnalysisResult.class);
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
    diagnostics = List.copyOf(diagnostics);
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
