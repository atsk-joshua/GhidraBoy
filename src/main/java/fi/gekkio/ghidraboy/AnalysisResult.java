package fi.gekkio.ghidraboy;

import java.util.List;

/** Versioned conclusions: prose is presentation only, never an authorization to mutate. */
public record AnalysisResult(
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
  public static final String ENGINE_VERSION = "20260905-dev2";

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
    findings = List.copyOf(findings);
    diagnostics = List.copyOf(diagnostics);
  }

  public boolean complete() {
    return completion == Completion.COMPLETE;
  }
}
