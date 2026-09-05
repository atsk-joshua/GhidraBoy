package fi.gekkio.ghidraboy;

import java.util.List;

/** Versioned conclusions: prose is presentation only, never an authorization to mutate. */
public record AnalysisResult(int schemaVersion, List<String> starts, MapperState assumption,
        Configuration configuration, Completion completion, int exploredStates, int pendingStates,
        String fingerprint, List<BankAnalysis.Finding> findings, List<String> diagnostics) {
    public enum Completion { COMPLETE, STATE_LIMIT, CANCELLED, INPUT_CHANGED }
    public enum Confidence { PROVEN, AMBIGUOUS, CANDIDATE, UNKNOWN }
    public record Configuration(int stateLimit, boolean reverseBranches) {
        public static final Configuration DEFAULT = new Configuration(4096, false);
        public Configuration {
            if (stateLimit < 1 || stateLimit > 100000) throw new IllegalArgumentException("State limit must be 1..100000");
        }
    }
    public AnalysisResult {
        starts = List.copyOf(starts); findings = List.copyOf(findings); diagnostics = List.copyOf(diagnostics);
    }
    public boolean complete() { return completion == Completion.COMPLETE; }
}
