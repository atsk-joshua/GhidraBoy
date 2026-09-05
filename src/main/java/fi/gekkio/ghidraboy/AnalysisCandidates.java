package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import java.util.*;

/** Aggregates alternatives per p-code access byte, not by prose or display-name delimiters. */
final class AnalysisCandidates {
  enum Access {
    READ,
    WRITE,
    CALL,
    JUMP,
    FLOW,
    LIMIT,
    CANCELLED
  }

  record Site(Address source, Access access, int operation, int operand, int byteIndex) {
    static Site control(Address source, String access) {
      return new Site(source, Access.valueOf(access.toUpperCase(Locale.ROOT)), -1, -1, -1);
    }
  }

  private static final Comparator<Site> ORDER =
      Comparator.comparing(Site::source)
          .thenComparing(Site::access)
          .thenComparingInt(Site::operation)
          .thenComparingInt(Site::operand)
          .thenComparingInt(Site::byteIndex);
  final Map<Site, Set<Address>> targets = new TreeMap<>(ORDER);
  final Map<Site, String> reasons = new TreeMap<>(ORDER);

  List<BankAnalysis.Finding> finish(AnalysisResult.Completion completion) {
    Set<Site> sites = new TreeSet<>(ORDER);
    sites.addAll(targets.keySet());
    sites.addAll(reasons.keySet());
    var findings = new ArrayList<BankAnalysis.Finding>();
    for (var site : sites) {
      var values =
          targets.getOrDefault(site, Set.of()).stream().sorted().map(Address::toString).toList();
      var confidence =
          values.isEmpty()
              ? AnalysisResult.Confidence.UNKNOWN
              : completion != AnalysisResult.Completion.COMPLETE || reasons.containsKey(site)
                  ? AnalysisResult.Confidence.CANDIDATE
                  : values.size() > 1
                      ? AnalysisResult.Confidence.AMBIGUOUS
                      : AnalysisResult.Confidence.PROVEN;
      findings.add(
          new BankAnalysis.Finding(
              site.source.toString(),
              site.access.name().toLowerCase(Locale.ROOT),
              values,
              reasons.getOrDefault(
                  site,
                  values.size() > 1
                      ? "Finite alternative destinations"
                      : "Explicit state, execution context, or constant p-code evidence"),
              confidence,
              site.operation,
              site.operand,
              site.byteIndex));
    }
    return List.copyOf(findings);
  }
}
