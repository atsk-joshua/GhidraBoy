package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** One immutable receipt index per capture; at most one current basis per Program revision. */
final class OrdinaryCallBasis {
  private OrdinaryCallBasis() {}

  record Snapshot(long revision, List<OrdinaryCallFlow.Receipt> receipts,
      Map<AnalysisOwnership.Point, List<OrdinaryCallFlow.Receipt>> bySource) {
    OrdinaryCallFlow.Receipt exact(Instruction ins) {
      if (ins == null) return null;
      return OrdinaryCallFlow.exact(ins,
          bySource.getOrDefault(AnalysisOwnership.Point.of(ins.getAddress()), List.of()));
    }
  }

  record Basis(Snapshot snapshot, String fingerprint) {}
  private static final Map<Program, Basis> cache = new WeakHashMap<>();

  static Snapshot load(Program p) {
    long revision = p.getModificationNumber();
    var receipts = Collections.unmodifiableList(new ArrayList<>(OrdinaryCallFlow.receipts(p)));
    var index = new HashMap<AnalysisOwnership.Point, List<OrdinaryCallFlow.Receipt>>();
    for (var receipt : receipts)
      if (OrdinaryCallFlow.currentProof(receipt))
        index.computeIfAbsent(receipt.installed().from(), ignored -> new ArrayList<>()).add(receipt);
    index.replaceAll((source, entries) -> List.copyOf(entries));
    if (revision != p.getModificationNumber())
      throw new IllegalStateException("Program changed while indexing ordinary CALL receipts");
    return new Snapshot(revision, receipts, Map.copyOf(index));
  }

  static Snapshot snapshot(Program p) {
    synchronized (cache) {
      var prior = cache.get(p);
      if (prior != null && prior.snapshot.revision == p.getModificationNumber()) return prior.snapshot;
      var snapshot = load(p);
      cache.put(p, new Basis(snapshot, null));
      return snapshot;
    }
  }

  static Basis current(Program p, TaskMonitor monitor) throws Exception {
    monitor.checkCancelled();
    synchronized (cache) {
      var snapshot = snapshot(p);
      var prior = cache.get(p);
      if (prior.fingerprint != null) return prior;
      var fingerprint = ProgramFingerprint.capture(p, monitor, snapshot);
      if (snapshot.revision != p.getModificationNumber())
        throw new IllegalStateException("Program changed while capturing ordinary CALL basis");
      var basis = new Basis(snapshot, fingerprint);
      cache.put(p, basis);
      return basis;
    }
  }

  static void clear(Program p) { synchronized (cache) { cache.remove(p); } }
}
