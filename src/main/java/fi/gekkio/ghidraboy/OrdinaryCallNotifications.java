package fi.gekkio.ghidraboy;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

/** Session feedback prepared while persistent publication can still roll back. */
final class OrdinaryCallNotifications {
  private OrdinaryCallNotifications() {}

  private record Token(AddressSet sources, String fingerprint, List<OrdinaryCallFlow.Receipt> receipts) {}
  record Prepared(AutoAnalysisManager manager, Token token) {}

  private static final Map<Program, Token> notifications = new WeakHashMap<>();

  static Prepared prepare(Program p, AddressSet changed, TaskMonitor monitor) throws Exception {
    if (changed.isEmpty()) return null;
    var manager = AutoAnalysisManager.getAnalysisManager(p);
    long revision = p.getModificationNumber();
    var snapshot = OrdinaryCallBasis.load(p);
    var token = new Token(new AddressSet(changed), ProgramFingerprint.capture(p, monitor, snapshot),
        snapshot.receipts());
    if (revision != p.getModificationNumber())
      throw new IllegalStateException("Program changed while preparing ordinary CALL notification");
    return new Prepared(manager, token);
  }

  /** No cancellable dependency work is allowed after the owning transaction commits. */
  static void publish(Program p, Prepared prepared) {
    if (prepared == null) return;
    synchronized (notifications) { notifications.put(p, prepared.token); }
    prepared.manager.codeDefined(prepared.token.sources);
  }

  static boolean consume(Program p, AddressSetView set, TaskMonitor monitor) throws Exception {
    Token token;
    synchronized (notifications) { token = notifications.remove(p); }
    if (token == null || set.isEmpty() || !token.sources.contains(set)) return false;
    var basis = OrdinaryCallBasis.current(p, monitor);
    if (!token.receipts.equals(basis.snapshot().receipts())
        || !token.fingerprint.equals(basis.fingerprint())) return false;
    for (var source : token.sources.getAddresses(true))
      if (basis.snapshot().exact(p.getListing().getInstructionAt(source)) == null) return false;
    return basis.snapshot().revision() == p.getModificationNumber();
  }

  static void analysisEnded(Program p) {
    synchronized (notifications) { notifications.remove(p); }
  }
}
