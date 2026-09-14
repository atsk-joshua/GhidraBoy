# Public predicate operations

The shipped `GhidraBoyTools` script routes conditional preview, explanation,
physical target/continuation navigation and stock predicate apply/refresh/remove
through runtime scheduling and publication adapters. The stock native consumer
remains Ghidra's normal DecompilerProvider and StockEntryInjection. This change
adds no persisted authority version and no native/cache replacement.

## Operation contract and routes

| Script action | Computation / mutation | Completion and consumer |
| --- | --- | --- |
| conditional-call-preview | ConditionalCallSites.preview | Explicit proof file; dependency-bound preview, not committed executable authority |
| stock-predicate-preview | PredicatedCalls.preview | Same preview contract |
| stock-predicate-apply / stock-predicate-install | PredicateOperations.apply → PredicatedCalls.install | Provisional operation, correlated outer outcome, eligible entry navigation |
| stock-predicate-refresh | PredicateOperations.refresh → PredicatedCalls.refresh | Provisional operation; correlated result; ordinary Decompiler Refresh remains a separate action |
| stock-predicate-remove | PredicateOperations.remove → AnalysisOwnership.undo | Correlated removal; edited artifacts and retired carrier spaces preserved |
| conditional-call-explain / target / continuation | PredicateOperations.explain → one ConditionalCallSites.Explanation | After outer outcome, original snapshot and consumer request checked at EDT publication |

Normal standalone script execution uses GhidraScript's `SUSPENDED` analysis mode.
Ghidra schedules the actual script with AutoAnalysisManager and `analyzeChanges=true`.
Explicit script-argument requests capture their consumer generation before waiting
for admission or analysis scheduling. Interactive selection captures it when the
public action is chosen. Heavy work is off the EDT. A cancellable submission gate serializes participating
Tools requests on one Program before their script transaction starts. It does not
exclude other Ghidra writers. Ghidra's analysis worker coordinates analysis; no
permanent ignore flag or suppression of analysis events is introduced.

A foreign transaction is deferred before this public script makes a write. A
caller that owns an enclosing transaction can explicitly use
`try (var owner = PredicateOperations.participate(program)) { ... }` around nested
script execution. This is an agreement by that owner to whole-owner rollback on
participating failure/cancellation, not an independent savepoint. It must not be
used to assert ownership of an unrelated transaction. Such nested execution stays
inline in `ENABLED` mode; it does not wait for an analysis queue or its caller's
commit. The caller is responsible for its enclosing scheduling boundary.

The low-level `PredicatedCalls.install/refresh/remove` APIs retain their existing
caller-managed shared transaction behavior. They do not become standalone
concurrency services. Native readers in `StockEntryInjection`, `StockEntries`,
`SoftwareCallStateEntryInjection` and direct `ConditionalCallSites` consumers keep
the incumbent validated snapshot/currentness contract. Unmigrated Tools actions
include ordinary-entry, software-call, far-call, symbol, analysis, discovery and
export actions. No shared ownership or persisted semantic contract is rewritten.

## Facts that must remain separate

`lastOperation` on a newly created script instance exposes a runtime operation
handle; the normal Script Manager creates one instance per execution. Its initial
receipt is `PENDING_IN_OWNER`, never committed success. `completion()` resolves
without blocking the caller's return. The observer attaches while its admitted
owner remains pending, retains that exact TransactionInfo object and ID, and
rechecks after registration/arming. It never holds the operation monitor while
entering the transaction manager or removing its listener; headless notifications
may be synchronous. A synchronization fence after observing a terminal status
prevents status visibility from being mistaken for the completed database end.
Owned observation resources release before completion callbacks. A transaction-ended callback only triggers
inspection of this retained object; a later transaction's getter cannot certify
it. `NOT_DONE_BUT_ABORTED` remains pending until rollback has finished.

After a committed outcome, the observer checks the expected registration and
surviving semantics at a stable Program revision off the EDT. The actual EDT
publication checks that revision again. Publication also waits nonblockingly for
the host wrapper to finish its state update and cleanup, so that update cannot
overwrite a completed headless navigation. No second registration is substituted
into the previously validated result. Receipts distinguish mutation, database
checkpoint, cancellation, currentness and source revision. Database commit means
changes in the open Program. It does not mean the domain file was saved or passed
immutable reopen. Read operations do not invent a database write.

Before the wrapper's final owner vote, failure/cancellation aborts its owned
subtransaction and therefore the agreed whole containing transaction. A dedicated
wrapper handle stays open through GhidraScript cleanup, covering cancellation after
the successful mutator returned but before the wrapper finishes. After a nested
wrapper returns, its explicit outer owner controls the final commit/cancellation
policy; participation never waits for or ends that owner. A previously
committed user edit is outside that rollback. After commit, cancellation suppresses
presentation and preserves both the committed operation and any later user edit.
No cancellation path calls Undo, performs blind compensation or restores a snapshot.
Explicit user Undo may restore durable valid authority; it cannot revive an older
runtime request.

Every graphical Tools consumer context is local to one tool. Headless requests
sharing one GhidraState share a separate request generation and serialization
point; independent states remain independent. Ghidra Swing.runNow runs inline
headlessly, so headless bookkeeping uses a private consumer monitor and atomic
resource accounting. Headless state selection is rechecked before publication;
without a newer request, an unobserved headless P/Q/P variable change is not a
graphical activation event and requires the caller to cancel its old request. A later request replaces
that consumer's request generation. Actual Program activation events invalidate
outstanding tokens, including P → Q → unchanged P. Other tools are independent.
Switching never compensates a committed operation. Explicitly requested background
work may finish historically, but cannot automatically replace the current UI.
Closing a target or tool cancels its monitor and suppresses publication. A pending
outer owner's observation can be abandoned with an explicit unknown-outcome receipt;
that does not end its transaction or claim rollback. Owned listeners, consumers and
contexts release when work settles. `inventory()` exposes owned runtime registrations
for bounded resource accounting; it is not a heap/RSS leak proof.

## Qualification limits

The public wrapper is exercised through `GhidraScript.execute`, not merely `run()`
or `BackgroundCommand.applyTo()`. Deterministic owner, cancellation and source
controls live in `PublicPredicateOperationsTest`; the original wrapper probe lives
in `PublicTransactionProbeTest`. Existing semantic assertions remain unchanged.
The standalone command scheduler and P/Q/P/normal-window rows require the separately
compiled headed runners. Compiling a runner is not an executed result.

Arbitrary independent threads can join Ghidra's shared transaction without obeying
this protocol. The exercised ad-hoc writer's sentinel survives the successful
shared commit; there is no universal writer-isolation guarantee. Do not use this
route concurrently with uncoordinated mutators that require independent rollback.
The precise executed/unrun disposition belongs to the external task report.

The attended window extension is `GhidraBoyPublicLifecycleWindow`, selected by
`tools/g1/run_window.py --mode conditional --public-lifecycle`. `--compile-only`
prepares an exact command without desktop access. It uses the normal window's
passive capture, event settlement and ordinary Refresh. The separate hidden headed
service probe in `tools/public_operations/` checks request ordering and closure;
it never captures the desktop. Neither is permission to alter desktop privacy
settings. Visible acceptance, first normal-session immutable reopen, broader
caller cohorts, forward compatibility, hardware/schema decisions, package identity
and installation recovery remain separate obligations.
