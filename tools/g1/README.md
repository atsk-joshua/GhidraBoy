# Stock normal-window runner

`G1StockBootstrap` adds only the test driver classes after Ghidra constructs its
runtime classpath. `G1StockNormalLaunch` opens the normal Front End and stored
CodeBrowser tool through `ToolServices`; it never constructs a DecompilerProvider,
controller, panel, or DecompInterface. Use the pinned stock Ghidra distribution,
JDK 21, and the exact installed extension under qualification.

`run_window.py` takes explicit runtime, profile, project, evidence, JDK and mode
arguments. It refuses an existing output directory. `full` expects disposable
current-language `/F1234.gb` and `/W4_MEMORY_IMAGE.gb` prepared by the two
`GhidraBoyStock*Prepare.java` scripts. Generate Q with `tools/make_w4_fixtures.py`.
Setup is separate from measurement. `reopen` requires the saved capture directory
and opens Programs using `DomainFile.getImmutableDomainObject`; no preparation,
proof refresh, analyzer, establishment or import runs in that session.

The launcher supplies no script Program, so no hidden Script Manager transaction
is created. The driver owns explicit operation subtransaction IDs, records public
encompassing TransactionInfo snapshots and commit-call entry/return, and closes
only its own entries. A bounded 60-second wait observes ordinary tool transactions
without ending them. Settlement requires the target Program/Function, no active
transaction, stable revision/event count and controller data for six seconds.
Real Program events carry persistent/runtime source identity, per-Program sequence,
types and affected ranges/options. The checker accepts either callback/return-receipt
order when exact operation, completed commit, source and revision evidence agree.
Captures serialize on the Swing thread and include real desktop screenshots.
Process listings are supplemental; they do not independently attribute results.
The displayed provider/controller, actual Program/Function, native resolution,
class origins and serialized lifecycle identify the measured consumer.

Capture completion is not acceptance. `tools/check_stock_window.py --root ...`
checks the initial passive witness and returns PARTIAL on successful safety.
Full checks additionally use `--reopen ...`; even successful capture checks
require separate visible-state and runtime/process/build review.

User-facing proof refresh is available in `GhidraBoyTools.java`: select an owned
stock ordinary entry, choose `stock-ordinary-preview`, save/review its JSON, then
choose `stock-ordinary-refresh` and select that file. The selected entry's domain,
invocation, source, ownership and current preview must validate. Cancellation
before application leaves authority unchanged; the existing transactional refresh
handles cancellation/rollback during application. Finally use the ordinary
Decompiler **Refresh** toolbar action. Explicit script arguments are
`stock-ordinary-preview /absolute/new-preview.json` and
`stock-ordinary-refresh /absolute/reviewed-preview.json`; the current location
must still select the intended owned entry. No implicit proof refresh occurs.

The `readiness` and `initial` modes leave a normal window open for operator
inspection and are not completed acceptance sessions. Only `full` and `reopen`
produce verified tool/process closure markers. Do not call a timeout successful.

## 2026-09-12 disposition

GUI access and P0/P1/P2 passive refusal were executed. The bounded confirming
run executed the two shipped proof actions, then found ordinary Refresh disabled
before the proof-write Program event was delivered. Its P3/Q/switch/reopen phases
were not captured. No G1 or scoped-workflow PASS is claimed.

The maintained runner now drains normal events after the explicit proof action
and before testing the ordinary Refresh action's enablement. This active-phase
ordering is prepared and compilation-checked only; it has not been run. Do not
continue automatically. The task stopped for master review at its retry boundary.

## Continuation result — 2026-09-12

The consolidated driver now records `P-post-proof` before ordinary Refresh and
separates requested/enabled/invoked/dispatch-completed action states. The negative
amendment records `NOT_AVAILABLE_ON_ERROR` without dispatch when Refresh is disabled;
only then may labelled `ACTIVE_NAVIGATION_REFUSAL` navigate away/back in the same
provider. This branch may never rescue P3.

The exact continuation run reached real P3 E4 recovery and Q1 passive refusal,
then stopped at the immediate open-transaction guard during Q2 navigation. The
negative branch and reopen were not reached. The initial checker additionally
rejects the genuine P event arriving just before its commit receipt. Do not call
this a product defect or rerun automatically; see the
[continuation disposition](../../docs/sa/G1-STOCK-NORMAL-WINDOW-CONTINUATION.md).

## Harness completion protocol

`--rehearsal` labels controlled support runs and prevents final checker qualification.
`suffix-rehearsal --rehearsal --saved-captures ...` exercises only the shared negative
and closure suffix of a disposable saved project; it is never a full acceptance run.
A copied Program receives a new ID, so explicit shipped preview/refresh prepares its
own authority before the warm negative. Removing its registration then requires the
stock dispatcher's specific missing-registration/carrier refusal, with no output.
A null ordinary action context is recorded as unavailable, never manufactured or
forced. P3 always requires actual enabled dispatch and a fresh result.

Second-JVM saved-Program reads use the public immutable-open API: Ghidra's API named
read-only still permits in-memory writes. Raw authority snapshots are retained;
comparison checks every parsed JSON value and array order while ignoring only JSON
object-key serialization order. Historical failed receipts remain unchanged.
