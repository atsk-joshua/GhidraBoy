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
and opens Programs using `DomainFile.getReadOnlyDomainObject`; no preparation,
proof refresh, analyzer, establishment or import runs in that session.

The driver ends its own initial Script Manager transaction before measurement
and rejects any remaining transaction. It observes actual queued Program events,
then stable controller data for at least six seconds (longer than the pinned
provider's five-second maximum debounce), with a bounded 60-second deadline.
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
