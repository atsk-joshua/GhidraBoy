# GhidraBoy integration — active handoff

Start here and in [handoff-state.json](handoff-state.json), then the original
[58-gate register](status.json) and relevant [plan](../debugger-integration-plan.md)
sections. **The non-Deck outcome is not yet qualified.** Physical Steam Deck is
explicitly deferred. No publication or remote archival is authorized.

## Current code and ownership

GhidraBoy code is committed through `1fce58f` on `integrate-ghigbc`:
`d5f3cf3` fixes lifecycle/mapper qualification, `bb0720d` documents dependency
setup, and `1fce58f` fixes asynchronous table readiness in the lifecycle harness.
Later qualification documentation/report generation does not change these
frozen runtime bytes. Source archive and six reproducible package indices are
under `dist/integration-final-1fce58f/`.

GhiGBC cutover is committed at `65e1208` plus JSON-redirect correction `413a971`.
Generic Python/C/Java implementations were replaced with tested thin delegates;
original `c1cfeef` history and verified source bundle, artifacts and rollback inputs
remain. GhiBW3 code/ownership is at `99802e0`, private evidence at `29145f8`: private household GBW3 validation/research/family
support, including three byte-preserved historical game Java harnesses. Their
old GhiGBC paths are relative links. Keep compatibility delegates for at least
two supported release cycles. No unrelated working files were committed.

## Resolved defects and exact evidence

- Original 1518f02 soak hashes were verified and both original bounded budgets
  reassessed PASS. The original mGBA lifecycle genuinely failed with 17 uncaught
  closed-database AWT errors; its marker was never accepted as a clean exit.
- The upstream Ghidra register provider retained closed comparison coordinates.
  The minimal Java repair clears invalid coordinates without hiding registers
  or suppressing exceptions. A shared collector catches real uncaught errors;
  deliberate AWT injection exits 1.
- New explicit dependency: **12.1.3+ghidraboy.register-lifetime.1**. Patched
  Debugger.jar SHA256 `3b75891c6734b23f03c0313cb5fc582a9410676b799c8c1af3e30e3696b10bbf`.
  Copy-only install/verify/rollback and two identical offline builds pass.
  Companion SHA256 `9bf8b95ad0eca51c7ffc78f91943fdf58b3e92a6727dbe12ac6ff18343f970a2`.
  Native decompiler remains **12.1.3+ghidraboy.switch-recovery.2**.
- Mapper expansion found core controller fallback mislabeled as the ROM header.
  The native constructor now rejects mismatches. Mac SameBoy SHA256
  `ba30da5996633003cbcf26ab528aa2f6bee1c774c97f5db194c1ddefd2714f49`;
  Linux `a8fd35157b1edb5325bbf3280946571bc3245930a4a3897af529f630bab1985c`.
  56 ROM geometry/model rows,14 RAM geometries, SVBK/echo/VRAM and real guest
  mode3 bus restriction/write-attempt checks pass.
- Fresh 110-test native suite, 55-row/165-variant pristine matrix, special speed
  pristine comparison, genuine old checkpoint and private decoder parity pass.
  Cross-backend STOP timing remains a classified disagreement with exit2.
  See [hardware reconciliation](final-hardware-resume-notes.md).
- Static source/payload/dependency reuse is explicit:137 inputs / 108 payload
  entries match, preserved 456 tests and 21,000 selected vectors, plus eight fresh
  database/schema/native checks. See [static audit](final-static-resume-notes.md).
- Both real backends now execute five profile scenarios, historical/current
  selection, raw/decoded provenance and provider-free separate-JVM reopen.
  See [shared contract](final-shared-profile-resume-notes.md).

## Recorded final automated checks

All **18 macOS component jobs PASS** on exact 1fce58f packages. All three final
Linux offline/compiler-free compositions PASS, including real failure lifecycle,
profiles/reopen, applicable 250-stop growth and research. Original bb0720d Linux
readiness failures are preserved; the 10 s bounded EDT readiness poll fixes the
harness race while keeping render/closure/error assertions intact. Read
[Mac receipt](../../dist/integration-final-1fce58f/macos/acceptance/receipt.json)
and [Linux receipt](../../dist/integration-final-1fce58f/linux/acceptance/qualification.json).

Both final `1fce58f` soaks completed with independent exit 0, original-budget
PASS and no uncaught JVM errors: SameBoy **109 cycles / 1800.46 s**, plus idle/
descendant cleanup; mGBA **112 cycles / 1801.37 s**. Maximum pauses were 61.08 ms
and 66.68 ms; resource bounds remain unchanged. All recorded soak processes
were absent before controlled timing. See
`dist/integration-final-1fce58f/soak-qualification.json`. Earlier clean bb0720d
soaks and original failed 1518 evidence remain preserved. Do not restart them.

Latency is now **PASS** for both the predeclared controlled 3+3 and the aggregate
across all retained 9+9 runs. Controlled median step capture p95 was baseline
38.356167 ms / candidate 37.313708 ms, below the original 48.356167 ms limit.
Original 3+3 and aggregate 6+6 FAILs remain unchanged; no samples were discarded.
All component/soak processes were absent for controlled measurement. Lower
recorded contention supports noise as a contributor without erasing failures.
Read [controlled report](final-quiescent-1fce58f-notes.md) and exact assessments
under `dist/integration-final-1fce58f/performance/`.

Two logged UI/cleanup limitations are retained separately from uncaught errors:
one earlier ObjectTableModel invalid-sort state reset to unsorted before metrics,
and three controlled-run caught launcher-waiter InterruptedException diagnostics
after metrics during termination. Exact installed bytecode/context explains the
handled branches; later launcher/sidecar/terminated-state/async assertions pass.
Neither exit 0 nor the collector alone is used to erase these diagnostics.

## Current pause: user-directed documentation only

**Latest update: the user reports killing the Ghidra sessions. All PID/live-state
observations below are historical. Do not restart anything in this docs-only task.**

The user explicitly stopped the CUA attempt and requested this plan/docs/handoff
refresh. They confirmed **all open Ghidra sessions were created by the assistant**
and objected to repeated fresh launches, first-run popups, and multiple instances.
They also questioned the Chrome connection. **Do not resume UI/test execution in
this documentation turn.** An execution resume must use one persistent configured
session and one project, with no timed-observer restart loop or concurrent native
GUI probe workers.

## Authoritative current UI/process state

Read `dist/integration-final-1fce58f/handoff-current-state/processes.json` and
[handoff-state.json](handoff-state.json). Recorded PIDs are observations, never
permission to signal a recycled process. At the recorded OS check:

| Process | Observed identity | State |
| --- | --- | --- |
| JVM47285, parent47270 | Patched12.1.3 `/private/tmp/ghidraboy-java-dependency/installed/distribution`; started17:49:29 local | Previously live; user reports killed |
| JVM47493, parent1 | Old `/Users/joshuahansen/ghidra_12.1.2_PUBLIC`; started17:52:07 local | Previously live; user reports killed |
| Earlier timed observer44733 / agent44797 | Explicit app-identity retry | Stopped via verified SIGTERM; raw wrapper exit143 retained |
| Teardown worker probes |12 inventoried prepare/compiler/JVM/agent PIDs | All verified gone |
| Linux desktop containers | `ghidraboy-linux-resume-desktop-jdk` and predecessor | Stopped; no matching relay process in current inventory |

The intended persistent launch uses the **normal** `support/launch.sh fg jdk ...
ghidra.GhidraRun`, not UiActionTest or a custom timed .app. Exact command,
settings/home, hashes, wrapper PID47269 and child47270 are in
`dist/integration-final-1fce58f/gui-consolidation/persistent-{spec.json,run/receipt.json}`.
Home: `/private/tmp/ghidraboy-ui-bb0720d-home`. Its preferences already contain
`USER_AGREEMENT=ACCEPT` and `SHOW_TIPS=false`; neither was changed through file
edits during consolidation. **The old license-only blocker is stale.**

Normal Java applications share CUA bundle ID `net.java.openjdk.java`. The old
12.1.2 process appeared during generic CUA selection; this is a timing-based
inference, not an independently captured launch ancestry. Do not assume that
`getApp` attaches to the desired already-running candidate. The last observed
`NO ACTIVE PROJECT` window and tips dismissal cannot be attributed to the candidate
with sufficient confidence. The attempted consolidation failed; the user subsequently reports killing both sessions.
Verify exact version/distribution/process binding before interacting, and do not
launch another instance to recover a stale handle.

The only deliberately opened browser view was Codex's in-app browser (`iab`) for
localhost noVNC. Chrome appeared in available-surface inventory; there was no
intentional Chrome-tab navigation in this continuation. The user's Chrome
connection concern is unresolved; do not speculate about the connector or infer
permission to use Chrome. VNC is stopped and must not be restarted without
explicit direction. No browser/CUA calls are part of this docs-only refresh.

## Failed GUI attempts and new lifecycle issues

The timed observer repeatedly reconstructed a tool from the shipped Debugger
template, retriggering extension/setup dialogs instead of preserving a configured
tool. Native button actions sometimes worked (one **Pin capture → Pinned snapshot1**
response), but text input/navigation was not verified. Raise/clipboard/Dock
attempts failed or timed out; an observer timed out at the first physical bank
breakpoint. **No complete physical GUI gate passed.** Raw logs and snapshots are
retained under `dist/integration-final-1fce58f/handoff-current-state/`, with an
[evidence inventory](../../dist/integration-final-1fce58f/handoff-current-state/evidence-index.json).
Do not treat a passing Pin action, a visible window, or startup as acceptance.

A later full-tool teardown exposed a distinct issue beyond the repaired register
renderer. See [full investigation](gui-teardown-investigation.md):

- Observed uncaught `IllegalStateException: Trace must be opened before activated`
  during UiActionTest timeout cleanup, through queued target withdrawal.
- Full-template probes reproduced stale manager coordinates (`current=teaching`,
  open traces=0) and logged logical-breakpoint `TraceClosedException` despite
  ASYNC_COUNT=0 and exit0. Those runs are **not clean passes**.
- An interrupted live-dispose probe also logged duplicate
  `StaticMappingGeneration` ObjectTreeModel nodes before disposal and a logical-
  breakpoint NullPointerException afterward. Do not collapse these into known
  terminal EBadF or launcher-waiter interruption diagnostics.
- The exact original IllegalStateException was **not independently reproduced**.
  Evidence supports inadequate harness ordering exposing an upstream manager
  queued-event/disposal weakness. It does not prove the exact failure under an
  orderly normal user close. No fix was applied or qualified.

Proposed only: keep the accepted connection available to finally; await process
exit, the actual TraceRMI close future, and deferred automatic trace closure;
verify empty open traces/null current and closure notifications before disposing
providers. `activateTrace(null)` is not a barrier when ensureActiveTrace=true.
Keep original timeouts, visible providers, auto-close/save and error accounting.
Review logged Ghidra service failures as well as uncaught exceptions. Qualify any
fix under the full tool before selecting a production patch or repeating affected
package/lifecycle checks. No new native Mac probe launches are authorized now.

## What is done versus what remains

The earlier exact-source component, native/static/hardware/consumer, package,
soak and controlled latency receipts remain unchanged and valid at their stated
scopes. They do **not** establish clean full-tool disposal or physical usability.
BACKEND-03/A-RUNTIME/MGBA-06 are reopened IN_PROGRESS; TOOL-03 records the observed
FAIL. Neither release nor the overall non-Deck migration is fully qualified.

On a fresh, explicitly resumed execution task:

1. Read this handoff/state and preserve the user's one-session constraint. Inspect
   actual processes and consolidate to the intended patched12.1.3 instance; do not
   use a generic Java bundle selector without proving its binding.
2. Configure/save one normal Debugger tool/project once. Avoid tips/help/plugin
   startup loops. Do not run timed/fresh-home GUI observers concurrently.
3. Resolve and qualify full-tool teardown and logged-error handling. Any worker
   must have bounded ownership and use non-visible/offscreen execution where
   appropriate; coordinator alone owns physical UI. Do not hide providers to pass.
4. Complete actual import/launch/control, listing/decompiler/physical bank and
   watch navigation, report filter/pin/compare/export/reopen/cancel/malformed,
   checkpoint/edit, selection/switch/reconnect and post-error usability workflows.
5. Rerun only genuinely affected checks through explicit dependency/hash matching,
   then regenerate original-gate qualification/support docs and local commits.
   Never relabel recorded failed runs or weaken budgets.

Physical Steam Deck remains explicitly NOT_RUN. No publication, remote archival,
compatibility-delegate removal or unrelated-file cleanup is authorized. Generic
GB/GBC source belongs to GhidraBoy; GBW3 validation/family support remains private
in GhiBW3. Runtime code is still `1fce58f`; this update changes documentation only.
