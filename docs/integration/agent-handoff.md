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

## Final artifact checks and active jobs

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

## Physical UI: actual external approval dependency

Both isolated GUI apps are stopped at Ghidra's User Agreement. The computer-use
tool requires confirmation at the time a license is accepted. One async question
asks permission for the validation apps; **no affirmative answer has been received**.
Do not click agreement buttons or bypass the prompt through preferences.

The user asked why VNC was being used. Coordinator explained it was a temporary
localhost-only viewer chosen to expose the isolated Linux GUI to CUA, not a
product/migration requirement, and paused GUI interaction. Do not infer approval
for that approach or for the agreement from the question.

Mac app bundle: `/private/tmp/ghidraboy-physical-ui-app/GhidraBoyValidation.app`,
ID `org.ghidraboy.validation`; setup/context/receipt are under
`dist/integration-final-bb0720d/gui/`. Linux desktop/relay remains isolated and
local at `http://127.0.0.1:16080/vnc.html?autoconnect=true&resize=scale`; full process,
image and network receipt is `/private/tmp/ghidraboy-linux-resume/desktop/readiness.json`.
Coordinator alone owns physical CUA. Do not control the unrelated user Ghidra.

The prepared GUI uses bb0720d package bytes; explicit per-file/class comparison
`dist/integration-final-1fce58f/payload-transition.json` proves all production
payloads and UiActionTest classes identical; only unrelated RealTraceTest classes
changed. Record this binding or use fresh 1fce58f extraction before UI acceptance.
Full launch/import/bank-navigation, capability controls, report filter/pin/compare/
export/reopen/cancel/malformed, checkpoint/edit, selection/switch/reconnect and
controls-after-errors remain physical gates. Do not turn preparation into PASS.

## Finish order and boundaries

1. Automated evidence is collected and passing within the recorded scopes. Read
   the final reports; do not repeat finished measurements without changed inputs.
2. When explicit agreement approval/GUI direction arrives, complete final physical
   GUI checks. Otherwise document this concrete blocker without claiming completion.
3. The original gate register and generated qualification report remain explicitly
   incomplete because of the physical GUI dependency. Update them after actual
   acceptance; `tools/integration_report.py --require-qualified` must keep refusing
   until the remaining non-Deck gates pass.
4. Keep physical Deck NOT_RUN, compatibility delegates, private household scope
   and all unrelated files. No publication, archival or quota-reset redemption.

Packaging is coordinator-serialized. Validation homes/extractions are isolated.
Use durable wrappers: `/private/tmp/ghidraboy-run-evidence.py` persists exact
command, input hashes, wrapper/child PIDs, logs and independent exit. Java 21 is
`/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`; final Mac Ghidra is
`/private/tmp/ghidraboy-java-dependency/installed/distribution`; final Linux copy is
`/private/tmp/ghidraboy-linux-resume/ghidra-updated/distribution`.
