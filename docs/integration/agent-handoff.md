# GhidraBoy integration: next-agent handoff

Updated 2026-09-06. **Start here and in [handoff-state.json](handoff-state.json).**
Implementation is committed through `1518f02` on `integrate-ghigbc`; documentation
is being reconciled for handoff. Neither release is fully qualified. The latest
user direction is: **finish everything else first; physical Steam Deck verification
will happen afterward.** This turn requests documentation/handoff, not new execution.

Read the plan's checkpoint and only the relevant milestone sections. The full
[plan](../debugger-integration-plan.md) and [58-gate register](status.json) remain
acceptance requirements, not proof of completion. [Progress](progress.md) is a
chronological ledger. Older entries refer to older snapshots. The prior long
handoff and source snapshot are preserved as
[historical handoff](agent-handoff-20260906-182947.md) and
[historical state](handoff-state-20260906-182947.json).

## First priority: completed measurements, cleanup and a real error

Both measurement phases completed during this handoff: **SameBoy 110 cycles /
1,802.36 seconds; mGBA 113 cycles / 1,810.64 seconds**. Both unchanged budget
assessments pass. Maximum pause was 75.78 ms / 83.86 ms respectively; primary
trace growth was 7,443.69 / 7,809.20 bytes per capture. This is bounded measurement
evidence, not release acceptance. **Do not restart just because old tool handles
are unavailable.** SameBoy subsequently completed idle/cleanup and printed `REAL_TRACE_TEST_PASSED`,
with assertions that its inventoried descendants were absent and no uncaught
asynchronous errors occurred. All four recorded JVM/primary-sidecar PIDs were
absent at the final OS check; mGBA also printed its marker despite AWT errors.
Independent harness exit codes were not recoverable. Recheck the state JSON/logs
for any completion that occurred after this snapshot.

| Job | Runtime / results | Recorded JVM / primary agent (now absent) |
| --- | --- | --- |
| SameBoy | Runtime `/private/tmp/ghidraboy-final-1518f02/both/GhidraBoy-Debugger-20260905-integration1-macos-arm64-both`; results `dist/integration-final-1518f02/soak-sameboy/`; adjacent `soak-sameboy.log` | 36938 / 36966 |
| mGBA | Runtime `/private/tmp/ghidraboy-soak-mgba-1518f02/GhidraBoy-Debugger-20260905-integration1-macos-arm64-both`; results `dist/integration-final-1518f02/soak-mgba/`; adjacent `soak-mgba.log` | 36971 / 36979 |

Original tool sessions `93199` / `59890` now return `Unknown process id`. OS checks
subsequently found all four recorded JVM/sidecar PIDs absent. Recheck identities, elapsed time,
log growth and report status before acting. Do not signal PIDs based on this stale
snapshot alone. Immutable copies of the currently observed logs/reports are linked
from the state file; earlier copies preserve the reports while they were still growing.

**The mGBA soak has repeated uncaught AWT `ghidra.util.exception.ClosedException:
File is closed` during target replacement (including cycles 30/60).** Stacks lead
through `DebuggerRegistersProvider.getRegisterMemorySpace`, `isRegisterChanged`
and register-cell rendering. The measurement loop and terminal `BACKEND_TRACE_CONTRACT_PASSED` completed afterward; that is not a clean lifecycle PASS.
Investigate actual trace/coordinate/renderer lifecycle and whether the defect is
in harness ordering, integration or Ghidra; do not remove the register view or
suppress the exception to turn the gate green. `BackendTraceTest.main` does not
install `RealTraceTest.main`'s uncaught-error collector, so its observed terminal marker (or a recovered exit
0) cannot prove an error-free soak. Fix the harness's error
accounting as well as the underlying failing behavior.

The deliberately induced `Socket closed` and familiar terminal `[9] Bad file
descriptor` diagnostics are separate. The new closed-database AWT exceptions must
not be grouped with those known diagnostics.

SameBoy invocation: `bash scripts/test_ghidra.sh --soak --failure-lifecycle --idle-cleanup`.
mGBA invocation: `bash scripts/test_backend_trace.sh mgba --soak --failure-lifecycle`.
Both use Ghidra `/private/tmp/ghidraboy-integration-20260906/rmi-install`, Java 21
below, unique homes `/private/tmp/ghidraboy-soak-{sameboy,mgba}-home-1518f02`, and
`GBC_EVIDENCE_DIR` pointing at the corresponding result directory. Limits were
copied before execution as `declared-limits.json`; never relax them after results.
SameBoy includes checkpoint/restore and post-close idle/descendant checks; mGBA
has no checkpoint capability and uses capture-only cycles plus replacement tests.
Collect final markers, exit evidence, assessments and actual cleanup separately.

## What is implemented and verified

| Commit | Scope |
| --- | --- |
| `fab0758` | Strict performance assessor, paired-run tooling, physical observations, idle/cleanup harness |
| `94ff3d3` | Models/MBC2, nondestructive/wake fixes, experimental mGBA, negotiated actions, packaging, portable observations and regression tooling |
| `9c2ea42` | Urgent pause/native teardown lifetime lock with deterministic old-race reproducer |
| `93b7130` | Shared backend failure tests and checkpointless resource soak |
| `1518f02` | Package missing assembly/Java experiment provenance inputs |

Architecture stays Java for Ghidra, Python for ordered session/profile policy,
and private C adapters. No native handles in generic code; no new plugin framework
or second IDE. GhidraBoy owns generic static/debugger work, GhiBW3 remains optional.
Legacy GhiGBC extension/classes/imports and persisted numeric regions remain.
Teaching workflows are excluded; named teaching ROMs are regression fixtures.

- SameBoy: actual DMG-B/CGB-E/native/compatibility observations, MBC2 nibble/mirror
  semantics, physical bounds and real static mappings. CPU inspection now uses a
  private stopped-state copy because original safe reads mutated live APU state.
- SameBoy pre-fetch hook fixes the first opcode breakpoint after speed-switch
  wake. Serialized continuation preserves arbitration/timing and deferred vblank
  work. New patch SHA256 `afb55300828df629058e9fde30024801705cb4ffc3c935e58c5720da5d217b67`.
  Exactly the prior CGB schema-2 patch identity is allowed through a tested reader;
  other identity checks remain strict. New pending-fetch checkpoints cannot be
  assumed compatible with downgrade readers. See [wake evidence](sameboy-wake-notes.md).
- Native/pristine coverage: 55 fixture/model rows × three variants, 3,986 unchanged
  serialized-state inspections; extra native-CGB speed/DMA and wake comparisons;
  actual retained M5 checkpoint restoration. See [accuracy](m7-accuracy-notes.md)
  and [CGB devices](m7-cgb-device-notes.md). These are bounded expectations, not
  universal hardware accuracy claims.
- mGBA: actual **CGB**, not CGB-E; CGB/MBC5 19–1B, no BIOS. PPU/DMA CPU lockouts and
  IO/IE stay unknown. Checkpoints, watches, edits and over/out are rejected; UI
  methods negotiate accordingly. `ExecutionBoundaries` includes IRQ dispatch;
  retired `Instructions` is unavailable. One canonical execution primitive/patch
  is shared by probe and production. See [adapter](m8-adapter-notes.md).
- [Cross-backend comparison](m8-cross-backend-notes.md): defined registers/RAM/banks
  agree at 12 boundaries; 10/11 timing intervals agree. Speed-switch interval is
  SameBoy 131,096 vs mGBA 20 ticks. Comparison deliberately returns 2 /
  `DIFFERENCES_RECORDED`; five verifier tests pass. Keep the source-mechanism
  classification and actual model/boot differences; no hardware adjudication or
  universal timing parity is established.
- History has exact field filtering, pin/compare/export/reopen, bounded JSON,
  memory-state fidelity, source mappings and optional boot identity. Report hash
  detects changes, not authorship. Exact-snapshot UNKNOWN is not replaced with
  stale bytes; ROM-only initialization bytes may be UNKNOWN later, so the controlled
  recipe uses captured CPU bytes plus verified physical/static coordinates.
- Controlled real RMI [research reproduction](m9-reproduction-notes.md) passed
  85 assertions, separate-process reopen, equal register/byte/+16-tick/+1-opcode
  intervals, wrong-config rejection and mGBA unsupported-checkpoint rejection.

## Final package and latency evidence

Code tuple is **1518f02**, with Java artifact manifest
`fa84c769065339233f441888b3201b2d7e8c72d808e85097baff0260cac72c05` at
`build/integration/artifacts.json`. Packages are under
`dist/integration-final-1518f02/{macos,linux}/`; use their indices and the platform
receipts for exact paths/hashes. All six selected-backend archives reproduced.

[Mac receipt](final-macos-1518f02-evidence.json): all 16 commands rerun PASS,
213 native/Python tests across three compositions, 34 installer checks,
102 observation assertions, four backend SDL smokes and 85 research assertions.
Mac used existing Homebrew SDL2; no bundled-SDL/fresh-Mac claim. Tests excluded
compiler/build tools from PATH and used a Java-only JDK proxy.

[Linux receipt](final-linux-1518f02-evidence.json): all three selections passed
fresh install/integrity/SDL/doctor; combined research/reopen/rejection passed.
Prior 91/17/105 native/RMI/report/growth checks are explicitly reused through
unchanged executable hashes. Only two provenance data files were added at 1518.
Linux uses emulated x86-64/Xvfb, offline/unprivileged/compiler-free execution and
bundled SDL. This does not qualify physical Deck behavior.

These are **component acceptance receipts, not full release certificates**.
The 93b7130 research packaging failures are retained, not rewritten as passes.

Final paired latency assessment is
`dist/integration-final-93b7130/performance/assessment.json`: three runs each;
all four unchanged budgets PASS. Candidate median-of-run-p95 step capture is
31.019 ms (baseline 32.522875), pause capture 38.396959 ms (baseline 35.954625).
1518's executable payloads are byte-identical to that measured candidate.
Earlier idle/cleanup passes are in [M6 notes](m6-idle-notes.md); current final
soak budgets pass, while final cleanup/error qualification above remains open.

## Remaining work, in order

1. Verify the retained completion/cleanup evidence and investigate the mGBA closed-
   trace AWT failure. Add reliable uncaught-error accounting and durable exit
   receipts. Do not accept a marker alone. Fix/retest affected lifecycle paths;
   rerun affected final resources/soaks after an actual fix, without redoing
   unrelated native accuracy/source baselines.
2. Finish **physical GUI acceptance on final bytes**: both backend launch/control,
   listing/decompiler/physical breakpoint navigation, capability-disabled actions,
   report filter/pin/compare/export/reopen/cancel/malformed files, checkpoint/edit
   where supported, historical/live selection, Program switching/reconnect and
   useful controls after errors. Earlier physical SameBoy keyboard/focus/minimize/
   close and bank/watch/history/bookmark sequence passed on older frozen bytes;
   final M9 UI has not received this full physical pass.
3. Refresh optional GhiBW3 static/full build/linkage and relevant existing private
   parity against the final tuple; do not introduce a new battle claim. The final
   consumer agent failed immediately with a usage-limit error and **ran no checks**.
   M5 receipts remain historical, available for explicit dependency-matched reuse.
4. Audit every original gate, including static source/artifact preservation reuse,
   shared profile/compatibility and full claimed hardware/GUI scope. Resolve gaps;
   do not promote scoped component results into blanket M7/M8/release PASS. Finish
   generated release/support evidence, migration/cutover docs and coherent commits.
5. Leave actual Steam Deck verification and any physical-device-dependent claims
   deferred, as explicitly requested. No remote publication/archival is authorized.

## Environment, ownership and context discipline

- Main repo `/Users/joshuahansen/dev/GhidraBoy`; consumer `/Users/joshuahansen/dev/GhiBW3`.
- Java `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`.
- Build Ghidra `/tmp/ghidraboy-switch-recovery2-mac-final/distribution`; installed
  validation copy `/private/tmp/ghidraboy-integration-20260906/rmi-install`.
- Native decompiler stays **12.1.3+ghidraboy.switch-recovery.2**. Unrelated retained
  index1 artifacts are not this migration tuple. Gradle cache
  `/tmp/ghidraboy-switch2-gradle-cache`; source Python `debugger/.venv12/bin/python`.
- Linux prepared native outputs `/private/tmp/ghidraboy-m8-linux-final/native` and
  copied Ghidra `/private/tmp/ghidraboy-integration-linux-20260906/ghidra-updated/distribution`.
  Exact Docker recipe/image/hashes: [Linux notes](m8-linux-notes.md).
- Packaging uses shared `debugger/build/candidate-test-classes`: serialize packagers.
  Give validations separate extracted roots, homes and evidence directories.
- Source test lanes: `GBC_TEST_BACKENDS=sameboy,mgba bash debugger/scripts/test_native.sh`;
  source default is SameBoy. Installed tests use their manifest selection.
- Preserve unrelated GhidraBoy `docs/changes-since-official-release-report.md`,
  GhiBW3 `.DS_Store`/`docs/integration/GBW3_DECOMPILATION_AGENT_HANDOFF.md`, and GhiGBC
  `docs/STUDENT_GUIDE.md`/`output/`. Parent's uncommitted consumer README/contributor
  edits and GhiGBC README redirect are intentional; review/commit only those paths.
- Previous implementation agents finished; do not assume their contexts are
  available. Use fresh bounded agents with `fork_turns="none"` and self-contained
  task packets, not full-history forks. Reserve coordinator capacity. Retire each
  worker after a concrete chunk; have it return concise results plus file-backed
  notes. Coordinator alone owns shared gate/progress/handoff updates and final UI.
- Launch future long tests through durable wrappers writing command, input hashes,
  start/end/PIDs, logs and **exit code**, so context/tool resets do not lose status.
  No quota reset was redeemed; usage-limit failure is not a test failure.

For physical CUA targeting, the existing empty user Ghidra shares the Java bundle
ID with test JVMs. A temporary jpackage launcher at
`/private/tmp/ghidraboy-physical-ui-app/GhidraBoyValidation.app`, bundle ID
`org.ghidraboy.validation`, previously solved selection. Its `.cfg` currently
points to an older runtime/home; rebind it to an isolated final extraction before
reuse. The Java classpath must list Ghidra/installed extension jars explicitly:
manifest-only Class-Path failed Ghidra extension-point discovery. Do not close the
user's unrelated Ghidra. `UiActionTest` phases appear in its runtime
`docs/evidence/ui-action-phase.txt`; Ghidra's action chooser is Cmd+3 on Mac.
