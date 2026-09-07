> Repository layout is now governed by [repository ownership](../repository-ownership.md). Old checkout, backup and retention statements below record earlier work and are superseded.

# Debugger integration execution ledger

Plan: [debugger-integration-plan.md](../debugger-integration-plan.md). This ledger tracks implementation of that plan; earlier GhiBW3 milestone numbers do not apply.

## Active work

M0's fixture inventory is complete; remaining baseline performance sampling and M1 conformance remain open. M2/M3 and M5 are complete at their recorded source snapshots. M4's implementation and process-failure checks pass, with physical display/focus acceptance still blocked by the locked desktop. The earlier sequencing adjustment did not waive any gate; the legacy/profile fixture catalog has now been verified. No supported second-backend claim has been made.

The 2026-09-06 [next-agent handoff](agent-handoff.md) and [state snapshot](handoff-state.json) record the uncommitted M6 measurement harness and M7 model work. The frozen macOS soak has now completed successfully as a harness run; budget assessment and matched comparisons remain open. Existing native/Python regression tests pass after the draft model changes, without establishing true-DMG acceptance. No release gate was promoted to PASS.

The `integrate-ghigbc` branch preserves the prior `suite-offdevice-candidate` ref. Unrelated untracked reports and GhiGBC output remain untouched. No remote writes or publication occurred.

## Retained baseline

- Source/artifact manifest and verified full-history bundles: `dist/integration-baseline-20260906/` in GhidraBoy. `baseline.json` records all three source trees, dirty/untracked files, worktrees and artifact hashes. Original generated extension archives are backed up under `artifacts/`; the decomp3 original was recovered from the hash-identical `dist/switch-recovery2` archive after the baseline build regenerated its build output.
- Disposable installations, runtime package, synthetic Programs and trace projects: `/private/tmp/ghidraboy-integration-20260906/`. Original source installations are not modified.
- Ghidra 12.1.3, JDK 21, macOS arm64; patched native dependency `12.1.3+ghidraboy.switch-recovery.2`, executable SHA256 `5b736c3e9236667d35a732f226c99f0014736b9fe506147886a7f15ccb94939a`.
- [Import dispositions](ghigbc-import.json): all 190 tracked GhiGBC files classified; 76 generic files and 7 compatibility files selected, 104 historical files retained through history/bundle, and 3 game-specific harnesses retained externally/historically pending consumer reconciliation.
- [Compatibility inventory](compatibility.md): preserved interfaces and test destinations. [Gate status](status.json) starts with the plan's full 58 gates; partial evidence never marks an entire milestone passed.

## Executed baseline checks

| Check | Result | Evidence relative to `dist/integration-baseline-20260906/` |
| --- | --- | --- |
| Native/Python debugger suite | PASS: 46 tests | `debugger-tests.log` |
| Full provider build and tests | PASS: 456 tests, zero failures/errors/skips | `provider-build-unsandboxed.log`, `provider-test-results/` |
| Comprehensive pinned vectors | PASS: 21,000 vectors, 21 files, pinned sample hashes verified | `external-vectors.log`; full XML copied to baseline results |
| Installed provider lifecycle/preservation | PASS in copied installation | `installed-smoke.log` |
| Actual copied 11.3.1 database migration | PASS; original synthetic database hash unchanged | `database-migration.log`, work directory `database-migration/migration-evidence.json` |
| Current provider + packaged debugger, real RMI | PASS including 250 stops, mappings, edits/restore, history reopen, launcher and structured termination | `rmi-baseline.log`, `rmi/` |

The real RMI run emitted the existing Ghidra `ThreadedTerminal` bad-file-descriptor diagnostic during launcher termination. The process exited 0 and its explicit async-error/termination assertions passed. The message is retained as a baseline diagnostic, not silently discarded or used to claim error-free logs.

Gradle initially failed before starting because the sandbox disallowed its local lock socket. The same build then passed with the required execution permission. Both logs remain; this was not a source failure. No automatic approval review rejection occurred.

## Validation improvement

`tools/installed_smoke.py` previously exercised old-language annotation preservation without invoking the existing comprehensive `GhidraBoyInstructionCompatibility` fixture. It now seeds all 501 valid base/CB encodings using the old language, restores the current language in `finally`, reopens the saved Program in a separate process, and checks persisted instruction display, length and p-code against fresh decoding. This directly exercises the known POP constructor compatibility risk. The new installed run passed, with zero instruction mismatches; see `constructor-smoke.log` and the retained `constructor-smoke` work directory.

Three real RMI/growth runs passed. Median run step p95 was 28.335458 ms (20 measured steps per run); median measured pause was 135.776666 ms including the existing harness's settling delay. Each run retained 250 further captures with zero dropped events. `performance.json` preserves exact per-run results, host and scope. Raw step medians and separate capture-publication latency remain unmeasured and must be added before declaring the performance baseline complete.

## Backend feasibility evidence

mGBA source is pinned to `685023e05d90d87050fb357f46f7bd2d907083f5`; no core source modifications were made. `tools/backend_probes/run_mgba.py` builds only the GB core plus debugger with CMake and records commands, hashes and bounded execution. Its second probe build passed bank-1/bank-2 breakpoints at CPU 0x4029, stepping, register edits, state restoration, physical WRAM write/same-value watches, input and timebase checks.

Two integration hazards were exposed rather than hidden:

- The generated mGBA `flags.h` does not contain all final ABI-affecting build definitions in this configuration. A hand-linked probe failed; the retained CMake integration inherits the actual library target's compile definitions and link dependencies.
- Full-address-space `rawRead8` inspection changes serialized state. Direct physical-memory block inspection preserves it. Both outcomes are recorded in the passing feasibility receipt, and the earlier failing inspection-only receipt remains available. A future adapter must use precise safe inspection semantics and report unobserved/device values rather than blindly reading every address through that API.

Emulicious archive SHA256: `6e1c6d511014033bbc2668360a0194389a5bad2bf6c5ffd0fe093b84da33c0fc`, official download, changelog 2026-03-27. Its official VS Code adapter source is pinned to `172b0b88ae682badfb8b6b6e9b0c480946db2c65`. The owned-process probe connected to its DAP port and received capabilities; launch did not complete within the bound. In particular this connection advertised no standard read-memory, instruction-breakpoint, data-breakpoint or stepping-granularity support. This is partial feasibility evidence, not proof those underlying emulator functions are unavailable through every interface. The two attempts and DAP messages are retained under the baseline work directory; owned processes were terminated after probe cleanup.

Further diagnosis found a first-run update dialog in the third attempt. The fourth uses an isolated application copy with its inspected `Update=0` setting, retaining the exact JAR without automatic updates. That passes the startup dialog but stalls while Java initializes native audio during ROM loading; `threads.log` identifies `SoundOutput.openLine` on the DAP thread. This is an unresolved environment/integration gate, not a successful ROM session or proof of safe remote capture.

## M2 import and M3 build integration

Import commit `7ab89505b5d982c7c1efeeb2a44de21271e323b6` has both the migration branch and original GhiGBC `c1cfeef` as parents. Its 83 selected source files were all verified against the inventory before committing. The 107 excluded files remain available in the original history and bundle. No GhiGBC or GhiBW3 source checkout was changed.

The relocated native/Python suite passes all 46 tests (`imported-debugger-tests.log`). This relocation test deliberately used hash-verified copies of the baseline native binary, boot and ROM fixtures in ignored build/dependency directories, and the existing test interpreter. It does not pass the fresh-checkout bootstrap or standalone runtime packaging gates.

The root wrapper now optionally includes `GhiGBC` with `-PwithDebugger=true`. Its compile-only dependency resolves the actual root project output; `integrationArtifacts` writes relative paths and SHA256 identities for selected archives/JARs. Without the property, the debugger subproject is absent. `debugger/scripts/build_extension.sh` delegates to this root build. The migration artifacts use the distinct `20260905-integration1` version and retain both extension IDs. Kotlin script formatting violations found during iteration were corrected with the repository formatter; final checked-build evidence is recorded separately from earlier failed attempts.

Final public-wrapper build and Kotlin script checks passed (`unified-wrapper-final.log`); static-only project/configuration checks passed and explicitly list no subprojects (`static-configuration-final.log`). `unified-artifacts.json` retains the verified output identities. Archive inspection confirms exactly `GhiGBC/lib/GhiGBC.jar`, no duplicate provider classes, and no second SM83 language in the debugger archive.

M3's macOS and Linux build/package work is implemented and verified at the recorded snapshots. No generated integration archive is being declared a release; later backend changes require renewed release qualification.

### M3 dependency, package and clean-build checks

The root `tools/dependencies.json` is now the canonical dependency source. The debugger's duplicate source lock was removed; runtime packages receive a generated view. Bootstrap uses the existing interpreter, creates a pipless environment, verifies pinned downloads and the complete SameBoy source diff, and refuses extra source edits or symlink destinations. It no longer downloads a separate Gradle distribution or assumes a neighboring repository.

Packaging consumes the hash-verified root artifact manifest, uses one packager for ordinary/Linux compatibility commands, and copies only selected tracked runtime sources. The static documentation payload is explicitly listed in `packaging/static-docs.txt`; unrelated untracked reports and internal migration ledgers are excluded. Install-facing READMEs are separate from developer build instructions. Internal migration and evidence directories are excluded from the source-hash payload to avoid circular artifact identities.

New packages declare the required native decompiler identity, carry the copy-only updater, and verify the selected marker/platform/executable hash before creating user directories. Schema-2 rollback remains supported through a small compatibility reader; new installations always use the current journaled installer. The installer test harness runs the extracted package's installer and no longer requires a game-specific study package for generic checks. Optional study checks remain available for M5.

Executed checks are collected in [m3-evidence.json](m3-evidence.json):

- Clean static source build: 456 tests passed with no debugger runtime, cache or subproject output present.
- Clean full source build: canonical dependency acquisition, fresh native build, both Java extensions and 46 native/Python tests passed without any neighboring repository. The native library, boot and ROM fixtures are byte-identical across independent build directories.
- Source path containing spaces: bootstrap, fresh native build, clean combined Java build and all 46 runtime tests passed.
- Five build-input checks passed, covering stale/path-escaping artifacts, dependency view generation, native identity mismatches, extra edits inside patched source and preservation of files behind symlinks.
- The final macOS runtime package reproduced byte-for-byte. Its extracted `Validate.sh` passed native tests and real installed Trace RMI, including 250 captures, mapping/history, edits/restore, launcher and cleanup.
- Its packaged installer passed 11 install/upgrade/interruption/recovery/self-rollback/user-preservation checks, including refusal of a missing native dependency before any user-home creation.

The final tested package and native binary hashes are in the evidence JSON and retained artifact manifests. The existing Ghidra terminal-close diagnostic remains visible in RMI logs with the same explicit successful termination/async-error checks as the baseline. Legacy game delegates now resolve the optional GhiBW3 checkout beside the root GhidraBoy repository, or use explicit `GHIBW3_ROOT`.

### M3 Linux qualification

[Linux evidence](m3-linux-evidence.json) records the exact builder/runtime images and artifacts. The adapter was built from verified source with GCC 11.4.0, inspected as ELF64 x86-64 with every required ABI export, and packaged with the hash-pinned Debian SDL 2.32.4 runtime and notice. The inspector no longer incorrectly labels every library as a Zig/glibc-2.28 build.

The native decompiler companion was applied through its copy-only updater in Linux; its real startup/protocol probe passed while preserving the source distribution. The package then passed 46 native/Python tests, real Trace RMI including 250 captures, 11 installer/recovery/rollback checks and display smoke in an unprivileged, network-disabled container with no compiler/make/javac/Gradle/RGBDS and no system SDL. The bundled SDL was loaded from the package.

Initial attempts remain recorded: the compiler/linker completed but a trailing `file` utility was absent, so the retained binary was inspected with the Python ELF verifier; an Xvfb PID-1 readiness wait was corrected with Docker `--init`; offline hostname resolution was corrected with an explicit loopback hostname entry. The successful run did not suppress test failures. Shader-cache permission warnings remained visible, with SDL disabling that optional cache. This is virtual-display/emulated-x86 evidence, not Steam Deck or physical GUI acceptance. The reusable environment guidance is in `tools/linux/`.

### M1 external attachment follow-up

The Emulicious probe passed in the Linux environment using the exact earlier JAR. It exposed registers and hardware scopes, including cartridge ROM-bank state, stepped from PC 0x0100 to 0x0101, and preserved the process for a bounded observation after disconnect. The earlier macOS native-audio failure remains an environment-specific failure. Raw bulk-memory coherence, exact loaded-ROM identity and broader pause/error conformance are not inferred from this result. [Backend decisions](backend-decisions.md) record the measured limitations and why mGBA remains the next embedded implementation.

### M4 initial adapter boundary

The SameBoy binding now lives in `ghigbc.backends.sameboy`; `ghigbc.native` retains compatibility imports. The shared protocol contains immutable descriptors, semantic buttons, normalized bank access, explicit CPU coverage, frame dimensions, capabilities and an optional timebase. Generic imports do not load an emulator adapter. Captures retain their descriptor so later configuration changes cannot relabel an earlier observation.

The agent/display no longer import the native module, access native handles, or interpret the flat native capture layout. They use backend control/input/frame methods, capture bank/coverage accessors and adapter-supplied event precision. The agent publishes additive backend/model/capability/timebase attributes and preserves the legacy 8 MHz field only for matching units. Profiles receive the selected backend's capability set. Direct unsupported edits are rejected before recovery creation, and ordinary reads reject a closed backend.

All 53 native/Python tests pass, including the new boundary, capability, immutable-buffer, descriptor-history, input/frame and closed-handle checks. Extracted real Trace RMI validation passed after the refactor. The SDL smoke aborted under the filesystem/process sandbox and passed with desktop execution permission; no physical input/focus acceptance is claimed. An overlapping validation invocation was refused by the existing-instance guard; its result is not counted. The separate serial run passed all new identity/timebase/reopen assertions; [boundary evidence](m4-boundary-evidence.json) records its exact logs.

### M4 shared session and recovery ownership

`ghigbc.session.Session` now owns UUIDs, public epoch/capture counters, execution policy, durable checkpoint/edit metadata, verified restore copies and recovery after failed writes. SameBoy supplies only hardware hooks and its compatible schema-2 identity. The default generic envelope uses schema 3 and supports a backend-specific payload filename and unavailable timebase; a separate test fixture verifies that policy without using SameBoy's payload format.

`CommandQueue` now owns bounded enqueue/execution, execution-time context checks, timeout cancellation and disconnect draining. Already executing commands are not falsely reported cancelled. Internal shutdown is intentionally independent of a prior epoch. The agent retains the separate ordered Trace RMI callback worker and records fault captures when a mutation fails after changing state.

The C sources/header/instrumentation patch moved byte-identically to `debugger/backends/sameboy/native`. Build scripts, canonical dependency paths and packaging follow the new location. Structural checks confirm generic modules do not import native bindings or access native handles. Explicit unsupported hardware models are rejected before reading inputs, and unsupported cartridge/controller requests remain rejected by the real backend.

[Session evidence](m4-session-evidence.json) records these executed checks:

- 69 native/Python tests and 7 build/architecture checks pass. New coverage includes a real pause while the execution owner holds the session lock, 80 matching watches producing a bounded 64-event prefix plus 16 reported losses, stale replacement/disconnect contexts, cancellation and post-write recovery.
- Eleven before/after records match the pre-refactor implementation's legacy state fields, full memory hashes and native event values, including physical bank stops, writes, same-value watches, edits and restore. Session UUID/path and new descriptive attributes are excluded from this comparison explicitly.
- An actual pre-refactor schema-2 checkpoint restores the expected PC through the new session reader; its original files remain hash-identical. A separate test replaces the original state file after verification and proves that the private verified copy is loaded.
- Real installed Trace RMI validation passes in macOS and the isolated Linux runtime. Linux also passes the packaged recovery/rollback installer and display smoke with no build tools or system SDL.

The physical window probe reached the paused fixture, but CUA reported that the Mac was locked. An asynchronous unlock request was sent. No desktop input/focus actions occurred; the bounded probe timed out and cleaned up with unchanged ticks and released keys. This is explicitly blocked acceptance, not a GUI pass.

### M4 real process-failure completion

The actual Ghidra harness now tests transport disconnect, forced termination of its owned sidecar, and a replacement process. Connections close and owned processes exit within their bounds. Saved raw bytes, source identity and completed mappings survive target loss. The replacement has a new session ID and rejects an action carrying the former session without creating a breakpoint. These checks passed with the existing async-error/cleanup assertions; logs are in `m4-failure-lifecycle-final.log` and [M5 evidence](m5-evidence.json).

M4 remains open only for physical keyboard/focus/minimize/close acceptance. CUA revalidated the locked Mac during this work. The only production adapter is still SameBoy; no mGBA support claim is inferred from the shared code.

### M5 saved-work and external consumer compatibility

[M5 evidence](m5-evidence.json) records the current artifacts, logs and fixture identities. The optional consumer changes are committed independently in GhiBW3 as `c8a858f` on `integrated-debugger-consumer`; its previous branch and untracked files are preserved.

- GhiBW3 uses the integrated root wrapper and a hash-verified debugger artifact manifest. Static-only builds work with deliberately missing live dependencies; stale JAR hashes and ambiguous composition inputs are rejected. Old explicit JAR/Gradle overrides remain available. Package composition accepts exact generic manifests rather than assuming old GhiGBC paths.
- The installed GhiBW3 static component and exporter pass without the live debugger. Its live Java plugin links to the integrated action/mapping services; an installed game profile rejects the synthetic nonmatching ROM while generic controls remain usable. The matched optional composition passes 13 installation/removal/recovery/rollback checks.
- Four copied trace fixtures reopen in independent Java-only processes with no emulator runtime or profile decoder installed: an authentic pre-backend trace, a clearly labeled synthetic legacy-boolean mapping variant, synthetic decoded-profile history, and history created with the live consumer installed. CPU bytes, mapping readiness, backend/profile identity, edit recovery hashes and checkpoint-parent provenance survive. Original project hashes remain unchanged.
- The existing old schema-2 checkpoint restores through the shared session reader. Expanded rejection cases cover schema, backend, core, configuration, patch, model, ROM, boot, payload path and timebase mismatches before native loading.
- Current installed Program preservation passes all 501 old-language constructor checks with zero mismatches, together with annotation/ownership/lifecycle checks. A fresh copied 11.3.1 → 12.1.3 database migration passes and preserves its original project.
- A failing synthetic decoder reports its error while real execution, mapping, edits and history checks continue successfully. Profile bounds, missing capabilities and stale session/epoch/capture checks retain their passing runtime tests.
- The existing exact-revision regression ROM copy passes current table and captured-decoder parity: 53 unit templates, 33 weapon templates, 100 captured units and 1,623 typed fields. Only hashes/counts are recorded; its bytes are unchanged and excluded from artifacts. This check does not claim a new battle replay.

`tools/prepare_profile_fixture.py` reproduces the synthetic/failing provider composition using the actual lowercase public `provider` entry point; the initial fixture's incorrect uppercase entry point was rejected by installation and corrected. `tools/reopen_trace_fixture.py` copies projects and runs the standalone reader; its optional legacy transformation is confined to the copied project and checked in a separate JVM.

## M6/M7 handoff checkpoint — 2026-09-06

GhidraBoy remains at `d78da47`, with the Java metrics/soak harness already staged and the model changes unstaged. GhiBW3's consumer migration remains at `c8a858f`. The handoff records exact source/log hashes, paths, known integration hazards and the resume order; unrelated files and the index were preserved.

The compiled M6 acceptance harness ran from a frozen macOS runtime archive (SHA256 `b2c8dac88ba6fe327c8af7bb6b67d96d9dbfe1e1f777a1a8358e3c2e9fdfce69`). `m6-soak.log` ends in `REAL_TRACE_TEST_PASSED`; the original process returned exit 0. It completed 109 checkpoint/restore cycles in 1,802.203868 seconds, with maximum measured soak pause 65.041667 ms and zero reported dropped events. The three previously observed shell/JVM/primary-agent PIDs were absent after completion. This is bounded execution/cleanup evidence, not a complete leak audit or `A-PERF` PASS. Intermittent stale static-binding warnings and the known terminal-close diagnostic remain in the retained log for review.

`tools/performance_limits.json` was declared before the soak; its assessment helper is untracked and not yet validated. One new 20-sample metrics report exists; three comparable baseline and three candidate runs for all four metrics remain outstanding. Full resource trend/storage/cleanup assessment and physical GUI qualification are also outstanding. `A-PERF` is now IN_PROGRESS.

The draft M7 native/Python work adds explicit CGB-E/DMG-B selection, observed hardware mode/memory sizes and model-specific boot coverage while retaining legacy CGB creation/checkpoint behavior. `m7-model-baseline-tests.log` reports 69 tests passing. Dedicated true-DMG and CGB-mode tests, launcher/package boot integration, MBC2 and independent accuracy coverage remain undone; `HW-01` is now IN_PROGRESS. The soak's frozen package does not contain these hardware edits.

## Next gates

Complete the remaining baseline/performance and M1 conformance details, and resume physical window acceptance when the Mac is unlocked. Proceed through M6 release/resource qualification, hardware/model expansion and mGBA implementation. Final release/device gates remain open; completed component checks do not imply the full migration is finished.

## Resumed implementation and qualification — 2026-09-06

The user resumed milestone implementation and explicitly requested parallel agents. Work ownership is recorded in [active work](active-work.md). Final physical Steam Deck verification is deferred by the user until all other work is solid; it remains an unexecuted device gate.

M6 now has three alternating baseline and candidate runs with identical external harnesses and isolated homes. All four raw-sample latency comparisons pass unchanged budgets. The retained 109-cycle soak passes its predeclared bounded budgets; positive Ghidra RSS trend requires separate idle/cleanup assessment. [Measurements and physical evidence](m6-measurements-evidence.json) records real keyboard, focus, minimize/restore and close acceptance plus the real Ghidra breakpoint/watch/history/bookmark sequence. A temporary uniquely identified macOS launcher avoided selecting the other running Ghidra. JDK accessibility-menu diagnostics remain in the passing action log and are not suppressed.

M7 implements true DMG/CGB observations, stable checkpoint identities, atomic native hardware snapshots, MBC2 nibble RAM, mirrors and physical bounds. Real imported MBC2 Program/trace mapping tests pass, including both boot topologies and invalid metadata rejection. Explicit launcher model selection and both redistributable boot assets are wired.

Independent pristine comparison exposed a pre-existing defect: CPU inspection through SameBoy safe reads flushes lazy device state during CGB boot. The corrected adapter resolves CPU bytes on an owned private inspection engine restored from the stopped engine state, preserving the live engine and output. Twelve focused model/mapper/observer tests pass; the independent matrix passes 55 rows/165 variants and 3,986 unchanged serialized-state observations. See [accuracy evidence](m7-accuracy-notes.md). The frozen M6 candidate predates this fix and is not a releasable artifact; final source/artifact/platform checks must use corrected bytes.

M1 expanded probes prove explicit ordinary-execution deadlines and record external DAP limitations. A HALT stall was reproduced and resolved in an isolated additive mGBA tick experiment, with 998 state differential cases and dedicated HALT/IRQ/STOP checks. Production adapter integration is underway, with actual CGB identity and capability-specific rejections. No Release A/B qualification or remote publication is claimed.

## Current handoff — source 1518f02

This checkpoint supersedes stale remaining-work statements above; earlier entries
remain historical evidence. Runtime/history/packaging source is committed through
1518f02. The changeset sequence includes 9c2ea42 (pause/teardown lifetime guard), 93b7130
(shared failure and checkpointless soak), and 1518f02 (missing packaged provenance).

All six corrected archives reproduce. Final Mac component acceptance reran all16
commands: 213 native/Python tests across compositions,34 installer checks,102
observation assertions,four SDL smokes and85 research assertions. Linux executed
fresh integrity/installation/display/doctor/research checks and explicitly reused
unchanged 91/17/105 native/RMI/report/growth receipts. Earlier93 packaging failures
are retained. See final-macos-1518f02 and final-linux-1518f02 receipts/notes.

Final paired latency passes all four predeclared budgets (3+3 runs); candidate
step capture median-of-run-p95 31.019ms and pause capture38.396959ms. Executables
are identical between measured93 and corrected1518 packages. Cross-backend data
agrees at12 synchronization points, but speed-switch timing differs (131096 vs20
ticks); the comparison reports differences, and verifier tests pass without
claiming hardware/timing parity.

Both final soaks remain in flight at the documentation handoff. The mGBA log has
repeated uncaught AWT ClosedException/File-is-closed errors during replacement,
through register rendering. This is a real qualification failure to investigate,
not the known socket/terminal diagnostic. Its harness also lacks reliable
uncaught-error collection. Original tool handles are lost; live OS processes were
confirmed, with immutable report/log snapshots retained. See agent-handoff.md and
handoff-state.json before resuming or rerunning anything.

Remaining: collect/assess jobs and fix lifecycle/error-accounting failure; final
physical GUI workflows; final GhiBW3 consumer refresh (agent quota prevented any
execution); full gate/source-artifact audit, support/release report and cutover
documentation commits. User deferred physical Deck verification. Neither release
is fully qualified. No new validation or agent was started for this handoff turn.

### Soak measurement completion during handoff

Both measurement reports subsequently reached COMPLETED_MEASUREMENTS: SameBoy
110 cycles/1802.36s, mGBA113 cycles/1810.64s. Both assessors returned exit0/PASS
against the original limits; maximum pauses75.78/83.86ms, zero reported drops.
SameBoy was still completing its final idle samples at the OS recheck; mGBA
printed BACKEND_TRACE_CONTRACT_PASSED and its recorded JVM/sidecar were absent.
Independent harness exit statuses remain unavailable after lost tool handles.
The mGBA uncaught closed-trace AWT errors remain a failed qualification condition.
See fresh state/report/log copies and budget-assessment.json files; do not infer
full cleanup/lifecycle success from completed counters or budget PASS.

Final handoff recheck: SameBoy completed its post-soak idle/cleanup, reported
all inventoried descendants absent and no uncaught asynchronous errors, and
printed REAL_TRACE_TEST_PASSED. All four recorded JVM/primary-sidecar PIDs were
absent. Independent harness exit codes remain unavailable. The mGBA AWT failure
remains unresolved despite its completed measurements, budgets and marker.

## 2026-09-06 — finish-migration resume

- Verified all handoff source/artifact/log hashes; reassessed both completed soaks
  against their copied original limits (both bounded budget PASS). Four recorded
  PIDs absent. No original independent exit was recovered; mGBA lifecycle remains
  FAIL with 17 uncaught closed-database register-renderer errors.
- Started three bounded workers for trace-lifetime/error accounting, explicit
  static/dependency reuse, and final private consumer verification/cutover map.
- Added an optional extended physical UI observation window and uncaught-error
  accounting to the UI harness; extra physical workflows require their own
  observation receipt. The teardown marker is not acceptance evidence.
- Clarified household-only GhiBW3 ownership/publication boundary in its README.
  No remote action or duplicate deletion has occurred in this resume yet.

## 2026-09-06 — final non-Deck automated qualification and local cutover

- Runtime code frozen at `1fce58f`; six selected-backend Mac/Linux archives and
  source archive reproduce. Java register-lifetime companion builds reproduce and
  copy-only install/rollback preserves original Ghidra. Native decompiler identity
  remains `12.1.3+ghidraboy.switch-recovery.2`.
- Final Mac 18 component jobs and all three Linux offline/compiler-free
  compositions pass. Shared profiles/historical captures/provider-free reopen,
  installation/recovery/Java guards, native/SDL/doctor, 250-stop growth, portable
  reports and controlled research pass at exact recorded package hashes.
- Final 30-minute soaks both exit0 with no uncaught JVM errors and all original
  budgets PASS: SameBoy109 cycles/1800.46s, mGBA112 cycles/1801.37s. SameBoy idle
  and descendant cleanup passes; owned soak processes absent before timing.
- Original latency3+3 and aggregate6+6 FAILs remain intact. The predeclared
  controlled3+3 and all-retained9+9 pass unchanged budgets. Background processes
  and logged handled sorting/shutdown diagnostics are separately documented.
- Static/CPU/hardware/source/pristine/checkpoint evidence is explicitly matched
  or refreshed. Expanded mapper tests found and fixed actual/header-controller
  mismatch acceptance; the final native/profile/private parity checks pass.
- GhiGBC `65e1208`/`413a971` replaces duplicate implementation with tested delegates.
  GhiBW3 `99802e0`/`29145f8` preserves household-only game source and private
  evidence. Original history/tags/artifacts/rollback/private/unrelated work remains.
- **Incomplete physical GUI qualification:** both isolated apps were observed at
  Ghidra User Agreement. Required confirmation remains pending. User questioned
  VNC; coordinator explained the temporary local Linux viewer and paused GUI
  interaction. No consent or physical acceptance is inferred. Steam Deck stays
  explicitly deferred; no release publication or remote archival occurred.

## 2026-09-06 — GUI attempts, targeting discrepancy and user-directed handoff

- Corrected stale license-blocker narrative: Mac progressed past agreement, and
  intended-home preferences show USER_AGREEMENT=ACCEPT/SHOW_TIPS=false. No consent
  preference files were edited during consolidation.
- Timed observer attempts retriggered setup/plugin dialogs; one Pin capture
  response was seen, but input/navigation and full workflows were not qualified.
  A first action timeout exposed an uncaught trace-activation cleanup exception.
- Full-template investigation reproduced stale manager coordinates and logged
  closed-trace/logical-breakpoint failures despite clean uncaught queues/exit0.
  Exact original IllegalStateException was not independently reproduced. An
  interrupted probe had additional duplicate-node/NPE diagnostics. No fix applied.
- User objected to repeated fresh Ghidra windows and confirmed all were ours.
  Timed observer44733/agent44797 and all worker probes were stopped. VNC desktop
  containers stopped; no matching relay process found.
- Started one normal foreground launcher with existing settings, but OS inventory
  then found an additional old12.1.2 JVM during generic Java CUA selection. Intended
  PID47285/patched12.1.3 and additional PID47493/old12.1.2 are both recorded live.
  Last tips/project-manager observations cannot be qualified as candidate UI.
- User questioned Chrome connection, then explicitly requested docs/plan/handoff
  only. No further CUA or test launches in this refresh. Intentional browser work
  was local noVNC in Codex's in-app browser; actual Chrome connection concern is
  unresolved and no permission is inferred from surface inventory.
- Preserved45 observation/probe files in the handoff evidence index. Reopened
  broad lifecycle gates and recorded TOOL-03 FAIL; prior bounded automated
  measurements remain unchanged. Completion/GUI/release claims remain unproven.

Latest user update: user killed the Ghidra sessions and requested immediate
completion of documentation only. Recorded live PIDs are now historical; no
restart, attachment, CUA or test execution is authorized in this update.
