# Debugger integration execution ledger

Plan: [debugger-integration-plan.md](../debugger-integration-plan.md). This ledger tracks implementation of that plan; earlier GhiBW3 milestone numbers do not apply.

## Active work

M0 and the remaining M1 conformance inventory are in progress. M2's mechanical import and M3 build/package qualification are complete at their recorded source snapshots. M4's shared session/recovery policies and native adapter boundary are implemented; remaining crash/lifecycle and physical display/focus acceptance are open. The import proceeded independently of the remaining legacy/profile trace catalog: original source, archives and baseline runtime remain preserved for comparison, and import itself changed no behavior. This ordering adjustment does not waive BASE-03, remaining performance details, or any later gate. No supported second-backend claim has been made.

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

M4 remains open for the remaining forced-crash/end-to-end lifecycle checks and physical keyboard/focus/minimize/close validation. The only production adapter is still SameBoy; no mGBA support claim is inferred from the shared code.

## Next gates

Retain detailed performance samples and the older trace/profile fixture catalog to complete M0. Finish the remaining M1/M4 failure/lifecycle inventory and resume physical window acceptance when the Mac is unlocked. Continue the independent M5 compatibility and release gates, then hardware/model expansion and mGBA implementation. Device gates remain unexecuted until their actual checks run.
