# Debugger integration execution ledger

Plan: [debugger-integration-plan.md](../debugger-integration-plan.md). This ledger tracks implementation of that plan; earlier GhiBW3 milestone numbers do not apply.

## Active work

M0 is in progress. M1 feasibility probes have executed. Mechanical M2 import can proceed independently of the remaining legacy/profile trace catalog: original source, archives and baseline runtime remain preserved for comparison, and import itself changes no behavior. This ordering adjustment does not waive BASE-03, remaining performance details, or any later gate. No supported second-backend claim has been made.

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

## Next gates

Retain detailed performance samples and the older trace/profile fixture catalog to complete M0. Resolve Emulicious launch and the remaining M1 semantics, preserving unsupported operations explicitly. Import only selected generic sources with original history, wire the root build, and proceed through backend/session extraction and compatibility gates. GUI/device gates and later release gates remain unexecuted until their actual checks run.
