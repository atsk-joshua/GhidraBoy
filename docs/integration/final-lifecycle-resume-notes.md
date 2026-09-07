# Closed-trace register lifecycle repair

Scope: bounded real Trace RMI failure lifecycle and JVM error accounting on source candidate derived from integrate-ghigbc b4f5095 / implementation 1518f02. No packaging, full soak, physical GUI acceptance, commits, shared documentation, or shared Ghidra installation changes performed.

## Root cause and repair

The Ghidra 12.1.3 `DebuggerRegistersProvider` keeps `previous` coordinates to color changed register values. `DebuggerTraceManagerServicePlugin.ForTargetsListener.targetWithdrawn` schedules automatic trace closure after a 100 ms transaction debounce. `doTraceClosed` changes the active trace (with `ensureActiveTrace` resolving NOWHERE to a remaining open trace), releases its trace consumer, and publishes trace closure. Activation of the remaining trace may reach providers asynchronously after the database is released. The provider then keeps the closed old `current` as `previous`. Its old `traceClosed` handled only clones, and never cleared `previous`. Register-cell rendering calls `isRegisterChanged` -> `getRegisterMemorySpace(previous, ...)` on the closed database. The retained mGBA soak's stack and the focused baseline reproduce this same defect.

This is a Ghidra provider ownership/lifecycle bug. mGBA replacement exposes it; it is not a native-core error. The harness did not own a trace consumer it forgot to release. Retaining traces in the extension to defer closure would alter automatic closure behavior and accumulate unwanted trace consumers; it would not repair the provider's invalid comparison coordinates.

The patch handles closing current coordinates for both the connected provider and clones; it clears a closing comparison baseline; and it never installs an already-closed old current as the next comparison baseline. It follows the existing trace manager's EDT closure and provider event ordering, does not add a catch/suppression, does not hide the register view, and does not disable automatic trace close.

## Owned repository changes (ready for coordinator review; no commit)

- `debugger/tests/ghidra/RealTraceTest.java`: reusable default uncaught JVM collector with explicit thread/error logging, injected real EventQueue failure switch, final error assertion, launch PID logging; failure lifecycle checks verify visible populated register rendering before and after actual automatic database closure.
- `debugger/tests/ghidra/BackendTraceTest.java`: installs that shared collector, exposes `--inject-uncaught-awt`, logs primary process PIDs, checks asynchronous failures after disposal before printing success.
- `tools/patches/ghidra-12.1.3-debugger-register-lifetime.patch`: narrow upstream Java provider repair.

Other concurrent source/docs changes belong to the coordinator. These owned files are released for subsequent work, including the MGBA-03 profile/history extension the coordinator mentioned.

## Checks and durable receipts

All evidence is under `/private/tmp/ghidraboy-lifecycle-validation/`. Each listed run has `receipt.json` (exact command, input hashes, start/end, wrapper and shell PID, exit code), `test.log`, isolated home, and agent evidence. `assessment.json` records log/receipt hashes and final OS cleanup. Final harness output additionally identifies JVM and all primary/lifecycle agent PIDs.

| Run directory | Command arguments after test_backend_trace.sh | Exit | Result |
| --- | --- | --- | --- |
| `unpatched-ready` | `mgba --failure-lifecycle` | 1 | Eight collected closed-trace errors; no success marker. Deterministic negative control on original Debugger.jar. |
| `patched-mgba` | `mgba --failure-lifecycle` | 0 | Six successful populated register rendering checks, no asynchronous errors. |
| `patched-sameboy` | `sameboy --failure-lifecycle` | 0 | Same six rendering checks, no asynchronous errors. |
| `injected-awt` | `mgba --inject-uncaught-awt` | 1 | Actual uncaught AssertionError from EventQueue reaches collector; final assertion rejects it; no success marker. |
| `final-both` | `sameboy mgba --failure-lifecycle` | 0 | Final harness bytes with launch PID logging; 12 populated/visible register rendering checks across six disconnect/crash/replacement targets, zero asynchronous errors, success marker. |

The final normal run's JVM 47581 and eight agents 47613, 47615, 47619, 47620, 47624, 47625, 47626, 47627 were all absent in the recorded read-only OS process check. Expected deliberately induced `Socket closed` diagnostics remain distinct from the absent ClosedException/uncaught errors. `git diff --check` passed for the two owned Java files.

Setup attempts are preserved: sandbox Java GUI startup aborted with exit 134 (`unpatched`), a first unsandboxed source test could not find SM83 in a fresh home (`unpatched-gui`, exit 1), and attempting the package installer on a source tree failed due to missing suite.json (`unpatched-installed/install.log`). The working source runner stages existing built extension archives into each isolated home before source-classpath compilation. None of these setup failures is counted as a lifecycle result.

## Rebuild and dependency integration

Isolated patched Ghidra root: `/private/tmp/ghidraboy-lifecycle-validation/patched-install`.

Reproducible route: `/private/tmp/ghidraboy-lifecycle-validation/build_patch.py`. It copies the baseline installation, extracts the original provider from Debugger-src.zip, applies the checked-in patch using `patch -p1`, compiles that source using Java 21 with `javac -proc:none -g` against the installed Ghidra jars, and substitutes compiled provider members into the copied Debugger.jar while preserving archive member metadata. It updates the matching source archive. The exact full javac invocation is in `patch-build/receipt.json`. Running the route twice reproduced the same output hash.

Only `ghidra/app/plugin/core/debug/gui/register/DebuggerRegistersProvider.class` changes inside Debugger.jar. All nested classes and every other archive entry have identical uncompressed bytes, and the full member list/order is unchanged. This verification is built into the build route.

- Original Debugger.jar SHA256: `7f72777cda59badf9f0b8e878f7a9d52040c39593a1e05251285ccafae6baecc`
- Patched Debugger.jar SHA256: `3b75891c6734b23f03c0313cb5fc582a9410676b799c8c1af3e30e3696b10bbf`
- Original provider source SHA256: `e93c32916d81a274678dfb133ee54a2913186b26bc36c08a7a519424a6d64c71`
- Patched provider source SHA256: `4b561f12b9dccc2312aea7e7238de8991133dac6a5c5544c942ddb9c1cab5bb3`
- Checked-in patch SHA256: `84a7da39520e7e2eaf12ebc49aa2f7c78f9e7e5fd19be3bda4e1ac55eb227df7`

Production packaging must declare/install/verify this separate Java dependency identity and preserve its source/patch/build provenance. The shared rmi-install remains unchanged. The native decompiler and its `12.1.3+ghidraboy.switch-recovery.2` identity remain unchanged; no native rebuild is necessary. Coordinator should rerun affected installed backend resource/soak and final GUI paths after packaging. These focused source/runtime checks do not certify a release or physical GUI acceptance. No new mGBA synthetic-profile or explicit historical-selected-capture contract was added in this bounded repair.
