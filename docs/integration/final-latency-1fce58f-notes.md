# Final 1fce58f paired latency refresh

Original alternating 3+3 result: **FAIL**. Fixed diagnostic 3+3 result: **PASS**. All six baseline plus all six candidate runs: **FAIL**. The original failure remains retained; no samples were discarded, best runs selected, or limits relaxed.

## Scope and identity

This is bounded macOS native SameBoy latency evidence. It does not assess a soak, post-close resource cleanup, other backends, physical Steam Deck, or whole Release A. Every real JVM harness exited 0 and retained both its completion marker and asynchronous-error-collector pass. Logged terminal/table diagnostics remain visible below.

Final source: `1fce58fa759babd1df1026eadf887acb1b757c84`. Candidate archive: `/Users/joshuahansen/dev/GhidraBoy/dist/integration-final-1fce58f/macos/both.tar.gz` SHA256 `ef1cf569b99641188b6651645e60b3891aa11dd988dbea9c82fd4eb9c8bd0de4`. Fresh isolated extraction: `/private/tmp/ghidraboy-latency-1fce58f/candidate/GhidraBoy-Debugger-20260905-integration1-macos-arm64-both`. Retained baseline was copied to `/private/tmp/ghidraboy-latency-1fce58f/baseline` to isolate runtime side effects; its four receipt payloads match every baseline run in the original M6 and 93b7130 receipts, and both runtime ROMs match.

| Final tuple item | SHA256 |
| --- | --- |
| build/libghigbc.dylib | `ba30da5996633003cbcf26ab528aa2f6bee1c774c97f5db194c1ddefd2714f49` |
| dependencies.lock.json | `8e0a6165db2585d44d2b6c29eb921e633bfa0548682f897697c5aeefd6a1712d` |
| extensions/ghidra_12.1.3_PUBLIC_20260905-integration1_GhiGBC.zip | `403d3b32ff1e0174b6d14cfef3776e1df8ebc174cb7b906c8875cd96c25e22ad` |
| extensions/ghidra_12.1.3_PUBLIC_20260905-integration1_GhidraBoy.zip | `55b1becd9002094dc0decfd0fef4ccddf8b8bc59fe0b77e7748de52154072cb5` |
| Ghidra corrected Debugger.jar | `3b75891c6734b23f03c0313cb5fc582a9410676b799c8c1af3e30e3696b10bbf` |

Both sides use `/private/tmp/ghidraboy-java-dependency/installed/distribution` with the full JAR hash inventory in receipt.json, JDK `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`, and matched identity `{"architecture": "aarch64", "config": "ghigbc-abi1-cpu-bus-v1:CGB-E:accurate-rtc:copied-stop", "core": "208ba4afabffab9edde416f2dbb8ae459e34adb8", "ghidra": "12.1.3", "host": "MacBookPro.localdomain", "java": "21.0.12.1", "os": "Mac OS X", "python": "Python 3.9.6", "rom_sha256": "ee2d9eaa2523526d6f8f254873d0d4c1f7ee999d793985ad6b13e3585a7561b3"}`.

Limits were copied before the first run; SHA256 `4b0f2aced9b7d8f5bdc3e5a3a257779f29349d3c3a1f4d9532f3458593f554c9` matches the original M6 declaration and unchanged working limits. Allowed candidate median-of-run-p95 is baseline + max(20% of baseline, 10 ms); minimum three independent runs per side. The native-host pause budget remains strictly below 2,000 ms; it was not changed. Metrics have 20 real cycles after five warmups and include command/publication latency; capture readiness polls every 5 ms.

## Results

| Batch | Metric | Baseline median p95 ms | Candidate median p95 ms | Limit ms | Pass |
| --- | --- | ---: | ---: | ---: | --- |
| Original 3+3 | step_reply | 46.274500 | 65.576833 | 56.274500 | False |
| Original 3+3 | step_capture_ready | 48.039875 | 67.834708 | 58.039875 | False |
| Original 3+3 | pause_reply | 3.527708 | 5.452167 | 13.527708 | True |
| Original 3+3 | pause_capture_ready | 56.030666 | 50.299250 | 67.236799 | True |
| Diagnostic 3+3 | step_reply | 45.753875 | 53.999792 | 55.753875 | True |
| Diagnostic 3+3 | step_capture_ready | 46.250958 | 54.168417 | 56.250958 | True |
| Diagnostic 3+3 | pause_reply | 4.829250 | 7.135709 | 14.829250 | True |
| Diagnostic 3+3 | pause_capture_ready | 43.331541 | 50.798459 | 53.331541 | True |
| All 6+6 | step_reply | 46.014188 | 55.358563 | 56.014188 | True |
| All 6+6 | step_capture_ready | 47.145416 | 57.158917 | 57.145416 | False |
| All 6+6 | pause_reply | 4.234792 | 5.958104 | 14.234792 | True |
| All 6+6 | pause_capture_ready | 51.969896 | 50.548855 | 62.363875 | True |

| Batch/run | JVM PID | Exit | Step reply p95 | Step capture p95 | Pause reply p95 | Pause capture p95 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| original baseline-1 | 68332 | 0 | 46.274500 | 48.039875 | 3.845333 | 48.710000 |
| original candidate-1 | 68456 | 0 | 68.036792 | 68.131792 | 3.782333 | 57.610750 |
| original baseline-2 | 68542 | 0 | 39.933583 | 40.715666 | 3.315042 | 56.030666 |
| original candidate-2 | 68610 | 0 | 44.209083 | 44.246708 | 5.452167 | 50.299250 |
| original baseline-3 | 68739 | 0 | 65.367250 | 68.207375 | 3.527708 | 56.237708 |
| original candidate-3 | 68873 | 0 | 65.576833 | 67.834708 | 6.464041 | 50.130208 |
| diagnostic baseline-1 | 69524 | 0 | 45.753875 | 46.250958 | 4.624250 | 43.331541 |
| diagnostic candidate-1 | 70560 | 0 | 56.717334 | 60.149416 | 7.917250 | 63.867292 |
| diagnostic baseline-2 | 76747 | 0 | 74.054708 | 77.325709 | 5.535125 | 55.229792 |
| diagnostic candidate-2 | 77733 | 0 | 53.999792 | 54.168417 | 7.135709 | 50.798459 |
| diagnostic baseline-3 | 79100 | 0 | 34.777041 | 39.502875 | 4.829250 | 36.397875 |
| diagnostic candidate-3 | 79374 | 0 | 35.859291 | 36.524333 | 1.780792 | 46.853709 |

Maximum observed pause reply across all retained samples: 23.175625 ms; maximum capture-ready: 78.078500 ms. These short latency samples do not establish long-soak pause compliance.

## Host noise and interpretation

Coordinator final soaks and component tests ran other isolated JVMs during the measurements; virtualization and other host processes also consumed CPU. Both sides ran alternately on the same host background, but alternating does not make instantaneous contention equal. Full five-second `ps` snapshots, with command, timestamp and exit, are retained for both batches. The first three pairs failed the step budgets amid broad run-to-run variation; that justified exactly three additional alternating pairs, fixed before that diagnostic batch began. The later samples and aggregate are reported alongside the original failure. Host load is evidence of contention, not proof that contention explains all candidate overhead; no passing release latency qualification is inferred by replacing the failed original set.

All run diagnostics are preserved in evidence-summary.json. All original runs logged ThreadedTerminal bad-file-descriptor diagnostics; original candidate-2 additionally logged an ObjectTableModel invalid-sort diagnostic. The harness error collector passed, but a completion marker is not being used to erase logged errors.

## Evidence and commands

Evidence root: `/Users/joshuahansen/dev/GhidraBoy/dist/integration-final-1fce58f/performance`. `receipt.json` and `diagnostic-pairs/receipt.json` bind harness source, every Ghidra JAR, runtime payloads and output hashes. Every installer, compiler and JVM has its full argv/environment, PID, log SHA256 and exit in sibling `*.command.json`. Top-level wrapper/assessor receipts and preparation scripts are retained. `assessment.json` is the original result; `diagnostic-assessment.json` and `all-pairs-assessment.json` preserve the fixed diagnostic and all-sample results. `evidence-summary.json` contains per-run PID/p95/diagnostic and filtered background context. `evidence-files.json` inventories retained file hashes.

## Object-table diagnostic investigation

Installed AbstractSortedTableModel.createSortingContext checks isValidSortState; on false it replaces local sortState with createUnsortedSortState, calls Msg.error(Object,Object) unless disposed, and returns TableSortingContext. No throwable is created or passed in this diagnostic branch, so no stack is logged and the uncaught collector is not expected to flag it. The UI sort state was invalid and resets to unsorted; this is handled degradation, not evidence of perfect table behavior. Current log occurs between historical CPU-byte assertion and WRAM watchpoint assertions, before performance measurement begins.

Corrected installed Docking.jar SHA256 `baed225fec4b8f32d3cad7f5f0d1feec7a1f73948c9c1052c854555ab0698842` is identical to the prior distribution. The exact diagnostic is at original candidate-2/harness.log:62; no Java stack accompanies it. Full ±12-line context and hash-bound search of 24 current/prior M6/93b7130 harness logs are in `table-diagnostic.json`; exact installed bytecode and javap command/PID/exit are retained in `table-model-bytecode.*`. Matched diagnostic count across searched logs: 1.

The original 3+3 failed; the fixed diagnostic 3+3 passed; all 6+6 still failed step capture-ready by 0.0135 ms. That threshold is unchanged and the result is FAIL. No more noisy batches will be added. Attribution remains unresolved; a separately predeclared quiescent 3+3 after component workers and soaks finish is coordinator follow-up, not completed evidence here.
