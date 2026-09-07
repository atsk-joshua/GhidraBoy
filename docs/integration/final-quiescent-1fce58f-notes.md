# Final 1fce58f predeclared controlled latency comparison

Controlled alternating 3+3: **PASS**. All retained 9+9: **PASS**. Original 3+3: **FAIL**; diagnostic 3+3: **PASS**; their 6+6 aggregate: **FAIL**, exceeding step capture-ready by 0.0135 ms. Every batch remains retained. No budget changes, sample exclusions, rounding into PASS, or automatic extra batches were used.

Plan SHA256 `755b97aa97c65656b1f08bc0551ac6c09e2c7079a5ffe52d31904868fa896c46` was declared before this run. Original limits SHA256 `4b0f2aced9b7d8f5bdc3e5a3a257779f29349d3c3a1f4d9532f3458593f554c9` was copied before execution and rechecked unchanged. Baseline + max(20% of baseline, 10 ms) applies to median-of-run-p95 for each metric, with three runs per side. This report concerns bounded macOS native SameBoy latency; it does not establish whole-release, soak, GUI, other-backend, or physical Steam Deck acceptance.

## Prerequisites and identity

Both final soak wrappers had recorded terminal exits before measurement; macOS 18/18 component jobs and Linux all-composition qualification were PASS. Exact hash-bound prerequisite receipts, independent soak exit codes, recorded PID absence, and initial process snapshot are in `quiescent-prerequisites.json` and `quiescent-prerequisite-processes.json`. No matching soak/component processes appeared in any five-second controlled snapshot. Coordinator GUI windows and user applications remained open.

Source HEAD at preparation: `1fce58fa759babd1df1026eadf887acb1b757c84`. Candidate archive `/Users/joshuahansen/dev/GhidraBoy/dist/integration-final-1fce58f/macos/both.tar.gz`, SHA256 `ef1cf569b99641188b6651645e60b3891aa11dd988dbea9c82fd4eb9c8bd0de4`, was extracted freshly into `/private/tmp/ghidraboy-quiescent-1fce58f/candidate/GhidraBoy-Debugger-20260905-integration1-macos-arm64-both`. Baseline copied into `/private/tmp/ghidraboy-quiescent-1fce58f/baseline` from the declared preserved baseline, whose payloads match the original M6/93b7130 receipts. All 18 runs share matching per-side payloads, harness sources, complete Ghidra JAR inventory and assessor matched identity.

Ghidra: `/private/tmp/ghidraboy-java-dependency/installed/distribution`; JDK: `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`; ROM SHA256 `ee2d9eaa2523526d6f8f254873d0d4c1f7ee999d793985ad6b13e3585a7561b3`. Corrected Debugger.jar and Docking.jar hashes remain in the complete JAR inventory. Source, limits, archive and Ghidra JAR rechecks passed.

## Exact assessment results

| Batch | Metric | Baseline median p95 ms | Candidate median p95 ms | Limit ms | Passed |
| --- | --- | ---: | ---: | ---: | --- |
| Original 3+3 | step_reply | 46.2745 | 65.576833 | 56.2745 | False |
| Original 3+3 | step_capture_ready | 48.039875 | 67.834708 | 58.039875 | False |
| Original 3+3 | pause_reply | 3.527708 | 5.452167 | 13.527708 | True |
| Original 3+3 | pause_capture_ready | 56.030666 | 50.29925 | 67.2367992 | True |
| Diagnostic 3+3 | step_reply | 45.753875 | 53.999792 | 55.753875 | True |
| Diagnostic 3+3 | step_capture_ready | 46.250958 | 54.168417 | 56.250958 | True |
| Diagnostic 3+3 | pause_reply | 4.82925 | 7.135709 | 14.82925 | True |
| Diagnostic 3+3 | pause_capture_ready | 43.331541 | 50.798459 | 53.331541 | True |
| Original + diagnostic 6+6 | step_reply | 46.014187500000006 | 55.358563000000004 | 56.014187500000006 | True |
| Original + diagnostic 6+6 | step_capture_ready | 47.145416499999996 | 57.158916500000004 | 57.145416499999996 | False |
| Original + diagnostic 6+6 | pause_reply | 4.2347915 | 5.9581040000000005 | 14.2347915 | True |
| Original + diagnostic 6+6 | pause_capture_ready | 51.969896000000006 | 50.548854500000004 | 62.36387520000001 | True |
| Controlled 3+3 | step_reply | 37.364834 | 36.766041 | 47.364834 | True |
| Controlled 3+3 | step_capture_ready | 38.356167 | 37.313708 | 48.356167 | True |
| Controlled 3+3 | pause_reply | 2.114625 | 2.795083 | 12.114625 | True |
| Controlled 3+3 | pause_capture_ready | 39.714292 | 38.523125 | 49.714292 | True |
| All retained 9+9 (mixed load regimes) | step_reply | 40.38825 | 44.209083 | 50.38825 | True |
| All retained 9+9 (mixed load regimes) | step_capture_ready | 40.715666 | 44.246708 | 50.715666 | True |
| All retained 9+9 (mixed load regimes) | pause_reply | 3.527708 | 4.867084 | 13.527708 | True |
| All retained 9+9 (mixed load regimes) | pause_capture_ready | 43.331541 | 50.130208 | 53.331541 | True |

| Controlled run | JVM PID | Exit | Step reply p95 | Step capture p95 | Pause reply p95 | Pause capture p95 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline-1 | 94315 | 0 | 40.38825 | 40.448458 | 2.114625 | 41.091583 |
| candidate-1 | 39606 | 0 | 36.729541 | 36.784291 | 2.795083 | 38.854125 |
| baseline-2 | 81679 | 0 | 37.364834 | 38.356167 | 2.371334 | 35.3945 |
| candidate-2 | 15978 | 0 | 36.766041 | 37.313708 | 4.867084 | 38.523125 |
| baseline-3 | 44205 | 0 | 28.652125 | 29.494291 | 1.561667 | 39.714292 |
| candidate-3 | 55469 | 0 | 37.522083 | 38.492042 | 1.714417 | 36.978625 |

## Host contention and interpretation

| Batch | Snapshots | With other soak/component jobs | Mean summed process CPU % | Mean other-job CPU % | Mean virtualization CPU % |
| --- | ---: | ---: | ---: | ---: | ---: |
| original | 22 | 22 | 805.7727272727274 | 143.04090909090908 | 261.8772727272727 |
| diagnostic | 22 | 22 | 771.6454545454546 | 40.4 | 289.4045454545454 |
| controlled | 18 | 0 | 522.8944444444445 | 0 | 2.338888888888889 |

CPU percentages are summed across processes and can exceed 100% on a multicore host. These five-second ps observations describe load, not per-command attribution or a causal estimate. Earlier batches ran alongside recorded soak/component work and showed broad variation; alternation did not equalize instantaneous contention. The controlled batch removes that known competing work while retaining normal user applications. The 9+9 aggregate is descriptive across different load regimes; it does not replace either failed original assessment.

The controlled comparison passes the unchanged budgets after competing test work finished. This supports host contention as a contributor to prior noise, but cannot prove contention explains every candidate overhead or retroactively turn the original and 6+6 failures into passes.

## Diagnostics and cleanup

- `baseline-1`: line 152: `ERROR Console input closed unexpectedly: java.io.IOException: com.sun.jna.LastErrorException: [9] Bad file descriptor (ThreadedTerminal)`
- `candidate-1`: line 154: `ERROR java.lang.InterruptedException (UnixShellScriptTraceRmiLaunchOffer)`; line 155: `ERROR Console input closed unexpectedly: java.io.IOException: com.sun.jna.LastErrorException: [9] Bad file descriptor (ThreadedTerminal)`
- `baseline-2`: line 152: `ERROR Console input closed unexpectedly: java.io.IOException: com.sun.jna.LastErrorException: [9] Bad file descriptor (ThreadedTerminal)`
- `candidate-2`: line 154: `ERROR java.lang.InterruptedException (UnixShellScriptTraceRmiLaunchOffer)`; line 155: `ERROR Console input closed unexpectedly: java.io.IOException: com.sun.jna.LastErrorException: [9] Bad file descriptor (ThreadedTerminal)`
- `baseline-3`: line 152: `ERROR java.lang.InterruptedException (UnixShellScriptTraceRmiLaunchOffer)`; line 153: `ERROR Console input closed unexpectedly: java.io.IOException: com.sun.jna.LastErrorException: [9] Bad file descriptor (ThreadedTerminal)`
- `candidate-3`: line 154: `ERROR Console input closed unexpectedly: java.io.IOException: com.sun.jna.LastErrorException: [9] Bad file descriptor (ThreadedTerminal)`

Every controlled JVM exited 0, printed REAL_TRACE_TEST_PASSED, and passed the asynchronous error collector through cleanup. These markers do not erase logged diagnostics. The earlier single ObjectTableModel invalid-sort reset, before metrics, remains documented in the unchanged `table-diagnostic.json`; its installed Docking.jar identity matches this batch. Any newly matched diagnostics remain above and in the summary JSON.

Cleanup status: **PASS**. Checked owned PIDs: `[13793, 13902, 15978, 25143, 31577, 33762, 36571, 39606, 44186, 44200, 44205, 55247, 55257, 55469, 64971, 65045, 75552, 78631, 81679, 85312, 85323, 86890, 87721, 91297, 94315]`. Alive owned PIDs: `[]`. Remaining matching processes: `[]`. Reused PIDs excluded by current process start time after the recorded owned exit: `[85323]`; original collision snapshot and full old/current command identity remain in `quiescent-cleanup-initial-pid-collision.json` and `quiescent-cleanup.json`. No user applications or coordinator GUI windows were killed. This PID check is cleanup evidence for these short runs, not a long-soak resource-leak claim.

Evidence: `/Users/joshuahansen/dev/GhidraBoy/dist/integration-final-1fce58f/performance`. Controlled samples and durable installer/compiler/JVM command receipts are in `quiescent-pairs`; exact results are `quiescent-assessment.json` and `quiescent-all-nine-assessment.json`. `quiescent-evidence-summary.json` preserves all 18 run metrics, diagnostics, host summaries and identity checks. `quiescent-evidence-files.json` inventories owned evidence hashes. Runner PID 85312, start 1788738713.0495691, measurement start 1788739580.730755, terminal exit 0 at 1788739672.460442. No additional performance run was started after the fixed batch.

## InterruptedException classification

Three separately retained occurrences: candidate-1 line 154, candidate-2 line 154, baseline-3 line 152. They follow all performance cycles and the interpreter-identity assertion, later checkpoint/history assertions, successful menu launch/save and rejected-default-write assertions. They occur during launcher shutdown, before main-sidecar exit and TERMINATED assertions, not during latency sampling. The exact installed bytecode catches this interruption in the PTY waiter and logs it via Msg.error(Object,Object), explaining why the line has no accompanying stack and is not an uncaught-collector failure. Termination explicitly interrupts that waiter after terminal termination, process destruction and PTY close. Inference: the logged events are consistent with that handled shutdown race. Subsequent successful control flow establishes awaited launcher kill/connection closure, main-sidecar exit, TERMINATED state and asynchronous collector postconditions. No unmet harness postcondition is observed; waiter normal completion versus the caught branch is not independently asserted, so these ERROR diagnostics remain recorded cleanup behavior rather than being declared harmless from exit 0.

Exact per-occurrence numbered log context, source/JAR hashes, installed waiter and termination bytecode, and command receipts are retained in `quiescent-interrupted-diagnostic.json`, `quiescent-launcher-source.json` and `quiescent-launcher-bytecode.log`.
