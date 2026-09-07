# Final macOS extracted-package component acceptance — 1fce58f

PASS: all 18 final-artifact component jobs exited 0. No blockers remain in this worker's scope. Long-duration soaks and physical GUI input/focus acceptance remain coordinator-owned and are not claimed here.

All three byte-reproducible selections in `dist/integration-final-1fce58f/macos/packages.json` were verified against their indexed archive and suite-manifest SHA256 values, then freshly extracted under `/private/tmp/ghidraboy-macos-final-1fce58f/local-access`. No older archive or acceptance result was reused. Each package had an independent extraction; each job had its own home and evidence directory. The doctor job intentionally inspected its package's completed validation install.

The compiler-free PATH omitted cc, gcc, clang, make, cmake, javac, gradle, and rgbasm. JAVA_HOME was a proxy exposing only Java21's java executable, backed by `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`. Ghidra was `/private/tmp/ghidraboy-java-dependency/installed/distribution`. Existing Homebrew SDL2 was the documented host prerequisite. Local socket/display/process access was approved before the run; there was no sandbox-failed attempt to supersede for this artifact.

| Package | Native tests | Installer checks | Remaining checks |
|---|---:|---:|---|
| both | 110 | 13 | Real RMI, SDL, doctor, observation/reopen, research/reopen, both-engine failure lifecycle/profile contract: PASS |
| sameboy | 96 | 13 | Real RMI, SDL, doctor, observation/reopen, full RealTraceTest and 250-stop growth: PASS |
| mgba | 17 | 14 | Real RMI, SDL, doctor, observation/reopen, isolated failure lifecycle/profile contract: PASS |

The combined lifecycle run passed all 60 new real-coordinate/populated-table readiness assertions and their 60 populated-register-render assertions. The isolated mGBA run passed all 30 corresponding pairs. These exercise the committed readiness fix after target loss, automatic trace release, replacement-session stale-action rejection, and profile error isolation. Separate JVM historical reopen and clean asynchronous-error assertions passed. Installer checks covered recovery/rollback, user-edit preservation, package integrity refusal, and native/Java dependency guards.

The bounded SameBoy growth run completed 250 real RMI stop captures in 22.612652416 seconds, advancing snapshots 34→284. Dropped events were zero at stops 0, 125, and 250. Agent RSS was 46,128→46,368→46,368 KiB; Ghidra RSS was 910,160→1,985,984→1,141,840 KiB. Retained trace storage grew from 3,506,176 to 5,275,648 bytes. This measurement does not establish a long-duration leak claim.

Every job has a prewritten spec, command/environment, input hashes, wrapper/child PIDs, timestamps, complete log, log hash, and exit receipt. OWNED_PROCESS markers and an additional descendant-process sampler support cleanup inspection. All 33 unique recorded inputs rehashed unchanged, and spec/log hashes matched their receipts. None of the 151 recorded owned PIDs remained alive in the final process audit.

The final scan covered 111 log files, including agent and Ghidra application logs. It found 30 duplicated occurrences of induced lifecycle `Socket closed` errors and 4 duplicated occurrences of the known ThreadedTerminal shutdown `Bad file descriptor`. The terminal message is followed by successful structured sidecar termination, truthful terminated-state assertions, and clean asynchronous-error assertions. No unexpected error signature was found. Full classifications are in `log-scan.json`.

Evidence: `/Users/joshuahansen/dev/GhidraBoy/dist/integration-final-1fce58f/macos/acceptance`. Raw extractions, homes, logs, and observations remain under `/private/tmp/ghidraboy-macos-final-1fce58f/local-access`. No source, docs, commits, package archives, hardware budgets, battle budgets, UI runs, or soaks were modified by this worker.

Compact machine receipt:

```json
{
  "source_head": "1fce58fa759babd1df1026eadf887acb1b757c84",
  "status": "PASS",
  "jobs": 18,
  "passed": 18,
  "log_files_scanned": 111,
  "log_findings": {
    "induced-lifecycle-socket-close": 30,
    "terminal-shutdown-EBadF": 4
  },
  "results_path": "/Users/joshuahansen/dev/GhidraBoy/dist/integration-final-1fce58f/macos/acceptance/results.json",
  "raw_evidence_root": "/private/tmp/ghidraboy-macos-final-1fce58f/local-access",
  "excluded": [
    "coordinator-owned 30-minute soaks",
    "physical GUI input/focus acceptance"
  ],
  "blockers": [],
  "unchanged_hashed_inputs": 33,
  "recorded_owned_pids": 151,
  "recorded_owned_pids_alive": 0,
  "input_recheck_status": "PASS",
  "cleanup_status": "PASS"
}
```
