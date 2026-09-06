# M6 fixed-workload idle and cleanup evidence

Observed 2026-09-06. The first external harness run supplements the frozen pre-M7 macOS measurements. It is historical evidence, not qualification of the corrected final candidate. The original 30-minute soak limits remain unchanged; a two-minute idle series cannot replace that soak.

## Harness and scope

`RealTraceTest --idle-cleanup --failure-lifecycle` performs its normal real Ghidra/Trace RMI workload, then verifies static binding and saves the primary trace. It samples 25 times at five-second intervals during 120 seconds of stopped idle, asserting that snapshot, capture ID, guest ticks and saved trace bytes remain fixed. It records RSS, threads, handles and dropped events. After structured termination and tool/project disposal, it samples Ghidra resources five more times over 20 seconds without forcing garbage collection. This distinguishes accumulated trace history from growth while the workload is fixed.

`tools/run_idle_cleanup.py` installs a preserved runtime into an isolated user home and compiles a retained external harness-source copy. It does not rebuild or mutate the package. It copies and hashes the existing `tools/performance_limits.json` before execution and records package payloads, interpreter/platform identity, source hashes, logs and raw measurements. The existing first-five-sample warmup exclusion and three-sample endpoint medians are used with the original resource allowances as explicit comparators; full rolling medians, ranges and slopes remain available. There is no newly invented plateau threshold and no short-run release-soak PASS.

The strengthened current harness additionally inventories owned Java `ProcessHandle` descendants at initial, lifecycle and menu-launch boundaries; retains each identity through reparenting; and asserts all have exited after disposal. The runner independently follows the private process group and recursively observed descendants, matching start time to guard against PID reuse. One-second polling can miss short-lived probe processes and is not kernel-level exhaustive fork tracing. The Java launch-boundary inventory covers detached PTY targets that a process-group-only audit would miss. The current harness also records saved trace size and agent resources separately for disconnect, crash and replacement targets. These additions compiled successfully after the historical run; they require a new runtime run before claiming measured coverage.

## Static binding assertions

After automatic transfers quiesce, a new stopped capture must contain `BoundStaticGeneration` equal to the current immutable static generation. The harness then calls the real `static_mapping` RMI method with a former epoch and requires rejection; uploads the complete envelope using the current session/epoch; obtains another stopped capture; and verifies the producer's accepted generation. Saving must acknowledge the exact nonzero current capture in both `MappingSaveBarrier` and `MappingSaveReady`. Reopening the persisted trace must retain the latest completed mapping, accepted generation and exact save barrier.

These checks passed on the historical runtime. They establish a successful stable binding and persisted mapping after quiescence. They do not prove that every historical warning retried successfully, or inject a transient same-epoch transport failure. Review found that the historical Java plugin cached an attempted binding before its asynchronous transfer succeeded and did not retry within the same epoch; the parent coordinator owns the production correction and its separate qualification.

## Historical run

Runtime: `/private/tmp/ghidraboy-integration-20260906/m6-matched/candidate`.
Evidence: `dist/integration-baseline-20260906/m6-idle-cleanup-historical-2/`.
Ghidra 12.1.3; Java 21.0.12.1; macOS aarch64. Total runner time 158.7878835 seconds. The JVM and launcher/lifecycle checks exited 0, `REAL_TRACE_TEST_PASSED` was present, and the recorded private process group had no survivors before forced cleanup. No forced cleanup was required. This historical run predates the strengthened detached-descendant inventory and separate lifecycle-resource samples described above.

| Resource | Post-warmup idle range | Endpoint median growth | Original soak allowance |
| --- | ---: | ---: | ---: |
| Agent RSS | 33,040 KiB | 0 KiB | 32,768 KiB |
| Ghidra RSS | 685,920–686,480 KiB | −480 KiB | 524,288 KiB |
| Agent threads | 4 | 0 | 4 |
| Ghidra threads | 25–27 | −1 | 12 |
| Agent handles | 5 | 0 | 8 |
| Ghidra handles | 193 | 0 | 32 |

Agent RSS slope was 0 KiB/minute; Ghidra RSS slope was −369.99 KiB/minute. All 25 paused samples retained capture 51, snapshot 40, ticks 26,434,744 and saved primary trace storage 3,473,408 bytes, with zero reported dropped events. Post-disposal Ghidra handles were 181 at every sample, threads were 24, 25, 24, 20, 20, and RSS was 701,472, 701,520, 701,264, 700,880, 700,896 KiB. Closing the trace does not require the JVM allocator to return all accumulated memory to the OS, and these measurements alone are not an absence-of-leaks proof. Queue occupancy is not exposed by the Trace contract and was not measured.

The deliberately induced disconnect retained `Socket closed` at harness log line 120. The menu-launch PTY cleanup retained `Bad file descriptor` at line 167. Expected stale-action and former-epoch rejections appear in `real-agent.log`. No asynchronous uncaught JVM error was recorded, and all structured cleanup/persisted-trace assertions completed. The diagnostics are retained, not silently treated as independent successful retries.

| Historical input | SHA256 |
| --- | --- |
| `receipt.json` | `25bc07d4660c22e9475be6997ddc2af923703f999bf6588fba37e7dd26ecb5d8` |
| `session-idle-cleanup.json` | `6569d8b81c192d8d2364ae2c0f712e211aba6c9da4a52e69808f69ad0cedff7f` |
| `assessment.json` | `0fad2f25f23711e4fea6efc42b032f28badd4e540a1eaa3db3bc438c385e5075` |
| `harness.log` | `d3d638f27b6c3ce4f5d523e85a4d7d8ce9b9d920df559b6602942036b5abf2fa` |
| `real-agent.log` | `efc66a4d8616fc5b2e7a47283caeaba2fc3d6400a25ac53830be72e0d54dccb1` |
| `declared-limits.json` | `4b0f2aced9b7d8f5bdc3e5a3a257779f29349d3c3a1f4d9532f3458593f554c9` |
| `classes/RealTraceTest.class` | `3720bc00c9a09f22f77ba5d82f969696b9f46aacf826dcc60efde790005780ab` |
| `classes/RealTraceTest$IdleCleanup.class` | `e41ebcecd5b6707f41fdff003c7e6d61bbf3365ad35ddef49e7ce28d9f36931b` |

The historical receipt binds the compiled harness source hash `8f786a4ebb251cedaea5ffd8604b1d9d6e7068492c7fb4f1c9720d6bedf260ee`; the working harness has since changed. Its compiled classes are retained, but that first runner did not snapshot source text. Current runner executions retain source copies before compilation. The runtime native library was `f6494bd8d65daac11a45dac10a1911afb71b9d6f95647f6db1ecd231a029eccf`; GhiGBC extension `493b001e273cf6ebe72cf1b1458fedc198c35fe6ca12cf60e13d88bb357a618f`; GhidraBoy extension `55b1becd9002094dc0decfd0fef4ccddf8b8bc59fe0b77e7748de52154072cb5`. The receipt contains the exact dependency-lock hash and command.

An initial sandboxed attempt in `m6-idle-cleanup-historical/install.log` stopped at installer process inspection before launching a JVM (`Cannot inspect selected Ghidra lifecycle; close it and make ps available`). The authorized unsandboxed run above supplied required process inspection and localhost RMI access.

## Verification and final candidate invocation

The strengthened Java harness compiles against the historical installed Ghidra extensions; only the existing AutoImporter deprecation warnings remain. Four runner regression tests pass, covering detached/reparented descendants, PID reuse, fixed-workload invariants, survivors and unchanged declared comparator semantics. `git diff --check` passes. The original staged `RealTraceTest.java` changes were preserved; this work adds unstaged changes without modifying the index.

```sh
PYTHONPYCACHEPREFIX=/private/tmp/ghidraboy-m6-pycache \
  python3 -m unittest discover -s tools -p test_run_idle_cleanup.py -v
python3 tools/run_idle_cleanup.py \
  --runtime /absolute/path/to/preserved-final-runtime \
  --ghidra /private/tmp/ghidraboy-integration-20260906/rmi-install \
  --jdk /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  --output dist/integration-baseline-20260906/m6-idle-cleanup-final \
  --limits tools/performance_limits.json \
  --scope 'Exact final candidate identity and qualification scope'
```

A final source/artifact-matched run of the strengthened harness remains required. Physical Steam Deck verification remains deferred by the user and is outside this receipt.

## Corrected-package follow-up

The corrected SameBoy package `49d786638e10df9a35324a52df49786634267feb18df5e1f9c9fdfdd90b3e0e7` passed the strengthened external harness at `dist/integration-baseline-20260906/m7-corrected-idle-2/`, exit 0. All launch-boundary inventoried descendants exited after disposal; the primary agent remained absent. No asynchronous JVM errors were recorded. Agent idle RSS stayed at 47,008 KiB; all resource endpoint comparators pass the original allowances. The initial fresh-package attempt correctly failed because `build/projects` was absent; the harness now creates its own project directory, and the failed log is retained.

The package predates later mGBA packaging and M9 UI work; reuse requires dependency matching. A new full soak for the final combined artifact still remains.

- `receipt.json` SHA256 `de1061aeaa35486840bd0bb7bf65675148ba2c17adbcc445fb6d2143b44bcfd2`
- `assessment.json` SHA256 `c17022957da1200d84715c26ae53dcff798095fe43aed47e49dbbf1f8894d175`
- `session-idle-cleanup.json` SHA256 `cafa8ed975c062b438dd66321a3a9c36e0f74435147fbf61a8170e1f67bf850f`
- `harness.log` SHA256 `1510527352a484faa8a804ee3f7adb9bf1d7514223f38d5c87539f647c3e8a84`
