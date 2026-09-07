# Register table readiness race: fixed and focused proof complete

Only `debugger/tests/ghidra/RealTraceTest.java` was changed. A 10-second monotonic deadline now polls register readiness on the EDT at 20 ms intervals before invoking the existing renderer assertions. Readiness requires a visible provider, the explicitly expected trace (new target while active; the original trace after automatic close), matching manager snapshot/thread/frame coordinates, and nonzero table cells. Capture publication alone does not guarantee that asynchronous register UI work has completed.

Renderer invocation remains outside the retry loop and unchanged. No renderer exception is caught or suppressed. The existing default uncaught-JVM collector, final collector assertion, real automatic trace release, reopened saved history, stale replacement rejection, process-exit checks, soak duration, and pause budgets are unchanged.

The file was released to the coordinator after successful external compilation. No production Java, documentation, package, commit, or running longsoak was changed by this work.

## Focused evidence

Fresh BOTH-backend package archives from `dist/integration-final-bb0720d/{macos,linux}/packages.json` were extracted into `/private/tmp/ghidraboy-register-readiness/{macos,linux}/extracted`. Each manifest payload hash was verified before execution. Only the three source harness classes were compiled into an external `classes` directory; those classes preceded installed extension and Ghidra jars on the classpath. Acceptance jars inside the archived/extracted packages were not replaced.

| Run | Exit | JVM PID | Seconds | Readiness/render checks | Real automatic trace closes |
| --- | ---: | ---: | ---: | ---: | ---: |
| macOS arm64, SameBoy + mGBA lifecycle | 0 | 64935 | 14.00 | 12 / 12 | 6 |
| Linux x86-64, SameBoy + mGBA lifecycle | 0 | 56 (container) | 42.64 | 12 / 12 | 6 |
| Linux same lifecycle with `--inject-uncaught-awt` | **1, expected** | 217 (container) | 41.27 | 12 / 12 | 6 |

Both positive runs emitted `BACKEND_TRACE_CONTRACT_PASSED` and `PASS no asynchronous JVM errors through cleanup`; neither contained uncaught errors or `ClosedException`. Every backend exercised disconnect, crash, and replacement, with active and after-automatic-close rendering.

The negative run collected exactly one `INJECTED_UNCAUGHT_AWT_ERROR`, completed all lifecycle rendering/release checks, and then failed with `Uncaught asynchronous JVM errors: 1`. Its exit 1 proves that the readiness wait did not neutralize asynchronous-error collection.

The Mac JVM is absent after completion. Docker container `ghidraboy-register-readiness` is exited, `Running=false`, `OOMKilled=false`, exit 0 (the wrapper expects negative-test exit 1). Linux used offline, nonroot Docker/Xvfb and compiler-free runtime image `sha256:1955ff1e743d7b182f5b991d3d192e05604fb7497fcdc8a2772d56dd072418ca`. This is Linux container evidence, not physical Steam Deck or GUI acceptance.

## Identity and reproducibility

- Source baseline: `bb0720dbcffc73510b06aab0c7f66ddd39df9c5b`.
- Modified `RealTraceTest.java` SHA-256: `42c8894d6132eff7872f8bf6e891f57a10a1f74cb71cf46798d934e2908b1c31`.
- Mac BOTH archive SHA-256: `a29350d218d9dcfcd6010dc568184332e3e8d9dae8d383f07ba78a3eefd434c7`.
- Linux BOTH archive SHA-256: `4827725219cf4017177f1aa707b2db7449be443f0cb638eb5b64550569f3745e`.
- Both Ghidra installations retained Debugger.jar SHA-256 `3b75891c6734b23f03c0313cb5fc582a9410676b799c8c1af3e30e3696b10bbf`.
- Mac Ghidra: `/private/tmp/ghidraboy-java-dependency/installed/distribution`.
- Linux Ghidra, mounted read-only: `/private/tmp/ghidraboy-linux-resume/ghidra-updated/distribution`.
- Compilation: host Java 21 at `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`, exit 0; `compile.json` stores the exact javac command, PID, and source hashes.

`/private/tmp/ghidraboy-register-readiness/assessment.json` stores exact positive/negative results and command/log hashes. Per-platform `*.json` receipts store full commands, PIDs, environments, start/end times, and exits. `verified-inputs.json` stores manifest verification and external class hashes. `prepare.py`, `worker.py`, and `launch.py` preserve the full recipe; their hashes and retained source/log hashes are in `command-input-hashes.json`. `owned-process-final.json` contains final owned-process checks.

Original Linux failures are preserved unchanged as `old-linux-{both,sameboy,mgba}.log`. They contain respectively 2, 1, and 3 uncaught active register-population assertion failures, no `ClosedException`, and successful later after-close rendering. This retained baseline demonstrates the pre-fix readiness race; it was not necessary to rerun or disturb the old final validations.

Initial restricted launches could not access Docker or inspect processes with ps. The authorized isolated runs were rerun with the required escalation and completed; no automatic approval rejection remains. This focused proof does not substitute for repackaging and rerunning affected final longsoaks, which remain the coordinator's work.
