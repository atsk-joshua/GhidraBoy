# Full Debugger teardown investigation

No repository, package, installed Ghidra dependency, or shared documentation was changed. Investigation files are owned under `/private/tmp/ghidraboy-gui-teardown`. Native GUI launches stopped on coordinator instruction; all identified owned processes have exited (`final-process-inventory.json`, ps returned no matching processes).

## Conclusion and limits

The timeout observer's teardown ordering is inadequate: waiting for an OS agent process to exit does not wait for the Ghidra TraceRMI connection's receiver/disposal work or the deferred target auto-close. Its `activateTrace(null)` is not a deactivation barrier. The installed Ghidra trace manager also has a lifecycle weakness: disposal can leave `current` pointing at a trace that it has removed from its open set, and queued target-publication callbacks have no disposal check. These two facts explain how immediate harness teardown can expose the observed `Trace must be opened before activated` stack.

The exact retained IllegalStateException was **not independently reproduced** before native GUI work was stopped. Do not characterize this investigation as a passing regression test or as proof a production fix is complete. Two completed full-tool probes did reproduce stale manager coordinates and separately logged closed-database exceptions. A third interrupted probe reproduced stale current+target coordinates, plus other errors described below. No physical UI action acceptance was attempted or qualified.

## Source evidence

Source extracted from the installed distribution's Debugger-src.zip is retained as `source/DebuggerTraceManagerServicePlugin.java`.

- `ensureActiveTrace=true` at line 293.
- `activateAndNotify` lines 1136–1138 substitutes most-recent open coordinates when activating a null trace. Therefore `activateTrace(null)` can leave the active trace selected.
- `dispose` lines 1083–1099 calls NOWHERE activation before removing open traces/listeners. This can leave current coordinates referencing the removed trace. Completed probes print current=teaching/open=0 after disposal.
- `ForTargetsListener.targetWithdrawn` line 224 queues `updateCurrentTarget` without checking disposal. `updateCurrentTarget` lines 613–619 calls `activate` when either old or computed target is nonnull. `activateAndNotify` line 1133 then throws if current trace is no longer in listenersByTrace, exactly as in the user's retained stack.
- TraceRmiHandler.dispose runs openTraces.clearAll (which withdraws targets), save/release work, then completes its `closed` future. OS process exit is independent of this receiver-side work. `connection.waitClosed()` is therefore a meaningful additional barrier, but is itself insufficient to await the later 100ms debounced save/auto-close path in ForTargetsListener.
- The usual close path `doTraceClosed` removes trace/last coordinates before selecting the next trace and emitting close events. This is more orderly than disposing all providers while a target is still closing.

Classification: evidence supports a harness lifecycle race exposing a Ghidra queued-event/disposal weakness. It does not prove this exact exception occurs under an orderly production close sequence.

## Controlled fixture and bytes

External `TeardownProbe.java` derives startup from UiActionTest, imports the packaged synthetic teaching ROM, and constructs GhidraTool from the shipped `defaultTools/Debugger.tool`, then adds the same GBC/navigation plugins as UiActionTest. It never invokes UI actions, hides providers, removes plugins, disables auto-close, or suppresses exceptions. Every managed plugin is printed in each completed log. `AUTO_CLOSE true SAVE_DEFAULT true` is asserted by observation in the logs.

The only template adjustment after one setup-dialog timeout was adding the names of already installed extensions to the template's EXTENSIONS metadata. This prevents “New Plugins Found!” prompting; the shipped PACKAGE/provider declarations remain intact.

Input package: `/private/tmp/ghidraboy-final-1fce58f/macos/both/GhidraBoy-Debugger-20260905-integration1-macos-arm64-both`. Its complete suite manifest verifies with zero mismatches. All 16 copied Python/native/ROM runtime inputs compared were byte-identical (`package-verification.json`); extension JAR, native library, teaching fixture and installed Debugger.jar SHA256 values are in `input-hashes.json`. Java21 is `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`. Python3.14 uses a private venv with the installed distribution's exact TraceRMI/protobuf wheels; an initial Apple Python3.9 venv construction failed before any test.

## Runs and observed outcomes

Each named `.receipt.json` contains exact Java command/classpath, command hash, harness source hash, start/end, PID and exit. Corresponding `-ui-actions.log` and `-ui-action-agent.log` are retained.

| Run | JVM / agent | Outcome |
| --- | --- | --- |
| original-1 | 44962 / none | Sandbox AWT startup SIGABRT, exit -6; no trace test |
| original-2 | 45388 / 45413 | Original teardown ordering, exit 0; current=teaching/open=0; logged TraceClosedException in logical breakpoint mappingsChanged; ASYNC_COUNT=0 |
| queued-1 | 45547 / none | Startup modal New Plugins Found; jstack retained; timeout exit -9 |
| queued-2 | 45861 / 45863 | EDT latch holds target withdrawal while agent exits/connection closes, then immediate tool disposal. current=teaching/open=0; logged same TraceClosedException; ASYNC_COUNT=0; exit 0 |
| live-dispose-1 | 46194 / 46215 | Disposed tool while target remained live; current=teaching/target=TraceRmiTarget/open=0. Awaiting connection closure when stopped on coordinator instruction; JVM exit143. Not completed/qualified |

Important extra failures, not hidden: live-dispose-1 also logged an uncaught `AssertionError: Duplicate node name: StaticMappingGeneration` in ObjectTreeModel before the disposal marker, and a logical-breakpoint mappingsChanged NullPointerException after disposal. The current observer's uncaught-error queue does not catch logged Ghidra service failures: original-2 and queued-2 print `UI_ACTIONS_CLEANUP_PASSED` despite a logged TraceClosedException. These are not clean runs.

Compiler/prepare PIDs 44827,44857,45800,46183 all exited0. `stop-owned-processes.json` records SIGTERM to only agent46215/JVM46194. `final-process-inventory.json` confirms every listed owned process is gone. No coordinator/user process was touched.

## Smallest proposed change, not applied

Coordinator-owned file only: `debugger/tests/ghidra/UiActionTest.java`.

Retain the accepted connection outside the action try block so finally can always complete shutdown. After requesting agent termination, await forced process termination if necessary, await the real connection's close with a bounded timeout, and await automatic trace closure on the EDT before disposing any tool/providers. Check manager open traces are empty and current trace is null; allow pending EDT closure notifications to run before tool/front-end/project disposal. Keep target auto-close/save defaults enabled. Treat a timeout waiting for those lifecycle conditions as a cleanup failure, not as permission to declare a clean run. Preserve the original action timeout and add cleanup errors as suppressed failures so diagnostics are not lost. Also retain/scavenge logged ERROR/TraceClosedException evidence rather than relying solely on Thread.defaultUncaughtExceptionHandler.

This is a proposal requiring a full-template reproduction under the newly requested single configured session or Linux Xvfb. The external probe contains a `drained` mode implementing part of that proposal; it was not run. No new macOS JVM should be launched for it.

No production patch is justified as complete by this evidence. If orderly close still fails, investigate the upstream manager's disposal invariant and deferred listeners under the full template before choosing a narrowly scoped production patch. A catch-and-ignore of the observed exception, hidden providers, or disabled auto-close would not address the lifecycle defect and is not proposed.
