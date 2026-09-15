# Bounded W2 normal-provider probe

`run_w2_probe.py` compiles support against an explicitly selected installed candidate,
verifies every extension archive member, and copies a prepared project into a new
output directory. By default it prepares only. `--run` launches the stored normal
CodeBrowser and its normal Decompiler provider. The probe does not capture the desktop,
replace a DecompInterface, reset the provider, or alter the installed extension.

```sh
python3 tools/public_operations/run_w2_probe.py \
  --runtime /path/to/disposable/ghidra --jdk /path/to/jdk21 \
  --candidate /path/to/qualified-extension.zip \
  --project-dir /path/to/prepared-project-directory --project-name carry \
  --program /carry.gb --out /path/to/new-output \
  --observe-native --comparison --run
```

Use a self-authored prepared conditional fixture with an existing registration.
The probe applies a second domain with stack interval `0xc200..0xc500` through the
installed public script. A synchronous layout listener is installed before apply.
Display callbacks alone observe published data, not every native request. The JSON
records explicitly preserve that distinction; they are not W2 PASS attestations.

`--observe-native` adds loopback-only JDI observation for pinned Ghidra 12.1.3. It
observes public `DecompInterface.decompileFunction` entry/return breakpoints and the
public Function-taking `DecompileResults` constructor. Verified return opcodes are
at code indices 61 and 396. It reads method arguments and constructor `this`, not
private fields. Provider exception events are bound to the active native thread.
A public support callback records Program/transaction/registration state and the
result identity, allowing native results to be matched to normal displayed data.
It also samples the public task monitor cancellation flag, result cancellation/timeout/
start-failure flags, and actual return code index. Temporary JDI object handles are
pinned only for the observation lifetime; these flags never retroactively explain
an older run that did not record them.
The event thread pauses for these observations, changing timing; retain an
uninstrumented comparison and do not infer identical scheduling. Any unmatched
request, exception, terminal or observer failure leaves coverage incomplete.

`--comparison` invokes explicit proof refresh and domain reversal only after the
pre-rescue result has been retained. Those later results cannot replace the first.
The support now retains the displayed HighFunction/C plus raw instructions, proof,
emitted p-code, fixture image and source bindings before comparison. It then captures
four domain reversals in new/old/old/new order and exercises physical target and
continuation navigation. Later navigation errors and unfinished requests must remain
separate from the bounded creation observation.

`normalize_w2.py OUTPUT` binds the real timeline, public native boundaries, exception
stream and launch log into the checker receipt. It rejects a later successful result
substituted for the first committed new-domain request, including an incomplete first
result. Only an old domain present before creation can receive `STALE_AUTHORITY`;
active-owner work remains `PROVISIONAL`. Raw logs and unsuccessful normalization
attempts are retained. A narrowly scoped creation receipt does not establish complete
later navigation or closure.

The optional `check_window.check(..., support_only=True)` replays the same native
semantic kernel and source bindings with visual status explicitly `UNOBSERVED`.
Default W2/V acceptance continues to require an actual desktop screenshot. A successful
settled-result replay cannot establish first-use causality or aggregate acceptance.

Each output retains source/class/runtime/fixture manifests, command, process exit,
Program events, transaction observations and failures. JDI failures must not be
relabeled as normal-consumer failures. Disposable cleanup is not a W6 witness.
