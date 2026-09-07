# SA-01 production integration handoff

Updated 2026-09-07 at the user's explicit request to stop implementation and hand
work to a fresh agent. **SA-01 is not complete. SA-02 is not complete.** Continue
the original production-integration request; do not restart the preceding finite
models or relabel the retained experiments as production qualification.

## Start here

1. Read root/scoped AGENTS, `docs/roadmap.md`, `docs/static-analysis-spec.md`,
   `docs/static-analysis-implementation.md`, the call/bank decisions, and this
   directory's [receipt](README.md) and [completion audit](completion-audit.md).
2. Inspect git status. Branch is `integrate-ghigbc`, base commit
   `16752093dce0147afd28762a2f8918144ec571c2`. There is extensive **preexisting**
   staged, unstaged and untracked work. Do not clean/reset it or attribute every
   dirty file to this task. No commit, branch change, push or publication occurred.
3. Use `handoff-manifest.json` for current source hashes and artifact identity.
   The latest focused run is **75 tests, 1 failure, 0 errors/skips**. The earlier
   full run's 531 passes do not qualify this later checkout.
4. Fix the confirmed canonical-root failure before broadening qualification.
   Retain its failed assertion and logs; do not simply drop that caller or change
   the expected outcome to obtain a green count.

## Confirmed primary blocker

`SoftwareCallBankedApplicationTest` successfully decompiles the created execution
view, then fails when it directly decompiles the original canonical caller.
`focused-13-xml/TEST-fi.gekkio.ghidraboy.SoftwareCallBankedApplicationTest.xml` says:

> Low-level Error: Injection error: Unresolved software-call injection at
> rom1::4100: No validated software-call site at rom1::4100

The assertion is physically present around `canonicalResult` in the test. An
initial attempted string replacement failed to add it, so an earlier passing
`native-root-check.log` did **not** prove canonical-root behavior. The actual
added assertion ran in focused-13 and failed.

Mechanism: application creates a companion shared-byte execution view and marks
the canonical source Function as a reviewed thunk. Registry installation omits
the canonical site when it registers the alias. Ghidra does not automatically
redirect a root decompile just because Function thunk metadata points elsewhere.
The original CALL/RST still asks for its helper fixup at the canonical address.

Do not solve this by restoring a cross-space canonical fallthrough: installed
run 3 already produced `Address are in different spaces rom2 != rom1` p-code
errors. Decide and verify a supported normal Decompiler/public-workflow route,
including saved/reopened behavior, with explicit representation/compatibility
semantics. No normal-window GUI campaign has run. The alias-only success is real
production progress but is not proof that every normal caller-opening path works.

## Implemented code and ownership

All paths below are under `src/main/java/fi/gekkio/ghidraboy/` unless noted.

| Area | Current implementation |
| --- | --- |
| Per-site injection | `SoftwareCallInjection`, `CartridgeBusInjectLibrary`; both installed dynamic fixups declared in all five `.cspec` files. No test registration needed for production suites. |
| Persisted configuration | `SoftwareCallRegistry`, strict public JSON reader `SoftwareCallConfiguration`; `GhidraBoyTools` preview/apply/remove actions. |
| Frame/validation | Existing `SoftwareCallModel` and `SoftwareCallValidation` extended to policy 3, preserving the previous work. Hardware and manually pushed frames remain distinct. |
| Callee proof | `SoftwareCallEffects`: raw architectural execution, physical fetch/read/write identities, exact entry premises, stack/register/F/mapper results, nested configured helpers and known nonlocal RET snapshots. Raw completion and native compatibility are separate. |
| Bank prerequisite | `SoftwareCallExecutionView`: finite shared-byte mappings across distinct nonoverlapping CPU ranges; no widening of CPU pointers or copied ROM storage. |
| Reviewed mutation | `SoftwareCallApplication`, `AnalysisOwnership`, `FarCallEvidence`: physical payload reservations, compatible scalar data, false noReturn/CALL_RETURN/thunk/body repairs, actual inventories, cancellation, edit-preserving cleanup and view retirement. |
| Bounded analysis | `BankAnalysis`, `InstructionInterpretation`, `ProgramFingerprint`, `AnalysisResult`: incoming-state premise checks; complete explicit Program context may seed known registers; unknown/contradictory incoming values stop. |
| Native return protection | `SoftwareCallMayReturnInjection`: exactly one unchanged CALL, no stack/register specialization. Prevents the stock three-suspicious-callers heuristic from reasserting a disproven target noReturn. Fresh return witnesses are required. |
| Installed campaign | `tools/sa01_production_persistence.py`, `src/test/scripts/GhidraBoySa01Production.java`; uses packaged public Tools and ordinary automatic analysis in separate processes. |

The implementation is conditional on explicit synchronous register/SP/mapper
premises, not an all-input ABI or an interrupt-aware whole-ROM proof. Omitted/null
JSON premises reject rather than becoming primitive zero values. No constructor,
register layout, CPU pointer width, compiler ID or mapping-schema change was made.
Current tokens: templates/preview/effects/registry 3; software injection 1;
neutral may-return injection 1; execution-view 1; ownership envelope 4;
`AnalysisResult.ENGINE_VERSION = 20260907-sa01-production`.

## Important mechanisms to preserve

- Inline payload selector is read in the old bank; the target word is read after
  the selector write. Actual physical segments/read events are recorded. Old-bank
  bytes after the selector are not claimed or cleared. Injection folds only the
  three validated immutable reads; real stack loads/writes remain.
- Nested software calls receive an immutable candidate-configuration list.
  Actual helper-entry registers/SP/mapper must match. Only the exact validated
  helper prelude/epilogue is transparent to native compatibility.
- Neutral return markers are native **identity CALLs**, not helper-wide target or
  register assumptions. Native `FlowInfo::setupCallSpecs` and Java
  `SymbolicPropogator.previousInjectionTarget` stop self-reinjection. Actual RET
  witnesses, not fetched Function names, populate `returningNativeFunctions`.
- A known NONLOCAL RET preserves actual PC/physical target/SP/registers/mapper,
  skips the wrapper epilogue and emits a proven destination branch. Expected
  return destinations with corrupted live frames remain unresolved.
- The native callee gate rejects unsupported physical fetch/data transport,
  indirect cartridge-control stores without native bus lowering, unsupported
  target contracts and unvalidated annotation changes. Do not promote a complete
  raw result into native support by removing these vetoes.
- Ghidra normalizes redundant fallthrough overrides. Receipts store the actual
  applied bit/value; do not assume `setFallThrough` leaves the bit true.
- Clean view removal **retires** real shared mappings (non-executable, owned
  listing/functions cleared) rather than deleting the final block/address space.
  Deletion broke queued stock analysis tasks in installed run 5. Edited views are
  preserved. No analyzer/queue was disabled or canceled as the fix.
- Registry dependency hashing excludes unrelated discovery rosters, but includes
  code/mapping/context/permissions, configurations, consumed native function
  contracts, deep native datatype closure and signature source. Live ownership
  checks separately veto flow/reference/view drift.
- Registry now excludes invalid candidate sites rather than borrowing their
  conventions. A reached invalid nested site must fail native compatibility;
  unrelated still-current witnesses can remain usable.

## Verification state

See [README](README.md) for exact logs. Current focused-13 passed the other 74
cases, including strict parsing, per-field cleanup, forged Review rejection,
neutral target protection, nested calls, known nonlocal CFG/execution and the
same-DecompInterface mutation/reapply cache regression.

The full provider run `full-2.log` passed 531/531 plus lint/build **before** later
changes. `full-2-xml/` is preserved. Do not call it current full qualification.
The initial 502-test claim was not independently rerun on an untouched snapshot:
one baseline command was up-to-date, and the forced rerun collided with an
in-progress edit. Both logs are retained; later full runs exercised the existing
suites plus new tests.

Installed campaigns 1–5 are preserved under `installed-runs/`. The most advanced
run 5 passed fresh import, separate reopen, annotated repair/reapply and edit-save
phases, then failed the edited-reopen/removal phase with expected stale-injection
rejection **and unexpected deleted-address-space errors**. Retirement is now in
source and focused tests, but has not received a new complete installed campaign.
The driver was subsequently expanded for nested calls and strict expected-error
classification; those latest script bytes have not completed a full run.

No fresh native GUI/normal-window evidence, final full-provider run, final package
qualification or final independent completion certification exists for this tree.

## Remaining investigation, explicitly not reproduced yet

These are source-review concerns to test, not established failures or selected
solutions:

1. `SoftwareCallApplication.preview` checks source flow overrides/fallthrough,
   but inspect its handling of **initial** conflicting CALL references/overrides.
   Post-install reference stamps veto later edits; they must not bless a wrong
   initial native helper endpoint. Test explicit conflicting CALL overrides and
   legacy `FarCallConvention` supplemental/primary references. Preserve compatible
   knowledge and review any normalization/migration instead of clearing it silently.
2. View creation currently tests whether the site and the **first** continuation
   address have different spaces. Test a same-space first continuation that later
   crosses a ROM CPU window, e.g. return near `3ffe` and fetch banked `4000`.
   Do not claim the full following native path from only its first address.
3. Imported false noReturn/CALL_RETURN on an ordinary nested callee/caller can
   make native compatibility fail before reviewed repair gets to use its actual
   matched-RET witness. This needs precise repair-context handling, not a blanket
   exemption for overrides or all fetched functions.
4. Expand installed/ordinary-analysis coverage for true nonreturn, known nonlocal,
   banked restoring and constant-return combinations. Generic callee metadata
   inferred during analysis can be a consumed dependency. A focused native pass
   alone does not close that lifecycle question.
5. Current raw proof expects defined instruction boundaries. Missing Function
   creation is implemented/tested, but wholly unprepared discovery from absent
   helper/callee instructions is not established by manually prepared fixtures.
6. General same-CPU/different-bank paths, later continuation calls/bank writes,
   broad mapper/ABI/RAM-image/interrupt behavior and all-input summaries remain
   architectural obligations. Do not redefine SA-01 or call all SA-02 complete.

## Next commands and environment

Use the checked-in wrapper and this read-only build distribution:

```sh
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
export GHIDRA_INSTALL_DIR=/private/tmp/ghidraboy-sa00/ghidra_12.1.3_PUBLIC
./gradlew test --tests '*SoftwareCall*' --tests '*ReferenceOwnershipTest' --tests '*FarCallReviewTest' ktlintCheck buildExtension
```

The existing Gradle cache requires sandbox escalation on this host; the original
lock failure was not a product failure. Do not run shared builds or formatters
while any agent edits Java **or Kotlin tests**. After focused fixes pass:

```sh
./gradlew test ktlintCheck buildExtension
python3 tools/check.py --suite build-inputs
python3 tools/sa01_production_persistence.py --help
```

The persistence driver requires a fresh temporary Ghidra copy without GhidraBoy
already installed and a nonexistent work directory. Copy the pinned disposable
build distribution, remove GhidraBoy only from that new copy, then let the driver
install the exact newly built zip. It snapshots its script and uses the packaged
Tools script. Never reuse an active installation or overwrite an old run.
Current driver also saves a post-repair project copy for a future relevant GUI
check; no such GUI check has yet run.

The JDK is 21.0.12.1. Ghidra is pinned 12.1.3 with macOS arm64 native companion
`12.1.3+ghidraboy.switch-recovery.2`; binary SHA256 is
`5b736c3e9236667d35a732f226c99f0014736b9fe506147886a7f15ccb94939a`.
See `environment.json` for exact runtime/source-archive/JAR hashes. No stock macOS
native pass is claimed.

At handoff there are no matching disposable SA-01 headless/test processes running
(process check found only its own search). All three workers are stopped. Their
cross-reviews are retained; obtain renewed independent review after the next fixes.
