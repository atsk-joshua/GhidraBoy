# SA-01 partial implementation receipt

**SA-01 is not complete.** This candidate implements finite software-call effect
models, Program-backed validation and safer legacy annotation review/application.
It supplies positive raw/injected/native mechanism evidence, but not reusable
production injection, interprocedural summaries, reviewed repair or general
banked intrafunction semantics. Required cases have not been excluded to claim
completion. SA-02 through SA-07 remain open.

See [decision](../../decisions/static-call-model.md),
[independent requirement audit](independent-review.md),
[mechanism investigation](ghidra-mechanisms.md),
[independent raw expectations](expected-semantics.md) and [manifest](manifest.json).

## Implemented and verified

- Four exact, versioned helper families model inline RET target transfer,
  register JP HL, selector restoration and constant-selector return. Ordered
  events account for caller pushes, helper pops, payload reads, selector writes,
  adjusted continuations and callee/wrapper transfers. Raw/effective selectors
  stay distinct. Returning-path evaluation requires explicit callee results and
  unchanged live frame bytes; it does not assert universal return.
- Program previews validate actual helper/caller bytes, context, instruction
  boundaries, physical views and payload conflicts, then recompute dependencies
  on revalidation. Forged configuration/frame and stale evidence reject.
- Legacy `FarCallConvention` now supports reviewed previews. The tools script
  applies exactly the displayed preview. Application checks dependencies before
  and inside its transaction, checks conflicts and final cancellation, and
  preserves later edits on owned removal. This remains an annotation API, not
  a new executable instruction interpretation.
- Actual Ghidra p-code execution checks injected frame bytes/SP/registers/F
  against architectural execution. The stock nonreturn heuristic negative,
  one-time repair and repeated ordinary analysis pass for the flat callfixup
  specialization. No analyzer is disabled and no recurring undo loop is used.
- Normal native cross-overlay CALL recovers the physical `rom2::4000` target and
  its function symbol after resolving primary-reference precedence. An expected
  native failure was disproved and retained. A distinct public-API test confirms
  that one function body cannot span address spaces. These results do not select
  the SA-02 architecture.

No SA-00 traversal/interpretation/engine/result changes, SLEIGH edits, compiler
ID changes, mapping-schema changes or ownership-envelope changes were made.
Existing historical receipts and unrelated work are retained. No branch, push,
publication, active installation change or GUI campaign was performed.

## Executed checks

| Check | Result | Receipt |
| --- | --- | --- |
| Accepted SA-00 source identity | All 136 source hashes match initial checkout | `sa00-source-revalidation.json` |
| SA-00 focused integrity rerun before edits | PASS | `sa00-revalidation-authorized.log` |
| Build-input contract | 7 passed | `build-inputs.log` |
| Expanded frame, Program validation, injection, native, automatic-analysis and lifecycle focus | 39 passed | `focused-7.log` and subsequent full XML |
| Enclosing-transaction stale-review correction | 18 passed | `transaction-fix.log`; final full XML contains the additional regression |
| Final provider `./gradlew test ktlintCheck buildExtension` | **502 tests, 0 failures/errors/skips; lint/build PASS** | `full-provider-final.log`, `full-provider-final-xml/`, `junit-final.json` |
| Legacy annotation persistence | **Three separate processes PASS** | `persistence-3/run.json`, phase logs and `persistence-driver-3.log` |
| Package doctor / packaged documentation links | PASS; 68 relative links resolve | `package-doctor-final.log`, `package-links.json` |
| Installed tools script | PASS, read-only inspect on disposable saved Program | `installed-tools.log` |
| Independent review | Bounded fixes reviewed; SA-01 completion rejected | `independent-review.md` |

The test tuple is Homebrew OpenJDK **21.0.12.1**, pinned official Ghidra **12.1.3**
archive and patched macOS arm64 native companion
**12.1.3+ghidraboy.switch-recovery.2**. The stock official archive does not include
the macOS native executable. No stock-mac-native pass is claimed. Exact identities
are in `environment.json`, `java-version.log` and `manifest.json`.

The persistence fixture is self-authored and starts from the accepted generic
MBC3 ROM bytes; the script installs its own helper/site bytes as explicit Program
patches. Original file identity and changed Program evidence remain distinct.
`-noanalysis` makes this an annotation save/reopen check, not normal automatic
analysis or fresh-discovery qualification. The ordinary-analysis experiment is
separately identified in the mechanism test.

## Retained failures and corrections

- The first focused baseline attempt hit the sandboxed Gradle cache lock; the
  authorized retry passed. The failure log is retained.
- Initial test compilation hit an incorrect GameBoyKind name and two Ghidra API
  mismatches. Corrected sources compile; intermediate logs remain.
- Reading an absent ownership option with a different default registered an
  incompatible default value. The reviewed evidence reader now checks presence
  before reading, avoiding changes to another component's option contract.
- The initial overlay test expected its explicit call override to outrank the
  decoded primary reference. Stock Ghidra gives the legacy primary CALL reference
  precedence. After resolving that conflict, native physical CALL succeeded,
  disproving the next expected failure. Both test failures are preserved in
  `focused-5-xml/` and `focused-6-xml/`; the final test asserts the observed positive
  identity and a separate intrafunction limitation.
- The first two persistence runs passed immediate listing checks but lost the
  later edit at save. Reacquiring an instruction object did not fix it. The cause
  was aborting an enclosing Ghidra script transaction when already-stale input
  was rejected inside a nested apply transaction. The preflight check plus inner
  recheck fixes that defect. The new enclosing-transaction regression and fresh
  three-process run both pass. `persistence/` and `persistence-2/` remain failures.

The initial full suite (501 passes) preceded the additional transaction regression
and correction. It is retained separately; the final 502-test receipt is the
current runtime qualification. No skipped JUnit cases are counted as passes.

## Remaining requirements and concrete next work

The independent audit maps every requested requirement to evidence or an open
obligation. Production per-site callfixups and validated `InstructionInterpretation`
integration are still absent. Callee return/effect summaries are supplied
premises, not derived proofs. Owned payload classification and reviewable
noReturn/CALL_RETURN repair are still absent. Executable convention persistence,
normal Decompiler-window qualification and general fresh/repaired automatic
analysis remain unverified. Fixed-MBC3 templates do not cover required banked
callers, partial mapper knowledge or arbitrary software conventions.

Next: integrate the proven cross-overlay CALL mechanism with per-site validated
injection, while comparing the SA-02 alternatives for bank-changing intrafunction
continuations and memory access. Complete the outstanding summary, ownership,
repair and persistence work before closing SA-01. The decision record does not
waive these independent obligations.
