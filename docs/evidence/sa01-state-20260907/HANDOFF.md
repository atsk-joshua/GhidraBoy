# SA-01 state-sensitive execution handoff

User requested wrap-up on 2026-09-07. **SA-01 and SA-02 remain incomplete.**
Implementation was paused at this checkpoint at the user’s request. The next
agent should continue from the
reproduced automatic-analysis failure, not restart the preceding finite work.
No push, publication, commit, branch creation or active-installation update was performed.

## Read first

1. Root/scoped AGENTS.md and `docs/README.md`.
2. This handoff, [completion audit](completion-audit.md), and
   [qualification manifest](qualification-manifest.json).
3. [Independent review](independent-review.md),
   [representation investigation](representation-investigation.md), and
   [installed annotation diff](installed-state-3/annotation-diff.json).
4. `docs/decisions/static-call-model.md`, `static-bank-model.md`, roadmap,
   specification and implementation handoff. Retain all original SA/M items.

The working tree contained extensive staged, unstaged and untracked work before
this task. Preserve it. `initial-identity.json` records the original status and
verified baseline; `handoff-git-status.txt` records the handoff state. Do not reset,
stash indiscriminately, or prefix a branch with `codex/`.

## Three distinct identities — do not conflate them

| Identity | Qualification |
| --- | --- |
| Original resumed artifact, registry 4 | ZIP `a18bc013d93c2815d4e929e814e9ec18248eb357c7c185f060ac1ffbed5cdd98`; original 567 tests/six phases/six GUI entries remain historical. All 161 source, 13 documentation, seven dependency hashes and 55 installed members matched at start. |
| Built state candidate, registry 5 | ZIP `e43975bcc1340574cab9ee84e35026a6285cd52a9761137a98c3034962f7839b`; **635/635 provider tests**, lint/build pass (`full-3`), six installed finite phases pass (`installed-production-1`). Fresh state/discovery installed runs fail after ordinary analysis. |
| Current source, registry 6 | Additional caller naming/redirect, redirect removal and caller dependency fixes; **not rebuilt into the ZIP and not fully qualified**. Latest focused run: **9 tests, 1 failure, 0 errors/skips** (`handoff-focused-3`). |

`provider-source-1.json` is the registry-5 provider source snapshot. The manifest
records current source separately. The latest focused compile overwrote the loose
`build/libs` JAR with current source; the distribution ZIP still contains registry5.
Never mix that loose JAR with the qualified ZIP or installed copies.

Runtime: pinned Ghidra12.1.3 / Homebrew JDK21.0.12.1, mac_arm_64. The optional
state companion is `12.1.3+ghidraboy.switch-recovery.2.state-entry.1`, binary
`d60be1dd82b660b4123adbe2a8c7c3353a7974e856d4298208f8dc68490db871`,
patch `91d8d2bfe6b2478cfb98f2c609d975036eb523a3c481c6f05d7516c87d503388`.
Its package is `d6041e4fe0115ba709a070fe23675fcf55a93d6c9da7fe4728d76534f2190ab9`.
No stock-native, other-platform or all-input qualification is claimed.

## Implemented work to preserve

- `SoftwareCallEffects`: complete state/fetch/access transcripts, later ordinary
  and configured software calls, mapper writes, real memory/register/flag/SP
  effects, matched returns, exact loops, known nonlocal outcomes and exact-boundary
  logical frame retirement. Physical saved words are never erased by retirement.
  Callee graphs end before wrapper epilogues. Nested invocation slices and
  prerequisite graphs retain original native vetoes and explicit proofs.
- `SoftwareCallContinuationView`: state-keyed local CFG lowering, immutable
  physical ROM reads independent of code view, supported indirect mapper-store
  lowering, actual physical calls, real external return words, contextual call
  routing and terminal/nonlocal propagation. Stable anchors retain native local
  branch targets. Keep raw/native assertions; do not waive vetoes to pass tests.
- Optional native pre-flow entry protocol, dynamic Java entry injection and an
  explicit prototype cloned from each existing default compiler model. No SLEIGH
  constructor, language1.0, register width, compiler ID or mapping-schema change.
  Native protocol rejects empty/falling-through/escaping graphs. Its C header
  explicitly identifies the selected conditional execution model.
- Context aliases retain multiple declared callee states, including F=00/F=80
  callers of one physical target. Proved calls route to their own aliases.
  Public `software-call-contexts` / `software-call-select-context` select the
  canonical display context transactionally; selection does not change callers.
- Rooted speculative discovery through proof-requested physical fetches, payload
  reservation, candidate rollback before fallback, exact no-follow-flow commits,
  named-root promotion, annotation preservation and cancellation. Canonical
  discovered instructions are conservatively retained on removal.
- Independent review fixes for nested native transport, visible context domains,
  unchanged owned convention cleanup, nested ABI eligibility and selection races.
  The transient absent ownership-option read was fixed without weakening hashes.

The new native build/package/copy-install tool and ten Python tests are under
`tools/state_entry_native.py`, `tools/test_state_entry_native.py` and the new patch.
It preserves original distributions and records a separate composite marker.
Earlier native experiments and failed alternatives are retained, including the
real widened-address candidate and failed ordinary entry-injection mechanism.

## Immediate reproduced blocker

The registry5 fresh installed campaign reaches `SA01_STATE_PREPARE_PASS`, including
public application and native context selection. **Ordinary automatic analysis
then invalidates the model.** In installed run3:

- Fresh alias `FUN_gb_call_view_291_4500__4500` becomes a thunk named `rst28` and
  inherits `ghidraboy_software_call_v1` from the helper.
- The newly created canonical `state_source` also inherits that helper fixup.
- Normal DATA→WRITE refinements and logical CPU READ references are separately
  visible in the exact inventories; they must not be confused with thunk drift.
- Strict injection/return-witness checks reject changed annotations. Native and
  symbolic-propagator warnings/errors remain failures, not expected success.

Current source attempts explicit alias naming from the original label, adds the
same owned canonical→alias redirect for newly created caller Functions, clears an
unchanged owned redirect independently of source rename/comment edits, and adds
caller prototypes/bodies to registry dependencies (registry6).

**These changes are insufficient.** The latest new regression passes its initial
application checks, then fails after full ordinary analysis at
`SoftwareCallAutomaticAnalysisTest.assertRedirect`: `sourceRedirectCurrent` is
false. Its log also records stale returning-target/software-call warnings and
flow into unmapped memory at `gb_call_view_291_4500_state1::4507`.
The eight other focused tests pass, including edited-source removal and the seven
independent context/nonlocal preservation tests. Keep this failing entry/assertion. Formatting-only changes followed this run;
separate `handoff-lint-2.log` passes. The two preceding handoff attempts failed
compilation before executing tests and are retained separately.

Investigate stock `CreateThunkFunctionCmd.getThunkedAddr` / `getSimpleFlow` and
`OperandReferenceAnalyzer` thunk conversion against the alias's terminal
CALL_RETURN representation. Merely naming an alias is not a complete semantic
barrier. Also inspect automatic function discovery in supplementary code fragments.
Do not disable analyzers, remove failed Functions, pad code, invent prototypes,
weaken ownership stamps or call rejection completed support. A different bounded
listing boundary/entry representation needs actual native + normal-analysis proof.
No such replacement was implemented during wrap-up.

## Exact next commands

Set these variables for the checked-in wrapper:

```sh
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
export GHIDRA_INSTALL_DIR=/private/tmp/ghidraboy-sa01-representation/tool-installed-native-context-header/distribution
./gradlew test --tests '*SoftwareCallAutomaticAnalysisTest' --tests '*SoftwareCallStateEntryIntegrityTest'
```

Retain new logs under a new receipt name. After focused fixes pass, include all
`*SoftwareCall*`, `InstructionInterpretationTest`, `ApplicationIntegrityTest` and
new classes, then run `./gradlew test ktlintCheck buildExtension`, build-input and
tooling suites. Every changed provider artifact needs its own installed campaigns.
Do not run simultaneous Gradle builds or mutate the same Program in GUI/headless.

Two installed drivers (both require new disposable installs/work paths):

```sh
python3 tools/sa01_production_persistence.py --ghidra NEW_COPY --jdk "$JAVA_HOME" --zip NEW_ZIP --work NEW_WORK
python3 tools/sa01_state_persistence.py --ghidra NEW_COPY --jdk "$JAVA_HOME" --zip NEW_ZIP --work NEW_WORK
```

The first retains all six finite persistence phases. The second has seven
processes: fresh discovery/apply, reopen/context cancellation, annotated repair,
edit/save, stale rejection/reapply, removal and final reopen. Its context fixture
also verifies actual callee c211 writes for both flag domains, selected-context
persistence and late callee rename/comment preservation. All input code is
self-authored. Earlier failures must remain retained.

## Saved-v4 migration and GUI work still pending

Actual v4 capture **passed** using the original qualified provider on a copy of
`/private/tmp/ghidraboy-sa01-resume-run-7/gui-projects`. This was not a synthetic
registry-version rewrite. Captured instructions agree with fresh pseudo decoding;
raw registry/ownership, images, user knowledge and original canonical targets are
in `migration-capture/`.

Prepared workspace: `/private/tmp/ghidraboy-sa01-state-migration-1`.
Old runtime: `/private/tmp/ghidraboy-sa01-state-legacy-runtime`.
Script: `src/test/scripts/GhidraBoySa01StateMigration.java`.
**New-provider `migrate` and independent `check` have not run.** Copy old-projects
to a new-projects directory before using them. Pass `evidence` and the copied
`configurations.json` to `migrate`; pass `evidence` to `check`. Use the final new
artifact and preserve the old-projects source.

The original GUI is still open. At recheck it was PID60837, bundle
`fi.gekkio.ghidraboy.sa01.window`, using original install7 and
`/private/tmp/ghidraboy-sa01-window-20260907/projects/sa01-production.gpr`.
Open-file evidence confirms this is distinct from the archived GUI-projects used
for migration. Its desktop was accessible. It was only inspected; **no new-artifact
GUI decompilation was performed**. Reverify process/install/project before reuse.
Use new GUI/project/profile copies and a verified optional companion; never run
headless mutation against an open GUI Program. The old wrapper build command and
accepted profile remain in the previous receipt. Do not mistake old GUI success
for validation of this new artifact.

Useful retained locations:

- Registry5 finite campaign: `/private/tmp/ghidraboy-sa01-state-production-run-1`
  and immutable install `/private/tmp/ghidraboy-sa01-state-production-install-1`.
- Failed fresh campaigns: `/private/tmp/ghidraboy-sa01-state-discovery-run-{1,2,3}`;
  each install and saved failed Program remains separate.
- Optional native package:
  `/private/tmp/ghidraboy-sa01-representation/tool-native-build-context-header/state-entry-native-mac_arm_64.zip`.
- Original ZIP backup: `/private/tmp/ghidraboy-sa01-state-baseline-a18bc013.zip`.

## Remaining requirement boundaries

Revisiting one *physical configured software-transfer site* with multiple
register/mapper/SP premise records still conflicts with the one-configuration-per-
site registration rule. Ordinary repeated callee contexts are a different feature
and must not be used to claim this case. Wider dispatch, RAM image lifetimes,
interrupt/DMA effects, mapper families and all-input coverage remain explicit
SA-02/03/04/06/07 obligations. The current graph/data ledger is not whole-ROM
instruction discovery or complete bank-sensitive reference recovery.

Finish the original requirement audit after fixing normal-analysis integration,
actual saved migration, complete installed state lifecycle and new normal-window
checks. Larger counts or successful isolated native graphs do not close SA-01.
