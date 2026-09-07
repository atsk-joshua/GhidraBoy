# Independent migration and lifecycle preparation

Status: preparation and read-only identity verification; **not current-artifact
qualification or SA-01/SA-02 approval**. No build, formatter, installation update
or Program mutation was run by this reviewer. The primary owns serialized
production integration and execution. Historical receipts remain unchanged.

## Revalidated original migration evidence

The original baseline ZIP at
`/private/tmp/ghidraboy-sa01-state-baseline-a18bc013.zip` still hashes to
`a18bc013d93c2815d4e929e814e9ec18248eb357c7c185f060ac1ffbed5cdd98`.
All 55 non-directory ZIP members match the corresponding installed members in
`/private/tmp/ghidraboy-sa01-state-legacy-runtime/Ghidra/Extensions`.
Its provider JAR hashes to
`f7502b8a0c7d80c0e171b5f77ca51f08e9f4f190e680217c1c99e40923c8f9f7`.
This is registry4 evidence, distinct from registry5 and the current loose JAR.

All nine entries in the retained
`../sa01-state-20260907/migration-capture/source-project-hashes.json` match both:

- `/private/tmp/ghidraboy-sa01-resume-run-7/gui-projects`;
- `/private/tmp/ghidraboy-sa01-state-migration-1/old-projects`.

The canonical database file `sa01-production.rep/idata/00/~00000000.db/db.3.gbf`
still hashes to `7d5fd40dde93845453f8ffc4f91b1cbb581ba556b3d4cd8616acdcc57bc4511e`.
Every captured JSON except the repository-only source-project inventory has an
identical peer in `/private/tmp/ghidraboy-sa01-state-migration-1/evidence`:

| Capture | SHA256 |
| --- | --- |
| actual-v4-capture.json | e8c3ec6f1e5298d2c0b4244e907f01b7bb6c93c5358a14e5b34983b35d2b2e91 |
| actual-v4-registry.json | ce8201632206360c6870dd0d328913e6e629377cf2e9944174789962971034f1 |
| actual-v4-ownership.json | f9f2104add7c678b87bade450cca10646ae31ff65bbcc3683355d005492afda7 |
| configurations.json | 8b705e755f7fa7b8939b3426075d319322ae65c73b3eb5e6d9428c26f62a0cf0 |
| decode-old-provider.json | add2c8b9c08b32e3799cfc000d9e242c2877f05d0288fdcc79693c68d29154be |

The snapshot contains 86 canonical Instructions, four initialized images, ten
canonical software-call targets and three active execution views. Its user
knowledge inventory contains 19 symbols, 18 Functions, 61 comments and three
references. This is a nontrivial actual saved-provider source, not a rewritten
version field. The retained old capture log shows processing read-only and
`SA01_STATE_MIGRATION_CAPTURE_PASS`.

Current `src/test/scripts/GhidraBoySa01StateMigration.java` and the old capture's
copied script both hash to
`e3dc344eecfd8f75c183b0492a4746fde4810562888d42b67ac313c883b8eb6c`.
Revalidate again if the script changes before final execution.

## Exact migration sequence to execute after the final build

Create a new work directory and copy `old-projects` into its `new-projects`;
copy the capture evidence and configurations, preserving original directories.
Use the final exact provider ZIP in a new disposable distribution and copy the
current migration script into a new script directory. Verify every installed ZIP
member, JDK, Ghidra and native identity before opening the copied project.

The first process should migrate before ordinary analysis can consume incompatible
old executable records, then independently check after that analysis. With
`MIGRATION_WORK`, `NEW_GHIDRA` and `JAVA_HOME` set to verified absolute paths:

```sh
JAVA_TOOL_OPTIONS="-Duser.home=$MIGRATION_WORK/profile" \
  "$NEW_GHIDRA/support/analyzeHeadless" "$MIGRATION_WORK/new-projects" sa01-production \
  -process production-mbc3-v2.gb -scriptPath "$MIGRATION_WORK/scripts" \
  -preScript GhidraBoySa01StateMigration.java migrate "$MIGRATION_WORK/evidence" "$MIGRATION_WORK/evidence/configurations.json" \
  -postScript GhidraBoySa01StateMigration.java check "$MIGRATION_WORK/evidence"
```

Then use a distinct process to reopen/check the same copied project with ordinary
analysis and the same verified distribution:

```sh
JAVA_TOOL_OPTIONS="-Duser.home=$MIGRATION_WORK/reopen-profile" \
  "$NEW_GHIDRA/support/analyzeHeadless" "$MIGRATION_WORK/new-projects" sa01-production \
  -process production-mbc3-v2.gb -scriptPath "$MIGRATION_WORK/scripts" \
  -postScript GhidraBoySa01StateMigration.java check "$MIGRATION_WORK/evidence"
```

Retain each process log and its receipts separately: the script writes common
`*-check` output filenames, so archive the first check before the second process
to avoid overwriting evidence. Require markers, exit status and phase-specific
log review. Repeat the nine original source-project hashes after all mutation.

The script verifies unchanged raw canonical decoding versus both saved records
and fresh pseudo decoding, original physical input/image hashes, retained user
knowledge, initial byte-exact old registry/ownership, explicit old-reader rejection,
public remove/preview/apply, retired mapping identity, current physical CALL
endpoints and independent migrated registry/ownership equality. It does not
manufacture fresh proof by changing an old version number.

Its knowledge comparison intentionally covers canonical USER_DEFINED symbols,
Functions and references plus canonical comments. It does not inventory all
bookmarks, types, context ranges, imported annotations, or user edits inside
derived spaces; broad preservation claims must remain scoped or acquire those
additional inventories. It excludes Function thunk/fixup/noReturn as owned
interpretation, so those fields require independent ownership and lifecycle
assertions rather than an unqualified claim that all Function metadata matched.

## Lifecycle driver findings requiring correction

1. `tools/sa01_production_persistence.py` records `otherWarnings` and
   `nativeDiagnostics`, but `passed` ignores both lists. Its exact expected stale
   rejection is scoped to `edited-reopen` and site0150, which should be retained.
   The blanket warning omission does not implement the user's strict accounting.
2. `tools/sa01_state_persistence.py` accepts every WARN containing
   `Removing unreachable block` and excludes it from phase failure. Such lines
   need a proven exact phase/site/count disposition or must fail. The fixture's
   expected stale rejection is caught and recorded by the script; unrelated
   injection/return-witness warnings must not receive that allowance.
3. The state driver verifies and records all installed archive members; the
   finite driver merely extracts its ZIP and hashes the source archive. Final
   finite qualification needs explicit installed-member checks too. Neither
   campaign may load current loose `build/libs` contents into an older archive.

### Source corrections prepared for primary execution

Both drivers now count every nonexpected process WARN/ERROR as a failure, while
retaining native/other-warning diagnostic categories in their receipts. The finite
negative allowance matches only the two exact observed logger messages for
site0150 in `edited-reopen`; another phase, site, reason, logger, or appended error
does not match. The state script catches its expected rejection internally, so
its process log has no warning/error allowance. The finite driver now verifies
every extracted member against its ZIP and records `installedMembers`, after
rejecting paths outside the extension before extraction.

Eight new tests in `tools/test_sa01_log_accounting.py` cover phase/site/reason/
logger isolation, native/unknown warnings despite success markers, mixed expected
and unexpected failures, exact installed-member inventory, substituted loose JAR
rejection and archive escape before extraction. These edits have **not been run
or formatted by this reviewer**, as requested for serialized primary execution.
Run `python3 tools/check.py --suite tools` with the broader required tooling
campaign; no old qualification receipt is retroactively relabeled.

The finite campaign retains six separate processes. The state campaign retains
seven: prepare/verify, context-cancel/verify, annotated-reapply/verify, edit,
stale-reapply/verify, remove/removed-verify and removed-reopen. Source assertions
include actual c211 callee writes22/33 in opposite flag domains, canonical public
selection and persisted selection, distinct alias calls, cancellation after a
real context-comment mutation, both source entry paths, banked reads and later
ordinary-call effects, stale rejection/reapply, late callee rename/comment and
removal. Source presence does not establish that later phases have run.

## Native and normal-window identity

At the reviewed optional companion distribution
`/private/tmp/ghidraboy-sa01-representation/tool-installed-native-context-header/distribution`:

| Input | SHA256 |
| --- | --- |
| mac_arm_64/decompile | d60be1dd82b660b4123adbe2a8c7c3353a7974e856d4298208f8dc68490db871 |
| state-entry-native.json | 9c2edda6aca19ead42108fd763ac09cc73d7527bd6b3d69b2c0609a3cca35164 |
| SoftwareModeling.jar | 220c419c4d94d65faddecf77ba899213b66382c092a3753be56f3bb08112c96f |
| application.properties | fb9b6292c801e4a18b7c20829437d3b18b2241b273aea9b1cbdebdf3e5d0dc15 |
| JDK21 release | 7b6f4e84249287203d8e1857254307a6b2dc0643b1efdeef5fa2aeaf791866f0 |

The attempted read-only `ps` inspection was denied by the filesystem sandbox
(`operation not permitted`), so this reviewer has not revalidated old GUI PID or
open-file identity. No GUI claim follows from the historical PID60837. The primary
must identify its actual process/install/project and use a new final-artifact
window/project/profile. Headless must never mutate that open GUI Program.
Explicit absent-protocol behavior and ordinary static-provider behavior outside
the optional protocol are separate required checks.

Renewed production review and requirement-by-requirement completion assessment
remain pending the causal fix and exact current-artifact results. Repeated
ordinary callee contexts remain distinct from the unfinished one-configuration-
per-physical-software-site requirement. Original SA-02/03/04/06/07 and M0–M10
scope is retained.
