# SA-00 implementation receipt

SA-00 is implemented and verified on this source candidate. This receipt does not
complete the static-accuracy milestone; SA-01 through SA-07 remain open.

See [decision and limitations](../../decisions/sa00-integrity.md),
[independent requirement review](independent-review.md), and [manifest](manifest.json).
The checkout already contained unrelated user changes; `initial-status.txt` records
them. No branch, push, publication, active installation change, or GUI campaign was
performed. Historical receipts and original test projects were retained.

## Changes and revalidated findings

- Actual pre-fix source execution reproduced all five omitted flow-reference
  dependencies: target, type, primary status, addition and removal. Old apply and
  discovery accepted every stale result; four mutations changed the call inventory,
  while primary-only edits did not. `flow-legacy-reproduction.xml`, its retained
  Kotlin source, and `flow-legacy-manifest.json` bind that reproduction.
- Engine `20260907-sa00` fingerprints consulted references and raw decoded effects,
  checks stored annotations against decoded flow, and stops unsupported overrides,
  fallthrough/length changes and callfixups explicitly unresolved. Generated data
  references cannot supply flow proof or invalidate their own application.
- Preview catches both persistent edits and edit/restore activity; INPUT_CHANGED
  results cannot be applied even after content is restored. Cancellation includes
  the last mutation before commit. Ownership envelope 3 rejects older destructive
  readers; missing legacy primary evidence and later user edits prevent deletion.
  Function receipt version remains 2, without re-baselining old evidence.
- The evaluator uses pinned Ghidra integer behaviors with width masks and conservative
  unknowns. The old 8-bit logical shift by 64 produced 128 instead of 0
  (`evaluator-before.log`). Contract tests and compiled-SLEIGH tests are separate.
- `tools/sa00_baseline.py` provides a self-authored fixture and reproducible inventories.
  The documented root `buildExtension` task now aliases the existing static ZIP task.

## Executed checks

| Check | Result | Receipt |
| --- | --- | --- |
| Build-input contract | PASS | `build-inputs-final.log` |
| Actual old-source flow reproduction, five mutations | PASS (bug reproduced) | `flow-legacy-reproduction.xml` |
| Initial combined new regressions | 35 passed, 0 skipped | `flow-focused.log`, `flow-focused-xml/` |
| Latest integrity, cancellation, ownership regressions | 20 passed, 0 skipped | `flow-focused-2.log`, `flow-focused-2-xml/` |
| Full provider: `./gradlew test ktlintCheck buildExtension` | 474 passed, 0 skipped/failures/errors; lint/build PASS | `full-provider-pass.log`, `full-provider-pass-xml/` |
| New saved-result/ownership check | Three separate processes PASS, twice | `baseline/run.json`, `baseline-repeat/run.json` |
| Repeatable inventory | All three parsed JSON reports identical | `baseline-reproducibility.json` |
| Final documentation package / doctor | PASS; all non-documentation payload bytes identical to the installed-tested archive | `final-documentation-package.log`, `final-package-doctor.log`, `artifact-history.json` |
| Existing installed extension and migration/lifecycle checks | PASS; 501 saved instruction identities; saved annotations, remove/reapply and function ownership | `installed-driver-2.log`, `installed/` |

Both current and old-function receipt tests ran; unsupported test tiers are not
counted as passes. Gradle's NO-SOURCE/SKIPPED main Kotlin/configuration tasks are
not skipped JUnit cases. Native debugger, private games, GUI, full hardware vectors,
SA-01 architectural prototypes and SA-07 qualification were not run or claimed.

After successful installation checks, finalized roadmap/decision documentation was
repackaged. `artifact-history.json` retains the tested archive identity and proves
all non-documentation payload bytes identical to the final archive. The final
package build-input/doctor checks pass; no runtime change followed verification.

The tuple is Homebrew OpenJDK **21.0.12.1**, pinned official Ghidra **12.1.3** archive,
and macOS arm64 native companion **12.1.3+ghidraboy.switch-recovery.2 (patched)**.
Exact archive/native identities are in `environment.json`; Java output is retained.
The official archive contains no macOS decompiler. No stock-mac-native PASS is claimed.

## Baseline inventory

Fixture: `sa00-generic-mbc3-v1`, SHA256
`d3b4ea5cc10546443573323d8b284c97429a29c7c53f748f38f94cbd3cc52944`.
ROM bytes are identical across the fresh, annotated and edited phases. Explicit
analysis roots are 0150/0180; Program entry points, assumptions and function body
ranges are recorded separately. `-noanalysis` makes fresh-import the loader-only
baseline, not a normal automatic-discovery qualification.

| Phase | Physical code bytes | Physical data bytes | Unresolved bytes | Functions | Unresolved reported edges |
| --- | --- | --- | --- | --- | --- |
| Fresh import | 0 | 76 | 65,460 | 0 | 2 |
| Annotated program | 14 | 76 | 65,446 | 1 | 1 |
| Deliberately edited flow | 14 | 76 | 65,446 | 1 | 2 |

Each denominator is all **65,536 physical file bytes**, with no code/data overlap.
These are listing classifications, not proven execution coverage. The annotated
phase passes its two named semantic checks: bank-2 direct-call destination and
unresolved JP HL. No semantic checks are claimed for unclassified bytes. All reports
retain their complete findings, warning categories, roots, body ranges and semantic
check/failure fields. The edited phase adds an explicit unsupported-flow warning;
it is retained rather than improving an aggregate by excluding it.

The new persistence sequence saves an applied result and a primary-only user edit,
reopens in a new process, verifies independent rerun equality, removes/reapplies
while retaining the edit, and rejects reference-only stale application/discovery.
A third process verifies that staleness and the user flow edit survive another reopen.
The second fresh run repeats all three processes and all inventories compare equal.

## Retained failures and their disposition

- `baseline-focused.log` and the first legacy attempt were blocked by the sandbox's
  Gradle cache lock. Authorized retries executed; these are not test passes.
- Both initial stock-distribution focused runs failed one native-dependent test
  because `os/mac_arm_64/decompile` is absent. Restoring ZIP executable modes did not
  supply that missing binary. Their XML is retained in the two baseline failure
  directories, including the originally named `baseline-extraction-failure-xml`.
- Evaluator attempts 1–5 retain intermediate compilation/fixture mistakes and the
  discovered division-by-zero behavior (Ghidra returns zero; static proof now stays
  unknown). Corrected evaluator tests pass in the combined and full receipts.
- `full-provider.log` failed because the documented `buildExtension` task was absent;
  the new alias fixes it. Later aggregate attempts retained wildcard/chained-call
  lint failures despite passing Java tests. Running formatting/checking together
  also exposed their unordered task execution; separate formatting then lint passes.
  `full-provider-pass.log` is the successful final aggregate.
- Initial baseline and installed runs hit the shared `/var/tmp` Ghidra cache sandbox
  restriction, despite the baseline's semantic marker passing. Those runs remain
  failed, not promoted. Retries used explicit isolated XDG cache directories and
  retained fresh profiles/projects; all processes passed without ERROR markers.

## Reproduce

Use the checked-in wrapper, explicit JDK 21, the pinned distribution, and the
platform native dependency stated above. Do not patch an active installation.

```sh
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
export GHIDRA_INSTALL_DIR=/private/tmp/ghidraboy-sa00/ghidra_12.1.3_PUBLIC
python3 tools/check.py --suite build-inputs
./gradlew test ktlintCheck buildExtension
python3 tools/sa00_baseline.py \
  --ghidra /private/tmp/ghidraboy-new-disposable-distribution \
  --jdk "$JAVA_HOME" \
  --zip build/distributions/ghidra_12.1.3_PUBLIC_20260905-integration1_GhidraBoy.zip \
  --work /private/tmp/ghidraboy-new-sa00-run
```

The runner requires a fresh disposable extension directory/work path and sets an
isolated cache/profile. `baseline/run.json` records exact process arguments.
The existing installed suite command and environment are recorded in `manifest.json`.

Next: **SA-01**, a validated software-call effect/return summary covering the actual
frame, payload-adjusted continuation, bank and flags, then normal auto-analysis
continuation checks. Do not bypass SA-00's unresolved policy with `getPcode(true)`
or a primary target reference.
