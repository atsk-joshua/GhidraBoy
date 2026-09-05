# dev3 final hardening evidence

Validation source commit: `b4d3b605f6333b3f6045f3ea0f03479ec935bb62`, branch
`modernization`, **clean** when the full runner completed. This descends from the
reviewed `7dd6ed18652dd3eaea0161506ebf9b711b0ad55f`; the intervening user commit
`35adebd` was preserved. Later evidence-only commits do not change packaged inputs.

Artifact: `ghidra_12.1.3_PUBLIC_20260905-dev3_GhidraBoy.zip`.
SHA256: `4c0fd62c1046ca52ad75a99953c4d8851d13efa568351f346fd0630cbfbc597b`.
Two clean package builds produced that identical hash. All 36 ZIP file members were
also compared byte-for-byte with the disposable GUI installation before launch.

| Requirement | Result | Evidence |
| --- | --- | --- |
| Function ownership preservation | PASS | 29 FunctionOwnershipTest cases, including 20 edit categories through each of three removal routes, variable detail edits, in-place type mutation, legacy receipts with/without edits, existing user functions, cancellation and unchanged removal |
| Original six audit reproductions | PASS | All six AuditRegressionTest cases retained |
| Full native tests and lint | PASS | 428 tests, 0 failures, 0 errors, 0 skipped; clean build and final tests both passed |
| External vectors | PASS | 21 files, 21,000 vectors, revision f9c30210245dd691661db39f5ace022c465ecc2f, per-file hashes verified |
| Ordinary vector samples | PASS | 21 files, 168 vectors; separate from external count |
| Installed lifecycle | PASS | Actual ZIP, separate processes, user locals/inline/parameter comments/type edits and legacy receipts survive reopen/removal/reruns; unchanged functions removed |
| Historical migration | PASS | Actual 11.3.1 project creation, copied 12.1.3 upgrade/reanalysis/reopen; original project tree hash unchanged |
| Schema, package doctor, dependency digests, epoch invalidation | PASS | Actual runner receipts and logs |
| Reproducibility | PASS | Both clean package hashes equal the SHA256 above |
| Interactive GUI workflows | BLOCKED | gui-evidence.json: verified install, but conflicting 12.1.2 process appeared during shared-Java target selection; zero workflow PASS claims |

The first maintained failing run (24 tests, 22 assertion failures) is retained at
`../function-ownership-before.log.txt`. This includes local/inline deletion and
missing preservation diagnostics. The expanded final suite has 29 cases; its XML
is retained in `test-results/`. Full machine evidence, dependency hashes, commands,
platform details, exact test suite digests and migration receipts are in
`validation/release-evidence.json` and `validation/`. Raw logs have `.log.txt`
suffixes here to keep them tracked; original absolute receipt paths remain verbatim
and also exist under `/tmp/ghidraboy-dev3-validation` and `build/reports/evidence`.

The function receipt envelope and per-function proof are version 2. Only unchanged
bare functions with a default undefined return are eligible for destructive removal.
Variables, non-default types, tags, thunks and namespace children make ownership
uncertain and cause retention. Legacy proof is never re-baselined; retention
relinquishes destructive ownership. Discovery forwards the preservation reason.

No push, GitHub write, release publication or GhiGBC change was performed. Baseline
remote CI run 33956121926 was read-only verified; this continuation was validated
locally on macOS arm64 / Ghidra 12.1.3 / OpenJDK 21.0.12.1.
