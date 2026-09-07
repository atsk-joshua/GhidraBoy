# SA-01 production integration checkpoint

**Status: user-requested handoff; SA-01 incomplete, SA-02 incomplete.**
Start with [HANDOFF](HANDOFF.md). The [completion audit](completion-audit.md)
separates implemented mechanisms, verified cases and remaining obligations.
`handoff-manifest.json` fingerprints the current source and last built archive;
`environment.json` identifies the exact JDK/Ghidra/native tuple.

The preceding `../sa01-20260907/` receipt remains historical. This work extends
its models and ownership rather than replacing them. Installed dynamic per-site
injection, code-derived effects, reviewed repair and shared-byte execution views
now exist in production source. They are not yet a completed SA-01 deliverable.

## Executed checks

| Check | Result / limit | Evidence |
| --- | --- | --- |
| Initial baseline | Cache-lock failure; retry up-to-date; forced rerun collided with in-progress source edit. Not a verified untouched 502-test rerun. | `baseline.log`, `baseline-authorized.log`, `baseline-rerun.log` |
| Earlier full provider | 531 tests, 0 failures/errors/skips; lint/build passed. Predates later work. | `full-2.log`, `full-2-junit.json`, `full-2-xml/` |
| Latest focused checkpoint | **75 tests, 1 failure, 0 errors/skips**; 74 passed. Canonical banked caller root decompile fails. | `focused-13.log`, `focused-13-junit.json`, `focused-13-xml/` |
| Per-site production injection subset | 7 tests passed in focused-13, including nested/nonlocal and cache reapplication. | `focused-13-xml/TEST-fi.gekkio.ghidraboy.SoftwareCallInjectionInstalledTest.xml` |
| Neutral may-return target protection | Stock three-suspicious-callers negative and repeated ordinary-analysis correction passed. | `focused-13-xml/TEST-fi.gekkio.ghidraboy.SoftwareCallMayReturnInjectionTest.xml` |
| Ownership/application | 16 tests passed in focused-13, including target creation, cleanup, user edits, cancellation and forged review rejection. | `focused-13-xml/TEST-fi.gekkio.ghidraboy.SoftwareCallApplicationTest.xml` |
| Build-input contract | Passed. | `build-inputs.log` |
| Independent review | Cross-reviews supplied concrete findings; no final SA-01 completion certification. | [integration review](independent-review.md), [effects review](independent-effects-review.md), [registry review](independent-registry-review.md) |

The focused class named `SoftwareCallInjectionInstalledTest` verifies the declared
compiler payload without test-only XML registration. Actual disposable installation
and separate processes are additionally exercised by the following campaigns;
the class name alone is not an installed-distribution qualification claim.

## Installed campaigns (retained failures)

Raw logs, manifests, self-authored ROMs and available script snapshots/native C
are copied into `installed-runs/run-N/`. Large disposable Ghidra Programs/installations
remain outside the repository at the paths recorded by each `run.json`.

| Run | Outcome | Correction / remaining obligation |
| --- | --- | --- |
| 1 | Phase 0 failed after ordinary analysis: overbroad dependency digest changed. | Removed unrelated instruction/function discovery rosters from executable dependencies; retained consumed contracts and live checks. |
| 2 | Phase 0 failed: legitimate generated payload READ references/default symbols were treated as conflicts. | Added exact compatibility policy; derived references remain excluded from semantic proof. |
| 3 | Script/native assertions reached success, but ordinary analysis emitted cross-space canonical fallthrough p-code errors. Driver correctly failed. | Canonical cross-space override removed; companion mapping used. Canonical root decompile remains a confirmed separate blocker. |
| 4 | Fresh import and separate reopen passed; repair/reapply failed on retained old view Functions with no registry site. | View cleanup stamp narrowed to relevant local state. |
| 5 | Phases 0–3 passed: fresh import, reopen, annotated repair/reapply and edit-save. Phase 4 failed with expected stale-injection rejection plus genuine deleted-overlay-address errors in queued analysis. | Source now retires mappings rather than deleting address spaces; focused coverage passes, but no completed installed rerun of that correction exists. |

Latest driver/source additions for nested cases, expected-error classification,
strict schema and optional post-repair GUI project snapshot are not qualified by
those older runs. A new complete campaign on a fresh exact artifact is required.

## Other retained diagnostic findings

- Early compilation failures and test fixture mutation guards remain in numbered
  logs; they were not erased after correction.
- `full-1.log` recorded an outdated ownership-envelope assertion and a missing
  RAM test backing block; both were corrected in later focused checks.
- Ghidra removes redundant fallthrough-override bits. Receipts now record actual
  applied state instead of assuming the bit remains set.
- The nonlocal C test incorrectly expected A as the inferred return register.
  Native debug proved RETURN at `0182` with HL; the original bytes were retained
  and the assertion was corrected to CFG plus separate actual execution checks.
  See `nonlocal-inferred-hl-native.xml` and the effects review. The unreachable-block
  diagnostic was not suppressed.
- One diagnostic invocation used an overly broad `/private/tmp` script path and
  stalled. Only its verified disposable Java PID was terminated; isolated-script
  retry logs are retained in run 2.

No active installation, private original, unrelated GUI session or publication
was modified. No GUI campaign ran. Documentation/package changes made for this
handoff need their next artifact rebuild; the existing archive hash is retained
without pretending that it contains the final handoff prose.
