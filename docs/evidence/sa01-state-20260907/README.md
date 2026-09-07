# SA-01 state-sensitive integration — user-requested handoff

**SA-01 and SA-02 remain incomplete.** Start with [HANDOFF.md](HANDOFF.md), the
[requirement audit](completion-audit.md) and [qualification manifest](qualification-manifest.json).

Three identities remain separate:

- Original registry4 baseline: all recorded source/dependency/package identities
  matched at start. Its 567-test, six-phase and GUI receipts remain historical.
- Registry5 artifact `e43975bc…`: 635/635 provider tests, lint/build and all six
  retained finite installed phases pass. Build-input checks pass; tooling51 has
  one explicit unconfigured Java-companion skip.
- Current registry6 source: partial caller naming/redirect/dependency fixes.
  Latest focus runs nine tests with one automatic-analysis failure. Lint passes
  after formatting. No current-source distribution/full/installed qualification.

Fresh state/discovery installed runs2/3 pass application and context checks but
fail after normal analysis changes aliases into helper thunks. Exact pre/post
inventories and errors remain in `installed-state-3/`. The latest source also
reports unmapped supplementary-fragment flow during automatic analysis. No
analyzer or veto was disabled to hide either failure.

Actual saved-v4 capture passed under the original qualified provider. New-provider
migration/reopen and new-artifact GUI checks are unrun. The existing old GUI was
identified and inspected only; it was not modified or used for headless mutation.

Representation/native experiments, independent review, focused and full failures,
exact package members, source hashes, runtime pins and next commands are retained.
No private game artifact, active installation or unrelated working-tree change
was overwritten; no push or publication occurred.
