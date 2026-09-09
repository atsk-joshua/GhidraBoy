# Static-analysis authority and evidence

Read [implementation status](IMPLEMENTATION-STATUS.md), the retained [implementation plan](IMPLEMENTATION-PLAN.md), and [decision gates](DECISION-GATES.md). Requirements remain in the [specification](../static-analysis-spec.md); design decisions remain in [decisions](../decisions/static-bank-model.md). Historical handoff instructions do not schedule new work.

[evidence-index.json](evidence-index.json) is the compact location and identity index. Its `external_root` is the selected SA workspace, not a required build input. Under that root, the cutover inventory maps every original `origin` plus repository-relative `path` to its SHA-256, external destination or retaining Git commit. Historical path fragments in links to the index are lookup keys, not assertions that the old path still exists. Original reports/captures are byte-preserved externally, including separate origin variants.

The earlier EX-02-05 archive remains referenced by identity and member path. Historical local paths in the preserved plans describe their planning provenance. Source-reference links resolve through the index’s `maintained_source_references` catalog to repository-relative maintained files; archived reference definitions are recorded externally without reconstructing predecessor campaigns.

See [cutover and history policy](REPO-CUTOVER.md) for recovery and main integration boundaries. Retained output must use an explicit external work/output directory. Debugger capture tools reuse `GBC_EVIDENCE_DIR`, with ignored `.local/results` as their package-local default; ordinary Gradle output remains in `build/`.
