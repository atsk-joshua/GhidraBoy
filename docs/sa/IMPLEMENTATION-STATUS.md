# Implementation status

## W4-MEMORY-IMAGE-G3 — integrated candidate, qualification pending

The v2 task explicitly authorizes this bounded successor. Its predecessor at
`e242dc4b0eaad741c85a2abae5a13a460fc6f767` is master accepted, including the
782-test Mac/qualified-companion checkpoint. Remote CI remains failed: the
supplied exact-head artifact localizes 100 failures to the missing/non-regular
pre-flow companion marker. No CI repair or Linux qualification is included.

The new [memory/image contract](../decisions/symbolic-memory-executable-images.md)
binds symbolic WRAM inputs and alias effects into production graph authority,
with separate durable initializer history, current generation and proof freshness.
Focused memory/image, ownership/cancellation and cyclic tests pass; one read-only
review identified and corrected may-write event correlation and checker gaps.
Full and installed qualification remain pending; this is not G3 PASS. Broader W4
and G1/G4 remain open. The evidence index identifies the external batch.


## REPO-CUTOVER-DOMAIN-PERSISTENCE-FIX — INTEGRATED; RETIREMENT BLOCKED

The bounded saved-domain workflow passes. Same-traversal diagnostics first
reproduced the uncorrected rejection: exactly six dynamic-symbol IDs changed
among 412 complete dependency fields. Registration and pre-save bytes matched;
all other fields and all eight ProgramFingerprint components matched on the
first reopened production check. The correction retains dynamic semantic
identity while preserving stored symbol IDs, reference bindings, Function,
thunk, parameter, context, ownership and permission dependencies. See the
[compatibility decision](../decisions/configured-domain-dependency-identity.md).

Configured-domain authority is v2 and FarCallEvidence is v3. Saved v1 authority
rejects before semantic use without rewriting records. No general migration,
native, SLEIGH or public mapping-schema change is included. The accepted
[discovery-order correction](../decisions/configured-domain-discovery-order.md)
and all five cutover commits remain intact.

The final clean checkpoint passes 782 tests in 79 classes, retaining all 776
accepted identities with six additions and no failures, errors or skips.
Lint/build and build-inputs7 pass; tooling passes79 with one existing optional
skip. Both fresh canonical and anti-canonical Programs pass forward/reverse,
save/process exit, first read-only reopen, proof/view/native and wrong-domain
checks. Complete production preimages match byte-for-byte; stale mutation and
native refusal pass on separate writable copies. Cyclic persistence and active
continuation-order installed regressions pass on the exact final provider.

The [evidence index](evidence-index.json) retains the original failures and links
new captures, independent comparisons, final identities and the report. The
supplemental project-directory assertion exposed only Ghidra backup-index/journal
housekeeping; actual Program database/properties and production preimages remain
unchanged. Exact differences and their source-backed classification are retained.

REPO is the sole active source. The inactive source remains read-only recovery.
Validation is complete; independent backup remains unverified and blocks
destructive retirement. History cleanup is not an implementation prerequisite.
**STOP for master review.** No W4/G3 planning or implementation, W3c, broader
qualification or source retirement begins automatically.

Accepted predecessor checkpoint: **W3b-CFG-CONVERGENCE PASS**. W3 FOUNDATIONAL GRAPH/CALL CONTRACT SUFFICIENT TO BEGIN W4 / G3.

Report/result/coverage: evidence/batches/W3b-CFG-CONVERGENCE/. All three bounded checkpoints pass; full773/78, lint/build, build-inputs7, new native relationships and cyclic separate-process persistence pass. Source `ad023bf61f5273b9d1466c5292f09aa738cd6911cfb89bb2aaf4d48cc3bcc06e`; extension `de7b17963d8f009ce2dabfb1fe2090e7dd3ab29000c20cd26b8b632bd81e00ed`. Native/SLA unchanged. No active implementation or unresolved bounded blocker.

This does not close the remaining W3 dispatch, discovery, richer return/frame, nested-entry or broader invocation families. Those remain tracked W3 backlog and may proceed later where required by composition or qualification. W2 remains frozen. W4/G3 and another W3 package were not started.

## Accepted predecessor record


Current checkpoint: **W3a-PREDICATED-CALLS / embedded G2 PASS**, bounded repeated ordinary invocation **PASS**. Report: `evidence/batches/W3-OVERNIGHT/REPORT-W3-OVERNIGHT.md`; coverage/result alongside it.

One unknown-input graph preserves predicate-qualified physical instruction identities, real CALL/matched RET/frame behavior and native child Functions. Repeated same-target calls retain current byte-register inputs and distinct continuations. Full759 tests/75 fresh classes, lint/build and7 build-input tests pass; focused13 are subsets. Primary/inverted and reuse all256 B x3 witnesses pass raw/emitted/native checks, including mutation/stale rejection. Actual saved graph v2 reopens in a separate process without reimport/analysis/reapply/explicit refresh. One reviewer closed all findings.

Source `36c6bc533c6b4c66a47c640464f37730d96f649321159878239fd1ea474287d9`; installed extension `71a98c98c88ea0ae731d28b0119baa7c07bc7a2f7d30e1ba7c356ffab6f0b0d4`. Native/SLA unchanged. Explicit separate predicated registryv1->v2; oldv1 rejects non-destructively; ordinary W2v5 unchanged. Domain and limitations are in the report and source decision note. Primary758 checkpoint retained before optional work; no later incomplete delta remains.

**W2 FOUNDATION REMAINS FROZEN.** W3/G2's bounded ordinary-call witness is accepted; allW3, W2/SA requirements and product qualification are not complete. No further feature started. Broader graphs, call/flag contracts, mutable/device/async memory and dependency precision retain existing W3/W4/W5 ownership in IMPLEMENTATION-PLAN.md and DECISION-GATES.md. No W2h.

The accepted W2g predecessor source is `665e6e7050b680da923c47f5f8d7285e65f45bdd1119731b10cbaa759ec1cc80` (746 historical tests), extension55459d8df67f3804677a696472164839ad0e0de4649d2267878f24e7d90a655d. Its report and earlier W1/W2 reports/receipts remain unchanged. No recursive predecessor replay or archive reconstruction occurred.

## Repository authority and cutover review

The cumulative accepted SA implementation is reconciled into the normal Git checkout on `integrate-ghigbc`. The [original plan](IMPLEMENTATION-PLAN.md) and [decision gates](DECISION-GATES.md) retain all requirements, backlog and ownership; their dated proposals do not override this status. The [evidence index](evidence-index.json) distinguishes accepted W3b evidence from new cutover validation. G2 is accepted within W3a’s bounded domain; G1, G3 and G4 remain open. Predicate v3 rejects incompatible earlier envelopes; configured-domain v2 rejects v1 and does not establish G4 migration.

Bounded finite relational convergence is not general scalability. Native HighFunction observations do not prove architectural SP/PC or write counts. Two configured domains at one site do not establish automatic discovery. Broader W3 dispatch, discovery, frame, nested-entry and invocation qualification remain open; W2’s scheduled foundation stays frozen.

REPO-CUTOVER awaits the coordinating master’s review. No W3c, W4/G3 or other semantic work starts automatically. Local recovery is verified; independent backup has not been verified, so old-source retirement cannot be claimed complete. See [cutover policy](REPO-CUTOVER.md).

## Original REPO-CUTOVER checkpoint — historical failure

The maintained tree at `d7027eaafa86f8b76e362044841b69a8c3ec3ea9` (tree `dbf5cf1b547455bfbebb0b3894eb72fa3d8a777b`) passed one fresh clean full build/lint checkpoint with all 773 accepted tests in 78 classes, no failures/errors/skips. Build-inputs7, tooling64 pass/one accepted optional skip, debugger-pure15, changed capture Java compilation and source/package link checks passed. Cyclic setup/reopen and active production continuation order installed checks passed.

**Cutover acceptance is BLOCKED:** the fresh same-site/two-domain capture throws `Domain discovery differs from rooted proof` at the initial discovery equality guard in `SoftwareCallDomains.current`, before domain installation/native requests. Headless exit zero does not override the script exception and missing completion marker. The source fixture, capture script, provider JAR, native and SLA match accepted identities; the cause is not established. Preserve the capture and stop for master review. No guard/checker was weakened, no semantic correction or favorable retry was attempted, and W3b’s original acceptance remains attached to its original execution.

The former workspace source is isolated read-only, with no compatibility symlink. Retirement remains blocked by this validation failure and unverified independent backup. The normal checkout remains the sole active development authority; further work requires master authorization. See the exact artifact/recovery/report references in [the evidence index](evidence-index.json).
