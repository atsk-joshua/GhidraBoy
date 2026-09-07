# Independent SA-00 review

Reviewed 2026-09-07 against final source, pinned Ghidra 12.1.3 source ZIPs,
retained JUnit XML, process logs and baseline JSON. This review covers SA-00;
it does not qualify the complete static-accuracy milestone.

The reviewer independently audited flow/evaluator/application/baseline changes,
requested additional negative cases, and implemented only the bounded reference
ownership change. The primary agent independently reviewed that ownership change,
including envelope version 3 and preserved function receipt version 2. Thus the
reviewer's own ownership implementation is not represented as independently
reviewed by its author.

## Requirement-to-evidence audit

| Requirement | Executed evidence and review disposition |
| --- | --- |
| Reproduce stored-flow dependency gap | `flow-legacy-reproduction.xml` executes old source for target, type, primary, addition and removal. Old apply/discovery accept all five stale snapshots. Four changes alter traversal; primary alone leaves `getFlows()` unchanged. Legacy source identities are retained in `flow-legacy-manifest.json`. PASS. |
| Fingerprint every consumed reference dependency | Final `FlowIntegrityTest` tests hold mapping/memory/data/instruction inputs fixed, compare flow-reference fingerprints and reject stale apply/discovery for all five changes. Source hashes endpoints, type, operand, source and primary; raw p-code/overrides and callfixups are also dependencies. PASS. |
| Define decoded, overridden, external and generated evidence | Source and `sa00-integrity.md` use decoded effects/destinations, consistency-check stored flow, reject unsupported overrides/fixups and ignore supplemental DATA/READ/WRITE as proof. New annotations cannot invent decoded edges. Flow and interpretation regressions execute this policy. PASS. |
| Preserve apply/remove/reapply and prevent circular proof | `FlowIntegrityTest`, `AnalysisLifecycleTest`, and baseline reopen process compare independent results before/after application, remove and reapply; generated navigation data cannot supply flow. Turning data into flow rejects the old result and yields unresolved interpretation. PASS. |
| Preview changes, including transient restore | Four final `FlowIntegrityTest` cases include mutation during preview and add/remove returning to the same content hash. The transient case requires INPUT_CHANGED, no PROVEN candidates, and apply/discovery rejection. Modification number is used only within preview, not as a persisted fingerprint. PASS. |
| Cancellation and later edits | `AnalysisLifecycleTest` covers intermediate rollback; `ApplicationIntegrityTest` covers late cancellation after saved-result/final function mutation. `ReferenceOwnershipTest` covers primary-only edits and missing historical evidence; installed processes cover persisted edits. PASS. |
| Saved-result/ownership version policy | Engine is `20260907-sa00`, result schema remains 2. Old engine results reject via lifecycle regression. Ownership envelope 3 prevents old version-2 readers from silently ignoring primary evidence; current reader accepts old envelopes without manufacturing missing evidence, and retains function receipt version 2. New reference migration test and 29 function-ownership tests pass. PASS. |
| Coherent raw/overridden calls and branches | Five `InstructionInterpretationTest` cases assert raw CALL stack address/order/value and final SP, modified CALL/JP transfers, and that JP-to-CALL override does not synthesize a hardware push. Unsupported variants stop before architectural effects are applied. PASS. |
| Conditional transfer and destinations | New interpretation test retains both decoded alternatives and demonstrates that an unconditional reference override removes CBRANCH from `getPcode(true)` while raw retains it. Existing 55 `ControlFlowInstructionTest` cases independently execute compiled branch/call/return behavior including conditional paths. PASS within bounded policy. |
| Inline-payload continuation | New test proves RST pushes hardware return 0201 while convention annotation changes continuation to 0204; raw effects stay unchanged and annotated interpretation becomes explicit UNKNOWN. Removal restores original fingerprint. PASS; full helper summary remains SA-01. |
| Callfixups and physical callees | New tests invalidate on callfixup change, reject logical and banked physical callee fixups, and show bare function creation does not invalidate. Same-CPU-offset fixup check is intentionally conservative across banks. PASS. |
| Operation definitions and behavior reuse | Evaluator audit matched pinned operation behaviors and narrowed dispatch to context-free integer operations. `evaluator-before.log` retains old oversized-shift failure. Final four contract tests cover every admitted opcode, all byte widths 1–8 for shifts, signedness, extensions, extraction/concatenation, wrap and zero division. PASS. |
| Unsupported values and overlapping writes | Contract tests cover register and unique overlap, unknown dependent outputs, unsupported LOAD and widths beyond eight bytes. New compiled-SLEIGH test separately executes actual HL/H/L overlap, arithmetic wrap and SRA propagation. PASS. |
| Reproducible baseline identity and assumptions | `baseline/run.json` pins fixture and extension hashes plus three process commands/exit statuses. Fresh, annotated and edited JSON contain roots/origin, assumptions, instruction inventory, functions/bodies, physical coverage, unresolved bytes/edges, warning categories and named semantic checks/failures. PASS. |
| Fresh versus annotated coverage | Fresh: 0 code, 76 data, 65,460 unresolved file bytes. Annotated: 14 code, 76 data, 65,446 unresolved. Both use the same 65,536-byte denominator with zero overlap. Classification is explicitly not execution coverage. Named annotated checks establish bank-2 call and unresolved JP HL only. PASS. |
| Separate-process persistence and reproducibility | `baseline-driver-2.log` and `baseline-repeat-driver.log` each record three passing processes. Baseline logs verify saved result/rerun equality, primary-edit preservation through removal/reapply, user comment/function retention, stale apply/discovery after a flow edit, and rejection after another reopen. Repeat inventory equality is recorded separately. PASS. |
| Appropriate provider and installed checks | Final retained JUnit XML sums to 474 tests, zero skipped/failures/errors. `full-provider-pass.log` records successful test/ktlintCheck/buildExtension aggregate. `installed-driver-2.log` ends INSTALLED_ZIP_PRESERVATION_PASS and includes saved-instruction/lifecycle/function ownership checks. PASS. |
| Runtime identity and retained failures | `environment.json` identifies JDK 21 and pinned Ghidra 12.1.3 with patched switch-recovery.2 macOS native companion. Stock native execution is not claimed. Missing-native, sandbox/cache, intermediate evaluator and lint failures remain retained; failures are not counted as passing checks. PASS. |
| Scope and preserved backlog | Decision explicitly leaves software-call summaries, broader banking architecture, memory/interprocedural analysis and SA-01 through SA-07 open. Generic fixture is self-authored; no private ROM, GUI campaign, push or active-install mutation supplies this evidence. PASS. |

## Findings resolved during review

Reference receipts originally lacked primary edit evidence; this is now nullable
with conservative legacy handling and a newer envelope. Old supplemental migration
also no longer deletes under incomplete receipts. Possible banked callee fixups
are now rejected. Tests concretely demonstrate conditional override and inline
return mismatches. Late cancellation checks and transient-preview detection close
additional lifecycle gaps found during integration.

No unresolved SA-00 correctness blocker was found in the final reviewed scope.
Remaining limitations are explicit: unsupported overrides/fixups and conditional
internal effects remain unresolved; no memory values, callee summaries or general
concurrent Program edit isolation are supplied. Program edits must be serialized
while applying/discovering. Fresh-import baseline deliberately uses `-noanalysis`
and does not qualify normal auto-analysis or GUI behavior. SA-01 is the concrete
next task: architectural software-call/frame/payload/return summaries and retained
continuations under ordinary analysis.
