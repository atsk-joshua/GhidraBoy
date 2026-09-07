# Renewed independent integration review

This is a source review of the resumed SA-01 integration, not SA-01 or SA-02
completion certification. The reviewer did not author the provider changes,
run builds, mutate Programs or modify implementation files. The primary agent
owns executable qualification and exact final artifact identities. Existing
failures and the previous handoff remain historical evidence.

The review read root instructions, the documentation map, static specification,
implementation handoff, roadmap, call/bank decisions, production handoff,
completion audit and preceding independent reviews. There are extensive
preexisting staged, unstaged and untracked changes; none were reset.

## Findings sent to the primary owner

1. **P1 — a current execution alias can reauthorize its stale canonical nested
   configuration.** In the initially reviewed registry, canonical Site records
   carry `executionAlias`, while the alias record has a null alias field.
   `current(canonical)` checks both receipts, but `current(alias)` checks only
   the alias receipt. `effects()` supplies a configuration whenever either
   record is current. A changed canonical CALL reference can therefore fail
   the canonical stamp without changing the local view stamp; the alias then
   supplies that stale canonical configuration as a nested candidate.
   `SoftwareCallEffects` deliberately treats an exact configured helper as
   transparent to ordinary native-annotation vetoes, so this asymmetry crosses
   the invalidation boundary. Both entry paths and nested candidate selection
   must require the paired canonical/alias receipts, with explicit canonical
   identity. A regression should mutate only a nested canonical flow reference
   and verify alias resolution and the outer summary reject it.
2. **P1 — nested metadata repairs are absent from the reviewable preview.**
   The new matched ordinary RET witnesses authorize repairs at
   `summary.returningCalls()` and `returningNativeFunctions()`. The public
   `Review.inventory()` exposes only top-level source/helper/target metadata,
   while apply clears nested CALL_RETURN and noReturn state and installs
   neutral markers. The review must expose each nested site/target, original
   and intended metadata, and matched-RET provenance before those mutations.
   Ownership rollback receipts are necessary but do not replace the S-13
   pre-apply inventory. Separate-process checks should verify the inventory and
   saved edits as well as successful native C.

These are source-established findings; the reviewer did not independently
execute reproductions. Disposition and post-fix review must be appended rather
than silently removing the findings.

## Mechanism observations and limits

The new canonical-root solution retains the exact physical target CALL and
architectural helper operations, then lowers the proven continuation CFG to
local p-code branches. This directly addresses the failed canonical root
callback; it does not rely on Function thunk metadata redirecting a root
decompile. Relative branch distances remain relative when the emitted tail is
appended to the helper payload. Each instruction receives separate relocated
unique storage while preserving intra-instruction overlapping temporaries.
Physical continuation ranges are rederived under the returned mapper, and
canonical source fallthrough stays in its own space. Reusing the same constant
configuration under another registry name alone would not establish these
semantics.

The reviewed effects change defers only precise CALL_RETURN/noReturn vetoes
keyed by site and physical target until an ordinary native call frame reaches
its matched RET. Other flow/reference, thunk, inline, fixup and stack-purge
vetoes remain. A complete raw path is still distinct from native compatibility.
The first-address-only continuation check has been replaced by examination of
all derived continuation segments, including subsequent ROM window changes.
Initial conflicting helper endpoints and override references now reject before
application rather than being blessed by a post-install stamp.

The continuation mechanism remains finite and rejects further calls, indirect
flow, selector writes, unsupported data transport and SP changes. Its addition
does not fulfill general same-CPU/different-bank execution, later continuation
call/bank effects, wholly unprepared import discovery or all-input summaries.
An explicit rejection preserves soundness but does not complete a required case.
Current provider/native/executor/save-reopen/normal-window observations must be
audited separately; old full-test passes do not qualify these new bytes.

## Initial reviewed identities

SHA256 values captured during this review (source integration was ongoing):

| Source | SHA256 | Comparison with production handoff |
| --- | --- | --- |
| SoftwareCallApplication.java | `86f13562d83338eb959396e175cc279fe2aeaad159d11aaef107f7c89acead7c` | changed |
| SoftwareCallRegistry.java | `4f747e35067c28e653831abe21765e3d60f8226908cc9a990f8d3eaeb36afa9e` | changed |
| SoftwareCallInjection.java | `62cfba82db33f198d1e2d650623aabf84ee8a1432135182b963b420d65023676` | changed |
| SoftwareCallExecutionView.java | `7bb47ed828e2c878623e2c7bf8d8a18c564970c6c6bec8df0537af7f8fc4133a` | changed |
| SoftwareCallEffects.java | `a26bbd7582fd1bf55ef8d3f1bb01d2d55783ad64c26fd6d8f3c97c0bd9098fc8` | changed |
| AnalysisOwnership.java | `fe733f887df84ea3395fab1c0c14d17023a78de770a4ed46e426caa184403cb2` | identical |

All source filenames above are in `src/main/java/fi/gekkio/ghidraboy/`.

## Post-integration source recheck

Both initial P1 findings are corrected by source inspection:

- `Site` now stores explicit `canonicalAddress` and `executionAlias` on both
  paired records. `current()` begins with the canonical receipt regardless of
  the requested entry and requires the alias's matching physical identity and
  live receipt. Because `effects()` uses that same predicate, neither paired
  record can supply the configuration after canonical-only or alias-only drift.
  The adversarial test adds a conflicting reference to each entry in turn and
  requires both registry resolution and both injection callbacks to reject.
  The reviewer inspected the regression but did not run it independently.
- `Review.nestedRepairs()` now exposes the exact ordinary call site, physical
  target, original/applied flow, original noReturn/fixup, applied neutral marker
  and matched architectural RET provenance. The packaged Tools preview returns
  this inventory, and application saves it alongside the original site inventory.
  Apply recomputes and compares the whole review before mutation. The regression
  checks the old and intended metadata, installed raw/native compatibility and
  reversible repair. The installed driver checks the repaired nested metadata
  after analysis/reopen; a direct assertion on the saved nested preview inventory
  was not found and remains an evidence gap rather than a demonstrated defect.

The ordinary CALL_RETURN repair now uses the architectural next address
(`site + instruction length`), avoiding Ghidra's null default fallthrough under
the false terminal annotation. The continuation scan now separates physical
CFG discovery from the stronger data/SP requirements for transported tails.
All fetched instruction bytes still require immutable initialized ROM with
the expected canonical address; additional calls/indirect flow and unresolved
selector changes remain unsupported. The stronger rules still apply to every
tail emitted into canonical local p-code or a companion mapping.

The added executor regression compares raw and lowered continuation operations
for both JR NZ outcomes and both conditional RET outcomes, with three distinct
callee flag/register results and two live outer return words. It explicitly
checks the physical target, stack bytes/SP, PC, flags/registers and selector
write, then decompiles both canonical and mapped roots. This is useful independent
expectation coverage rather than a test that only restates emitted opcodes.
Its executed outcome belongs to the primary focused-test receipt.

No further concrete semantic defect was found in this bounded source recheck.
This does not qualify unrun installed/GUI behavior, broaden supported continuation
effects or close the original SA-01/SA-02 obligations.

| Rechecked source | SHA256 |
| --- | --- |
| SoftwareCallApplication.java | `675525cc2cd254b003a56ae473ae2ddde23e06dabc4a6c17791799a818653a2c` |
| SoftwareCallRegistry.java | `80a3b4791e2eeaf45a0a1b30b6e61f2c4036e4bc0f899a2e86ae9aeca5f1001d` |
| SoftwareCallInjection.java | `62cfba82db33f198d1e2d650623aabf84ee8a1432135182b963b420d65023676` |
| SoftwareCallExecutionView.java | `b0a3e30c7c715adea6d5dbc0d1c30d2eeac10942b5323e43407c03328208fb8f` |
| SoftwareCallEffects.java | `a26bbd7582fd1bf55ef8d3f1bb01d2d55783ad64c26fd6d8f3c97c0bd9098fc8` |

## Canonical native-tail and concurrent-analysis follow-up

The retained `canonical-tail-before-native.xml` exhibits a local branch targeting
the CALLOTHER emitted by the continuation's `LD (c200),A`. Pinned native
`FlowInfo::updateTarget` (`flow.cc:204-212`) updates the visited first operation
for an address, but does not retarget arbitrary local sequence-number edges.
Replacing that nested injection operation can therefore lose the branch target.
The inspected correction emits a stable scratch COPY at every continuation
instruction entry. Edges point to these anchors, scratch pages are separate from
relocated instruction temporaries, and intra-instruction relative offsets remain
unchanged. Dead scratch assignments affect no architectural state.

Canonical mapped-continuation sites now receive owned CALL_RETURN/null listing
fallthrough so native initial flow recovery cannot speculatively decode the old
physical payload/continuation before processing the injected complete CFG.
The injected tail still contains its actual returning or looping control flow;
the source/helper/target are not thereby classified as architecturally
nonreturning. `canonicalTransport=TERMINAL_CONTINUATION_EXPANSION` and
`appliedCanonicalFlow=CALL_RETURN` are separate public inventory fields from the
derived exit classification. Alias entry paths retain normal mapped fallthrough.
Raw architectural pushes and Function bodies are preserved, and the paired live
receipts continue to reject later changes. Injection policy is now version 3.

Stock `ConstantPropagationAnalyzer.java:192,335-375` runs analyses of multiple
functions through ConcurrentQ. `SymbolicPropogator.java:2725-2729` materializes
references while sibling callbacks can be deriving effects; its callback handler
at 1793-1798 logs exceptions as WARN and returns no injected p-code. This supports
the observed optimistic-validation races. Both injection callbacks now retry the
complete resolution/derivation/emission at most four times, only after a failed
attempt during which the Program modification number moved. Every attempt keeps
the dependency and live-ownership checks. Stable stale input still fails. No
analyzer, queue, warning or consumed dependency is suppressed by this mechanism.
The exact modifying event in installed run 2 was not traced independently.

The primary reports focused run 8 passed 94 tests plus lint/build, including 14
adversarial cases and same-DecompInterface canonical/alias payload mutation.
The reviewer inspected the source tests, not their execution independently.
The new installed campaign was still running at this review point; its result
cannot be inferred from the focused pass.

## View-stamp normalization review

The new `software-call-view-3` stamp permits ordinary refinement of proven
decoder DEFAULT DATA references to generated READ/WRITE references. Its token
change makes old view-2 receipts fail the current comparison; cleanup therefore
conservatively retains those mappings rather than declaring them newly owned.
Old receipts are not silently recomputed. This is preservation, not qualification
of old saved Programs: incompatible executable registry/injection dependencies
must still reject until reviewed reapplication, and retained views must remain
visible in the migration/removal diagnostics.

One narrow **P2 ownership finding** was sent to the primary at this checkpoint:
the direct-bus fallback in `decodedDataReference()` checks the pointer target but
initially accepts any valid operand index. A DEFAULT primary DATA reference to
`c200` attached to the A operand of `LD (c200),A` is not decoder output, yet that
fallback would omit it from the view stamp. The existing unrelated-DEFAULT test
uses another destination/mnemonic index and does not cover this case. Require
the actual destination operand as well as the exact direct-bus target, and add
the same-target/wrong-operand negative before considering this finding closed.
The initial ownership hash for this finding is
`62a78c0616e7675d01149c885cc0d0a55a5c22d2ae91ab5e03d04fb1fab1116c`.

Additional source identities at that checkpoint:

| Source | SHA256 |
| --- | --- |
| SoftwareCallApplication.java | `cd31f48e65d783ab748530f9f4df8bc8bc5a1baeba7c74bceb7902f74f9aec57` |
| SoftwareCallRegistry.java | `915ce976cbc9723bdf329a24e5fcf38b3af7b4569564da2e202fc6188d42a174` |
| SoftwareCallInjection.java | `db705adfc4f50502baaaccb3029986cea6fd58fa1ca0cd2f4c8d5ef25652e1ff` |
| SoftwareCallMayReturnInjection.java | `dfd5302cb48ed454aa2875d5979fcbe00099229ecaac996b07ac4ae18723ef74` |

## Narrow ownership correction and final bounded source review

The P2 wrong-operand finding is corrected. The direct-bus decoder-reference
fallback now requires operand zero as well as the exact constant destination.
The inspected SM83 constructors `LD Mem8,A` and `LD Mem16,SP` place their
destination in operand zero; their A/SP source operands cannot qualify through
this fallback. The regression explicitly observes A at operand one, adds a
DEFAULT primary DATA reference to the correct CPU destination on that wrong
operand, requires both canonical/alias resolutions to reject, and verifies the
reference remains after edit-preserving removal. Its restoration step also
checks both entries become current after deleting only that edit.

The retry bound is now **16 complete attempts**, superseding the earlier
four-attempt checkpoint. Returning-witness search now abandons an attempt as
soon as its original Program modification number changes, prioritizes sites
whose physical target matches the requested target, and attempts a paired
canonical/alias configuration only once. These changes remove redundant doomed
work; they do not reuse partial effects or bypass paired ownership, semantic
digests, raw proof, native compatibility or the final modification fence.
Stable failure still rejects immediately and exhausted attempts still fail.

The primary reports focused run 9 passed 94 tests plus lint/build. Installed
run 4 reportedly completed its assertions but retained proof warnings after
exhausting the previous retry bound; that is not a clean installed pass.
Full provider run 3 and installed run 5 were running when this review was
updated. Their outcomes and artifact qualification belong to the primary
receipt. This reviewer performed no build, Program mutation or product edit.

No additional concrete source defect was found in this bounded final recheck.
All three actionable review findings above now have inspected source fixes.
This is not SA-01 completion certification: normal-window and final installed
evidence, current full-provider results and every original unresolved same-CPU
banking/discovery/continuation obligation still need their explicit audit.

Final source identities for this recheck:

| Source | SHA256 |
| --- | --- |
| SoftwareCallApplication.java | `cd31f48e65d783ab748530f9f4df8bc8bc5a1baeba7c74bceb7902f74f9aec57` |
| SoftwareCallRegistry.java | `520b54cb9323ed98e0ae7e4ca305d34547d6b3403f3ff846501c77cdbcd043c8` |
| SoftwareCallInjection.java | `3ec4edd4f9d5ecfc0c078493a25ab8c85925ec77712cb63395dafb6cb84a9c9f` |
| SoftwareCallExecutionView.java | `b0a3e30c7c715adea6d5dbc0d1c30d2eeac10942b5323e43407c03328208fb8f` |
| SoftwareCallEffects.java | `a26bbd7582fd1bf55ef8d3f1bb01d2d55783ad64c26fd6d8f3c97c0bd9098fc8` |
| SoftwareCallMayReturnInjection.java | `dfd5302cb48ed454aa2875d5979fcbe00099229ecaac996b07ac4ae18723ef74` |
| AnalysisOwnership.java | `f91bcb41631e5bfc434c3a671640613d952d66d49b7c02bfb19a662afac7c8da` |

## Independent audit of completed installed run 5

The reviewer read and independently classified all six retained phase logs in
`../sa01-production-20260907/installed-runs/resume-run-5/`, inspected its exact
script snapshot and saved inventories, and recomputed artifact hashes. This was
read-only evidence inspection, not another installation or Program execution.

All six process records have exit zero, the required phase markers and an
explicit successful Program save in their logs. Independently running the saved
driver's classification function over those logs reproduces every classification
in `run.json`. Phases 0, 1, 2, 3 and 5 contain no WARN/ERROR lines. Phase 4 contains
exactly four expected rejection messages: three SymbolicPropogator WARNs and one
DecompileProcess ERROR, all for the deliberately edited `0150` site with
`Software-call annotations changed after review`. The ERROR stack's cause is
that same ownership rejection, not an address-space, service or unrelated
analysis failure. There are no additional logged errors, injection warnings,
other warnings or native diagnostic lines hidden by passing markers.

The script first applies prepared self-authored fixtures, reopens and verifies,
then installs explicit false helper/target/nested ordinary noReturn/CALL_RETURN
annotations and exercises reviewed reapplication. Separate later processes save
a user continuation override and payload comment, observe stale rejection before
removal, preserve those edits through removal, then reopen again to verify the
final saved state. The last process verifies retained shared mappings are
non-executable, their owned instructions/Functions remain removed, executable
ownership is absent, and the exact six-space retirement inventory matches the
previous process. The retained view snapshots separately show original views
with cleared instructions and the new active view generation after reapply.

The formerly missing saved nested-review inventory check is now present and
executed: after reapply, verify/edit/reopen paths compare the saved option with
`reapplied-inventory.json` and assert the `rom3::4300` to `0360` row records the
original false noReturn and CALL_RETURN-to-NONE repair. Both canonical and alias
native entries and physical CALL endpoints are checked for the installed banked
cases. The script also checks restoring/constant-bank return state, nested
flag behavior, true terminal behavior and the known nonlocal destination.

Retained C is **not warning-free**. It contains callfixup-replacement comments,
the native `This is an inlined function` comment on nested routines, and
`Removing unreachable block` comments for canonical terminal expansions and
the known nonlocal path. These comments are preserved, not filtered from C.
The manifest's empty `nativeDiagnostics` arrays classify process log lines only.
No bad-instruction, truncated-flow, unresolved-injection or fabricated `rst00`
failure was found in the saved C. Its assertions establish the stated physical
CALL/CFG/effect cases; they are not a general proof of bank-sensitive pointer
or data transport throughout arbitrary native C.

Verified identities:

| Artifact | SHA256 |
| --- | --- |
| Exact extension archive in build/distributions | `0bbea54f5c497c3c586d55987e001dcdb61a8bdc1b06546ec1c9cdeb3d4719e3` |
| Installed GhidraBoy-20260905-integration1.jar | `f7502b8a0c7d80c0e171b5f77ca51f08e9f4f190e680217c1c99e40923c8f9f7` |
| Script snapshot | `e002e88c9812846ab5dd044d676512bd7a3efbb9f3f5240dd9083a0db1865c79` |
| Driver | `218314ba3d73c3e321f45584a7fa17e5a525b9f78e1f5d84f4aeeb2df1019426` |
| Self-authored fixture | `b7e0403c9c8c6cfb182be91bb771016b4c588f4793e8e271c330f57f988bd5b8` |

All seven provider sources in the final source table above byte-match their
entries in the installed source archive. Independent aggregation of retained
JUnit XML confirms full run 3 has 566 tests and focused run 9 has 94 tests,
with zero failures, errors or skips. The full run log shows tests executed and
the lint/build tasks accepted their up-to-date inputs; it is not described as
a fresh execution of every lint/package task.

The discovery limitation is explicit and retained: before preparing instructions,
preview rejected the missing helper boundary at `0200`. This campaign qualifies
prepared application and persistence, not wholly unprepared automatic discovery.
The primary reports the verified disposable GUI session was launched but the
Mac screen was locked. No normal Decompiler-window success has been observed
by this reviewer or certified here. That gate and the original broader required
cases remain open; the successful installed campaign does not close SA-01/SA-02.

## Final package and installed run 7 audit

The final package is
`a18bc013d93c2815d4e929e814e9ec18248eb357c7c185f060ac1ffbed5cdd98`.
The reviewer independently recomputed that archive hash and compared all **55**
archive files against the disposable run-7 installation: all match byte-for-byte.
All **27** packaged documentation files also match current source documents.
`final-package-installed-check.json` agrees with these checks, and
`package-link-check-final.json` records zero missing packaged links for this
exact hash. The provider JAR remains
`f7502b8a0c7d80c0e171b5f77ca51f08e9f4f190e680217c1c99e40923c8f9f7`;
the source implementation and installed fixture/script/driver identities audited
above are unchanged. The archive change includes the final documentation and
package-link correction, not another unqualified provider implementation.

The reviewer independently reclassified all six retained run-7 logs. All six
have successful saves and passing phase markers. Again, only phase 4 has
diagnostics: exactly the four expected `0150` stale-ownership rejections, with
no additional WARN/ERROR lines, native diagnostics or other warnings. The
manifest arrays reproduce the independent classification exactly. Saved C has
the previously dispositioned injection/inline/unreachable comments and no
bad-instruction, truncation, unresolved-injection or fabricated `rst00` finding.
The six-phase lifecycle conclusions above therefore apply to the final package,
with the same prepared-discovery and finite-semantic coverage limits.

The added backwards conditional continuation-edge test has a retained one-test
XML pass for both canonical and mapped native roots. During this audit, full
run 4 completed successfully; independent aggregation of its current JUnit
outputs found **567 tests, zero failures/errors/skips**. The primary owns the
retained final test snapshot and source/artifact association. No test/build or
Program mutation was launched by this reviewer.

The primary reports the final disposable GUI session is likewise blocked by the
locked Mac screen. Launch/installation identity does not establish normal-window
behavior. No GUI pass is claimed. All original unresolved requirements remain
required; this final artifact audit certifies only the concrete tested lifecycle
and recorded review scope, not SA-01 or SA-02 completion.
