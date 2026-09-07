# Independent integration review: initial state-sensitive implementation

Status: **changes required; SA-01 and SA-02 are not complete.** This is a read-only
source review of the initial integrated implementation, not execution of the
provider, installed or GUI campaigns. The primary owns those serialized checks.
Earlier failures, artifacts and unrelated work were left intact. No shared build,
Program mutation, source edit or active-installation operation was performed by
this reviewer. This new report is the reviewer's only workspace write.

The review reads the original task, root/scoped processor instructions, current
specification, roadmap, implementation guidance, call/bank decisions, resumed
receipt/audit/GUI evidence, qualification manifest, initial-identity receipt,
representation investigation, new effect/transport/discovery/application code,
ownership, native patch/delivery tools and relevant tests. The initial identity
receipt records 161 source, 13 documentation, seven dependency and 55 installed
member matches, with zero mismatches, at HEAD
`16752093dce0147afd28762a2f8918144ec571c2`. That is historical baseline verification;
it does not qualify the new files. The baseline remains 567 provider tests and
six installed phases, with the six finite canonical/alias GUI entries described
in the original receipt.

## Actionable findings

### R1 — P1: later continuation callees can lose their required native transport

`SoftwareCallContinuationView.requireTransport` recursively extracts
`calleeInvocations` and discharges their fetch-space, data-identity, mapper-write
and call-target vetoes. `Lowering.emit` nevertheless emits an ordinary CALL to
the original physical target. `SoftwareCallApplication.apply` builds the
`stateEntries` map only from `review.stateCallees`, not nested invocations in
`review.stateContinuations` (initial lines 407–439).

Consequently a later ordinary continuation call whose callee crosses a bank or
reads bank-dependent data can be declared transportable while its native target
still uses the original ordinary body and wrong physical interpretation. The
simple fixed-ROM `later_target` regression does not exercise this discrepancy.
Install/revalidate the contextual callee graphs required by continuation calls,
and add the nested bank-switch/restore fixture as a later continuation call.
Compare the actual native callee effects and physical accesses, not only the
call endpoint and constants copied into the caller after CALL.

### R2 — P1: one caller's concrete premises replace a global canonical callee body

Application installs `__ghidraboy_state_entry_v1` directly on the canonical
physical Function. The native patch replaces original flow with the graph tied
to one configured source site. `Lowering.emit` omits the original conditional
branches and follows the concrete proof's chosen successor. Registry resolution
checks the saved source site's premises and dependencies, but not the premises
of any other incoming ordinary caller of this canonical target.

A second caller with different F/register/mapper/stack values therefore sees a
canonical callee whose ordinary decompile presents another caller's selected
path. This differs from the existing call-site injection, which validates each
actual software-call site. A registry execution-condition string does not scope
a Function's global native semantics to one incoming invocation. Preserve
contextual entry identities and route calls by those contexts, or retain guarded
branch semantics with explicit unknown paths where premises are not established.
Add two callers of the same physical callee with opposite flags and verify both
normal canonical and derived-entry results.

The associated incompleteness is explicit in the code: preview rejects two
configured sites sharing a stateful target (initial lines 84–85), and apply
rejects repeated nested invocations at the same physical entry with different
graph indexes (initial lines 422–424). These safe rejections do not satisfy the
requested competing-path/premise support. The current conditional raw fixture
runs two independent concrete proofs and explicitly disclaims a combined graph;
the production callee test has no conditional fixture.

### R3 — P1: removing a renamed/commented state entry strands its native protocol

`AnalysisOwnership.undo` restores a state entry's original convention only if
the entire `helperMetadataStamp` still matches (initial lines 270–276). The stamp
includes name, comments, tags and body as well as semantic metadata (457 onward).
Public removal always deletes the registry (228). Rename or comment a canonical
state callee, then remove the software-call feature: its unchanged reserved
calling convention survives while its required registry is deleted. Subsequent
native decompilation requests a missing state-entry graph and fails.

Restore the unchanged, owned convention field independently of unrelated user
metadata, preserving user changes to their actual fields. The adjacent helper
fixup cleanup already implements this distinction. Test rename/comment, paired
invalidation, removal, normal decompile and separate-process reopen.

### R4 — P1: nested state entries bypass native contract eligibility review

Only the top-level state target is checked with `defaultCallerContract` or an
existing owned state-entry receipt (initial Application 86–89). Every nested
invocation is later assigned the reserved convention. The effect engine's nested
callee checks reject thunk/inline/fixup and unsupported stack purge, but do not
exclude nondefault calling conventions, custom variable storage or user
parameters/return contracts. A nested Function can therefore have its explicit
ABI replaced even though the equivalent top-level target would reject.

Apply per-function contract eligibility to every graph receiving the reserved
convention. Include the exact old/new convention and affected signature in the
public review inventory, with tests using a preexisting nested custom contract.
Do not infer permission to rewrite an ABI from a concrete returning trace.

### R5 — P2: later terminal calls remain an unimplemented requested case

A later ordinary nonreturning call has no `afterCall`; `requireTransport` rejects
it as requiring a matched post-call state. `calleeInvocations` only extracts
balanced returning invocations. Nonlocal callee exits bypassing an active frame
retain a native incompatibility. These explicit rejections preserve safety, but
the requested later call/loop/known-nonlocal combinations still need transport.
A configured manual transfer with no `afterCall` also deserves a negative test:
the guard currently names only `CALL`, while lowering invokes
`results(step.afterCall())` for the configured BRANCH path.

## Evidence and acceptance limits

The new rooted discovery design has useful preservation boundaries: speculative
PseudoDisassembler results live in a scoped session; each requested fetch carries
a proof reason; reservation/physical byte/data/label/reference/function checks
precede commit; `apply` commits restricted instruction extents inside a rollback
transaction. Its cancellation tests and fresh missing-Instruction cases are
materially stronger than the prepared baseline. This review found no reason to
replace them with a linear sweep. Actual new installed save/reopen evidence is
still the primary's pending obligation.

The native pre-flow mechanism deliberately places all injected operations at one
entry address, with `VisitStat.size = 1` and one-instruction native extent. The
original saved listing/body is preserved, which is preferable to deleting code,
but this is a transport abstraction. The decision must specify address-to-C
navigation, native address/coverage consumers and physical source provenance;
synthetic insertion-probe success alone is insufficient qualification.

Current state-callee native assertions check successful decompile/RETURN on the
canonical and derived callees. They check result constants on the outer caller,
where production explicitly copies graph-derived constants after CALL. This can
pass even if the native callee's arithmetic, memory or control flow is incorrect.
Strengthen the callee assertions and execute emitted effects against architectural
expectations with distinct live return words. Include both sides of conditional
bank selection, repeated calls under changed premises, later terminal calls,
indirect mapper operations, and state-entry metadata edit/removal.

The same-fixture representation investigation improves materially on the earlier
16-bit overflow observation: it records ordinary overlay and widened-adapter
failures and compares insertion mechanisms. Its synthetic pre-flow insertion
graph is intentionally identical across source shapes, however, and does not
itself prove graph-derived architectural semantics. Production derived-graph
cases and public navigation/lifecycle checks must supply that missing evidence.

Original requirements still open at this review snapshot include R1–R5,
competing conditional contexts in the public workflow, native callee semantic
comparisons, convention/ownership migration with preservation, the complete new
installed campaign and changed-path normal GUI checks. No full-provider count
can substitute for those outcomes. Broader SA-02 mapper/RAM-image/asynchronous
architecture and SA-04 discovery remain explicitly outside current qualification.

## Reviewed source identity

The files below were hashed during this review. Concurrent primary changes may
postdate these values; corrections require targeted re-review and new execution
evidence. This report must not silently be interpreted as approval of later bits.

| File | SHA256 |
| --- | --- |
| `src/main/java/fi/gekkio/ghidraboy/SoftwareCallApplication.java` | `ff51fa1f0d24f3f08a38699ccae2c170de655b967017c0a1c07f2e2dd78a1f7f` |
| `src/main/java/fi/gekkio/ghidraboy/SoftwareCallContinuationView.java` | `f38a9bd16239c7af4c91a9b4e2e32a095f50a840b59da4b5545747acea4e8331` |
| `src/main/java/fi/gekkio/ghidraboy/SoftwareCallEffects.java` | `eabaad4acaed30072495fbb333f5edd670495fd14258d8ad7d3dd929fc3aa3df` |
| `src/main/java/fi/gekkio/ghidraboy/SoftwareCallRegistry.java` | `700aa95f25ece1853c4c46f73ab8198c9f720482c57bc16c84870990d10bbaa8` |
| `src/main/java/fi/gekkio/ghidraboy/SoftwareCallInstructionDiscovery.java` | `7867deba7de333ca9c09c370309e78cc719f454a3b5a5e0ab170ee65f2fbc893` |
| `src/main/java/fi/gekkio/ghidraboy/SoftwareCallStateEntryInjection.java` | `1f9653901c8a000b610e407e5db9047e5804fc9895e3641c8044f0b714b17079` |
| `src/main/java/fi/gekkio/ghidraboy/AnalysisOwnership.java` | `1a0055b034bb8cbe131dcba9d99928283cc1c6150f4f2fc842842435fcf89ec7` |

## R2 clarification after targeted contract inspection

The initial R2 is a canonical interpretation/domain finding and a competing-context
support gap. It is **not evidence that a non-inlined ordinary caller receives the
specialized callee's return constants**. Inspection of `SoftwareCallMayReturnInjection`
shows an opaque CALL to the same target after an existential returning witness;
Ghidra ordinarily applies the call prototype rather than importing the callee body.
A concrete unconfigured-caller constant-propagation failure has not been executed
or established by this review. The canonical decompile itself still presents one
source site's selected conditional path without a per-entry visible domain guard.
The registry's exact execution premises make a conditional specialization valid
inside that domain; they do not make the displayed Function valid for other domains.

The proposed two-context acceptance fixture uses one Program with configured roots
0200 and 0240, both targeting bank2::4100 at the same SP/mapper/A/HL but F=00 and
F=80. Use the existing conditional bank-selector fixture, adding LD(c210),A before
each terminal RET: bank2::4200 writes 22 and bank3::4200 writes 33. Both configured
contexts must coexist, and normal target/context navigation must retain their
correct domain and physical effects. An ordinary CALL root at 0280 supplies the
negative control that no site-specific result injection leaks into an unconfigured
CALL. Current non-inline code suggests that CALL will remain opaque; test this
rather than treating the earlier concern as a proven propagation defect.

An invocation-only contextual alias with recorded premises is a sound bounded
specialization. Canonical navigation can remain meaningful if the public workflow
explicitly selects/displays its analysis context and native output makes those
conditions visible; the result must not be reused outside that context or advertised
as an all-input canonical Function. A canonical guarded union is another possible
representation, but its unmatched branch must have an honest analysis-unknown
meaning. An opaque userop followed by RET fabricates a return; a noReturn marker
fabricates nonreturn. A domain assertion can state a conditional analysis premise,
but must not be described as an architectural hardware guard/trap. Modeling arbitrary
unknown execution would require effects on memory, registers, flags, mapper, SP and
nonlocal/return/nonreturn control; it is not supplied by a convenient fallback ABI.

The smallest independent native assertion places the c210 writes *inside* physical
callees and inspects target/alias high p-code directly. This avoids the caller's
post-CALL graph-derived result constants. Separately reuse the existing
`SoftwareCallContinuationTest` PcodeProgram executor harness to compare a CALLEE
payload against raw physical execution with two different live return words,
checking registers, F, SP, mapper, c210 and stack inventories. This proposed check
has not been run by the reviewer.

## Targeted source re-review after contextual-entry integration

R1 source disposition: application now plans entries from both initial callee
graphs and transported continuation invocations. `StateEntry` retains the origin
kind and source site, and ordinary/software CALL lowering resolves a dedicated
invocation alias. This addresses the initially missing continuation-callee
transport at source level. The primary reports its later bank-changing callee
regression passed; this reviewer has not independently run that test.

R2 source disposition: distinct invocation aliases coexist at the same physical
callee. The public `stateContexts` and `selectStateContext` APIs expose and select
an exact domain for canonical navigation. The Function comment describes that
domain, and the revised native patch adds a visible conditional-model warning.
The canonical result is explicitly a selected-context specialization, not a
union covering unknown entry values. This addresses the interpretation ambiguity
identified in the clarified finding, subject to public UI/save-reopen evidence.
The primary reports one-Program opposite-flag context selection and direct callee
c210 assertions plus actual payload-versus-raw execution passed. These assertions
are materially stronger than the initial caller-constant-only checks.

R3 source disposition: removal now restores the unchanged owned convention field
without requiring unrelated name/comment metadata to match. An unchanged tool
comment is separately restored, while a changed user comment remains intact.
This addresses the reported stranded-native-protocol case at source level.

R4 source disposition: every planned invocation entry is now tested for bare or
current owned native contract eligibility, before application. This addresses
the nested ABI bypass at source level.

The reviewer added the new nonoverlapping file
`SoftwareCallStateEntryIntegrityTest.kt` with six regressions: rename/comment
preservation and alias retirement on removal; clean removal after selecting the
other context; nested explicit return contract rejection; nested custom-storage
rejection; cancellation after a real context-comment mutation with complete
rollback; and stale cached selection after a consumed-byte change. **These tests
were handed to the primary without running a shared build.** Their outcomes
remain unrun in this reviewer receipt until execution evidence is supplied.

One new selection race remains to check: `selectStateContext` first obtains the
validated context list, then captures a new semantic digest as its comparison
baseline. A dependency mutation in between can be incorporated into that new
baseline and written to the registry even though the selected entry-state/comment
came from the old proof. Preserve a pre-enumeration modification/digest token and
require it to remain current through transaction entry; context selection must
never rebaseline changed consumed bytes. The added ordinary stale-selection test
covers preexisting drift, not this narrow concurrent boundary.

R5 terminal-call integration was still changing during this targeted read and is
not approved by this update. Full provider/lint/build, installed lifecycle, actual
old-work migration and changed-path normal GUI checks remain primary obligations.

| Targeted file | SHA256 at targeted review |
| --- | --- |
| `src/main/java/fi/gekkio/ghidraboy/SoftwareCallApplication.java` | `da3462b02d7d453e291d8e6719c74f24864b7cff75090d15f48a76c439237d22` |
| `src/main/java/fi/gekkio/ghidraboy/SoftwareCallRegistry.java` | `ddaf7f46e0a1588b68b2daf2135c8452b912dcdb2edab1c63c0e53c91d551912` |
| `src/main/java/fi/gekkio/ghidraboy/SoftwareCallContinuationView.java` | `467b7a3485d96154a50b3e027f670277686790d2c91edc9a72f0a3561a3f674f` |
| `src/main/java/fi/gekkio/ghidraboy/AnalysisOwnership.java` | `f8179e6a5d44bb70fb767aef3792b170e014f54d514cffa8ae95a1059d89858d` |
| `src/test/kotlin/fi/gekkio/ghidraboy/SoftwareCallStateEntryIntegrityTest.kt` | `571f4817ed60f9ee98ac8cf739f91462cacb66d92fea9e1f34f7af20b819e882` |

## Independent integrity-test execution feedback

The primary's retained `focused-10-junit` run executed the six new integrity
regressions. Rename/comment removal, clean removal after context selection, and
cancellation after actual context-comment mutation passed. Both nested custom
contract previews rejected as required, but their exact before/after
`FarCallEvidence` assertions failed. This is an unresolved preservation/digest
failure, not a passed contract test; the expectation is retained. Diagnostic
assertions now compare component hashes, function prototype/storage/annotations,
symbols, references and modification number, and record a second digest after
those reads. No cause (including lazy getter materialization) is claimed without
the next execution output.

The sixth test initially failed while arranging its stale input because Ghidra
correctly refused changing a byte inside an existing callee instruction. The
fixture now clears and redecodes the exact 0028–002a helper instruction around a
consumed operand edit, avoiding writes through live callee alias instructions.
This is a test setup correction; the original failure remains in focused-10.
The revised diagnostic/stale-input tests have not been run by this reviewer.


## Exact cause of the rejected-contract digest failure

The focused-12 exact-field diagnostic isolates one difference:
`analysis.ownership.v1:absent` became
`analysis.ownership.v1:{"version":1,"groups":{}}`.
The component, function, symbol, reference and modification-number snapshots
were unchanged. `AnalysisOwnership.registry` called Ghidra Options.getString
with a default while the option was absent; that read registered a transient
default. The newly added `stateEntryCurrent` contract eligibility check reached
this path during rejected preview. This was a read-side option-presence/evidence
instability, not a rewrite of user annotations or a native type mutation.

The primary changed `registry` to test `contains(KEY)` before calling the getter
and use the default JSON locally when absent. The reviewer removed the temporary
exact-field observer from FarCallEvidence and all diagnostic helpers from the
regression class. The original strict before/after digest assertions remain.
The earlier failures and exact-field diagnosis stay recorded; the clean next
run must verify the fix. The primary reports the other four integrity tests pass.

## Terminal-call follow-up: multiple departed native frames

The new terminal-call model now records live frames and exact nonreturning/nonlocal
outcomes and keeps noReturn confined to contextual aliases. A source review found
an additional boundary to exercise before closing R5: `retireNonlocal` assigns the
same root resume-step to every departed call. When a nonlocal RET retires two
native frames, the intermediate CALLEE slice ends at that RET and does not contain
the outer resume-step. Its nested CALL lowering currently searches that slice for
the resume-step and can fail with an empty lookup, despite a complete raw proof.

Concrete proposed fixture: later continuation CALL0240; 0240 CALL0260; at0260,
`c1f8003680233603c9` discards the inner return with POP BC, overwrites the remaining
outer word with0380 and RETs through it. At0380, LD A,7; STORE(c230),A; RET consumes
the untouched external frame. Both departed boundaries are exactly known. The
intermediate native entry must propagate a terminal nonlocal outcome without
requiring an in-slice resume node. This is a source finding and proposed native
regression; it was sent to the primary and has not been executed by this reviewer.

The primary's subsequent source fix distinguishes an in-slice resumed step from a
terminal nonlocal outcome leaving a CALLEE slice. The latter requires the slice's
NONLOCAL exit and matching terminal-step identity, copies the proven state, and
emits only a 16-bit logical RETURN for the already executed foreign transfer.
It adds no architectural LOAD, POP or additional stack increment. This abstraction
is appropriate for the exact proved departed frames; it must not become a generic
unmatched-return rule. The enclosing graph executes the real resumed instructions.

The reviewer added a seventh test to SoftwareCallStateEntryIntegrityTest using the
exact later continuation fixture above. It checks both native source entries write
c230=7 (the skipped encoded path would write9), decompiles the intermediate
canonical/context entries, and checks the actual intermediate injection has zero
LOADs, only the STOREs from its original hardware CALL push, and a 16-bit final
RETURN. The primary owns its pending execution. Stronger composed raw-equivalence
would execute the outer emitted prefix/CALL, actual leaf payload, and emitted
outer post-CALL tail against raw outer/leaf execution with varied live external
words; PcodeExecutor CALL does not recurse automatically.

Focused-13 follow-up: both strict R4 before/after evidence comparisons now pass.
Its remaining return-type assertion incorrectly compared the process-wide
ByteDataType singleton by object identity against the Program manager's equivalent
clone. The test now captures the original Program type and checks semantic
equivalence, path, storage and signature source without weakening the unchanged
evidence requirement. The new multi-frame test initially selected more than one
canonical static alias for a ROM0 file offset; its fixture now also requires the
architectural CPU offset. Both failures remain in focused-13. The corrected
seven-test class was returned to the primary for the next serialized run.

## Primary verification at user-requested wrap-up

The registry5 artifact subsequently passed all635 provider tests and the retained
six installed finite phases. Its new fresh installed campaign fails after normal
automatic analysis; exact inventories show caller aliases acquiring helper thunk
metadata. Current registry6 source adds partial naming/redirect and caller
dependency changes. The newly added automatic-analysis regression still fails
at `sourceRedirectCurrent` after analysis, with stale-witness/injection and
unmapped-fragment-flow diagnostics. Latest focused result is8/9; all seven
independent state-entry integrity tests and edited-source removal pass. This is
primary execution evidence, not an additional independent approval.

The temporary fingerprint observer has been removed. Separate lint verification
passes after formatting. Actual saved-v4 capture passed; migrated new-provider
reopen and new-artifact GUI remain unrun. See HANDOFF.md and the completion audit.
No milestone closure is approved by this handoff.
