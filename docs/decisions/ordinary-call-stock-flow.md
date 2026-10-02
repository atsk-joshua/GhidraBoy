# Ordinary returning CALL stock flow (WUX-1A)

This bounded integration consumes the [WUX-1P certificate](ordinary-call-proof-certificate.md).
It does not change the evaluator, raw SM83 p-code, mapper premises, conditional
CALL or software-call admission. JP HL remains a separate obligation.

## Selected representation

A current complete result with an exact OrdinaryCallProof can replace precisely
one decoded DEFAULT unconditional CALL reference with one ANALYSIS unconditional
physical CALL. The replacement uses the decoded operand index and becomes primary.
Generic singleton Findings are insufficient. Competing flow, an existing target
reference at that operand, or a competing primary DATA reference refuses publication.
USER_DEFINED, IMPORTED and edited references remain intact.

The physical reference transports the proven target through stock Listing,
Instruction.getFlows(), block CFG and overridden p-code. The alternative of only
making the physical CALL primary was rejected by [WUX-0](proven-stock-flow-integration.md):
the retained DEFAULT CPU reference adds a false second stored CFG edge. No SLEIGH,
override type or custom native transport is introduced. Coincident static physical
and CPU target addresses still use the same reversible reference contract.

## Compatibility and ownership

Ownership envelope 6 adds a separate `ordinary-call-flow` group with receipt
version 1. Existing envelopes 1–5 remain readable; they cannot acquire ordinary
CALL displacement authority through an envelope upgrade. Old reference/function
receipt deletion rules remain unchanged. The receipt uses AnalysisOwnership.Point,
records all three certificate static/physical identities, engine/basis fingerprint,
source bytes, and exact installed/displaced reference tuples including source,
type, operand, primary state and symbol identity. No language, compiler, mapping
or AnalysisResult schema/engine identity changes. Known receipt version 1 retains
structural removal/restoration authority when its proof engine becomes obsolete.
Only an exact unchanged installed tuple can be removed; source semantics must
still match before restoring DEFAULT. Obsolete engines confer no normalization,
architectural exemption or publication authority. Unknown future receipt formats
confer no destructive or proof authority; recomputation never upgrades them.

Removal undoes an exact unchanged physical tuple and restores the exact original
DEFAULT tuple when its original decoded source still matches. An edited physical
reference or a competing restoration tuple is preserved. If source semantics
changed, the unchanged owned physical tuple can be retired but the obsolete
DEFAULT is not recreated; current decoded/user references are retained. Stock
Functions are not owned or removed by this group.

## Dependencies and architectural evidence

Only the AnalysisResult fingerprint path normalizes an exact unchanged owned
physical CALL plus its displaced DEFAULT receipt back to the original DEFAULT
representation. Shared ProgramFingerprint component contracts still hash stored
references. Additional/edited flow remains visible, invalidating currentness.
Structural receipt matching is separate from basis comparison to avoid recursive
fingerprints. Architectural interpretation ignores only that exact receipt-owned
CALL while its original normalized proof basis is current. Fresh certificates
still require the original raw byte/stack/mapper/matched-return exploration.
Generated/native flow without correspondence cannot establish proof.

Each result fingerprint capture loads one immutable ordinary-CALL receipt index,
keyed by exact source identity. Architectural encounters reuse one normalized basis
per Program modification number. Pinned 12.1.3 increments that number synchronously
for Program events, including ownership option writes and rollback restoration;
checks inside open transactions therefore invalidate before event delivery.
Changed bytes, mapping, permissions, generated-storage eligibility and independent
flow retain the existing dependency contract. Cache entries are transient, discarded
on revision mismatch and analysis end, and confer no authority after save/reopen.

Every preview retires stale derived flow before capturing the modification number
and new fingerprint, including previews that subsequently reach STATE_LIMIT.
An unchanged original basis remains installed during a smaller incomplete invocation.
This retirement is a reversible preview-side Program mutation, not a new incomplete
result publication. Retirement happens on analysis invocation, not immediately on
arbitrary external edits without analysis.

## Stock scheduling and bounded verification

Actual publication changes notify AutoAnalysisManager.codeDefined at the exact
source addresses. The owning transaction prepares the manager, exact normalized
fingerprint and immutable receipt snapshot while cancellation or failure can still
roll back. Only successful commit publishes the prepared token and queues
codeDefined; that step performs no fingerprint capture or monitor check.
Idempotent apply sends no notification. A session token containing
sources, normalized fingerprint and receipt identities consumes only unchanged
publication feedback; source, flow or ownership changes cannot suppress another
relational pass. analysisEnded clears the token. The incumbent analyzer remains
an INSTRUCTION_ANALYZER at LOW_PRIORITY. No stock analyzer is invoked manually.
Pinned 12.1.3 AnalysisScheduler unions pending instruction addresses and passes the
whole accumulated set to one analyzer invocation. A coalesced superset refuses
suppression and retires the token. A hypothetical partition consumes at most its
first exact subset; remaining subsets conservatively rerun analysis. This producer
contract therefore has no missed-analysis case requiring a token redesign.

Pinned Ghidra 12.1.3 InstructionDB, InstructionPcodeOverride, PcodeEmit,
ReferenceDBManager, FunctionAnalyzer and AutoAnalysisManager source confirms the
mechanisms linked in [references](../references.md). Focused tests cover Java stock
flow/high p-code, raw equivalence, admission, edits/restoration/currentness,
stale/incomplete controls, real same-session scheduling and packed save/reopen.
The native DecompInterface test requires the pinned platform executable and reports
an explicit skip when it is unavailable. Detailed commands and source/dependency
identities are indexed in [evidence](../sa/evidence-index.json).

## Qualification closure

WUX-1A is **CLOSED / QUALIFIED** for bounded ordinary unconditional returning
direct-CALL stock integration. Publication requires an exact current typed WUX-1P
certificate; the selected representation and semantic boundaries above remain unchanged.

Q1-R1 qualifies pinned Linux Ghidra 12.1.3 / JDK 21.0.12.1: 1,130 tests PASS
across 108 JUnit XML reports, with zero failures, errors or skips. Native
DecompInterface follows the sole physical target `rom2::4100`. Raw SM83 p-code
remains architectural. Inherited mapper-store native lifecycle, lint, extension
build and build-input/static checks pass. The test-only legacy state-entry oracle
repair removes a zero-bytechunk assertion disproved back through WUX-1P by D1;
semantic missing-state-entry rejection remains correct. This is an oracle erratum,
not a WUX-1P production regression.

Q2A's independent JVM phases establish that derived physical CALL, its receipt,
saved result and normalized currentness survive save/reopen without transient
cache state. Mutation of a consumed proof dependency retires stale presentation
on analysis invocation before incomplete recomputation can reuse it. Exact DEFAULT
restoration survives process boundaries; no stale receipt/physical CALL reappears,
and the old result is not falsely current. An unrelated incomplete invocation
does not retire still-current authority, including after fresh reopen. Ordinary
flow retirement does not destroy stock/user Function work or saved annotations.

PQ1-D2 classifies the prior external harness CPU-native result as
**HARNESS_ORDERING**: legitimate fingerprint invalidation/stale retirement occurred
before the harness supplied its independent `0150` root. Stored flow, high p-code
and CPU-native target agreed contemporaneously; no physical-high/CPU-native mismatch
or production repair was indicated. The normal default stock workflow with an
external entry converges to physical native CALL `rom2::4100`.

Q2B is **RECREATED_BUT_USER_SAFE**: qualifying user-edited Functions retain names,
comments, tags, signature annotations, body and user work through repeated analysis
and fresh-process reopen. Receipt-free DEFAULT Functions and unrelated user
Functions survive; no duplicate or false CPU callee appears. Untouched generated/
owned Functions may be removed by `AnalysisOwnership.remove("functions")` and
recreated by FunctionDiscovery. Numeric Function ID stability is not part of this
contract. All seven native checks target `rom2::4100`, with current fingerprints
and no production repair indicated.

See [status](../sa/IMPLEMENTATION-STATUS.md) and durable receipt/report hashes in
[evidence](../sa/evidence-index.json). These are bounded fixture results, not
whole-ROM or broader mapper/control-flow completeness. Conditional CALL and
software-call behavior are unchanged. JP HL / WUX-1B remains separate; installed/
headed, Steam Deck, Wyatt, debugger and release acceptance is not implied.
