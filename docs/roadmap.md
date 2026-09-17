# Development roadmap

PREVIEW-M2 implements the normal stock-Ghidra analyzer/preparation/status path and
outer primacy-safe migration boundary. Generic qualification and the private
headless migration/full-analysis/reopen workflow pass locally; the actual intended
Linux/Steam Deck headed workflow is NOT_RUN, so ENGINEERING-PREVIEW remains
NOT_READY. The next unresolved obligation is exactly that candidate-specific headed
target workflow, not further capability expansion. See
[current status](sa/IMPLEMENTATION-STATUS.md) and the
[M2 decision](decisions/preview-m2-native-analysis.md).

PUBLIC-OPERATIONS-LIFECYCLE V1 is PASS for its scoped contract on the exact AUTH-R3
candidate `54fc048798025691789da706508d9c5fd674c2655b8192152a65eb146899e07c`.
All H0/H1/H2/I1/W1/W2/W3/W4/W5/W6 positive rows, actual desktop visual review and
the twelve-control aggregate sensitivity matrix pass under one candidate identity.
Production remains frozen. This closes only the lifecycle gate: Wyatt release
readiness, hardware/schema completion, migration, package/install/recovery and general
whole-ROM correctness remain open. The next bounded task is PREVIEW-P1/P2:
target-specific compatibility audit and copied-Program rehearsal. It does not begin
successor migration, hardware implementation or release work.

AUTH-R1's local candidate is rejected by AUTH-R2 review. Its post-write verification
could discover failure only after an exact-default write had removed a genuine
database property, and its shallow paired predicates could select one family without
classifying ambiguity in the other.

AUTH-R3 repairs both blockers. Writes and removals prove safety before mutation;
caller-caught refusal plus outer commit cannot change authority. One shared paired
classifier drives membership, transport selection, creation, replacement and removal
for stock and companion records. Both ambiguity orientations and genuine conflicts
fail closed, while a clean reopen restores readable genuine authority. Local provider
qualification passes and the resulting artifact is an **AUTH-R3 source-qualified and
candidate-specific W2-qualified candidate**; its SHA-256 is
`54fc048798025691789da706508d9c5fd674c2655b8192152a65eb146899e07c`.
W2-R3 proves cache-only physical pollution remains non-authoritative, normal physical
and genuine-carrier native use succeeds, the first actual new-domain native request
succeeds before refresh, old stale work is attributed correctly, and immutable
separate-JVM first use remains current. Production is unchanged. V remains
`UNOBSERVED` and aggregate lifecycle/release readiness remains blocked. No installation,
remote publication or release is authorized.

The W2 root-cause follow-up closes bounded W2 without a production change. The
recorded early call is `PRE_NATIVE_CANCELLED` at Ghidra's pinned pre-dispatch guard;
the next request is the first actual native execution and succeeds. The physical
refusals were caused by the JDI support observer registering missing physical keys
through a typed `Options.getString` read. A guarded lookup and bounded normal-provider
replay pass at both physical destinations. V and aggregate lifecycle acceptance remain
blocked by unobserved desktop review and incomplete aggregate sensitivity. See
[current status](sa/IMPLEMENTATION-STATUS.md) and the W2-R2 evidence entry. No release
or wider SA obligation is closed by this correction.

The pre-W2-R2 PUBLIC-OPERATIONS-LIFECYCLE R3 checkpoint was PARTIAL after attended
service and normal-window execution. Its historical scope was frozen with creation-time
injection errors and first topology use unresolved; W2-R2 above supersedes those two
findings. Later unexecuted refinement remains parked.
See [current status](sa/IMPLEMENTATION-STATUS.md) and the [operation contract](public-operations.md).
This partial checkpoint does not close any retained release or wider SA obligation.

Stock route completion passes its scoped local checkpoint: normal public requests
use stock, the retained semantic tests are green, and bounded carrier/native
refusal plus current-format installed reopen are verified. See
[current status](sa/IMPLEMENTATION-STATUS.md) and the
[route decision](decisions/stock-route-completion.md). The [G1 normal-window workflow](sa/G1-WINDOW-HARNESS-COMPLETION.md) now has complete
scoped evidence awaiting master review. Stock release qualification, language
migration and broader switch coverage remain open. The bounded STOCK-FINITE-DISPATCH
slice passes its scoped local checkpoint using the retained W3 graph; exact qualification is recorded in
[its decision](decisions/static-dispatch-model.md) and current status. No retained backlog item or historical G2/G3 acceptance is removed.

Retained roadmap and original SA/M scope. Current package sequencing and accepted checkpoints are in [SA status](sa/IMPLEMENTATION-STATUS.md), the [retained implementation plan](sa/IMPLEMENTATION-PLAN.md), and [decision gates](sa/DECISION-GATES.md). The dated entries below preserve requirements and historical dispositions; their next-step instructions are superseded by that authority.
The [static accuracy specification](static-analysis-spec.md) defines the required
outcome; [research and design decisions](static-analysis-research.md) records its
evidence. Requirements and research are not implemented capabilities or release
qualification. Current behavior remains documented in [analysis](analysis.md),
[input policy](input-policy.md), and [compiler support](compiler-support.md).

Agents should begin with the [implementation handoff](static-analysis-implementation.md),
which maps these items to source files, focused regressions, commands and decision
deliverables. SA-00 is complete within its bounded integrity scope. The original sequence began with
SA-01; SA-01 through SA-07 remain open. Do not assume the unselected banking architecture.

## First priority: complete and trustworthy static analysis

Static correctness, software-call recovery, bank-dependent semantics, and useful
fresh-import discovery take priority over adding emulator backends, new debugger
features, or additional packaging variants. Fixes needed to preserve existing
work and diagnose failures remain necessary. Existing debugger lifecycle and
release blockers remain open; this priority change does not waive them.

The target is accurate instruction effects, control flow, memory identity, call
contracts, and data interpretation across the supported GB/GBC hardware and
software patterns. Fewer warnings or more named functions do not establish that
target. Unknown required behavior remains unfinished work, with its missing
proof recorded. Do not narrow a corpus or silently strengthen assumptions to
make an accuracy gate pass.

| Work | Priority / current status | Dependencies | Required exit evidence |
| --- | --- | --- | --- |
| SA-00: analysis integrity and baseline | COMPLETE / executed receipt in source: `docs/evidence/sa00-20260907/README.md` | None | 474 provider tests; reference-only negatives; conservative interpretation; evaluator conformance; repeated baseline and separate-process persistence; [decision](decisions/sa00-integrity.md) |
| SA-01: software-call and return semantics | P0 / incomplete: state graphs, contexts and rooted prerequisites implemented; fresh installed automatic-analysis integration remains blocked | SA-00 | Exact frame, payload, return, bank and flag behavior; ordinary auto-analysis retains valid continuations on fresh and repaired Programs |
| SA-02: banked decompiler architecture | P0 / scoped state-context aliases and optional native entry protocol implemented; general architecture and qualification open | SA-00; coordinate with SA-01 | Comparative prototypes pass the same memory/flow fixtures; select and document an architecture plus migration and normal Decompiler-window integration |
| SA-03: memory and interprocedural analysis | P0 / not implemented generally | SA-01, SA-02 | ROM-table propagation, bank-shadow relationships, call summaries, ranges, interrupt effects and invalidation; proven conclusions survive negative controls |
| SA-04: discovery and annotation repair | P0 / rooted software-call instruction prerequisites implemented; full discovery and installed closure remain open | SA-03 | Rooted discovery through helpers, pointers, callbacks and RAM images; reviewed repair of invalid boundaries/references without hiding losses |
| SA-05: compiler and data knowledge | P1 / partial compiler profiles and RGBDS symbols exist | SA-00; integrate with SA-03/04 | Verified ABI/helper models, metadata import, source mappings, far-pointer formats, script/data classification and storage lifetimes |
| SA-06: cartridge and hardware completeness | P1 / ordinary mapper subset exists | SA-02; inform its design before selection | Controller/wiring/geometry matrix, mode-specific semantics, unusual windows/devices, source-conflict resolution and independent regressions |
| SA-07: integrated static qualification | Required milestone exit / open | SA-00 through SA-06 | Semantic and discovery evidence across all required corpora; native GUI, save/reopen, migration and repair gates pass on exact artifacts |

P1 work is part of this milestone, not a permanent exclusion. Cartridge geometry,
compiler conventions and game patterns must inform the P0 design immediately;
their broader implementations follow the core dependencies.

The effectful-call continuation work remains within SA-01/02/03 and W3/W4/W5.
Its [conditional implementation](decisions/effectful-call-continuation.md) adds
source-derived symbolic helper/callee inlining, matched outgoing-state continuation
and owned stock presentation for the bounded family. General summaries, loops,
interference and wider device domains remain open.
No retained requirement or predecessor qualification is replaced.

## Architectural decisions before broad implementation

1. **Software calls:** compare supported callfixups, validated flow/reference
   overrides, and helper summaries. Account for every actual stack operation and
   inline byte. A p-code CALL does not push a return address. Prevent false
   nonreturn inference by supplying correct semantics, rather than repeatedly
   clearing its annotations or disabling the analyzer.
2. **Banked memory and flow:** compare existing overlays with explicit context,
   a segmented physical-address model, and a narrowly scoped Ghidra extension
   where needed. Test fixed-to-banked and banked-to-fixed intra-function flow,
   multiple bank changes, data accesses, aliases, wrapping and saved-work
   compatibility. A custom single-bank decompile script is not normal-window
   integration or a general solution.
3. **Dispatch:** first classify pointer calls, software transfers and actual
   tables. Compare ordinary native recovery, verified overrides and jumpassist
   only where applicable. Prove domain/default behavior; never invent a bound
   from adjacent plausible words or an observed playthrough.

Each decision record must identify tested alternatives, failures, selected
behavior, remaining obligations and exact source/artifact identities. Existing
native switch fixes remain separately versioned dependencies until superseded
by verified upstream behavior.

## Delivery and measurement

Use the requirements and acceptance matrix in the
[specification](static-analysis-spec.md#acceptance-matrix). Track semantic failures,
unresolved required edges, classification coverage, stale-result rejection and
fresh/imported-work differences alongside warnings. Keep original and repaired
rosters visible, with an explicit disposition for every removed or reclassified
entry. Preserve reference material and user annotations during development;
preservation is not an assertion that every old annotation is correct.

Generic implementations and self-authored tests belong here. Optional private
game studies provide additional evidence and own their exact-ROM conventions,
addresses and artifacts; they are not generic build dependencies. See
[repository ownership](repository-ownership.md).

After static qualification, resume broader debugger expansion and platform work
according to their separate support and release gates. The historical
integration campaigns do not define current priority or qualify new builds.

## Retained integration and release backlog

This roadmap adds SA-00 through SA-07; it removes none of the prior work.
Reprioritization is not cancellation. Full original M0–M10 definitions and their
58 gates remain in the source checkout at `docs/debugger-integration-plan.md`
and `docs/integration/status.json`. The historical statuses stay attached to
their original artifacts, rather than being reset or promoted by this roadmap.

| Existing item retained | Scheduling after this priority update |
| --- | --- |
| M0: baseline, ownership inventory and compatibility fixtures | Maintain throughout static work; qualify changed artifacts anew |
| M1: mGBA/external-attachment feasibility and provisional contract | Retain receipts and unresolved conformance/coherence requirements; new expansion follows static work |
| M2: history-preserving source migration | Preserve delivered history/provenance and any remaining obligations |
| M3: unified build, dependency and package entry points | Maintain existing paths and reproducibility; avoid unrelated packaging expansion |
| M4: backend-neutral session and SameBoy parity | Preserve parity; fixes required for trustworthy validation remain eligible |
| M5: persisted compatibility, mappings and external profiles | Maintain saved work and consumers through static changes |
| M6: Release A acceptance and reproducible packages | Retain installation/recovery, performance/resource, GUI and release gates |
| M7: explicit hardware models and accuracy/coverage expansion | Retain runtime scope; SA-06 adds static requirements rather than replacing M7 |
| M8: real mGBA backend and common conformance | Preserve current backend and unresolved conformance gates; expansion follows static priorities |
| M9: integrated analysis, debugger usability and research tools | SA work takes priority within analysis; remaining debugger/research scope is retained |
| M10: Release B qualification and repository cutover | Preserve cutover/provenance work and all outstanding release/platform gates |

The static GUI checklist, saved-Program migration, publication/rollback
requirements and existing full-tool teardown/coordinate/service-error blockers
also remain. Physical Steam Deck verification retains its existing deferral;
other unqualified platforms do not become supported by this update.

If future work replaces an item, record the old ID, replacement IDs, full scope
mapping and any residual obligations. Keep that replacement record in the
roadmap. Items must not disappear merely because their priority changed.


SA-01 partial implementation and mechanism findings are recorded in
[the call-model decision](decisions/static-call-model.md) and the source receipt
`docs/evidence/sa01-20260907/README.md`. The finite effect model and raw-frame
regressions do not close SA-01. Physical target/continuation transport must be
resolved jointly with SA-02 before general native integration is claimed. No
SA or M item is replaced or removed by this update; SA-02 through SA-07 stay open.

Production follow-through and retained failed integration runs are recorded in
`docs/evidence/sa01-production-20260907/`. The scoped prerequisite is documented in
[the bank decision](decisions/static-bank-model.md). Neither the larger test count
nor this implementation checkpoint closes SA-01 or the general SA-02 milestone;
the requirement audit owns the final disposition. All original items remain.


## Historical SA-01 integration (2026-09-07)

The retained production handoff and its failures remain in
`docs/evidence/sa01-production-20260907/HANDOFF.md`. The resumed source receipt and
requirement audit are in `docs/evidence/sa01-resume-20260907/`.
Canonical and execution-view roots, paired invalidation, later-window transport,
precise nested metadata repair and the six-phase installed lifecycle now have
passing finite evidence. General architecture and original requirements remain open.

Normal Decompiler-window comparison now passes for the retained canonical/alias
fixtures, including a saved-Program GUI reopen. This is finite-case verification.
Next: implement same-CPU competing physical paths, later continuation call/mapper
effects and missing-instruction discovery with their original tests.
The completion audit distinguishes those requirements from safe rejections and
prepared fixtures. SA-01 and SA-02 remain incomplete; no SA or M item is replaced.

## State-sensitive handoff (2026-09-07)

The historical successor was [the state-sensitive handoff](sa/evidence-index.json#docs/evidence/sa01-state-20260907/HANDOFF.md)
and its [original requirement audit](sa/evidence-index.json#docs/evidence/sa01-state-20260907/completion-audit.md).
The built registry5 candidate passes full provider/lint/build and the retained six
finite installed phases. Fresh state/context installation still fails during
normal automatic analysis; its thunk/fixup drift and fragment-flow diagnostics
remain visible. Current registry6 source includes partial metadata fixes but is
not fully qualified and retains a failing regression.

Next: resolve that normal-analysis representation failure, then qualify a new
artifact with both complete installed campaigns, actual saved-provider migration
and normal Decompiler windows. Keep the repeated configured-site premise limit
explicit. Broader SA-02/03/04/06/07 work is not waived. The user requested this
handoff; SA-01/SA-02 remain incomplete and every existing SA/M item is retained.
