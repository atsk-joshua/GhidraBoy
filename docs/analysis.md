# Bounded static analysis

This page describes the implemented bounded analyzer. Completing static accuracy
is the first [roadmap](roadmap.md) priority; the
[planned specification](static-analysis-spec.md) is not a claim that the current
analyzer already meets it.

## Stock Auto Analysis integration

`GhidraBoyBankAnalyzer` is a public `AbstractAnalyzer` extension point named
**GhidraBoy Bank and Mapper Analysis**. Its class name ends in `Analyzer`, so pinned
Ghidra 12.1.3 discovers it through ClassSearcher. It is a low-priority instruction
analyzer, after stock code/function/reference recovery has stabilized, and is enabled by default only for
`SM83:LE:16:default`, and supports the stock one-shot action. Its normal options are
a 1..100000 session state limit (100000 for full Auto Analysis) and justified
Function creation.

The adapter derives roots from external entry points, user/imported Functions not
owned by GhidraBoy, and the first defined instruction of local or currently
uncontained notified code ranges. Stock
DEFAULT Functions are not all promoted to independent roots merely because they
exist; proved flow from the justified roots can still reach them. It runs one
deduplicated `BankAnalysis` worklist for all roots, restricted to the supplied
`AddressSetView`; it does not start a 4096-state session per instruction. Only
COMPLETE results are applied. Cancellation uses Ghidra's analyzer monitor.
Incomplete/cancelled runs publish no result or new confident mutation. Before
preview, stale owned ordinary-CALL flow is retired; an unchanged original proof
survives a smaller incomplete invocation. Function
discovery then consumes the same roots plus proved call destinations; its owned
Functions are excluded from later root seeding to prevent circular evidence.
The manager analyzer recognizes Ghidra's initial broad full-analysis notification,
unions later instruction batches into that session and clears the state in
`analysisEnded`; the separate one-shot analyzer instance remains range-local.

Expected legacy prerequisites are logged clearly. Missing cartridge/RAM preparation
does not escape as `Cartridge descriptor required` or an InvocationTargetException.
The normal workflow uses Tools → GhidraBoy → Program Status... and Prepare Legacy
Program..., followed by Analysis → Auto Analyze.... Script JSON remains an advanced
diagnostic/recovery interface.

`BankAnalysis.preview` evaluates existing defined instructions. `AnalysisResult`
schema 4 is typed and versioned: start points, explicit assumptions, per-root
physical entry premises and provenance, configuration,
completion, explored-state count, diagnostics, candidates and evidence fingerprint.
`AnalysisResult.read` rejects incompatible engines. Only COMPLETE runs can contain
PROVEN conclusions. STATE_LIMIT, CANCELLED and INPUT_CHANGED preserve useful
candidates without publishing confidence. The default bound is 4096 distinct
explored address/state/constant combinations; duplicate queued states do not
consume that count. Unknown alternatives prevent proof at the affected byte site.

Evaluation (`PcodeConstants`, `MapperKnowledge`), aggregation (`AnalysisCandidates`),
result validation, application (`AnalysisApplication`) and ownership
(`AnalysisOwnership`) are separate units. Analysis uses compiled p-code, not a
second instruction interpreter. It expands memory accesses to little-endian bytes
with 16-bit wrap. SLEIGH exposes architectural ordering for SP loads and pushes.
Unmodeled values and relevant unknown writes invalidate knowledge conservatively.
ROM register knowledge does not imply reset SRAM/RTC/VBK/SVBK state. A physical
MBC5 ROMX entry derives only the selector bits needed for that fetch; unrelated
fields remain unknown. A conflicting explicit mapper assumption is rejected.

Every fallthrough is checked against the CPU execution window. Same-window
physical context is reused only while consistent with known mapper registers.
Cross-window fallthrough, relative branches and wrapped PC resolve through actual
Program views. Cross-boundary fetch stops if identity or bytes cannot be proven.
Undefined code and data markings stop traversal; analysis does not sweep bytes.
Unsupported or unproved calls invalidate return-state knowledge. The bounded
ordinary direct returning-call subset below can compose established callee state.
No general interprocedural summaries or runtime bank switching are provided.

Fingerprints cover mapping, initialized bytes, defined data, raw instruction p-code,
length/flow/fallthrough overrides, language/compiler identities, consulted flow and
reference overrides (including endpoints, kind, operand, source and primary state),
and target callfixups in canonical order. Apply/discovery reject stale results;
preview detects changes during traversal. Ordinary supplemental navigation/data
references are not analysis inputs, so application does not invalidate itself.
Exact owned ordinary-CALL flow uses one receipt index per fingerprint capture and
a transient basis cache bound to the Program modification number; independent
flow edits invalidate immediately, including inside a transaction. Known obsolete
proof engines retain only exact receipt-based removal/restoration authority.
Publication prepares stock notification dependencies before commit so cancellation
rolls back the mutation instead of reporting failure after successful application.
See the [ordinary-CALL lifecycle contract](decisions/ordinary-call-stock-flow.md).

The architectural path evaluates raw `getPcode(false)` and decoded default flows
only when stored flow annotations are consistent. Flow/reference overrides, altered
fallthrough/lengths and callfixups are explicitly unresolved; they are not mixed with
raw architectural effects. This includes annotated inline-payload continuations
until SA-01 supplies a validated effect summary. Unmodified conditional jumps
retain every feasible alternative; internal conditional p-code effects remain conservative.
The evaluator delegates integer operations to pinned Ghidra behaviors with width
and extraction guards. Separate contract and compiled-SLEIGH regressions qualify
this bounded behavior, not whole-ROM semantics. See the source checkout's
`docs/decisions/sa00-integrity.md` and `docs/evidence/sa00-20260907/README.md`.

Pure raw conditional jumps use known predicate bits to select only feasible
successors; unknown predicates retain both. Known Z can survive with unknown C
through transient partial flag facts. Ordinary-call termination requires a complete
acyclic explored abstract-state graph, so register-counted finite loops can return
under the 179-state invocation resource budget. Reachable repeating state cycles
remain refused. See the [finite-loop contract](decisions/finite-conditional-loops.md).

To converge changing exact register states around loops, an instruction with more
than 32 distinct incoming non-memory states is reprocessed once with mapper/register knowledge
widened to unknown. Later backedges to that instruction reuse the unknown state.
The widening is explicit in findings and preserves uncertainty; it does not select
one observed value or silently drop the unresolved loop.

Ordinary BankAnalysis propagates scalar values from actual p-code LOAD operations
when a known 16-bit CPU pointer and path-local mapper knowledge establish every
physical ROM/BOOT byte. It reads current initialized, readable, non-writable,
nonvolatile direct static storage bound by a file source or explicit loader ROM/BOOT
anchor; all eligible physical sources must agree. Byte-mapped aliases share backing
storage and cannot independently establish immutability. Generated
execution/presentation storage cannot supply byte authority. Values assemble
little-endian into the existing register/unique domain and can drive mapper writes.
Mapping findings remain independent of value proof, including for unknown loads.
One-byte COPY inputs in the default CPU memory space denote storage contents,
as in `(register, 0x1, 1) COPY (ram, 0xc100, 1)`. They use the same
mapper/physical read and independent value/coverage policy as LOAD. Constant,
register and unique inputs remain scalar even when their value resembles a CPU
address. Other spaces and wider storage COPY forms are not qualified. Unsupported
reads remain unresolved; a supported read with absent exact data remains unknown.
Ordinary WRAM/HRAM LOADs additionally consume only exact path-written physical
byte facts from the incumbent SymbolicMemory state. STORE updates or invalidates
each physical byte, so echo aliases share facts and disjoint writes preserve them.
Exact FF24 (NR50), FF25 (NR51), FF26 (NR52), FF40 (LCDC), FF42 (SCY), FF43 (SCX), FF4A (WY) and
FF4B (WX) writes on established GB/CGB hardware preserve ordinary WRAM/HRAM
facts within the synchronous analysis domain, for known or unknown byte values.
This finite rule creates no device facts and establishes no interrupt, timing,
PPU or APU completeness. FF40 LCD/control transitions and FF26 APU power changes
remain unmodeled. Unclassified device writes, including FF23/FF27/FF41/FF0F/FFFF and
FF46/FF55 DMA triggers, still clear facts. Each wider STORE byte qualifies
independently in architectural order with 16-bit wrapping. Mapper transitions
and physical stack identity checks remain independent.
Initialized Program RAM never supplies runtime values. Branches carry transient
snapshots. At an identical static address, MapperKnowledge and register map, N3
joins physical byte facts by retaining only exact values established on every
incoming path. Disagreement or absence becomes unknown. A weakened processed
state is requeued; compatible memory revisions do not consume address diversity,
but every evaluation consumes the global state budget. Incompatible mapper or
register states stay separate. Unsupported calls and the existing diversity fallback drop facts. Existing
resolved WRAM banks stay distinct without new bank inference. See the
[bounded RAM contract](decisions/ordinary-ram-byte-facts.md).
See the [bounded memory join contract](decisions/ordinary-memory-join.md).
Engine `20261002-call-stack-liveness-2e-1` uses schema 4 with a fingerprint
component for certificate storage eligibility; preceding schema/engine results require a new preview. N3 memory joining remains intact.

An unmodified unconditional direct CALL can compose a bounded callee with
sequential nested direct callees (maximum active ordinary depth three) when
exact SP, the actual pushed return bytes, defined executable ROM and one physical
target are established. The same evaluator executes callee instructions and
unconditional RET; the popped physical frame bytes, returned PC/SP and outgoing
mapper must prove an available continuation. Compatible returning paths retain
common register/flag bytes and N3 RAM facts. Mapper state comes from actual callee
effects. Different return mapper/continuation identities and any incomplete path
retain the conservative unknown continuation. The 179-state callee resource cap consumes
the original global state budget too. Frames and memory remain transient. See the [three-level contract](decisions/three-level-ordinary-call.md).
Unknown data from supported ordinary RAM or the bounded CGB FF70 read stays
unknown without independently making callee coverage incomplete. Unsupported or
unresolved read effects still refuse coverage; unknown data used by control,
return, stack or mapper checks must satisfy the existing exactness requirements.
The preceding `20261001-call-stack-liveness-2b-1` engine requires recomputation;
the persisted shape remains schema 4.
See the [returning-call contract](decisions/ordinary-returning-call.md).
Successful unconditional CD composition additionally produces a structured durable
ordinary-call certificate with exact source/target/continuation static and physical
identities. Every relevant encounter at a source must succeed compatibly; failed or
unresolved alternatives veto that site. Generic CALL Findings remain destination
observations. Conditional and software calls have no ordinary-CD certificates;
incomplete results expose none. See the
[certificate and compatibility contract](decisions/ordinary-call-proof-certificate.md).
Applying a current ordinary-CD certificate installs a primary physical stock CALL
on the decoded operand and temporarily displaces its exact DEFAULT CPU reference.
Raw architectural p-code remains CPU-addressed. Exact receipt-based normalization
keeps the unchanged proof current without accepting generated flow as evidence.
Edited/user/imported competing references refuse publication or remain preserved
on removal. Changed proof dependencies retire unchanged owned flow before fresh
analysis; removal restores the original DEFAULT only while its source matches.
Stock Function discovery is notified only on actual publication changes, with
bounded self-feedback. See the [stock flow contract](decisions/ordinary-call-stock-flow.md).
Nested returned state resumes the containing callee's actual continuation before
its own RET can return state to the outer caller. A failed nested proof invalidates
the containing invocation. N7 admits multiple sequential direct returning sites:
each new callee receives the previous returned state and a fresh physical frame,
while the containing invocation retains its original frame. Admission counts active
frames, not completed sites. See the [N7 contract](decisions/sequential-returning-call.md).
N6 additionally interprets CALL NZ/Z/NC/C and RET NZ/Z/NC/C through validated
instruction-local raw p-code guards. Exact F selects one outcome; unknown F
preserves both. False CALL/RET has no stack effect, and true paths retain the same
physical frame proof. One conditional transfer site per invocation is supported;
reachable incomplete alternatives invalidate composition. See the
[N6 contract](decisions/conditional-call-ret-microflow.md).
N8 follows unmodified E9 `JP HL` when both architectural HL bytes are exact
and current mapper knowledge proves one defined immutable executable physical
ROM target. Every target instruction byte must agree with current authoritative
Program sources. The jump preserves registers, flags, SP, mapper, physical RAM
facts and any active ordinary frame; it creates no call frame or fallthrough.
Unknown pointers, ambiguous sources and generated views remain unresolved.
No Function is required or created. See the [N8 contract](decisions/finite-pointer-successor.md).
Finite pointer tables, arbitrary computed flow and indirect calls remain open.
RETI, RST, fourth-level/recursive/computed calls, RAM code, general
summaries, symbolic pointers and device/interrupt summaries remain unsupported.
Discovery requires existing defined instructions and currently refuses any seed
with a non-DEFAULT label, including imported symbols. These limitations are
explicit work in the [research record](static-analysis-research.md), not proof
that the missing code or named routine is invalid.

# Owned enhancements

Preview is separate from application. Apply/remove/reapply receipts persist native
identities and original states for references, bookmarks, functions and supported
far-call fallthrough overrides. Removal checks the current object still matches
what GhidraBoy added. A later user edit or another component's object is preserved.
New applied runs remove unchanged old additions before replacement, avoiding stale
bookmarks. Transactions and cancellation roll back partial mutations. Installed
separate-process tests verify save/reopen and lifecycle, not only in-memory calls.

Reference receipts now include primary status. Missing historical primary evidence
or a later primary edit prevents removal; envelope 3 rejects older destructive
readers, and saving another group never fabricates
missing proof. Older `analysis.ownedReferences` records and their references are
retained because they cannot establish unchanged status.

Ownership receipts use envelope version 3 and individual function version
2 under the existing `analysis.ownership.v1` option key. Legacy function receipts
are retained with an explicit reason and their destructive ownership is dropped;
saving another feature never upgrades old function proof or re-baselines it against
current annotations. Discovery returns these preservation diagnostics on reruns.

Destructive removal is limited to unchanged bare functions with the built-in default
undefined return, no locals/parameters, tags, thunks, or namespace children. Any
variables or non-default types (including pointers and typedefs) make ownership
uncertain and prevent deletion, even if already present when the receipt was made.
This deliberately retains more functions: a data type path, size or timestamp cannot
prove that its members, comments or nested definitions are unchanged in place.
Eligible receipts compare function identity/name/namespace, body, signature source,
return storage, comments, calling convention, inline/no-return/varargs, call fixup,
stack cleanup/frame, pinning and entry-point status. Retained functions are skipped
on subsequent discovery; destructive ownership is not reacquired. Cancellation
rolls back both deletion and relinquishment. Existing user functions are never claimed.

Function discovery is seed based: existing entry points, explicitly declared code
and proven direct calls. It uses defined instructions and preserves existing
functions, bodies, prototypes, storage, overrides and marked data. Labels and
vectors do not automatically become functions. Incomplete results contribute no
proven call seeds; stale results are rejected.

References added as supplemental navigation information do not implement a
mapper-aware memory model or select a live bank. Ghidra separately supports
primary flow override references which can alter p-code calls/jumps under strict
conditions. Those must not be confused with ordinary navigation references;
see [research](static-analysis-research.md#software-call-semantics).

# Exact supported far-call convention

The opt-in ordinary-MBC3 trampoline pops the RST return, reads bank:u8/target:u16,
pushes the return advanced by three payload bytes, then transfers through a
pushed target and RET. It **changes the ROM bank without restoring it**. Therefore
accepted callers, payloads and return sites must be proven fixed ROM0 below 4000.
Switchable-ROM callers are rejected. Explicit SP must keep all four stack bytes
within fixed WRAM0 or HRAM. Body bytes, payload bounds, mapper/view identity,
existing overrides and target/continuation boundaries are validated before mutation.
Undefined target code is not a proof of return behavior.

Compiled-p-code fixtures check target entry, return address/SP and fixed caller
physical identity. Preview, application and unchanged-owned removal are exposed
in the tools script. Default RST behavior remains unchanged. This is not universal
support for arbitrary game-specific conventions, arbitrary MBC1 conventions,
or runtime execution. Live execution is provided by the optional debugger.

# Software-call effect previews (SA-01 partial implementation)

`SoftwareCallModel` provides exact, versioned finite helper contracts for inline
RET transfers and register-target JP HL helpers with nonrestoring, restoring or
constant-selector return policies. `SoftwareCallValidation.preview` checks those
contracts against actual Program bytes and instruction boundaries, using explicit
register/mapper/stack premises. It reports real frame operations and physical
target identity. These read-only previews do not install executable semantics;
The production application described below installs validated interpretations;
unsupported overrides and callfixups remain unresolved.

`FarCallConvention.previewReviewed` returns a versioned review token; the apply
overload rejects changed evidence inside its transaction. Payload instructions,
defined data, incoming references, symbols and function bodies are conflicts,
as are target/continuation interiors. Conflicts are preserved for review.
Unknown targets are not asserted to return. Existing annotation application is
separate from the production software-call application; its legacy behavior
does not silently convert undefined payload bytes to owned data.

The new review digest additionally covers context, permissions, incoming
references, function contracts and ownership state. This is independent of the
separately versioned bounded-analysis engine/result format. See the source checkout's
`docs/decisions/static-call-model.md` for tested Ghidra mechanisms and outstanding
qualification. SA-01 remains open; a passing raw-frame fixture does not
qualify general banking, native decompilation or automatic-analysis behavior.

### Reviewed software calls (integration candidate)

`GhidraBoyTools.java` now exposes `software-call-preview`, `software-call-apply`
and `software-call-remove`. Supply a JSON array of
`SoftwareCallValidation.Configuration` records describing exact helper templates,
physical mapper entry state and explicit register/frame premises. Preview records
payload ownership and original/repaired annotation inventories before mutation.
Application rejects unsupported effects and conflicting knowledge; it does not
infer a convention from a name or ROM title. The installed dynamic callfixup
resolves each site independently and rejects stale or unregistered sites.

These are finite synchronous contracts, not universal callee ABIs or a claim of
whole-ROM discovery. Returning effects come from raw code under the stated
premises. Unknown RAM/volatile effects, invalid frames, unsupported nonlocal exits
and unrepresentable banked continuation/data views remain unresolved. Ordinary
bounded analysis additionally requires its incoming register and mapper facts to
establish the saved site premises. The original architectural SLEIGH semantics
remain the fallback outside validated conventions.

For a proven return into a different physical bank, reviewed application may
create a companion function in a shared-byte execution view. The original
canonical function and storage remain available. This view is limited to proved
nonoverlapping CPU ranges; it is not a general bank-aware native architecture.
Source checkout evidence and remaining gates are in
`docs/evidence/sa01-production-20260907/` and `docs/decisions/static-bank-model.md`.


Canonical and execution-view entries now both use the installed per-site mechanism.
The canonical entry expands the validated continuation CFG into local p-code edges;
the alias follows its shared-byte mapped listing. Canonical listing uses a reviewed
CALL_RETURN terminal-expansion override to prevent payload/obsolete-bank decoding;
its injected tail still has the actual architectural returns. Both require the paired canonical
and alias ownership state to remain current. Physical call targets and real stack,
register and flag operations remain explicit. The canonical p-code tail is located
at the call site; use the reviewed execution view to navigate its physical instructions.

Initial conflicting CALL endpoints, including legacy supplemental far-call targets,
are rejected for explicit migration rather than recorded as valid initial state.
A same-space first continuation is scanned through later direct flow to detect ROM
window crossings. Transported tails still require finite, nonoverlapping physical
ranges; later calls, mapper changes and same-CPU competing identities remain open.
Nested false noReturn/CALL_RETURN metadata can be repaired only with a matched raw
RET witness for that call, with original/applied metadata shown in preview.

Qualification remains incomplete; current source evidence is
`docs/evidence/sa01-resume-20260907/`. Prepared instruction fixtures do not establish
fresh-import discovery when helper or callee instructions are missing. The public
JSON entry point requires every register and mapper premise explicitly;
missing/null fields are unresolved input, not implicit zeros.

### State-qualified software-call review

Public software-call review now includes exact missing-instruction candidates and
state graphs. Discovery follows only proof-requested physical roots and validates
bytes, data boundaries, payload reservations and annotations before committing.
Cancellation rolls back the whole application, and removal retains discovered
canonical code rather than claiming unproved deletion ownership.

State graphs preserve later call/mapper/register/flag/memory/frame effects under
the recorded synchronous entry premises. Known nonlocal transitions retire only
proved logical frames; their physical saved words remain available to real cleanup
instructions. A deterministic bounded loop is conditional on those premises.
Unknown effects, missing state and exhausted bounds remain unresolved.

The architectural interpretation remains distinct from a selected native display
context. An ordinary unknown caller must not borrow a context's output constants.
The bounded analyzer still checks its incoming register and mapper facts before
consuming a configured software-call effect; a context alias is not independent
evidence for those facts. See the current state integration receipt for executed
native, discovery, persistence and normal-window coverage and remaining scope.


## Bounded ordinary finite selector reads

The straight-line ordinary-entry producer can lower an N-member byte selector
through the existing list-shaped proof records. It retains the actual selector
computation, captures its operand at the mapper write, and derives every
selector/physical-ROM-byte association through the concrete mapper authority.
Each non-first alternative adds a byte equality, product and modular sum. A
single incoming domain therefore preserves selector/value correlation rather
than choosing a bank from the displayed address.

This path retains exact/singleton/two-way behavior and refuses the completely
unknown 256-member byte set as TOP. Supported finite expansion is bounded by
4,096 added p-code operations per payload, including selector snapshots, and by
the reserved scratch region and actual unique-space capacity. Every added
operation consumes a 16-byte scratch slot. The complete cost is checked before
proof admission and emission; exhaustion reports a finite frontier without
truncating alternatives. This is a provider work budget, not a native protocol
limit. The existing 4,096 raw-operation producer bound remains separate.

Broad Program fingerprints still conservatively invalidate proofs after an
unrelated byte edit. Explicit refresh rederives the selector/byte relationship;
this generalization does not narrow dependencies, interpret branches, add
unknown-pointer support or model symbolic mutable RAM.

## Experimental symbolic RAM and executable images

The programmatic predicate-analysis path accepts an explicit checked unknown-RAM
input declaration through `SymbolicMemory.declare` and `PredicatedCallGraph.preview`.
It preserves fixed-WRAM echo aliases and rejects undeclared inputs. An analyzed
may-write invalidates current byte knowledge and dependent executable FETCH facts;
native execution of declared interference remains unsupported.

`ExecutableImages.establish` validates an explicit ROM snapshot, copies bounded
bytes into canonical writable RAM, and creates a durable generation with its own
execution snapshot. Every proof names that generation. RAM replacement rejects old
native use until explicit new establishment; changing source ROM does not recopy
RAM. Source edits may require a separate explicit proof refresh. Old snapshots are
historical and do not acquire current authority from matching bytes or addresses.
These experimental APIs have no ordinary GUI workflow or general migration claim.
See the [memory/image contract](decisions/symbolic-memory-executable-images.md) for
the precise frame, hardware, lifetime and compatibility limits.
