# Bounded static analysis

This page describes the implemented bounded analyzer. Completing static accuracy
is the first [roadmap](roadmap.md) priority; the
[planned specification](static-analysis-spec.md) is not a claim that the current
analyzer already meets it.

`BankAnalysis.preview` evaluates existing defined instructions. `AnalysisResult`
is typed and versioned: start points, explicit assumptions, configuration,
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
ROM register knowledge does not imply reset SRAM/RTC/VBK/SVBK state.

Every fallthrough is checked against the CPU execution window. Same-window
physical context is reused only while consistent with known mapper registers.
Cross-window fallthrough, relative branches and wrapped PC resolve through actual
Program views. Cross-boundary fetch stops if identity or bytes cannot be proven.
Undefined code and data markings stop traversal; analysis does not sweep bytes.
Unknown calls invalidate return-state knowledge. No general interprocedural
summaries or runtime bank switching are provided.

Fingerprints cover mapping, initialized bytes, defined data, raw instruction p-code,
length/flow/fallthrough overrides, language/compiler identities, consulted flow and
reference overrides (including endpoints, kind, operand, source and primary state),
and target callfixups in canonical order. Apply/discovery reject stale results;
preview detects changes during traversal. Ordinary supplemental navigation/data
references are not analysis inputs, so application does not invalidate itself.

Engine `20260907-sa00` evaluates raw `getPcode(false)` and decoded default flows
only when stored flow annotations are consistent. Flow/reference overrides, altered
fallthrough/lengths and callfixups are explicitly unresolved; they are not mixed with
raw architectural effects. This includes annotated inline-payload continuations
until SA-01 supplies a validated effect summary. Unmodified conditional transfers
retain alternatives, but internal conditional p-code effects remain conservative.
The evaluator delegates integer operations to pinned Ghidra behaviors with width
and extraction guards. Separate contract and compiled-SLEIGH regressions qualify
this bounded behavior, not whole-ROM semantics. See the source checkout's
`docs/decisions/sa00-integrity.md` and `docs/evidence/sa00-20260907/README.md`.

The current evaluator records memory references without propagating ROM lookup
contents or bank-shadow memory values. It has no general returning-call summaries.
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
