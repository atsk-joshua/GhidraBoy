# SA-01: software-call model and Ghidra mechanism decision

Status: **production integration under qualification; SA-01 remains open pending its completion audit**. This record does not
exclude required cases or select the SA-02 address-space architecture. The
source checkout evidence directory is `docs/evidence/sa01-20260907/`.

The task targets S-01–S-04, S-08, S-13 and A-CALL/A-GHIDRA/A-DEPENDENCIES/
A-MIGRATION. All 136 source hashes in the accepted SA-00 manifest matched the
initial checkout. Its focused integrity tests were rerun before changes.
Historical receipts have not been rewritten.

## Preceding checkpoint contract (retained history)

`SoftwareCallModel` supplies finite, versioned, exact implementation templates,
not another instruction interpreter. The families use an inline target and RET,
a register target and JP HL, a saved-selector restoring wrapper, or a wrapper
that writes a constant selector before returning. Hardware CALL/RST and an
explicit manually pushed continuation are distinct entry kinds. The model
records actual high-then-low stack writes, pops, payload reads, target physical
identity, adjusted continuation, selector writes and register effects.

The restoring template saves AF but pops it into BC: returning A/BC are clobbered
by bank restoration while the callee's F survives. A saved byte is checked against
an explicit entry mapper register; a RAM shadow is never silently promoted to
physical bank knowledge. Raw selector bytes remain separate from effective bank
selection. Payload lengths are validated independently from the target fields.

Return evaluation is conditional on independently established callee SP, live
stack contents, registers and mapper state. `MAY_RETURN` does not mean every
path returns. Unknown, nonreturning and nonlocal outcomes do not acquire a
fabricated continuation. This is a reusable effect contract, **not a callee
summary prover**. Register and mapper inputs remain explicit premises.

`SoftwareCallValidation` binds these templates to actual Program helper/caller
bytes, defined instruction boundaries and coherent raw interpretation. It reads
payloads from the Program and rejects conflicting boundaries/ownership. Its
read-only previews do not install overrides or claim native integration.

The existing `FarCallConvention` annotation API remains supported. It now offers
an immutable reviewed preview and an apply overload that checks its version,
configuration and dependency digest before opening and again inside the mutation
transaction. The preflight check matters for enclosing Ghidra script transactions:
a rejected stale preview must not abort unrelated earlier edits. Separate-process
verification exposed this issue; a regression now covers the enclosing transaction.
Payload instructions, data, symbols, incoming references and function bodies
are conflicts; target/continuation instruction interiors and defined data are
conflicts. It rejects duplicate resolved sites and checks cancellation before
commit. It does not erase conflicting annotations or claim undefined payload
bytes as owned data.

Review dependencies extend beyond the unchanged SA-00 analysis fingerprint:
helper/payload bytes, all references, context, memory permissions, symbols,
function bodies, noReturn/fixup/prototype/storage information, and existing
ownership/convention options. Review inputs and generated annotations remain
distinct. A changed Program requires another preview. The bounded analyzer still
rejects unsupported effects instead of trusting the new annotations.

## Preceding mechanism experiments and selected direction

The pinned stock Ghidra 12.1.3 Java and native sources were inspected and compared
with the pinned official archive. Detailed source locations/hashes and experiment
limits are in `ghidra-mechanisms.md` in the evidence directory.

1. **Supplemental call reference plus adjusted fallthrough:** retained only as
   the legacy annotation feature. SA-00 regression verifies raw RST still pushes
   the encoded return, and the bounded engine rejects the unsupported summary.
   It does not implement the wrapper or prevent false nonreturn analysis.
2. **Flow override alone:** rejected as a frame model. Raw/overridden tests show
   JP reclassification adds no stack write; conditional jump overrides can erase
   conditions. References cannot establish their own semantic validity.
3. **Supported callfixup injection:** selected as the mechanism to develop for
   helper expansion, subject to the unresolved integration obligations below.
   The experiment preserves the original hardware pushes and explicitly models
   helper stack effects before an ordinary p-code CALL. Ghidra replaces only the
   CALL operation. Its injection `nextAddr` is the call address in this path,
   so it is not a payload-adjusted continuation source. The stock nonreturn
   analyzer honors a fallthrough callfixup without disabling the analyzer.
4. **Physical overlay target in ordinary native transport:** the experiment
   first found that a decoded primary CALL reference takes precedence over the
   explicit override. After removing that competing primary flag, the native
   decompiler successfully recovers the physical callee call. An earlier expected
   transport failure was disproven and retained in the failed-test receipt. This
   supports cross-bank calls; it does not establish multi-bank intrafunction flow.

The selection is an implementation direction, not a qualified production fixup.
The test's in-memory XML injection is not installed in compiler specifications.
A helper-level fixup affects every caller: validating one site cannot authorize
all its other callers. Dynamic injection must validate each site's current
premises and refuse stale/unknown input; its global fallthrough metadata alone
cannot encode target-specific return possibilities.

## Compatibility and remaining obligations

No SLEIGH constructor, context/register layout, language version, compiler ID,
mapping schema, SA-00 engine/result schema or ownership envelope is changed.
Existing receipts retain their conservative removal rules. The new finite model
and read-only preview have independent version identities. The legacy reviewed
preview has version 1; its evidence hash includes a separate review policy token.
It is not an executable persisted interpretation. Actual annotation lifecycle is
checked in separate processes, including removal, reapplication and later edits.

**SA-01 is not complete.** Required outstanding work includes production dynamic
injection and validated InstructionInterpretation integration; effect-aware
callee summaries and invalidation; owned payload application and reviewed
noReturn/CALL_RETURN repair; fresh and repaired ordinary automatic-analysis
qualification with the reusable mechanism; and normal Decompiler-window plus
saved/reopened executable semantics. Conditional/nonlocal raw fixtures do not
prove native interprocedural completeness.

Cross-overlay native calls have positive evidence. The concrete remaining SA-02
dependency is intrafunction physical continuation and memory transport when
execution moves between bank views, including banked callers, return policies
and several bank changes within one routine. Current Ghidra function bodies use
one address space and native flow is bounded by the entry space; the overlay
encoder selects one entry overlay. Compare overlays with explicit execution
context/views, a segmented physical representation and a scoped Ghidra extension
on the same fixtures before selecting a general integration. Do not silently
substitute a single-bank script or broaden CPU pointers beyond 16 bits.

Next task: resolve that comparative transport prototype jointly with the
production callfixup design, then complete the remaining SA-01 integration and
qualification. SA-02 through SA-07 remain open; no roadmap item is replaced.

## Production integration follow-through (2026-09-07)

The subsequent candidate is tracked separately in
`docs/evidence/sa01-production-20260907/`; the earlier partial receipt remains
historical. The installed compiler definitions now declare a dynamic callfixup
implemented by `SoftwareCallInjection`. `SoftwareCallApplication` supplies a
reviewed public entry point and `GhidraBoyTools` exposes preview, apply and remove.
Each callback resolves its physical site from `SoftwareCallRegistry`, checks
saved semantic dependencies and live owned annotation state, and rederives raw
callee effects. No helper-wide target constant or per-site native cache is used.
Unregistered callers fail explicitly rather than borrowing another site's model.

The injected sequence retains the original caller's architectural push, expands
the exact helper implementation, performs the physical callee CALL, restores the
proven post-callee SP, and executes the wrapper epilogue. Proven result registers
(including F) are supplied only under the site's explicit entry contract. These
contracts are synchronous, exact-premise specializations, not inferred universal
ABIs or interrupt-aware summaries. The bounded analyzer independently requires
incoming register/mapper facts to establish those premises before consuming them.

Uniform proven nonreturning paths use a reviewed per-site CALL_RETURN terminal
interpretation. They do not mark every target globally returning or globally
nonreturning. Nonlocal exits without representable target/frame evidence remain
explicitly unsupported for injection. A helper's global may-fallthrough metadata
is only a may-return property; it cannot prove the return behavior of its targets.

The concrete SA-02 prerequisite is the finite execution-view mechanism described
in [the bank decision](static-bank-model.md). Canonical storage remains intact;
reviewed shared-byte views allow distinct caller and continuation banks within
one native function without widening CPU pointers. Same-CPU competing physical
identities and unproved memory transport remain explicit architectural work.

Review found and corrected gaps in incoming-state premise checks, live annotation
validation, immutable physical fetch, native target contracts, view-prefix proof,
and redundant-fallthrough normalization. The first installed automatic-analysis
runs also exposed overbroad dependency hashing and compatible generated payload
READ references. Their failed receipts are retained. Current executed results
and the completion audit belong to the new evidence directory; this section does
not declare SA-01 complete.


## User-requested handoff disposition

SA-01 remains incomplete. `focused-13` executed 75 tests with one failure:
canonical banked source-root decompilation is not redirected by the stored thunk.
The seven production injection cases and neutral may-return heuristic regression
passed, but they do not close that normal-workflow gap. The latest installed
campaign also remains failed; later retirement/marker/schema changes require a
fresh complete campaign. No GUI/normal-window verification ran.

The neutral `ghidraboy_may_return_v1` payload emits exactly one unchanged CALL and
requires a current, independently code-derived matched-RET witness. It protects
proven returning targets from the stock suspicious-caller heuristic without
assigning a helper-wide target, register result or universal ABI. Pinned native
and Java injection implementations prevent self-reinjection. Registry version 3
records explicit execution conditions and native dependency closure; strict JSON
parsing prevents missing primitive premises from silently becoming zero.

Resume from the source file `docs/evidence/sa01-production-20260907/HANDOFF.md`.
The original requirements and unresolved architectural obligations are retained;
no milestone is closed by this handoff.

## Canonical-entry integration revision (2026-09-07)

The retained failure was reproduced at the unchanged canonicalResult assertion.
Pinned DecompInterface starts at the requested Function entry; thunk metadata
cannot redirect that request. Registering a second name alone would still decode
the continuation from the wrong bank, and cross-space fallthrough remains rejected.

The supported dynamic callfixup now records a canonical/alias pair in registry v4.
Both entries require both live ownership receipts. Canonical injection expands
the same helper and physical CALL, then revalidates and lowers the complete finite
continuation CFG to relative p-code branches and architectural RET operations.
Execution-alias injection keeps ordinary mapped native flow. Both routes preserve
16-bit CPU values, actual stack accesses and helper register/flag effects. Local
lowering makes canonical high-pcode tail locations refer to the call site; the
reviewed segment inventory and alias listing retain physical instruction locations.

A separate executor regression compares conditional branch/RET tails with raw
architectural execution, including distinct live external return words. Native
canonical and alias assertions are retained. Evidence and failures are recorded
in `docs/evidence/sa01-resume-20260907/`; passing individual cases is not SA-01 closure.

Initial conflicting helper CALL endpoints now reject, including legacy far-call
supplemental endpoints. No blanket reference deletion or silent migration occurs.
Exact ordinary nested CALL_RETURN/noReturn repairs require matched architectural
RET witnesses and expose original/applied metadata in the public review. Other
flow, target, fixup, purge and memory transport vetoes remain in force.

Compatibility: injection implementation token 2, registry/effects 4, execution-view
2; template/validation policy 3 and ownership envelope 4 remain. Old executable
registry records require public remove/review/reapply; no decoder, register layout,
compiler ID, native dependency or physical mapping schema changed. The bounded
engine advances to `20260907-sa01-canonical`. General same-CPU/different-bank paths
and later continuation effects remain original obligations, not exclusions.

### Installed follow-up: parallel analysis and reference refinement

The expanded installed campaign exposed two further integration issues. Stock
constant propagation analyzes functions concurrently and writes generated
references during sibling injection callbacks. The payloads now retry a complete
validation up to sixteen attempts only when the Program modification number moved;
unchanged stale dependencies remain failures. The neutral payload implementation
advances to 2; final failure retains a rejected witness cause where available.

Pre/post installed view snapshots isolated a false ownership invalidation:
a decoder DEFAULT DATA reference on LD(c103),A was refined into an ANALYSIS WRITE
reference by normal analysis. View-stamp policy 3 normalizes only an unedited
DEFAULT DATA reference matching its actual decoded operand. Arbitrary DEFAULT
and user/imported references still veto and preserve edited views. Old stamps
remain conservative; no historical receipt is upgraded into deletion authority.
Campaign failures and separate regression outcomes are retained in the resumed
evidence and the production installed-runs directory.

### Native local-target follow-through

The stronger same-interface inline-payload mutation fixture exposed an incorrect
canonical write to address zero followed by truncated flow. Its native dump proves
the correct c200 STORE was injected. Pinned `FlowInfo::doInjection` deletes the
original CALLOTHER; `updateTarget` updates only the address's first-op record, not
local relative sequence targets. `findRelTarget` then treated the deleted local
target as original instruction fallthrough and reached payload LD(BC),A.

Injection v3 places a stable scratch COPY anchor before each continuation
instruction, so local edges survive nested injection without rewriting the
architectural operations. Canonical sites also receive a reviewed CALL_RETURN
terminal-expansion override: native initial recovery must not decode payload or
obsolete-bank bytes before the full continuation is injected. The alias keeps
ordinary mapped fallthrough. This is not helper/callee nonreturn, and original
raw p-code pushes and Function bodies remain intact. Public site inventory records
`canonicalTransport=TERMINAL_CONTINUATION_EXPANSION` and `appliedCanonicalFlow`.
The existing canonical native assertions remain; listing assertions reflect this
explicit representation change. The retained diagnostic dump is
`docs/evidence/sa01-resume-20260907/canonical-tail-before-native.xml`.

## State-qualified continuation and discovery follow-through

The next integration, recorded in `docs/evidence/sa01-state-20260907/`, extends
architectural execution through later ordinary and configured calls, direct and
supported indirect mapper writes, conditional returns, exact-state loops and
proved nonlocal transfers. Call outcomes distinguish matched returns from
nonreturning or nonlocal outcomes. They preserve the actual physical stack words;
logical frame retirement never erases saved wrapper bytes or executes an
unreached epilogue. Unknown inputs and exhausted bounds remain unresolved.

The corresponding state transport and optional native entry protocol are
specified in [the bank decision](static-bank-model.md#state-qualified-execution-revision-2026-09-07-qualification-in-progress).
A native compatibility veto is retained in the architectural summary until a
separate graph proof supplies its transport. Canonical callee navigation explicitly
selects a reviewed context; actual proved callers target their own context aliases.
Selection is transactional, dependency checked and persisted. It does not change
the caller's actual register, mapper or stack premises.

Rooted instruction discovery is read-only during review. It uses Ghidra's
speculative decoder only at physical roots reached by the proof, reserves inline
payloads first, and checks bytes, annotations, permissions, boundaries and context.
A failed finite traversal rolls its candidates back before the state-graph
fallback. Application commits exactly reviewed instruction extents without
following speculative disassembler flow. Existing labels/comments/references
are preserved and named justified function entries may be promoted. Removal
conservatively retains discovered canonical instructions; no new deletion
ownership is inferred for code that ordinary analysis or users may now consume.
Broader SA-04 callback, table, script and mutable RAM-image discovery is unchanged.

Compatibility and executed qualification belong to the new receipt. Historical
567-test and six-phase evidence remains tied to its original package; neither
that baseline nor this implementation description qualifies a new artifact.

## Ordinary-analysis boundary correction (registry7 candidate)

The reproduced registry6 failure and new evidence are retained in
`docs/evidence/sa01-integration-20260907/`. Pinned EntryPointAnalyzer retries
one-byte Function bodies. CreateFunctionCmd then recognizes a terminal RST as a
thunk through CreateThunkFunctionCmd.getSimpleFlow, before inspecting its real
stack-write p-code. FunctionDB delegates the alias's fixup to the helper, and the
canonical redirect inherits the same invalid contract. Explicit names do not
prevent this. Setting an empty default signature's source to ANALYSIS was rejected:
native serialization would lock a no-argument prototype.

Canonical complete expansions and stateful caller aliases instead retain CALL
flow and own an explicit self-fallthrough. Initial native decoding stays within
the actual transfer instruction; the complete injected CFG executes its actual
return, loop or nonlocal outcome before reaching that transport edge. Raw bytes,
hardware/manual stack writes, CPU widths, original Function bodies and default
signatures remain unchanged. The owned edge is not a claim that the CPU loops.
Strict flow, reference, prototype and ownership drift rejection remains required.

The public inventory identifies `BOUNDED_SELF_FALLTHROUGH_EXPANSION`. Registry7
rejects older executable records and requires remove/review/reapply; injection5
identifies this transport contract. Ownership5 remains conservative, with original
fallthrough and override fields restored only when their owned replacements are
unchanged. Actual saved-provider migration and current-artifact installed/GUI
qualification are separate gates, still pending at this candidate checkpoint.
