# SA-02 prerequisite: physical software-call continuations

Status: scoped implementation under integration and qualification. **SA-02 remains
open.** This decision does not reduce SA-01's original acceptance requirements.
The primary integration receipt records actual executed checks; source and test
presence alone are not evidence of a passing installed workflow.

## Which SA-01 cases need a different transport

The ordinary MBC3 templates now admit banked caller CPU addresses, provided the
caller instruction and inline payload do not cross a ROM CPU window. Returning
callee effects are derived from raw p-code under the explicit entry register,
stack and mapper premises. Every instruction fetch and ROM read resolves its
physical identity again after writes. A RAM bank shadow is not a mapper premise.
`Frame.continuation` is unknown for banked callers until callee/epilogue execution
establishes the physical continuation; `Returned.physical` carries that result.

Restoring helpers can return to the original caller's physical overlay. Fixed
ROM continuations also remain in their original space. Cross-overlay calls are
already supported by stock native transport, as the retained SA-01 evidence
shows. Those cases do not require a new address architecture.

A nonrestoring or constant-return helper may resume at the caller's next 16-bit
CPU address in a different physical bank. The current `FunctionManagerDB`
requires one address space in a function body. Combining the original caller
bank's instructions and another bank's continuation in one ordinary Function
therefore fails. Merely storing an adjusted fallthrough or physical reference
cannot repair this representation constraint.

Banked inline templates resolve the selector byte in the entry bank and the
following target word in the bank selected by that byte. The exact helper writes
the selector **before** reading the target word. `PayloadSegment` records the
physical intervals, logical positions and actual read lengths; the skipped tail
is reserved separately from actual read events. `Read.physical` records each
ordered bus read. Old-bank bytes after the selector remain untouched, including
preexisting instructions, data and symbols there. Native integration specializes
only these immutable reads with their validated values; stack reads stay real.

## Alternatives on one self-authored fixture

`SoftwareCallExecutionViewTest` uses one MBC3 image: a bank-1 caller at CPU 4500
and bank-3 continuation at CPU 4503. The continuation's immediate result byte
is distinctive. The same source ranges are used for each comparison:

| Alternative | Mechanism and obligation |
| --- | --- |
| Existing physical overlays | The public Function API rejects a body spanning the bank-1 and bank-3 spaces. Cross-bank calls between Functions remain valid. |
| Segment physical bank bits into the current CPU address | The current 16-bit address space cannot represent 14503 as a distinct CPU address. A real segmented alternative requires a new language/address-space, pointer semantics and saved-Program migration; no such redesign is claimed by this check. |
| Scoped execution overlay | Shared byte-mapped blocks place the bank-1 prefix and bank-3 continuation in one overlay at unchanged CPU offsets. The public Function API can represent that body. Source patches remain visible through shared backing. |

This comparison is deliberately limited to the concrete continuation transport
prerequisite. It is not a claim that a complete segmented implementation has
been evaluated or that the general SA-02 memory/alias suite passes.

## Selected prerequisite and public contract

`SoftwareCallExecutionView` provides a reviewed, dependency-checked creation API
for a finite routine's proven execution ranges. Each range states its CPU start,
length and canonical physical source. Multiple ranges may select different ROM
banks. The implementation uses Ghidra's supported `createByteMappedBlock` API,
keeps ROM read-only and leaves canonical storage intact. The caller owns the
transaction, annotation migration and rollback inventory.

Overlapping CPU ranges are rejected even if their physical identity is equal;
a CPU range cannot silently select different physical bytes on different paths.
Ranges cannot cut existing instruction boundaries. Creation refuses an existing
view name and rejects stale previews. Derived view aliases are excluded when
resolving canonical proof inputs, so a generated view does not make its own
physical bank premise true. The whole Program dependency digest covers source
bytes, mapping and annotation changes.

This is a multiple-bank finite execution view, not a single-bank copy. It still
cannot encode paths that revisit the **same CPU address** under different
physical banks inside one Function. It also does not establish arbitrary
bank-sensitive indirect data accesses in native C. Those obligations require a
broader context-sensitive representation or a scoped native/Java integration
hook and remain in SA-02. Production application must reject a case when its
required ranges cannot be represented faithfully; it must not extend a proved
prefix to a whole bank by assumption.

## Callee proof and its limits

`SoftwareCallEffects` executes raw instruction p-code using the existing integer
evaluator, exact physical ROM reads and tracked physical RAM/stack writes.
Nested architectural calls use their real pushed return words. Matching balanced
RET and unchanged live wrapper frame bytes establish a returning path; modified
or nonlocal frames do not. Restoring and constant epilogues then compute actual
registers, F, SP and mapper state with the versioned call model. The proof never
uses function noReturn/prototype annotations or generated call references as
source semantics.

The result is conditional on all supplied entry premises, including flags. It is
not an all-input callee ABI. Unknown initial RAM, volatile reads, unsupported
userops, unknown required values and exhausted instruction/recursion bounds are
unresolved. A repeated exact deterministic machine state establishes a loop only
within these premises; a helper return path does not establish callee return.
The summary exposes actual memory writes and result-register changes. Integration
must preserve distinctions between value changes under these premises and a
universal clobber contract.

## Compatibility and primary evidence

The call template and preview policies advance to version 3 because their
accepted banked-caller domain and physical inline-read records change. The effect proof policy has its own version-3 identity; the execution-view record
retains its separate version-1 identity. No SLEIGH constructor, CPU register width,
compiler ID or physical mapping schema changes. Existing Programs retain their
canonical blocks; view creation is an explicit reviewed Program mutation.
Separate-process persistence and installed native checks are required for the
application path before it is qualified.

Primary mechanism sources inspected in the pinned stock Ghidra 12.1.3
`SoftwareModeling-src.zip` are `FunctionManagerDB.java:218-225` (single-space
body check) and `Memory.java:365-402` (shared byte mapping). The source archive
identity is retained in the source-only receipt
`docs/evidence/sa01-20260907/ghidra-mechanisms.md`.
Hardware selector semantics continue to use `MapperState` and the ordinary MBC3
contract; raw selector masking and disconnected ROM address lines remain separate
from CPU address arithmetic.

Remaining architectural work: same-CPU multiple-bank execution, general
bank-sensitive native loads/stores and aliases, arbitrary mapper variants,
interrupt-driven state transitions, and complete SA-02 comparative qualification.
None is waived by this prerequisite.

Continuation data accesses are additionally gated: the scoped view currently
admits immediate immutable ROM0 reads, whose physical identity is independent
of the selected bank, and exact RET/RETcc stack reads in fixed WRAM0/HRAM.
Register-indirect and switchable-ROM data loads require further native physical
data-view proof and are rejected. Preceding SP writes are likewise rejected by
the finite continuation scanner. A code execution range is not silently reused
as a data identity or enlarged to include an unproved banked table.

The effect summary now separately exposes its physical fetch transcript and
`nativeCompatible` result. Completing architectural execution does not establish
that the original native callee view represents it: unrepresented intrafunction
bank changes, indirect native targets and data accesses whose physical identity
differs from the native execution context veto production application. Ordinary
nested calls must agree with decoded physical destinations and supported native
contracts. The raw effect result remains available when this transport gate fails.

Explicit nested software-call configurations are passed as an immutable review
context, then persisted by the registry; no temporary global registration is used.
At each nested transfer, the actual raw machine's registers, SP and mapper must
match the separately validated configuration. Only that exact helper's prelude
and epilogue are transparent to native compatibility checking. Its physical
callee is a separate native frame, and its returned live frame and epilogue results
are checked. Unknown nested helpers receive no such exemption. This context
supports exact hardware and manually pushed-continuation entry templates without
turning an ordinary unrecognized RET or JP into a software call.

A proven RET to a different known destination now retains a NONLOCAL snapshot:
actual CPU/physical destination, post-RET SP, registers, mapper state and the final
RET event. No wrapper epilogue is executed by that snapshot. Production integration
can redirect to its proved code boundary instead of inventing the encoded
continuation. An unchanged expected destination with unproved stack purge or
modified live wrapper frame remains unresolved; frame disagreement alone is not
a nonlocal-flow classification. Native transport still separately gates the actual
destination and any required continuation view.

The finite continuation scanner now admits decoder-known writes to fixed WRAM0
and HRAM outside the two bytes of the live return word at the proved SP. It
recovers constant address calculations within each instruction (including LDH),
checks each byte with 16-bit wrapping, and rejects mapper/device, unknown,
bank-selected, conflicting native-memory and live-return-word destinations.
It does not infer an indirect pointer from untracked register state. SP-changing
continuations remain unsupported. These write effects are preserved, not turned
into claims that subsequent volatile reads are constant.

`returningNativeFunctions` records actual matched native-frame RET witnesses,
including nested functions that return before an outer nonreturning path. Fetching
a Function does not add such a witness. The neutral may-return marker preserves
an ordinary CALL and consumes a freshly derived witness through the registry;
it does not supply registers, stack effects or a universal returning ABI.

Native compatibility also distinguishes bus lowering from raw mapper execution.
An indirect STORE or scalar address-output write to cartridge control space can
be modeled architecturally, but it is not accepted as native mapper semantics
without the decoder-known direct-write lowering. Reselecting the same bank does
not waive that check. FF4F/FF70 writes require their exact writable, volatile
native I/O transport; subsequent fetches and data accesses still undergo physical
identity checks after the state transition.


## Confirmed qualification boundary at handoff

The latest focused checkpoint directly decompiled both the companion execution
Function and the canonical source Function. The companion passed; the canonical
root failed with an unregistered software-call injection at `rom1::4100`.
`Function.setThunkedFunction` metadata did not redirect that root decompile.
Earlier installed tests also disproved cross-space canonical fallthrough as a
solution by producing p-code address-space errors. No replacement normal/public
window route is selected or qualified by this checkpoint. The original entry
must remain visible in the failure inventory; alias-only success does not close
SA-01. See the source receipt `docs/evidence/sa01-production-20260907/`.

Clean view removal now retires real shared mappings as non-executable after
removing unchanged owned code/functions. It preserves address-space identity for
queued ordinary analysis tasks. Last-block deletion caused actual installed
errors; no queue cancellation or analyzer disablement is used to conceal them.
Edited or uncertain views remain protected. At that handoff, the corrected lifecycle still needed
a complete installed rerun; subsequent current outcomes are recorded in the resumed receipt.

## Canonical root and later-window correction

The resumed integration keeps mapped alias flow and adds local continuation CFG
lowering inside the installed callfixup for canonical roots. The latter avoids
cross-space native fallthrough and needs no custom decompile script or private API.
Canonical and alias registry identities are paired; either entry rejects drift in
either receipt. Physical-tail source locations remain available through the view.

View selection now inspects later direct continuation flow, including a first
continuation at fixed ROM0 3ffe followed by selected-bank 4000. Every consumed
instruction byte must be immutable initialized physical ROM, including bytes in
split blocks. Same-space native tails retain their ordinary data/stack semantics;
transported tails additionally require the existing physical data/SP constraints.
Unknown later call/mapper effects and overlapping CPU identities still require
further work. No general SA-02 architecture or completion is claimed.

Execution-view policy advances to 2; registry/effects advance to 4 and injection
implementation to 2. Shared-byte storage and mapping schema remain unchanged.
Current evidence is `docs/evidence/sa01-resume-20260907/`; prior campaigns are retained.

The stronger canonical mutation test required stable scratch entry anchors for
local branch targets that otherwise disappear during nested native injection.
Canonical sites now explicitly terminate initial listing flow with CALL_RETURN;
the installed expansion supplies the complete continuation's actual RET/loop CFG.
Alias listing fallthrough remains mapped and ordinary. This representation has
injection implementation identity 3; it is distinct from architectural nonreturn.

## State-qualified execution revision (2026-09-07, qualification in progress)

The new work is recorded separately in
`docs/evidence/sa01-state-20260907/`. Earlier receipts and the finite v2 view
contract remain intact. The new representation is a graph of physical fetches
and complete declared machine states, rather than a map keyed only by CPU PC.
Its node identity includes mapper state, register bytes, physical memory and
live call-frame state. A repeated CPU PC can therefore have several physical
sources and several graph nodes. The original CPU addresses, return words and
pointer arithmetic remain 16 bits.

`SoftwareCallContinuationView` lowers validated graph edges to local p-code
labels, with stable anchors retained across nested native injection. It retains
raw register/flag/stack operations, emits actual physical calls, and specializes
immutable ROM reads using their separately proved physical **data** identities.
Indirect mapper stores are lowered byte by byte to the existing cartridge bus
userop, retaining ordering and widths. A code fragment is never reused as a
banked data identity. Original native compatibility vetoes remain in the proof;
transport must discharge individually typed obligations, including separately
proved nested invocation graphs and prerequisite callee graphs. Annotation and
ABI conflicts do not become transport exemptions.

Shared byte-mapped fragments preserve every fetched physical range. Different
contexts have different execution aliases even when their CPU offsets overlap.
Canonical blocks and existing function bodies are retained. Fragments carry
only proved ranges; no whole-bank padding is introduced. Public Tools can list
and select the reviewed execution context displayed at a canonical callee.
Proved calls route to the corresponding context alias, independent of the
canonical display selection. Exact premises remain recorded, and the native
Decompiler displays a conditional-model header. Ordinary unknown callers do not
receive another site's output constants or a fabricated unknown ABI. This is
explicit context selection, not an all-input function summary.

### Mechanism comparison and native protocol

The retained investigation executes a real widened physical-space candidate
with 16-bit CPU registers, pointers and return words plus explicit address
adapters. It represents the addresses, but the identical branch/data/nested-call
fixtures still produce wrong flat targets and missing bank-sensitive flow in
native output, including separate reopen. This is evidence against that
candidate; it is not a claim to have completed every possible segmented design.
The same investigation records the existing overlay limitation and a SLEIGH
hook experiment. Ghidra's ordinary `uponentry` mechanism rejects branching
injection because it executes after basic block construction.

The selected callee mechanism is the optional, narrowly scoped native protocol
`__ghidraboy_state_entry_v1`. Only that explicitly assigned prototype requests
its dynamic entry graph **before** raw flow recovery. The native patch rejects
empty, falling-through or escaping graphs and retains normal handling for all
other prototypes. The Java callback rederives the graph from current Program
bytes, configuration, dependencies and ownership. It cannot serve an unregistered
entry. Ordinary continuation lowering continues to work with the preceding
native companion where no state-qualified callee protocol is required.

The optional composite companion is built and installed into new copies by
`tools/state_entry_native.py`. Its separate marker fingerprints the original
switch patch, new entry patch, pristine source lock and actual binary. The Java
application checks that marker and binary before admitting an entry context.
A contradictory old switch-only binary marker is removed only from the new
copy, with the prior marker and binary retained in its rollback inventory.
Source distributions and active installations are not modified.

### Compatibility decision

No SLEIGH constructor, register/context layout, language version, CPU pointer
width, compiler ID or physical mapping schema changes. Compiler specifications
add an explicit protocol prototype cloned from their existing default storage
model; their default models are unchanged. Assigning that prototype requires
reviewed bare metadata or a current owned context. The original convention and
comments are retained for removal, including when unrelated user fields change.

The built candidate uses registry/ownership/effects 5. Current source advances
registry to 6 for caller prototype/body dependencies; ownership/effects remain5.
The registry6 source is not a newly qualified artifact. State graph,
rooted discovery and entry protocol each have independent version-1 identities.
Injection advances to 4. Finite execution-view 2 and view-stamp 3 remain unchanged.
The bounded analysis engine is `20260907-sa01-state-contexts`. Older executable
registry records must be removed, reviewed and reapplied; their ownership
receipts are read conservatively and never acquire new destructive authority.
Fresh, saved and installed verification is reported by the new receipt. This
section does not itself close SA-01 or SA-02.

### Normal-analysis failure and user-requested handoff

The built state candidate passed provider and finite installed checks, but fresh
ordinary analysis converted a default-named caller alias into a helper thunk and
propagated the helper fixup to the canonical source. Inventories isolate that
change from normal data-reference refinement. Current source adds explicit alias
naming and an owned redirect for newly created callers, but its new full-analysis
regression still fails after analysis and reports supplementary fragment flow
into unmapped memory. This is an open representation/integration obligation, not
a reason to weaken stale checks. Exact current-source and prior-artifact results
are separated in `docs/evidence/sa01-state-20260907/HANDOFF.md`.

## Supplementary fragment integration (registry7 candidate)

The new integration retains every mapped physical range and original instruction.
Stock DecompilerSwitchAnalyzer may open a temporary UndefinedFunction at any
callfixup site inside a supplementary fragment. It does not require a saved
Function or consult the fragment's execute flag. A partial physical listing can
therefore expose an unproved raw conditional edge before the caller's complete
graph is used. Treating only saved Function roots as entry points was insufficient.

Supplementary Functions now select an actual depth-zero state in their owning
complete invocation graph. Registry7 distinguishes `graphEntry` from `entryStep`
and explicitly marks projection entries. Native lowering follows the proved local
successors from that selected step, including backedges to earlier step IDs. It
retains the complete original graph for nested-call, prerequisite and veto checks;
unreachable prefixes are not emitted as executable graph operations. Projected
Functions partition existing listing ranges and neither pad code nor truncate
existing bodies. Each native fragment remains tied to the exact invocation used
to plan it, even where two invocations reuse identical physical bytes.

Projection entries have explicit conditional-state comments and the existing
native conditional header. They do not replace canonical callee context choices
or become alternate ordinary call targets. Original canonical storage, language1.0,
compiler IDs, mapping schema and the optional native binary protocol remain
unchanged. State-continuation lowering2 and state-entry injection2 identify the
changed graph-entry contract; older registry records require reviewed reapplication.
Stateful continuation projections now also require the optional pre-flow native
companion at preview, even if their callees themselves need no state entry.

Current qualification belongs to `docs/evidence/sa01-integration-20260907/`.
Independent review still requires full coverage of nested software-wrapper
projection entries and the complete installed/migration/normal-window lifecycle.
Repeated configurations at one physical software-transfer site, general SA-02
architecture and all original broader requirements remain open.
