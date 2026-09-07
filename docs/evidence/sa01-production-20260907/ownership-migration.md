# Software-call ownership and reviewed repair

Current view removal retires unchanged owned listing and functions while retaining
real shared-byte mappings with execute=false. It does not delete address spaces.
Edited or uncertain views remain intact. The historical deletion attempts below
explain the later correction; they are not the current removal contract.

This note describes the production application implementation, not a completion
certificate. The primary integration receipt records the exact source identities,
executed commands and final results. Earlier SA-01 receipts remain historical.

`SoftwareCallApplication.preview` inventories the original transfer override,
continuation, helper noReturn/fixup/thunk state, caller body and exact payload
units. It derives callee effects before offering executable application. Unknown
or unsupported nonlocal effects reject; a wrapper return instruction is not proof
that its target returns. The immutable Review stores configurations and the
whole review dependency fingerprint. Application checks this fingerprint before
opening a transaction and again inside it, preserving enclosing-transaction user
edits when already-stale input is rejected. Cancellation before commit aborts the
application transaction.

The payload classifier preserves contained built-in byte/word/undefined scalar
units and byte arrays. It rejects partial data-unit extents, instructions,
symbols and references. A caller body claim is repairable only when the same
function contains the immediately preceding call and starts before the payload;
application subtracts only the proven inline bytes. The reviewed inventory retains
original and repaired ranges. Arbitrary overlapping function claims remain
conflicts. No instruction or conflicting user data is cleared to obtain a match.

Application clears a false helper thunk before changing helper noReturn/fixup
properties, avoiding forwarded edits to its former target. The original thunk
identity is retained. Site CALL_RETURN repairs and fallthrough adjustments carry
original and applied values and source instruction bytes. Manual transfers use
CALL classification at the final JP; their preceding stack push stays architectural.
Uniform proven nonreturning sites use CALL_RETURN with no invented continuation.

The ownership envelope advances from 3 to 4. Envelopes 1, 2 and 3 still load; no
legacy incomplete receipt is promoted into permission for destructive removal.
New receipts cover data, helper repairs, flow repairs, body ranges and reference
primary changes. Removal changes only matching applied state and reports preserved
edits. A generated payload byte is removable only when its type/settings/comments,
bytes, symbols, references and function claims remain bare and unchanged. Missing
or uncertain stamps never authorize deletion. Compatible pre-existing data is
never owned. A later body change relinquishes restoration ownership.

`AnalysisOwnership.softwareCallCurrent` provides a live veto for changed installed
flow/fallthrough/helper state. It is not proof of semantics; recognition and effect
derivation still consume actual code, physical identity and explicit premises.
The registry must call this veto before providing production injection.

The added `SoftwareCallApplicationTest` covers compatible data, conflicting
extents/symbols, later payload comments and continuation edits, stale review inside
an enclosing transaction, false noReturn/CALL_RETURN repair, false thunk/caller
payload-body repair, and final cancellation. Its first coordinated run recorded
7 tests with no failures/errors/skips. Subsequent Java changes and installed or
separate-process qualification require the primary receipt's later checks; this
initial focused run alone does not establish persistence or whole-SA-01 completion.

Subsequent integration adds returning-target noReturn repair with original-state
ownership. Target callfixups and explicit nonzero stack-purge contracts reject
instead of silently replacing a potentially meaningful ABI. The live veto now
also compares each site's complete installed reference inventory, including
physical target, operand, type, source, primary status and symbol identity.

The first live-veto regression run exposed a Ghidra normalization detail:
setting fallthrough to its architectural default clears the override bit. Both
the register-call and banked-view checks initially rejected this valid installed
state. Repair receipts now capture the actual applied override bit after mutation
and compare that exact bit and continuation; the failed focused receipt remains.

Bank-changing continuations use a reviewed companion execution view. Its mapped
ranges share canonical bytes; the original caller function and original-bank
continuation bytes remain intact. The caller prefix requires contiguous decoded
boundaries without unexplained control transfer or memory/mapper writes. The
continuation suffix comes from bounded architectural CFG inspection under the
proved return mapper. The view's helper call override explicitly targets the
physical fixed helper; competing decoded primary status is retained in a
reversible receipt. The companion function uses the actual caller entry.

View cleanup has its own conservative receipt. It hashes review inputs without
including its self-referential ownership option and additionally checks view
mapping metadata, comments and bare function/data constraints. An unchanged view
can be removed transactionally. A changed or uncertain view remains present with
an explicit diagnostic; a later reapplication chooses a new unused view name.
This whole-Program dependency policy can preserve a view after unrelated changes;
it intentionally prefers retained work to incomplete destructive evidence.
The banked application regression now exercises native CALL/RETURN, unchanged
view removal, reapplication and retention of a later continuation comment.

Ordinary installed analysis subsequently produced expected payload READ references
from the validated adjacent call and dynamic DEFAULT byte labels. These outputs
are compatible: only ANALYSIS READ/operand-0 references from that exact call and
dynamic DEFAULT symbols are ignored as conflicts. Other references and static or
user symbols still reject. The live per-site reference veto compares FLOW and
OVERRIDE records; derived memory-read annotations are not executable premises and
do not invalidate an otherwise unchanged convention. A regression supplies the
compatible reads and then demonstrates rejection of a wrong-origin read.

The first full provider run reached 525 tests. Its two failures were an old test
expecting ownership envelope 3 and the independently owned RAM-negative summary
assertion. The ownership test now explicitly expects envelope 4 and checks that
legacy envelope 2 and 3 receipts lacking new lists and primary edit evidence stay
non-destructive after another group is saved. These corrections require the
subsequent coordinated full run; the earlier failures are retained.

Installed ordinary analysis exposed that a canonical instruction cannot carry a
fallthrough to another address space: Ghidra's listing p-code override rejected
that state. The corrected application preserves canonical architectural flow and
registers executable semantics only at the companion view's transfer instruction.
A source function with bare compatible metadata receives an explicitly owned
thunk to the companion. Custom signatures/storage or uncertain function metadata
reject instead of being silently replaced by the companion's default contract.
Redirect removal checks the applied metadata stamp and restores the source before
considering view deletion. The canonical listing bytes and fallthrough therefore
remain architectural while the normal function destination identifies the proved
execution view. The failed installed campaign is retained as mechanism evidence.

Banked inline payloads are no longer treated as a contiguous range in the caller's
original bank. The shared validator reports physical segments: the selector byte
comes from the entry bank; target bytes and skipped reserved tail come from the
selected bank. Application inventories, classifies and subtracts body claims for
those exact segments and maps the same physical sources into the companion.
Unconsumed old-bank bytes and their annotations remain untouched. Each segment
retains logical offset and actual-read length; reserved bytes are not mislabeled
as loads. Target noReturn and explicit purge/callfixup conflicts now have dedicated
ownership regressions; the independent injection worker owns banked-inline native
and p-code execution qualification.

The coordinated focused-9 run compiled these changes and passed all ownership,
banked native and injection tests. Its remaining failure was the separately owned
bounded-analysis premise fixture. The readable site inventory includes helper
and target noReturn state, helper thunk identity, physical payload segments and
original/repaired caller body ranges. Execution-view plans identify the companion
ranges; redirect receipts retain original and applied metadata stamps. Clearing
an unchanged source redirect restores its original local function metadata.

Independent source cross-review examined the live reference veto and view cleanup
and found no destructive hazard in those reviewed paths. This is source review,
not a substitute for the primary owner's final installed save/reopen campaign or
requirement-by-requirement completion audit.


The later installed campaign reached the edited-removal phase and exposed queued
ordinary-analysis tasks holding addresses in a removed overlay. Deleting the final
mapped block removed that address-space identity and produced genuine follow-up
analysis errors. The supported correction retains the original shared-byte blocks,
clears only unchanged owned listing/functions, and marks the derived mapping
non-executable with explicit retirement metadata. It does not create fake bytes,
cancel queues, disable analyzers or modify canonical source bytes. Retired mappings
can therefore resolve saved/queued addresses without remaining executable provider
views. The bounded analyzer excludes these retired derived execution candidates.

View receipts now compare relevant local identity rather than unrelated Program
changes. Compatible automatically generated nonflow references and dynamic default
symbols do not prevent retirement; comments, bookmarks, user references, code/flow,
metadata and source mapping changes remain vetoes. A final retained-function check
prevents retiring a view beneath a preserved source thunk or user function. Active
registry aliases additionally compare their complete view receipt, so a later
continuation flow edit invalidates execution before removal preserves the edit.

Prefix memory validation covers explicit LOAD and direct address-varnode/COPY
reads and writes. Only proven immutable fixed-ROM0 reads are admitted in this
scoped view; unknown/indirect/banked data reads reject. Target inline/thunk state
rejects during review, and source redirects require default semantic caller
contracts. Raw effect completion is separate from native representability;
application now requires the effects producer's nativeCompatible result. Nested
registered-helper derivation receives the full immutable candidate configuration
list rather than obtaining proof from generated references.

Missing native callee Functions are now created before the registry snapshot from
Ghidra's ordinary body calculator. Application first rejects defined-entry,
existing-function, symbol, data and body-range conflicts; it does not use the
command path that silently subtracts ranges from other functions. The supported
FunctionManager creation records actual body ranges and an absent-to-created
disposition, with standard edit-preserving function ownership. A regression begins
with a decoded target and no Function, applies publicly, then runs two ordinary
analysis passes and checks registry validity. This addresses default Function
creation invalidating a just-installed native contract.

Finite known nonlocal returns now receive an explicit NONLOCAL disposition and
actual derived destination. Same-space destinations add only the validated suffix
ranges to the caller body; original unreachable ranges remain inventoried and
untouched. Cross-space destinations use the same companion representation. A
nonlocal path does not prove that a target's true noReturn contract is false, so
that conflicting contract rejects instead of being cleared. Sequential body
changes for multiple sites are coalesced from stored original/applied chains
before rollback; a dedicated two-call regression prevents partial restoration of
one shared caller body. Final runtime acceptance remains in the primary receipt.
