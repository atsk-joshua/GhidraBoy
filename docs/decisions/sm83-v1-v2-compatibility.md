# SM83 language 1 to 2 compatibility

The extension provides an explicit, installed simple translator from
`SM83:LE:16:default` version 1 to version 2. The destination remains language 2.0,
with unchanged 16-bit hardware storage and compiler IDs. No core, native or
instruction-semantics changes are part of this transition.

`data/languages/old/sm83-1.lang` was generated with the public
`OldLanguageFactory.createOldLanguageFile` API under the actual final version-1
provider from `eaf60575e212ae91e64aef48ba691fed2d3f878a`. Its ten input hashes match
the retained migration preparation manifest. Recompiling those exact inputs
reproduced SLA SHA-256 `02f52cc6eeb44ebc94cfda1d24e58e73b27b8585e729ea30dff1807a0a994a2a`.
The generated descriptor SHA-256 is
`3c0e4151480cc7fef7b0e82b745f502e08abd5c64975a050be97caf4e88f9ab7`.
`GenerateSm83OldLanguage.java` is the reusable generator; its installed input
must first pass the manifest verification in `tools/sm83_compatibility.py`.

A declarative translator is sufficient: existing spaces and registers map by
identity, all five compiler IDs map explicitly, and newly introduced
`gb_analysis_entry` context is zero. No context clearing or post-upgrade handler
is used. The old descriptor describes storage, not an old decoder. Generating it
from version 2 and relabeling it would not establish compatibility.

The six language files in the retained `42032f9` installed test and the actual
11.3.1 provider have the earlier hardware register/space schema. The final
version-1 provider adds four compiler profiles and semantic corrections, but
no conflicting old hardware fields. The 11.3.1 ADC carry defect remains an
intentional correction, checked by the historical creator and current enhanced
verifier. Older p-code is inventoried and its differences retained; it is not
required to reproduce that defect after upgrade.

## Separate executable authority policy

Core language translation preserves serialized executable records and ownership.
It does not authorize execution, proof conversion, rederivation or removal.
Unsupported/corrupt software-call registries are rejected before ownership
save/removal and direct registry removal. Supported current records retain
ordinary removal behavior, including stale-record removal. No versions, hashes,
ownership stamps or proofs are refreshed by the compatibility guard.

The genuine indexed registry-4 input and one old-provider later-fallthrough-edit
variant are separate witnesses. Their language preservation, read-only public
refusals and actual native refusal must be reported independently. A version
integer negative is not evidence of historical migration. General old-proof
migration remains unimplemented; G4 disposition belongs to master review.

## Preservation and recovery contract

Use complete closed project copies and task-owned installations. Capture under
the old provider, inspect immediately after `DomainFile.getDomainObject` performs
core translation, save and release, then use `getImmutableDomainObject` in another
JVM before any enhancement, analysis or proof application. The immutable flag,
process identities, exact commands, installed translator log and full inventories
are evidence requirements. Enhanced/reanalyzed observations use another copy.

Inventories include original/current bytes, FileBytes sources, overlays, storage,
Functions, types/settings, symbols, bindings, comments, bookmarks, register facts,
raw and structured p-code, assumptions and option records. The comparator accepts
only the declared language/context additions, per-instruction UNIQUE base
normalization preserving relative byte offsets/widths, and a specifically observed
blank Ghidra namespace default that returns on immutable reopen. Complete raw
observations and classified diffs remain available.

Cancellation occurs after core translation and a transaction edit. The original
is never opened by the candidate, and an aborted copy is not published as an
accepted result. Restoring an original copy under its old provider is recovery,
not reverse migration. The captured rollback also distinguishes a transient
registered `Specification Extensions.FormatVersion=0` default from saved data.

## Qualification limits

The default stock route remains incumbent. Only executed compiler/profile cases
are qualified; mapping five IDs does not imply a five-profile preservation matrix.
G1 remains reported complete with master evidence review pending. This task does
not qualify stock release, every historical tuple, broader W4, debugger consumers
or general old-proof migration. Local checks do not constitute hosted CI success.
The task report and [evidence index](../sa/evidence-index.json) contain exact
executed identities, phase results, failures and outstanding obligations.

The historical fixture comparator uses an explicit 49-entry exact p-code-pair
allowlist under `src/test/resources/compatibility/`. It covers only the retained
self-authored encodings from `42032f9` and the 11.3.1 ADC/RET fixture. Unlisted
changes fail; complete pre/post operation streams remain in the evidence.
Current architectural correctness continues to depend on the CPU and native
regressions, not on this identity allowlist. Final version-1 to version-2 requires
unchanged structured canonical semantics and does not use that allowlist.
