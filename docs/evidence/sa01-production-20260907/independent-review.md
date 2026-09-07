# Independent cross-review of production integration

Status: review in progress; this is **not SA-01 completion certification**.

The reviewer authored `SoftwareCallEffects`, `SoftwareCallExecutionView`, the
banked model/validation changes and their tests. Those files are **excluded from
this review's independent coverage**. The injection author independently reviews
those areas. This review covers the separately authored registry, injection,
application, ownership changes, bounded-analysis integration and installed
workflow. No parallel builds or Program mutations were performed by the reviewer.
The primary receipt owns executed test and installation identities.

## Findings sent to implementation owners

1. **P1: summary premises must match incoming analysis state.** `BankAnalysis`
   initially consumed a registered exact-premise summary without comparing its
   current `Work` mapper/register values to those premises. A different incoming
   A/HL/SP or mapper could acquire another path's physical target and constant
   outputs. Matching must account for the actual caller transfer (the manual
   prefix has already pushed its continuation at the JP site). Unknown or
   contradictory required inputs cannot establish that conditional summary.
   Sent to primary owner for correction and regression.

2. **P1: generated site state needs an independent consistency veto.**
   `semanticDependencies` intentionally excludes ordinary flow annotations, but
   initial `resolve` did not consult `AnalysisOwnership.softwareCallCurrent`.
   Consequently a user-edited fallthrough/flow could retain accepted injection.
   The receipt may veto an edited interpretation; it must not prove the raw
   convention. The registry owner was notified. Reference/alias identity and
   helper fixup changes must also remain checked.

3. **P1: native callee contracts can contradict proved architectural return.**
   A target Function with `noReturn` set can suppress the injected epilogue even
   though the raw callee proof reaches RET. A custom native stack purge can
   move the restoring helper's POP operations to the wrong stack word. The
   initial application repaired only helper metadata. Injection owner was asked
   to reject/repair contradictory target contracts through reviewed inventory,
   or explicitly establish the proved post-callee SP before helper epilogue.
   Register-result COPYs alone do not repair these stack/control discrepancies.

4. **P1: generated execution aliases broke canonical application lookups.**
   Application created new mapped ranges before resolving each canonical site
   and continuation again. Those helpers initially selected every physical
   alias, making the first banked-view apply ambiguous. Canonical source lookup
   must exclude derived execution views, while the explicit alias is registered
   separately. Ownership owner was notified.

5. **P1: a mapped caller prefix needs its own flow/mapper boundary check.**
   Mapping caller entry through the call does not prove that preceding branches,
   calls or selector writes use that physical range. A conservative prefix
   validator has since been added: it requires contiguous decoded boundaries
   and rejects unsupported flow/writes, with only the exact manual prelude
   exception. A companion Function must use the original caller entry rather
   than the lowest segment, since a continuation can branch backward; the
   application now selects the actual caller entry. These changes were source
   inspected, not independently executed by this reviewer.

## Mechanism observations

The installed injection is per-site: every callback resolves the Program-backed
registry and rederives effects. The helper-wide fallthrough metadata is expressly
return-capable, not a declaration that every target returns. Uniform proven
nonreturning sites use reviewed terminal flow and omit the return epilogue.
Unknown/nonlocal sites are rejected, rather than converted to returning calls.
These are meaningful production changes beyond the earlier in-memory prototype.

The emitter reuses helper raw p-code, preserves original hardware caller pushes,
renames instruction-local unique storage and uses the physical target Address.
It supplies explicit result-register constants only when all proved returning
paths agree. Such constants are conditional on site premises; they must not be
advertised as an all-input ABI or an inferred universal clobber set.

Payload application inventories exact extents, preserves compatible existing
built-in scalar/byte-array data, and rejects conflicting instructions/symbols/
references. Removal uses live stamps and preserves later edits. The reviewer
has not independently executed every ownership branch or new execution-view
cleanup. Separate-process and edited-view retention evidence remains required.

## Installed evidence scope and remaining audit obligations

`tools/sa01_production_persistence.py` installs the built extension into a fresh
temporary distribution and invokes the public `GhidraBoyTools` workflow. Its
phases run ordinary headless automatic analysis. This is a stronger integration
mechanism than test-only injection registration.

The prepare script manually defines helper/caller/target instruction boundaries
and Functions before applying the convention. Therefore the campaign can qualify
fresh Program **prepared-call application** and persistence, but does not by
itself prove fresh-import automatic call discovery. Its native checks use the
ordinary `DecompInterface`; they are not GUI Decompiler-window observations.
The repeated 0/1/0 decompile sequence checks site cache separation. A same-session
Program mutation/reapply/native-refresh check is additionally needed to establish
that cached native state cannot outlive changed dependencies; no dedicated
production cache-refresh hook was found in the inspected initial implementation.

The final completion audit must distinguish executed passes from source review,
prepared imports from automatic discovery, physical CALL identity from complete
native stack/memory semantics, and explicit rejection from implemented support.
Nonlocal executable integration and unrestricted bank-sensitive same-CPU flow
remain incomplete unless subsequently implemented and independently qualified.

## Follow-up source inspection

The primary owner added exact incoming-register/SP and `MapperKnowledge` equality
checks before `BankAnalysis` consumes a conditional software-call result. The
manual-entry SP adjustment is explicit. `Registry.resolve` now calls the live
ownership veto before revalidation. These address findings 1 and the basic
flow/fallthrough portion of finding 2 by source inspection; focused and installed
regressions remain owned by the primary receipt.

The initial installed campaign reportedly found that hashing every unrelated
instruction/Function caused ordinary automatic analysis to invalidate the
registry. The registry now limits native prototype entries to the target/helper
and rederives consumed raw instruction semantics on each resolution. This is a
reasonable direction, but cache refresh and all actually consumed native inputs
remain obligations. In the follow-up source inspected here, native `isInline`,
thunk identity, varargs/custom storage and formal type identity were not included
in the reduced native digest. A target callfixup/thunk/inline policy can substitute
native semantics for the raw callee proof; until equivalence is justified, these
must be rejected or handled by reviewed repair. This concern was sent to the
primary and injection owners.

The injection author's independent review of this reviewer's implementation
identified mutable/RAM instruction-fetch acceptance and weakened fixed-helper
validation. Those findings were corrected with immutable initialized ROM fetch
checks, fixed-ROM0 helper identity checks and helper architectural-override
rejection, with new negative tests. These are **not independent self-approval**;
the injection author's review and primary executed regressions own their final
validation.

### Native cache mechanism correction

Further primary-source inspection resolves the earlier missing-hook concern:
stock pinned `DecompInterface.java:828-834` invokes `flushCache()` after each
completed decompile. `DecompilerProgramListener.java:60-83` refreshes for Program
changes and resets the process for memory-block add/remove and restore events.
Therefore a separate provider-specific cache hook is not inherently required;
the initial search found no bespoke hook because this responsibility is already
implemented by the supported Ghidra integration. A same-session mutation test
would strengthen executed evidence, but **no native cache defect is established
by this review**. Sources were read directly from the pinned distribution's
`Ghidra/Features/Decompiler/lib/Decompiler-src.zip`.

The injection owner subsequently added target thunk/inline/fixup/false-noReturn
rejection and an explicit proved post-callee SP before the helper epilogue.
This addresses the identified native-frame mechanism by source inspection.
Application preflight should surface any such unsupported target contract before
mutating the Program; rejection only at decompile time is not a qualified
successful application. The full regression receipt must establish the final
behavior and any target-annotation repair support actually delivered.

A remaining live-guard concern was sent to the primary: flow/fallthrough and
helper metadata comparison alone does not veto an added conflicting site
CALL_OVERRIDE reference. With reference annotations intentionally excluded from
semantic proof dependencies, exact relevant reference consistency must be
checked separately against the decoded helper/owned alias installation. This
check is a veto on drift, never evidence of software-call semantics.

### Ownership follow-up

The final ownership source inspected adds a complete `SiteReferences` stamp and
checks it in `softwareCallCurrent`, closing the reported reference-drift veto
gap. It also records Ghidra's actual normalized fallthrough-override state rather
than assuming `setFallThrough` always leaves the override bit set.

Execution-view cleanup determines removable views before undoing owned changes.
Its stamp captures Program evidence, source mapping, view instruction comments,
strict data settings and strict Function metadata, excluding the ownership
record itself. `ProgramFingerprint` does not reintroduce that ownership record,
so this exclusion avoids a hash cycle. An unrelated change conservatively
retains the view. Actual removal is restricted to the captured view address-space
names. No destructive-cleanup defect was identified in this source inspection;
executed removal/edit/save-reopen tests remain required evidence.

### Banked inline folding and redirect follow-up

The separately authored injection now specializes only the exact helper's three
immutable payload LOADs at offsets +1/+5/+7. Each expected width-one read must
be consumed; stack reads, pointer arithmetic and mapper writes remain raw. With
Program-backed nonvolatile/read-only payload validation and dependency checks,
this specialization is a sound constant-folding mechanism by source inspection.
The injection author's actual p-code/native tests own execution evidence.

The application now leaves canonical cross-bank fallthrough unmodified and
registers the execution-view alias. A bare source Function redirects to the
companion through an owned thunk; custom contracts are rejected. The source's
identity, destination and applied metadata stamp are checked before removing a
redirect. This prevents an existing edited thunk from being silently reset.
Physical payload segment application leaves old-bank bytes after the selector
outside the owned interval. The reviewer found one new data-view guard gap:
absolute scalar memory reads can appear as COPY/address varnodes, bypassing a
LOAD-only prefix check. This was sent to the ownership author; the analogous
continuation scanner correction and negative test were implemented separately
and require independent verification.

### Neutral returning-target marker

The neutral target payload was independently source inspected: it emits exactly
one CALL to the original context target, requires zero parameter shift, adds no
stack or register effects, checks fresh registry return evidence and uses a
Program modification fence. Pinned native `flow.cc:680-696` explicitly cancels
reinjection when that emitted CALL has the same entry as the active fixup,
preventing recursive self-expansion. The witness must come from an actual matched
RET, not a fetched Function or the outer wrapper's return capability.

The effects author's new `returningNativeFunctions` implementation is excluded
from this review's independent coverage and requires the other reviewer's tests.
A preflight concern was sent to the primary: complete raw return witnesses can
justify repair of false nested noReturn/CALL_RETURN metadata even when that very
metadata currently vetoes native compatibility. Planning such a repair must be
specific to the proved returning endpoint/call; it must not broadly bypass native
contract checks or use incomplete raw execution as return proof.
