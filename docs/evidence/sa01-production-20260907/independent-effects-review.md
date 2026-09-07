# Independent effects and execution-view review

Reviewer: production injection worker, reviewing other workers' `SoftwareCallEffects`,
`SoftwareCallModel`, `SoftwareCallValidation`, and `SoftwareCallExecutionView`.
This is not an independent review of the reviewer's injection implementation.
The effects worker separately reviews that surface. Reviewed 2026-09-07.

Disposition: changes require the corrections and qualification below. This review
cannot certify SA-01 complete. The primary receipt owns final artifact identities,
executed installed/persistence results and requirement completion audit.

## Findings communicated during implementation

1. **P1: mutable code fetch was not tied to the actual code image.** The effects
   machine tracked writes in a physical memory map but fetched preexisting listing
   p-code without checking that its instruction bytes remained the executing image.
   A target could write RAM code and jump into an older decoded RAM listing. The
   bounded safe correction is rejecting non-ROM or mutable instruction fetch until
   a proper code-image mechanism exists. Require a written-RAM-code negative.
2. **P1: helper validation had lost its physical ROM0 requirement.** The helper
   was selected by default-space CPU offset; generalized boundary checks required
   only some physical ROM identity. Arbitrary remapping could therefore validate
   helper bytes at the wrong bank. Require mapper-resolved ROM0 identity for every
   helper byte and reject altered mapping rather than trusting a space name.
3. **P1: continuation transport admitted memory reads without supplying their
   data identity.** `continuationSegments` permits arbitrary LOAD while the view
   initially maps only code intervals. A banked ROM read through HL or an immediate
   pointer needs a mapped and proven data source. For this scoped transport, reject
   unsupported non-stack reads unless their data ranges are added with proof.
   Architectural RET stack access must retain its actual semantics.
4. **P1: generated annotation acceptance must be exact.** Generalized template
   validation ignores all flow overrides and references while reviewing repairs.
   That is not by itself authorization for arbitrary later helper/site edits.
   Installed resolution must compare the owned current annotation inventory, or
   reject conflicting overrides, while keeping repair previews distinct. A changed
   helper RETURN override or site continuation must not be silently trusted by
   bounded analysis after installation.

The effects owner was asked to fix findings 1, 2 and the validation portion of 4;
the primary owns finding 3 and integration of owned annotation validation. Final
fix/test disposition must be appended after inspecting the corrected sources and
executed regressions. Merely requesting a correction is not evidence it passed.

## Positive bounded findings

The effects machine executes compiled raw p-code with byte-width operations,
physical read/write translation, mapper updates before the following fetch, and
an explicit bound. Unknown initial RAM, device access, unsupported userops and
unknown required values remain unresolved. Its concrete initial register and
mapper values are declared entry premises, not a universal calling convention.

Stable repeated architectural state supports a nonreturning cycle only within
that explicit deterministic state model. Exhausting the instruction bound remains
unresolved. Changed-register sets reflect value differences for those premises;
they are not all-input clobber summaries. The production injector must not use
such sets as a global ABI.

The model distinguishes the caller frame, wrapper epilogue frame and callee RET.
It compares live frame bytes before accepting return and resolves physical
continuation after restoration/constant-selector effects. The banked inline
restriction correctly accounts for the selector write preceding target-word
loads: changing the physical payload source is currently rejected rather than
reading target bytes from the old bank.

The selected execution view retains 16-bit CPU offsets and shares source bytes.
It explicitly rejects overlapping CPU intervals requiring different physical
identities; this is a scoped SA-01 prerequisite, not general SA-02 completion.
Nonlocal exit transport, general state-dependent code/data identity, asynchronous
interference and broader symbolic premises remain distinct obligations.

## Reinspection during integration

The effects fetch now requires an initialized, non-writable ROM block for every
instruction byte; runtime RAM code remains explicitly unresolved. The validation
helper loop now checks physical ROM0, mapper-resolved execution address equality,
and raw-interpretation conflicts before accepting the helper. These close the
source defects in findings 1 and 2. The effects worker added both a writable-ROM
negative and the motivating written-RAM-code negative; the latter was added after
the test timestamp below and still requires its next executed result.

Inspected current JUnit XML timestamp 2026-09-07T05:46:44.526Z: effects tests 7,
zero failures/errors/skips. Validation XML timestamp 05:46:46.491Z: tests 7,
zero failures/errors/skips. Those counts establish only the then-executed cases;
they do not qualify later edits or the entire required integration matrix.

Helper conflicting-flow rejection closes the helper portion of finding 4.
Installed site ownership/invalidation and unsupported continuation read handling
remain subject to primary/ownership integration. Configuration still does not
express interrupt/interference policy; deterministic concrete callee results must
not be promoted to asynchronous or all-input proofs. Nonlocal exit transport and
unknown input-path closure remain incomplete architectural requirements.

## Subsequent banked inline extension

The earlier conservative rejection of a changed payload bank is being replaced
by ordered physical payload validation: the selector uses the entry mapper and
the target word uses the mapper after the helper's real selector write. The
`Read` events now retain physical provenance. The injection worker implements
sound constant folding only for these three proven immutable ROM reads, retaining
architectural stack reads and selector writes. This extension requires its new
old-bank/new-bank counterexample, native-view and actual-injected-execution tests
before it supersedes the earlier verified restriction; final receipts own that
qualification. It does not generalize folding to arbitrary banked loads.

Continuation read reinspection: the implementation now rejects unsupported
register-indirect/banked LOAD and SP changes, while admitting validated immediate
fixed-ROM0 loads and fixed-RAM RET stack reads. This addresses finding 3 within
the declared scope. I checked pinned `OverlayAddressSpace.getAddress(long)`:
addresses outside the overlay's mapped ranges fall back to the underlying space.
Thus fixed-ROM0 data need not be duplicated into each view; arbitrary banked data
still require additional physical mapping. The new continuation-data test checks
indirect rejection and immediate fixed-ROM acceptance; native data-folding evidence
should remain separately identified from that boundary test.

## Executed correction checks

Reinspected JUnit outputs from 2026-09-07T06:03:05Z–06:03:09Z: effects 8/8,
validation 8/8, execution-view 2/2, all with zero errors/failures/skips. The effects
output explicitly includes the written-RAM-code counterexample and writable-ROM
negative; both pass. The validation suite now checks ordered banked payload
sources. Findings 1 and 2 are corrected in inspected source, with the mutable-code
counterexamples exercised. Finding 3 is corrected within the intentionally bounded
continuation-read policy; broader banked data remains unsupported.

The injection suite from that same run reports 5/5, including the new banked inline
native/actual-pcode counterexample and payload mutation rejection. That is supporting
integration evidence, not this reviewer's independent certification of their own
injection code. The separate effects worker owns its injection review.

This receipt still does not certify completion of SA-01. In particular explicit
asynchronous premises, general unknown-input path summaries, nonlocal native exit
transport, broader continuation graphs, and final installed/persistence acceptance
remain the primary requirement-by-requirement audit's responsibility. Narrow
rejection rules preserve correctness but do not redefine required milestone scope.

## Final re-review: current actionable items and closure

This section supersedes earlier pending-disposition lists. Inspected the latest
banked-inline payload order, immutable-read folding contract, canonical source
thunk redirect, and target effect/native boundary. No implementation edits were
made during this re-review.

Current actionable findings communicated to the primary:

1. **P1 — Native compatibility of mapper-changing target fetch is not established.**
   Effects follows physical fetch after each mapper write. The production CALL
   identifies the original canonical target, whose ordinary native decompilation
   remains in its entry overlay. A returning raw proof that crosses physical views
   therefore does not establish the target's native CFG/C. Add a target execution
   view with a proven fetch transcript, or gate executable acceptance on native
   transport compatibility while retaining the raw effect proof separately.
2. **P1 — Prefix reads need the same physical data policy as continuation reads.**
   `validateViewPrefix` admits arbitrary LOAD without adding its data source to the
   generated view. A banked read through HL or a banked immediate address can fall
   back to an absent or different underlying-space range. Reject unsupported reads
   or supply validated physical data ranges before redirecting the source function.
3. **P2 — Application preview must agree with injection target-contract rejection.**
   Preview checks target fixup and purge, but permits an inline target or a thunk
   with noReturn false; injection rejects both. Reject or explicitly repair those
   target contracts during preview, so successful application cannot guarantee a
   subsequent injection error. A target thunk with noReturn true likewise needs
   rejection before the mutation transaction, rather than midway through apply.
4. **P2 — Redirect compatibility is broader than ownership-stamp eligibility.**
   `functionStamp` records but does not reject custom convention/purge, inline,
   noReturn, varargs or custom-storage flags. Using non-null stamp as evidence of
   a bare caller contract can redirect such a function to a fresh default view
   without an explicit metadata disposition. Gate these attributes or review and
   preserve them deliberately; an ownership digest is not an ABI compatibility test.

### Target body question: not a new rejection rule

Do not reject a callee merely because raw execution leaves its annotated
`Function.body`. Pinned native `Funcdata::startProcessing` (`funcdata.cc:150–163`)
starts flow recovery across the entry address space. `FlowInfo::newAddress`
(`flow.cc:218–229`) checks those address-space bounds. Java
`DecompileCallback.getPcode` (line 212) obtains instructions through
`getInstruction` (line 363), which uses the listing or pseudo-disassembly without
requiring membership in the annotated body. Bodies influence symbol/comment and
stack-override metadata; they do not define the full native execution extent.
This source evidence supports same-space recovery beyond a truncated body. It
must not be extrapolated into mapper-aware cross-space recovery.

Inspected source SHA256 values:

- `DecompileCallback.java`: `8908d3c35079377d31f57279cf111eda40ec24e7747135a687400723658d5e26`
- `funcdata.cc`: `1a2ea213a4fcd9e3fdfa44d2def9f4c5eaca76678d00a611e5d3da0fafcdcca3`
- `flow.cc`: `bde7bed05b3cd01b0032610b517533e0414f2bb008cf87d81b7c9e577ad860ad`

### Original requirement closure assessment

The new mechanism is substantive production integration, including site-specific
injection, ordered banked inline reads, explicit frames/results, reviewed payload
application, scoped continuation transport and ordinary provider/native tests.
It is not another isolated XML-registration prototype.

**The original SA-01 requirements are not yet closed.** The actionable acceptance
mismatches above require resolution or accurate unsupported classification. Even
a safe rejection does not satisfy required general native target/continuation
behavior. Nonlocal native exits, explicit asynchronous premises, unknown-input
path closure and broader continuation graphs remain architectural obligations.
Only the primary's final installed/persistence and requirement-by-requirement
receipts can qualify their actual completed subset; a larger passing test count
cannot close these missing requirements or mark general SA-02 complete.

## Final finding dispositions after corrective integration

Reinspected the corrective sources. Application now gates raw summaries with
`nativeCompatible`, checks inline/thunk target contracts in preview, restricts
redirects to explicit default caller contracts, and applies the fixed-ROM0 read
policy to prefixes. The injector independently gates native compatibility.
Effects records physical fetches with active native-call context, compares actual
fetch through the entry overlay's address-resolution fallback, and audits native
read/write physical identity (with only explicit fixed WRAM0/HRAM fallback when
optional hardware blocks are absent). Raw complete proofs remain separate from
native transport acceptance. These corrections address all four actionable
items in the preceding final re-review at source level.

No additional accepted-semantics defect was identified in this pass. Verification
of these final edits, including the same-interface payload mutation/reapply native
cache regression, belongs to the next/current primary test receipt. Unsupported
native transport is now explicit, but its rejection is not completion of that
original requirement. The SA-01 closure assessment above remains unchanged:
production integration has advanced materially, while the full original scope
cannot be certified complete by this review.

The 2026-09-07T06:19:23.671Z installed-injection XML reports 5/5 passing tests
and includes the updated same-`DecompInterface` regression: a selector mutation
invalidates the saved callback, public review/reapplication accepts the new bytes,
and the already-open native interface then calls bank 2 and computes the new
`0x52` result. No test-side native cache flush or custom injection registration is
used. A subsequent nested two-configuration native regression was added later
and is not covered by that timestamp.

## Nonlocal native diagnostic adjudication

The first known-nonlocal native assertion expected A's `0x66` destination value
in C despite leaving the caller ABI unspecified. The retained native dump
`nonlocal-inferred-hl-native.xml` and high-pcode output show the actual CALL to
`rom2::4100`, injected branch to `0180`, and final RETURN at `0182` carrying HL
(`0xc0ff`). The destination was reached; its otherwise-unused A assignment was
optimized away when native return inference selected HL. This was a test
expectation defect, not evidence of lost nonlocal branch transport.

The corrected test retains the original self-authored bytes and requires native
RETURN at `0182`, excluding the original continuation's `0153`–`0155` CFG. Actual
p-code execution separately verifies A becomes `0x66` after reaching `0180`.
This tests control transfer without imposing a synthetic A-return prototype or
adding unrelated continuation-store support merely to make a value visible in C.
The native duplicate-branch unreachable-block warning remains in the diagnostic
evidence rather than being suppressed. The corrected assertion requires a fresh
passing run before claiming qualification.
