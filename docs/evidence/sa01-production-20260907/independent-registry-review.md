# Independent registry and bounded-analysis review

Reviewed by the ownership/application worker. Independent coverage here is
`SoftwareCallRegistry`, the software-call branch and context initialization in
`BankAnalysis`, and their dependency connection through `ProgramFingerprint`.
The reviewer authored application/ownership code and does **not** independently
certify that surface. The other workers' cross-reviews cover it.

This is not a certificate that SA-01 is complete. The primary receipt owns final
source hashes, full tests and installed process acceptance. No independent builds,
Program mutations or active-installation changes were performed for this review.

## Findings and disposition

1. **Native type dependency closure required correction.** Initial registry
   dependencies included native return/parameter type paths and sizes. A mutable
   composite or typedef can change in place without either changing, leaving a
   consumed native contract stale. This was reported to the primary. The current
   `nativeTypeIdentity` traverses the type graph, including composite offsets and
   component identities, pointer/typedef targets, array shape, bitfield layout,
   enum values, function definitions and settings. It bounds traversal and retains
   graph edges. The primary added a same-name/same-size composite mutation behind
   a pointer regression. This closes the identified source-level omission for the
   represented type families; final execution belongs to the subsequent receipt.

2. **A custom cache hook is not inherently missing.** Initial source search found
   no provider `flushCache` hook. Inspection of the pinned Ghidra implementation
   corrects that concern: `DecompInterface.decompileFunction` calls `flushCache`
   after an active native request. Registry resolution also recomputes dependencies
   and effects per request rather than caching a site result. A provider-specific
   flush is therefore not necessary merely to obtain between-request native
   refresh. A same-interface mutation/reapply regression remains useful explicit
   qualification; the repeated 0/1/0 fixture primarily proves site separation.

3. **Complete context seeding is appropriately conditional.** The new bounded
   path reads Program context only when an executable registry is present and
   only accepts `RegisterValue.getUnsignedValue`. The pinned implementation returns
   null unless the complete register mask is known. Unknown flag bits are not
   invented from the helper configuration or from an assumed CPU reset. Context
   values are declared entry premises, not facts inferred from the convention.
   Context dependencies retain both value and mask because `RegisterValue.toString`
   explicitly prints both. This addresses the initial failed positive fixture
   without introducing a guessed flag value.

4. **Incoming state is checked before summary substitution.** The actual bounded
   work item must equal the configured mapper knowledge and all required A/F/
   BC/DE/HL/SP values. At a manually framed JP, expected SP accounts for the already
   executed PUSH; ordinary CALL/RST checks use caller SP. Unknown or contradictory
   inputs generate an unresolved finding. The current code does not authorize a
   site's constants simply because that site has a registry entry.

5. **Live annotations are vetoes, not evidence.** `resolve` calls the ownership
   consistency check before returning a freshly validated frame. Current flow,
   fallthrough, helper identity and relevant FLOW/OVERRIDE reference state must
   match installed state. Generated READ annotations are deliberately excluded
   from that flow veto; validation still checks real code and physical payload
   sources. The registry never derives the target from its generated references.
   View-required canonical sites are omitted from the executable registry; only
   the reviewed companion alias is registered, avoiding the disproved cross-space
   canonical fallthrough mechanism.

## Dependency and analysis observations

The semantic digest includes mapped initialized bytes, mapping identity, memory
permissions, configuration/site/physical-target identity, component versions,
language/compiler identity, complete Program context and consumed helper/target
native contracts. The stored digest does not hash itself. Generated bodies and
ordinary references do not become semantic proof. Boundary and payload checks
are repeated during resolution; target effects are rederived from raw instructions.
Missing or edited decoding therefore cannot become a stale reused summary even
though generated listing state is not itself the semantic digest's authority.

The summary branch propagates returned registers, SP and mapper state and follows
physical continuation views. It does not explore a fabricated continuation for a
nonreturning exit. The bounded worklist still limits exploration; a complete run
is not whole-ROM completeness. Memory-write traces remain available in the effects
summary, while the bounded findings branch currently emphasizes call targets and
continuation traversal rather than reproducing every helper/callee memory-access
finding. Do not describe that branch as a general interprocedural memory analysis.

## Primary-source checks

Read directly from source ZIPs in the disposable pinned Ghidra 12.1.3 installation:

- `ghidra/program/model/lang/RegisterValue.java`, SHA256
  `54587fdc9cd2dbd01ab8678d567a339225c6922d23480b883f4ce800f7e0eeb6`:
  complete-mask behavior of `getUnsignedValue`, mask/value rendering in `toString`.
- `ghidra/app/decompiler/DecompInterface.java`, SHA256
  `296eb7147ab65f6caed59b97518679659093d925a44819127aa5ae8dcbda878c`:
  `decompileFunction` performs the native cache flush after requests.

## Requirement audit and evidence limits

| Requirement | Current disposition |
| --- | --- |
| Production per-site recognition and native injection | Installed registry/compiler mechanism exists; raw bytes/premises are revalidated, with different sites retaining different configurations |
| Bounded-analysis interpretation | Exact incoming-state check and returned-state propagation implemented; current positive context fixture XML reports one passing test at 2026-09-07 06:09:10 UTC |
| Stale contract rejection | Code/mapping/context/permissions/native-contract digest plus live annotation veto; mutable-type closure was corrected during this review |
| Banked continuations | Scoped shared-byte companion views preserve 16-bit offsets; this is a specific SA-02 prerequisite, not general same-CPU multi-state transport |
| Callee effects | Deterministic concrete-premise execution is implemented; universal unknown-input clobber/path summaries and asynchronous interference remain architectural obligations |
| Native representability | Newly added `nativeCompatible` distinguishes raw execution proof from native transport; unsupported intra-callee bank changes/indirect nested transport must reject before mutation |
| Nonlocal exits | Explicit unresolved behavior remains; general production nonlocal-exit transport is still an architectural obligation |
| Ordinary analysis and persistence | Installed run 4 passed initial analysis and reopen phases, but remove/reapply logged errors from retained old views and was correctly marked failed despite PASS markers; subsequent cleanup correction requires a new campaign |
| Native cache | Pinned implementation flushes each completed native request; direct same-interface mutation/reapply qualification should remain separately identified |
| SA-01 completion | Not certified here; narrow unsupported-case rejection does not redefine the original milestone requirements |

The next acceptance step is the coordinated full and installed campaign after
view lifecycle and native-representability corrections, followed by the primary
requirement-by-requirement audit. The remaining architectural items above must
retain their original scope and cannot be closed by a larger passing-test count.

## Subsequent nested-call inspection

The reviewer independently inspected the separately authored effects producer's
registered-helper transparency. It matches each candidate against actual current
mapper/register/SP state, validates its frame, executes the raw helper prelude,
tracks the actual nested target as a separate native function, and validates the
return/epilogue state. An unmatched or unsupported nested transfer does not gain
transparency from a helper address alone. Raw execution completion and native
representability remain separate results.

A concrete omission was reported: ordinary nested native-call targets initially
rejected thunk/inline/fixup/noReturn annotations but did not reject explicit
nonzero stack purge. That could invalidate native inner-frame behavior even when
outer injection later restores outer SP. The effects owner added the purge check
and its counterexample. The primary also extended persisted dependency closure
with the fetched native-function entries so nested native prototypes are consumed
and invalidated rather than only direct outer targets/helpers. These source
corrections require their coordinated test receipt.

One acceptance limit remains important: an absent Function is accepted for a raw
callee, while subsequent automatic creation of a default Function changes the
stored native-contract digest from absent to present. This is conservatively
stale, not unsafe certainty, but prepared fixtures with precreated Functions do
not establish seamless unprepared function discovery. Likewise concrete-premise
native compatibility qualifies that execution path, not universal native C for
all inputs to a shared callee. Preserve these distinctions in the final audit.

The installed lifecycle campaign subsequently passed initial, reopened and
remove/reapply phases before exposing stale queued addresses when an overlay was
deleted. The ownership worker is correcting that separate surface by retiring
owned listing while retaining real shared mappings/address-space identity. This
reviewer authored that correction and therefore leaves its independent acceptance
to the other reviewers and the new installed campaign.

## Qualification updates

The current installed-injection regression now keeps one `DecompInterface` alive,
changes a consumed selector byte, confirms stale injection rejection, reviews and
reapplies, then checks both native C and CALL target identity for the new bank.
The archived full-2 XML reports that test passing. Combined with the pinned
per-request flush implementation, this closes the between-request native-cache
qualification concern identified above for the tested production workflow.

The absent-Function issue is being corrected in application using the supported
ordinary function-body calculator with explicit overlap/data/symbol preflight and
owned function creation before the registry snapshot. This reviewer authors that
application correction and does not independently certify it; a dedicated public
apply plus repeated automatic-analysis regression accompanies it. General fresh
automatic convention discovery remains distinct from supplied-site application.

Known nonlocal RET destinations are also being integrated as actual CPU/physical/
SP/register snapshots rather than a fabricated normal continuation. Unknown
nonlocal destinations and incompatible target contracts must remain unresolved.
The final audit should replace the earlier blanket nonlocal transport obligation
only with the finite cases actually executed and accepted by the later receipts.

A final public-boundary check identified that Gson can default omitted primitive
premises to zero. The primary added `SoftwareCallConfiguration`: required fields
must be present and non-null, integer values must fit exactly, and mapper enable
state must be a JSON boolean. The public workflow now uses this boundary before
constructing configurations. This prevents absent F/BC/etc. from becoming invented
known inputs. Saved registry configurations are checked through the same boundary.

Pinned `FunctionPrototype.java` inspection also established that signature source
controls native input/output locking and that function-definition noReturn is
consumed. The registry now includes those fields. Source member SHA256:
`d69ec238b8e24857f011d9398b5e66d8e2d3cb2565e77c4b3d64fde32dfb964f`.
These are concrete dependency corrections, not new ABI guesses.
