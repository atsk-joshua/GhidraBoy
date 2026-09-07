# Independent correctness review and SA-01 audit

Reviewed the new `SoftwareCallModel`, `SoftwareCallValidation`, `FarCallEvidence`,
the `FarCallConvention` changes against the accepted SA-00 implementation, the
software-call tests, the separate-process persistence script, and
`docs/decisions/static-call-model.md`. This review includes the unified ordered
event stream and the Program manual-entry regression. The focused-run-7 XML was rechecked after these changes: injection 2/2,
legacy review 4/4 and Program validation 6/6 passed. The native CALL endpoint was
`rom2::4000` with the expected address-space ID. The primary receipt owns exact
final source/dependency identities, broader and persistence checks; this review
does not turn pending checks into passes.

**Disposition: SA-01 remains incomplete.** The implemented bounded model and
read-only validation are useful independent progress. They are not a production
software-call interpretation or an accepted general decompiler architecture.
There is no completion certification here.

## Correctness findings

The exact inline template accounts for the hardware caller push, helper POP,
three consumed payload bytes, selector write before target-word reads, adjusted
continuation push, target push and RET pop. Extra payload bytes are skipped by
INC HL rather than read. The ordered event stream preserves that distinction.

The restoring register template has three live words at callee entry. Its POP BC
restores the saved selector through B into A while preserving the callee F; BC
becomes the saved AF. The constant template leaves callee BC unchanged during
its epilogue and writes its literal A selector. The nonrestoring template leaves
the caller frame for the callee. These effects agree with independently authored
compiled-SLEIGH fixtures, including actual stack contents and final SP.

`returnFrom` requires an explicit returning-path classification, matching SP and
unchanged live frame bytes. It does not classify all callee paths itself. Unknown,
nonreturning and nonlocal classifications acquire no invented continuation. Its
mapper input remains explicit; unknown mapper state is not replaced with reset
state. A saved selector must match the explicit raw register state, with MBC3
masking distinguished from effective physical bank selection.

Program previews read actual helper/caller/payload bytes and require decoded
boundaries accepted by SA-00's instruction interpretation. Known context that
contradicts supplied premises rejects. Unknown context does not prove the
premises; those remain user-supplied conditions. Recomputing the entire preview
on `requireCurrent` protects the public record against mismatched configuration
or frame substitution.

Reviewed legacy application now checks the complete review digest both before
opening its transaction and again inside it, then revalidates boundaries. It rejects conflicting payload claims
and changed continuations without erasing them. The earlier duplicate-site
spelling issue was addressed by checking resolved addresses. Cancellation before
commit rolls back changes. The dependency extension includes helper/payload
bytes through the base fingerprint, context (including default ranges and disassembly defaults), references,
functions/prototypes, permissions and ownership/configuration. It is a review-input policy, not an
executable persisted-summary invalidator.

Separate-process persistence subsequently exposed a real transaction defect
missed by the initial source review: rejecting an already-stale preview only
inside a nested Ghidra transaction aborted the enclosing script transaction.
Catching the rejection and making a later user edit produced an immediate listing
assertion that passed while the edit did not survive save/reopen. The failed
persistence receipt must remain visible.

The correction now rejects an already-stale digest before opening any transaction,
while preserving the inner digest check against intervening changes. This follows
the established SA-00 preflight pattern and avoids aborting an unrelated enclosing
transaction for a predictable stale-input rejection. The new regression changes
a user label, catches stale apply, makes a continuation edit, commits the enclosing
transaction, and checks both edits afterward. The transaction-fix focused XML
was rechecked: all five `FarCallReviewTest` cases passed, including that new
regression. The subsequent disposable `persistence-run-3` manifest and all three
logs were independently inspected: prepare, reopen/reapply and edited/reopen
processes each exited zero with their expected PASS marker and no ERROR or
exception marker. That campaign used fixture SHA256
`d3b4ea5cc10546443573323d8b284c97429a29c7c53f748f38f94cbd3cc52944` and extension SHA256
`02882e28c51c2fb7e75e39a9cfc8a827d77a6fe46e684c60c87563d1353b4a3b`. The specific
saved-work defect is verified resolved within the legacy annotation scope. The
headless commands explicitly use `-noanalysis`; this persistence evidence does
not qualify ordinary automatic analysis or persisted executable software-call
interpretation.
Mid-application failures still require transactional rollback rather than partial
annotation application. No additional incorrect frame arithmetic was identified.
These findings do not waive the following implementation and verification gaps.

## Actionable remaining implementation and verification gaps

1. There is no production callfixup/injection installation or validated
   `InstructionInterpretation` integration for the new models. Existing legacy
   annotations remain rejected as unsupported by SA-00 rather than becoming
   executable semantics. Implementing that connection is required.
2. The final injection experiment now executes hardware RST p-code, the actual
   injected p-code, and callee p-code. Its word/SP/register/F checks pass and
   establish raw/injected agreement for the single flat specialization. Native
   output also contains the call and continuation. General per-site injection,
   native SP/register/F consequences and broader software-call effect families
   still require qualification; the new executor evidence closes the earlier
   unexecuted-injection gap only within its stated scope.
3. The real nonreturn-analyzer negative and repeated-analysis experiment support
   the chosen mechanism direction only. There is no reusable, per-site validated
   repair/application path tested on fresh and repaired annotated Programs. The
   test's one-time direct repair is not a reviewable migration implementation.
4. Preview-only models neither own payload data nor persist executable results.
   Legacy removal/reapplication and separate-process listing checks qualify that
   annotation lifecycle only. They do not qualify persisted software-call
   semantics, installed dynamic injection or saved/reopened native CFG/C.
5. Callee return, register/memory/frame effects and mapper output are supplied
   premises. There is no validated interprocedural summary producer or dependency
   closure for derived callee summaries. Conditional/nonlocal execution fixtures
   must not be promoted to such a prover.
6. The MBC3 fixed-helper/fixed-continuation restriction is explicit. Required
   banked callers, multiple bank transitions, physical fetch/read identity,
   aliases and continuation transport remain architectural work. The initial
   expected cross-overlay CALL failure was disproved by execution: once the
   competing decoded primary CALL reference is cleared, normal native
   decompilation reaches the physical callee. The retained failed assertion is
   evidence of that correction. This is not a physical-CALL transport blocker.
   The final test also verifies that the public function-body API rejects one
   body containing addresses from both spaces and preserves the original body.
   Same-function multi-space flow and memory identity still require the
   comparative SA-02 prototypes.
7. `CartridgeBusEmulation` retains flat backing for reads/fetches. Independent raw
   frame tests execute fixed-window targets and check mapper resolution
   separately. Add architecture-aware execution and memory-effect comparisons
   before claiming physically banked software-call execution.
8. Current tests do not provide normal Decompiler-window installed/GUI evidence
   for a reusable mechanism. A disposable installation and separate processes
   are appropriate prerequisites but cannot substitute for that missing
   mechanism or its qualification.

## Requirement-by-requirement audit

| Requested requirement | Evidence and disposition |
| --- | --- |
| Distinguish hardware CALL/RST and pushed continuation/JP HL/RET transfers | Explicit entry kinds, exact Program prelude matching, model events and independent raw fixtures; bounded coverage implemented |
| Recognition/version, premises, payload, target, frame, continuation and exits | Versioned exact templates plus Program-backed previews and conditional return model; derived summaries remain open |
| Restoring/nonrestoring/constant policies | All three have model and independent architectural checks; general native integration open |
| Raw selectors versus effective banks and RAM shadows | Raw/effective records, MBC3 zero-mask tests and stale-shadow execution counterexample; arbitrary mapper/unknown-entry support open |
| Callee result flags and may-return versus always-return | Actual restoring/constant flag checks; return APIs expressly conditional; native flag qualification open |
| Recognize implementation/context without title or vector ABI guesses | Exact helper and caller bytes, decoded boundaries and explicit context checks; implemented for finite templates |
| Inspect pinned Ghidra alternatives | Source/mechanism receipt and callfixup/override experiments and corrected positive cross-overlay CALL observation; direction selected, production mechanism not delivered |
| Every real stack operation and physical target/continuation | Ordered writes/pops and raw word/SP tests; cross-overlay native CALL succeeds after reference precedence is handled; single-specialization raw/injected frame agreement passes; general banking and native effect equivalence remain open |
| Raw/validated/native consistency and SA-00 guarantees | SA-00 unresolved policy retained; no unsupported override bypass; new executable interpretation absent |
| Ordinary analysis preserves valid continuations without disabling/undo loop | Stock analyzer negative plus bounded fallthrough-fixup experiment; reusable fresh/repaired Program qualification open |
| Preserve existing conventions/Programs; preview conflicts | Legacy API maintained with reviewed input and conservative boundary/ownership conflicts; broad migration/repair open |
| Reject stale/incompatible evidence including dependencies | Recomputed Program preview and transactional legacy digest tests; future summary/injection dependencies not implemented |
| Later edits, cancellation, removal/reapplication, actual reopen | Legacy lifecycle and independently inspected three-process run pass after the nested-transaction fix; executable semantics persistence open |
| Deliberate compatibility versions | Independent model/preview policy versions; no language, mapping, SA-00 engine/result or ownership envelope bump; consistent with bounded changes |
| Register and inline payload regression families/lengths | Raw 3/4-byte tests, model 3/4/7/16 and Program preview; other conventions remain unrecognized |
| Nested calls, register effects, flags and return policies | Independent fixed-window raw tests plus pure nested frame checks; native nested banking open |
| Conditional, nonreturning and nonlocal targets | Explicit raw path checkpoints and model negative exits; no general termination or summary proof |
| Unknown state, bad payloads, modified helper bytes, boundary conflicts | Explicit rejection and stale-preview negatives; arbitrary partial-state propagation open |
| Repeated automatic analysis, fresh imports and repaired copies | Narrow mechanism and legacy persistence evidence; reusable production corpus remains open |
| Actual SP/stack/registers/flags/physical identity/mapper/native/listing | Raw/injected frames agree for the flat specialization and native physical CALL identity passes; no end-to-end physically banked equivalence evidence |
| SA-02 coordination without silent redesign or exclusions | Decision explicitly retains architecture dependency and all requirements; SA-01 cannot close |
| Generic-only fixtures and static dependency isolation | New fixtures self-authored; no private ROM or game-study dependency introduced |
| Decision record, environment identity, full checks, separate-process tests | Decision present; primary owns final JDK/Ghidra stock-versus-patched identity, commands and final result receipt |
| Disposable verification, preserve unrelated/historical work, no push | Review observed no active-installation changes or publication in its assigned work; primary owns campaign identity |
| Current docs/roadmap, SA-02–SA-07 retained open | Decision explicitly preserves unfinished scope and next comparative transport task; final docs consistency belongs to primary integration |
| Independent review and completion audit | This review provides the audit; it rejects SA-01 completion |

The next concrete task is the comparative intra-function banking/memory prototype coordinated
with production per-site callfixup design, followed by its integration into
`InstructionInterpretation`, reviewed repair/ownership, persisted summaries and
ordinary-analysis/native qualification. Independent fixed-window implementation
work remains possible while the transport decision is resolved.
