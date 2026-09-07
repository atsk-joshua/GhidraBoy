# Stock automatic-analysis integration investigation

This independent worker inspected source and historical inventories without building,
formatting, mutating Programs, or changing production files. This document is the
worker's only repository write. Runtime attribution remains the primary's serialized
reproduction obligation; source reachability alone is not a captured call stack.

## Revalidated identities

HEAD is `16752093dce0147afd28762a2f8918144ec571c2`, branch `integrate-ghigbc`.
The extensive preexisting status was inspected and preserved. At inspection, these
production files matched the registry6 handoff manifest exactly:

| File | SHA256 |
| --- | --- |
| `SoftwareCallApplication.java` | `6c80c5754a39188e7d01938b2740addb906018697c21f80dfc59830ae16cb8fe` |
| `AnalysisOwnership.java` | `342a37948c57dd3b9102eae02fe6a16b6b719f9cb1472f21b9a0435ff68d0793` |
| `SoftwareCallRegistry.java` | `6ebffdda4fd2b5fc57735e11c73a77d66b2950ca1c89e57159da98a29cb81d10` |

The inspected pinned Java distribution is
`/private/tmp/ghidraboy-sa01-representation/tool-installed-native-context-header/distribution`.
These hashes were recomputed, rather than borrowed from old receipts:

| Distribution member | SHA256 |
| --- | --- |
| `Ghidra/Features/Base/lib/Base-src.zip` | `a18a8650132670230cd12fdcfaa3e20605a1e1d24c07d033d20986fea2cff2d2` |
| `Ghidra/Features/Base/lib/Base.jar` | `1b6b4063ed5c04c6137ecfc588e72ec7d795a57b07ab34324a8245e85d50a56c` |
| `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling-src.zip` | `fed5e47f0578b04597ead75fef77e2316a0458b9dbeeb1eb2cfa3d01472411b3` |
| `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar` | `220c419c4d94d65faddecf77ba899213b66382c092a3753be56f3bb08112c96f` |

Registry4 and its historical GUI remain original evidence. Registry5's 635 tests
and finite six phases did not qualify fresh state/discovery analysis. Registry6
source initially matched the handoff and its nine focused tests had one failure;
this read-only inspection does not rebuild or qualify either artifact. No loose
provider JAR was paired with a distribution ZIP.

## Exact stock paths

All Base paths below are members of `Base-src.zip`; SoftwareModeling paths are
members of `SoftwareModeling-src.zip`. Line numbers refer to those source members.

1. `ghidra/app/plugin/core/disassembler/EntryPointAnalyzer.java` is the enabled
   **Disassemble Entry Points** byte analyzer. `added` (83 onward) invokes
   `findDummyFunctions`, then `fixDummyFunctionBodies`. `findDummyFunctions`
   (434) adds **every one-address Function body** to the redo set before checking
   whether instructions already exist. A terminal, named RST is still included.
   `fixDummyFunctionBodies` (258) directly calls
   `CreateFunctionCmd.fixupFunctionBody` for these functions. Neither the entry
   name nor its symbol source exempts it.
2. `ghidra/app/cmd/function/CreateFunctionCmd.java:658–674` recomputes the body
   and calls `resolveThunk` when the signature source is DEFAULT and the Function
   is not already a thunk. This occurs even if the body has not changed.
   `resolveThunk` (718 onward) uses `CreateThunkFunctionCmd.getThunkedAddr` and
   applies `CreateThunkFunctionCmd` to an existing Function.
3. `ghidra/app/cmd/function/CreateThunkFunctionCmd.java:579–583` calls
   `getSimpleFlow` **before** its raw p-code STORE/register side-effect checks at
   611 onward. `getSimpleFlow` (836–847) accepts an unconditional jump or terminal
   call with no delay slot and exactly one flow target. Therefore a terminal RST
   receives a helper thunk classification without inspecting its real stack writes.
   `applyTo` (179–190) calls `setThunkedFunction(referencedFunction)` on the same
   existing Function and optionally updates its body.
4. SoftwareModeling `ghidra/program/database/function/FunctionDB.java:2610–2618`
   makes `getCallFixup` recursively return the thunk target's fixup. The apparent
   helper fixup on the alias and canonical caller can therefore be **inherited**
   through thunk metadata; it need not be a separate installer write to either.
   `getSignatureSource` (2431 onward), calling-convention access, return/storage
   access and other contract accessors likewise delegate. Clearing a fixup on a
   thunk without first resolving this distinction can modify the actual helper.

This is a complete source path matching the one-byte terminal RST regression and
installed alias drift. The historical logs show the entry analyzer ran. Capturing
the exact runtime mutation stack would turn this strong causal attribution into
a direct event trace.

`ghidra/app/plugin/core/function/FunctionAnalyzer.java` (**Subroutine References**)
creates called Functions, but its own placeholder check (151 onward) does *not*
redo a one-byte terminal instruction. It must not be confused with the broader
entry analyzer above.

`ghidra/app/plugin/core/analysis/OperandReferenceAnalyzer.java:292–319` has an
additional computed-flow thunk conversion path. It calls `isThunk`, then
`CreateFunctionCmd(... recreateFunction=true)` and announces `functionDefined`.
This path matters for adversarial computed transfers. The current RST and
`CALL_OVERRIDE_UNCONDITIONAL` references are direct: SoftwareModeling
`ghidra/program/model/symbol/RefType.java:310–316` sets call/override/fallthrough,
not computed. Thus this branch is not established as the current RST trigger.
For an existing body larger than one byte, `CreateFunctionCmd:464–474` can resolve
a thunk before its signature-source guard; a generic signature-source barrier
would not cover all computed forms even aside from its semantic problem below.

## Historical annotation transition and dependency consequences

The registry5 installed annotation diff removes the default-named one-byte alias
Function at `gb_call_view_291_4500::4500`, then adds the same Function ID 70 named
`rst28` with `ghidraboy_software_call_v1`. The canonical Function ID 77 retains
`state_source` but now reports the same helper fixup. Bodies remain one byte.
The serialized inventory does not itself expose the thunk chain, so the stock
accessor semantics above explain the observed inheritance without inventing an
extra fixup write.

The registry6 focused test initially establishes canonical→alias, alias non-thunk,
no inherited fixup and successful native behavior on both entries. After ordinary
analysis its first failure is `sourceRedirectCurrent`. The canonical receipt
includes the resolved calling convention, signature source, fixup and other
Function metadata (`AnalysisOwnership.functionStamp(..., true)`). A changed alias
thunk therefore changes the canonical contract even if its immediate canonical→
alias endpoint stays fixed. View stamps also include full Function stamps; the
registry6 dependency policy includes caller bodies/prototypes. Strict injection
and returning-target failure is the appropriate rejection of this semantic drift,
not grounds to blindly refresh receipts.

Separately, installed analysis replaces decoded DEFAULT DATA references with
ANALYSIS WRITE at `0156`, banked `4104`/`410a`/`4702`, and contextual `4702` views.
It creates ordinary logical CPU READ references, including CPU `4200` from fixed
and derived code. These are not evidence that thunk/fixup changes are safe and
are not proof of physical bank-sensitive data-reference recovery. The existing
view policy specifically normalizes decoder-matching DATA and generated nonflow
analysis references; it does not normalize Function contract changes.

New entry instructions at `0100`/`0101` and the shared-return override at `0101`
are separate stock entry discovery/shared-return changes. The focused log also
shows decompilation starting in supplementary
`gb_call_view_291_4500_state1::4501` and escaping at `4507`. That fragment issue is
an independent graph/listing integration problem; hiding its Function or disabling
its analyzers would not repair it.

## Rejected source-only workaround

The supported `Function.setSignatureSource(ANALYSIS)` setter changes no stored
parameter or return value by itself (`FunctionDB:2454–2474`). It would block the
entry analyzer's DEFAULT-only thunk path. **It is not semantically neutral.**
SoftwareModeling `ghidra/program/model/pcode/FunctionPrototype.java:156–157`
sets `voidinputlock = signatureSource != DEFAULT && parameterCount == 0`.
Changing the source on a default empty signature locks a native no-argument
contract. A named/default contract is not a proof of no inputs; these executions
consume declared registers, mapper and stack premises. Do not promote the source
merely as an analyzer barrier or describe that change as naming only.

A RETURN override is also not a drop-in fix for current callfixup transport:
SoftwareModeling `ghidra/app/plugin/processors/sleigh/PcodeEmit.java:312–350`
replaces the original CALL with COPY/RETURN (or CALLIND with RETURN), removing
the CALL operation that the helper fixup must replace. A complete pre-flow caller
graph could supply that behavior but would be a larger, separately proved change.

## Smallest candidate for primary integration experiment

A bounded self-fallthrough at the software-transfer listing instruction can retain
its real CALL operation and prevent initial native decoding from leaving the
reviewed instruction while the callfixup supplies the complete continuation.
This is a candidate transport boundary, **not an executed qualification or a claim
that the CPU actually loops there**.

Source support:

- `InstructionDB.getFlowType` (321–323) depends on FlowOverride, not an explicit
  fallthrough. Ordinary CALL flow plus self-fallthrough avoids terminal-call
  classification; thunk scanning then sees the real RST STORE side effects.
- `InstructionDB.getFlows` (289–307) includes all non-indirect flow references;
  a self-fallthrough also introduces a second distinct destination, unlike the
  former single helper target.
- `InstructionPcodeOverride.getFallThroughOverride` (83–91) returns a changed,
  nonnull fallthrough. `PcodeEmit.resolveFinalFallthrough` (183–200) emits a real
  BRANCH to that boundary after p-code generation. `setFallThrough(null)` alone
  supplies no such operation and does not solve native pre-injection escape.
- The existing complete continuation graph must make this transport back-edge
  unreachable, or explicitly model its true terminal/loop/nonlocal outcome.

Before selection, prove original hardware stack effects occur exactly once,
both canonical/alias native entries retain actual callee effects, repeated normal
analysis does not create thunks or modify the protected boundary, same-interface
mutation remains stale until review/reapplication, and removal restores original
fallthrough/reference state while preserving late user edits. Ownership and
registry versions must explicitly account for the new boundary. The listing UI
and decision record must make its transport role visible. Supplementary fragments
still require their own truthful flow closure; this proposal does not waive them.

## Independent correction regression supplied

The primary's first production correction retains ordinary CALL flow and applies
explicit self-fallthrough to canonical view sites and stateful caller aliases.
Inspection confirms it does not change signature source, prototype, storage or
raw instruction bytes. The primary reports the original nine focused tests pass;
this worker did not run that build and does not independently certify its logs.

`SoftwareCallBoundedListingTest.kt` adds four independently authored regressions
for the primary's serialized run. It covers hardware RST and manual
LD BC/PUSH BC/JP prelude, checking the unchanged raw two byte-store/two 16-bit SP
-decrement sequence and default contract, direct stock thunk rejection and
`CreateFunctionCmd.fixupFunctionBody` stability. A rollback-only counterfactual
restores the old terminal boundary and asserts the exact same-ID alias→helper
conversion, inherited canonical fixup and rejection. A further test independently
mutates flow, fallthrough and helper override endpoint and requires both registry
entry paths to reject each change. These tests were supplied **unrun and
unformatted**, because the primary owns shared build/format operations.

The primary subsequently reported all four bounded-listing regressions passing
in `projection-probe-2`, after the initial compile exposed ambiguous Kotlin
Iterator/Iterable `asSequence` selection. Both sites now select `.iterator()`
explicitly; the failed compile log remains `projection-probe-1.log`.

The rollback regression now emits four explicitly prefixed
`SA01_STOCK_TRANSITION_JSON` records: bounded-before, legacy-terminal-before-repair,
legacy-terminal-after-stock-repair, and bounded-after-rollback. Each records every
Function's identity, names, body, immediate/recursive thunk relationships, fixup,
signature/convention/storage and metadata; all instructions' bytes, raw p-code,
flows/fallthrough and references; exact raw registry/ownership strings; and the
complete knowledge fingerprint. JSON nulls are retained explicitly. New assertions
require the raw registry and ownership strings to remain byte-identical across
stock repair and rollback. This inventory enhancement is pending the primary's
next serialized compile/run and does not retroactively alter probe-2 evidence.
