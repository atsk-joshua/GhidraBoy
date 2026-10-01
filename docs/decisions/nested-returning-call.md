# Bounded nested ordinary returning-call composition (N5)

N5 extends [N4](ordinary-returning-call.md) with exactly two active ordinary
invocations: caller → A → B, B RET → A continuation, A RET → caller continuation.
Both calls must independently satisfy N4's unmodified unconditional SM83 CD/C9
contract. This is a bounded SA-03 foundation, not general interprocedural analysis.

## Frames and execution

The same BankAnalysis exploration and compiled raw p-code evaluator execute each
level. Each CALL executes its real SP decrements and two stack STOREs before
entry. An immutable preview-local list retains at most two validation frames:
return CPU PC, expected restored SP, both physical pushed-byte identities and
callee physical ROM identity. Architectural stack bytes remain exclusively in
the incumbent SymbolicMemory.State; the list is not a symbolic memory model.
Each RET's actual LOADs, RETURN operand and restored SP must match the top frame,
including physical byte identities. A numeric PC/SP match in another WRAM bank
cannot impersonate a frame. The inner return leaves the outer frame to be
validated independently by A's eventual RET.

Every target, fetched instruction and returned continuation must resolve to one
established available static physical execution view in readable, initialized,
executable, non-writable ROM. B cannot borrow A's execution view. The outgoing
mapper must independently establish the continuation, including when it selects
a different physical bank. No Function, instruction, reference, symbol or
ownership record is created by preview.

## State composition and completeness

B receives A's actual post-CALL mapper, register/flag bytes and N3 physical RAM
snapshot. B's completely proved outgoing state resumes A at the resolved physical
continuation. A's remaining instructions execute before its RET can compose state
into the outer caller. Neither return restores an earlier caller snapshot or
mapper. Actual B writes therefore replace earlier caller RAM facts; A can modify
returned registers or mapper state before returning again.

Compatible return paths intersect exact register/flag bytes and use unchanged
N3 physical RAM must-fact joining. Missing/conflicting bytes become unknown.
The incumbent mapper/continuation compatibility rule is unchanged: differing
mapper knowledge or continuation identities refuse composition instead of
selecting a return arm or introducing a new lattice. At a nested boundary this
invalidates the containing invocation; the outer caller receives the incumbent
unknown continuation. A cannot reconstruct a fact from the original snapshot.

Every explored path must complete the bounded matching-return proof. Unresolved
flow, missing code, unsupported effects, unavailable loads, nonreturning exits,
cycles, diversity widening, bounds and cancellation invalidate the invocation.
A failed nested invocation invalidates A even if a sibling arm returns correctly.
No partial B state becomes an outer return proof.

## Bounds and refusals

Maximum active ordinary depth is exactly two; a CALL at depth two refuses before
another invocation is explored. Active physical callee identities also refuse
self or mutual recursion; no recursive solving or summary cache is used. Each
invocation admits at most one nested call site, including across alternative
paths. Reprocessing that same site for an N3 weakened snapshot does not count as
a second site. Sequential distinct nested sites remain unsupported.

Each invocation has the existing 128 instruction-state evaluation cap. A's local
cap counts A instructions; B has the same local cap. Every actual evaluation at
either level also increments the single session counter and consumes the original
configured global state limit. There are no separate additive global budgets.
Global exhaustion/cancellation makes the entire result incomplete; local refusal
cannot establish return proof.

Only direct unconditional CD targets are admitted. CALLIND, computed dispatch,
JP (HL), conditional CALL/RET, RST/RETI, software/helper calls inside an invocation,
RAM code, ABI inference and discovery expansion remain unsupported. Ordinary
conditional branches retain N4's exploration of both alternatives; known
conditions do not authorize guarded architectural effects.

## Compatibility and evidence

Engine `20260930-n5-nested-returning-call-1` rejects old N4 results through the
existing reader/currentness/application checks. AnalysisResult stays at schema 3.
Frames, register snapshots, RAM snapshots and invocation worklists are transient,
local to one Program preview under its existing fingerprint/modification guard,
and never serialized. No persisted summary cache is introduced.

No new Program dependency is consumed: physical topology, permissions,
initialization, current bytes, raw instructions and interpretation are already
covered by N4's ProgramFingerprint. The active-identity check uses the same mapped
physical identities. Transient frames are not fingerprint inputs.

Self-authored nested fixtures check compiled CALL STORE/RET LOAD operations,
explicit return words and distinct physical stack bytes, B → A → caller register,
flag, RAM and mapper effects, A's post-B instructions, conflict meets and bounded
refusals. Exact validation and installed save/reopen receipts are recorded through
the [evidence index](../sa/evidence-index.json).

General summaries, arbitrary depth, recursive solving, indirect-call recovery,
symbolic stacks/pointers, interrupt/device-aware summaries, software conventions,
whole-ROM call closure and discovery remain open. N5 does not close SA-01,
SA-03 or SA-07. No N6 work begins from this checkpoint.
