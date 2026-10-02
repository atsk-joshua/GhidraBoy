# Bounded sequential returning-call composition (N7)

N7 extends the accepted [N4](ordinary-returning-call.md),
[N5](nested-returning-call.md) and [N6](conditional-call-ret-microflow.md)
ordinary BankAnalysis contracts to multiple sequential direct returning calls
within one invocation. The positive chain is caller → A → B → A continuation → C
→ A continuation → caller. Maximum active ordinary depth remains two.

The local limit recorded below is historical: [LOCAL-STATE-3](local-analysis-budget.md)
now sets the per-invocation analysis resource guard to 179.

## Admission and physical frames

The encountered nested-site set previously refused a second distinct call even
when the first had completely returned. Admission now explicitly uses the immutable
active CallFrame chain through `hasOrdinaryCallCapacity`. Both the nested flow
guard and composition entry require spare active capacity. Synchronous nested
exploration adds one frame to a copied chain; only a complete matched return
provides a Work to the original containing exploration. A subsequent site can
therefore enter with one active frame, while a call reached inside B still has two
and refuses. Physical self/mutual recursion checks remain unchanged.

Each new frame consumes the real CALL stores, actual current SP, physical pushed
byte identities and physical callee identity. No stack word is synthesized. B's
return resumes A with B's register/flag, SP, mapper and N3 physical RAM must-facts.
C receives that actual state after A's intervening instructions. A's original
frame remains authoritative for its own eventual RET; numeric PC/SP equality
cannot substitute for physical stack identity. Normal sequential calls can reuse
stack storage; fixtures that move A's SP between calls additionally demonstrate
physically distinct B and C storage while preserving the outer frame.

## Completion and bounds

No return-state meeting, widening, cancellation or completion rule changes.
Any incomplete B blocks the continuation that could reach C. Successful B followed
by incomplete C invalidates A's returned proof. Successful partial paths cannot
rescue incomplete alternatives. Global COMPLETE continues to mean a drained
session worklist, not whole-invocation or whole-ROM proof.

Every instruction evaluation in every sequential callee consumes the same global
budget. Each invocation retains the 128-state local cap. N6's one conditional
transfer site per invocation remains unchanged; no new conditional solver or
second conditional dimension is added. Reachable third active levels and
recursion refuse; known-false conditional calls remain non-executed.

## Compatibility and alternatives

Engine `20260930-n7-sequential-returning-call-1` requires recomputation of N6
results. AnalysisResult schema remains 3 with unchanged fingerprint dependencies.
Frames, registers, RAM, site sets and worklists remain preview-local. There is no
persisted frame, callable summary or new IR. The existing state/frame model was
sufficient; increasing depth, relaxing recursive admission, or introducing a new
summary abstraction was unnecessary and outside this slice.

Self-authored focused fixtures, scoped affected regressions, independent semantic
review, lint/package integrity and a disposable pinned Ghidra Docker witness with
separate-JVM save/reopen are recorded in the [evidence index](../sa/evidence-index.json).
The installed witness binds an observable B → C → A → caller dependency to actual
physical fetch and stack identities; persisted N7 agrees with recomputation and
rejects immediately preceding N6 read/application.

## Remaining obligations

Only multiple sequential direct returning calls within the existing depth-two
ordinary frame model are accepted. Arbitrary depth, recursion, indirect calls,
RST/RETI, software-call summaries, ABI inference, interrupt/device effects,
RAM-code execution, general conditional/interprocedural closure, discovery
expansion and whole-ROM call closure remain open. SA-01, SA-03 and SA-07 remain
open. No historical N4/N5/N6 decision or evidence is rewritten. STOP after N7;
N8, main changes, PRs, releases and persistent installation are outside scope.
