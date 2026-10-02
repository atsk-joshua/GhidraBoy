# Bounded finite conditional loops

LOCAL-LOOP-1 refines the existing ordinary-call evaluator. Qualification is
bounded by the fixtures and evidence recorded in the
[current status](../sa/IMPLEMENTATION-STATUS.md); it does not establish arbitrary
loop or whole-ROM completeness.

## Predicate and flag semantics

Raw SM83 p-code remains authoritative. The compiled JR NZ predicate shifts F
right by seven, negates that boolean, and supplies it to an external CBRANCH.
Z/N/H/C are slices of F, recombined through ordinary integer p-code operations.
INC/DEC preserve carry: an unknown C must not erase a newly established Z.

The evaluator retains a canonical known-mask/value F byte using the existing
PartialBits representation. Ordinary register bytes stay exact or unknown;
instruction-local unique bytes may carry partial bits for flag recombination.
No expression history enters state identity. Exact operations use the incumbent
Ghidra operation behaviors; partial bit transfers retain only sound common bits.
Overlapping F/AF writes invalidate or replace the affected facts. Returned paths
retain agreeing flag bits through a must-fact meet. Unknown flags are not filled
from architectural guesses. Widening discards partial facts as well as scalar ones.

A conditional jump is admitted only when its raw p-code consists of a pure
unique-output predicate prefix followed by one external CBRANCH corresponding
to its decoded destination. A proven zero predicate schedules fallthrough alone;
a proven nonzero predicate schedules the destination alone; unknown schedules
both. Internal microbranches and effectful guarded suffixes retain the previous
conservative boundary. Conditional CALL/RET retains its separately validated
microflow contract.

## Termination authority

Each ordinary invocation records transitions between JoinKeys: execution-view
address, mapper knowledge, scalar register bytes and partial flag facts. Physical
RAM facts are deliberately omitted because enqueue meets RAM at that same key.
Every successor edge is recorded even when enqueue suppresses or supersedes its
RAM snapshot. All edges from reevaluation remain in the graph.

Admission requires complete worklist exhaustion, an acyclic reachable JoinKey
graph, and compatible matched returns under the existing frame/physical checks.
An infinite concrete execution would induce a cycle in this finite conservative
quotient. An acyclic exhausted graph therefore establishes termination in the
supported synchronous domain. Worklist exhaustion alone does not establish it.
An address can recur with a different counter state; diamond convergence can
repeat a key without forming a cycle. A reachable state cycle remains refused,
including a cycle with a separate returning arm. A finite RAM-only ranking can
still be conservatively refused because RAM is omitted from the graph identity.

The alternative of exact Work graph identity without explicit join/subsumption
edges was rejected: RAM enqueue suppression could erase a real backedge.
Address-only cycle rejection was too coarse for register-counted loops. Ranking
summaries, bound increases, game-specific patterns and unbounded exploration are
not part of this change.

## Compatibility and retained limits

Engine `20261002-local-loop-1` replaces the preceding CALL-stack engine. Schema
4 and persisted result shapes are unchanged; partial flags are transient.
Old results confer no current proof authority and require recomputation.
Known obsolete owned physical CALL receipts retain exact retirement/restoration
authority only, as specified by the
[stock-flow contract](ordinary-call-stock-flow.md).

The 128-state invocation limit, 32-key per-address widening, global configured
budget, cancellation, depth-three/recursion guards, unsupported effects,
mapper/physical identity, structural coverage and WUX-1P/WUX-1A unanimity and
lifecycle remain required. State limits are independent of finite-loop semantics:
a hardware-finite path can still exceed the existing invocation budget.

No SLEIGH, language, compiler, mapping schema or hardware-domain change is made.
Private source-path evidence cannot qualify a generic build dependency or replace
self-authored fixtures. Stock publication and native qualification require a
current actual proof; a successful bounded preview alone is insufficient.
