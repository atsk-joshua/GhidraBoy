# Predicate-qualified ordinary calls

W3a adds an opt-in graph adapter for an unknown-input acyclic root, physical
ROM fetches, one internal ordinary-call depth and matched symbolic frames.
It does not replace the existing exact software-convention analyzer or enable
loops, recursive calls, general mutable memory or automatic analysis.

`PredicatedCallGraph` delegates numeric operations and structural predicates to
`AbstractValues`, physical accesses to `ScalarAccess` and existing mapper
semantics, fetch validation to `BankAnalysis`, and justified decode to
`SoftwareCallInstructionDiscovery`. `SoftwareCallEffects` supplies explicit
relative ordinary-frame validation and byte result liveness. The symbolic
root SP ranges over C082..CFFC; actual CALL writes and RET reads are checked
as offsets from that base. Outputs below C080 are disjoint from live frames.
No test SP or outer return word becomes a static premise.

Graph identity includes physical source, mapper, predicate, current register
definitions, invocation and live frame. Explicit edges, rather than traversal
indices, determine lowering. Predicate-qualified child Functions retain the
canonical byte sources in separate execution views. The existing pre-flow
state-entry protocol carries root branches and ordinary CALLs to those
Functions. Callee results flow through actual native CALL outputs; no inline
result stub replaces the Function-identity obligation.

The existing concrete continuation records were not silently reinterpreted as
symbolic state. Their selected-path lowering and fixed frame coordinates do
not represent this domain. Full inlining was rejected as primary acceptance
because it would leave G2's native call/Function identity unproved.

The experimental `GhidraBoyPredicatedCalls` registry is separate from ordinary
record v5 and the software-call registry. Version 1 qualified zero-live-in
byte-A callees, and was sealed with W3a/G2 validation before the invocation
follow-on. Version 2 records actual byte-register live-ins derived by backward
p-code liveness, binds them to per-invocation custom Function parameter storage,
and preserves distinct current inputs and return continuations at repeated
calls. The return byte in A, preserved BC/DE/HL and matched RET stack effect
come from validated raw effects. Native flag-dependent results/control remain
explicitly unsupported by this byte-A contract. No global ABI or compiler
language specification is changed.

Old experimental envelopes reject before changed-field decoding, without
migration or record mutation. Every callback rechecks broad dependencies,
physical views, Function contracts and a fresh read-only graph derivation.
Discovery inventories are also graph-bound before installation. Complete
coverage is required; unknown compatibility and budget exhaustion retain
frontiers and cannot authorize a native result.

The durable W3-OVERNIGHT batch owns exact source/runtime identities, the
primary checkpoint, input/frame/native/persistence receipts, final follow-on
disposition and the consolidated report. These witnesses do not complete all
W3 or SA-01/02. Remaining general graphs, richer call effects, flag contracts,
mutable/device memory and migration retain their existing plan ownership.
