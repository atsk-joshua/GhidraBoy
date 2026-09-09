# W2e: bounded N-way finite selector lowering

Status: implemented within the existing straight-line ordinary-entry domain.
Related requirements: S-02, S-05, S-06 and W2 finite selector generalization.

## Decision and correctness

Keep `FiniteEntryProducer.Selector.values` and `Read.alternatives` as the proof
representation. Concrete MapperKnowledge/MapperState still establish each leaf
physical source through ScalarAccess. Do not introduce set-valued mapper state.
Capture the actual selector varnode at its original device-write operation;
retain the raw selector computation and all architectural writes in order.

For byte values, lower a complete, distinct selector domain as
`v0 + sum((selector == si) * ((vi - v0) mod 256)) mod 256` for each member after
the first. The first selector makes every guard false; each other admitted
selector makes exactly its own guard true. This is exact even if multiple banks
contain the same byte. The producer's sound may-domain must cover every concrete
selector, and the lowerer verifies list coverage. The full 256-value byte set
remains TOP and refuses; this does not add a partial-value representation.

A general branch chain was an alternative, but would introduce native control
flow where the incumbent two-way form is branchless. Replacing two with four
would merely create another unexplained cardinality limit. Neither is needed.

## Resource policy

The provider permits at most 4096 **added** finite-lowering operations per
payload, matching the incumbent producer's 4096 raw-operation work allowance.
This is a host resource choice, not a native protocol maximum. Cost is one COPY
per captured selector plus three operations per non-first alternative of each
read that lacks an incumbent exact replacement. It is computed before returning
a proof and again before emission, and checked against actual emitted counts.
No alternative is dropped or replaced by a representative when the budget fails.

Scratch uses one 16-byte slot per added operation, in the incumbent 16 MiB scratch
region following the per-instruction unique regions. Both reserved-region use
and the actual unique-space maximum are checked. Four alternatives with one
selector/read add 10 operations and 160 scratch bytes. Ten dependent reads of a
128-member domain add 3811 operations; eleven add 4192 and refuse before alias
creation. The four-way fixture is a witness, not the supported cardinality cap.

## Compatibility and validation

Persisted/public record shapes and version identifiers remain unchanged. List
members were already represented; installation and emission still rederive and
compare the complete proof in its owning Program. Old exact/singleton/two-way
proofs keep their meaning; the generalized two-way loop emits the same operations
and temporary layout. Existing broad fingerprint/stale refusal policy remains.
No native companion, transport, SLEIGH, mapping schema or hardware policy changes.

`OrdinaryNWayFiniteAccessTest` checks one eight-bank code-derived domain for all
256 incoming B bytes, ordered raw/emitted effects, corrupt-proof/payload negatives,
one-alternative stale/refresh, conservative unrelated-byte invalidation, Program
isolation and resource refusal. The retained F12, F12_SAME, F12_INDEPENDENT,
exact/banked/unknown/isolation and scalar adapter regressions remain authoritative.
`GhidraBoyW2eFinite.java` and `tools/check_w2e_native.py` supply the bounded installed
native original/stale/refresh witness and independent rooted relation checker;
exact run identities and outcomes belong to REPORT-W2e and its fresh receipts.

The older four-bank mask-03 fixture keeps its original bytes and historical
capacity-refusal evidence. Its bank-4 wiring aliases bank 0; W2e uses the separate
eight-bank F1234 fixture to establish four distinct physical choices.

Remaining obligations include actual broader W2 value semantics and dependency
precision. No branch interpretation, unknown pointers, symbolic mutable RAM,
relational joins, fingerprint narrowing, G1–G4 or W3/W4/W5 are claimed here.
