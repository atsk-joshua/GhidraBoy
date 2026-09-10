# W4 symbolic memory and executable images

This experimental bounded slice addresses FX-18/19 and G3. It extends the existing
predicate graph, AbstractValues, ScalarAccess, frame/discovery and state-entry
paths. It does not establish broader W4 hardware, writer discovery, G1 or G4.
Qualification results and exact artifacts belong to the linked
[implementation status](../sa/IMPLEMENTATION-STATUS.md).

## Shared authority

A checked SymbolicMemory declaration binds unknown byte inputs to a Program,
physical WRAM byte and actual canonical native storage. The graph persists that
declaration and revalidates it before lowering. Loader fill is not an input fact.
Ordered byte observations/writes use the same physical identity for CPU echo
spellings. A may-write replaces current knowledge with a new unknown origin,
retaining earlier observations and disjoint facts. Unknown does not imply unequal.
The same write footprint invalidates path-local executable-byte knowledge before
FETCH. It never mutates persistent image history or reseeds killed knowledge.

This first slice uses fixed WRAM0 C000..C7FF and an explicitly disjoint symbolic
outer frame C800..CFFD. It preserves real RET, byte arithmetic and 16-bit pointers.
Cyclic memory joins, general unknown pointers and native interference execution
remain explicit refusals. Ordinary ROM/call paths retain their existing domain.
These are experimental analysis premises, not hardware-wide restrictions.

## Initialization, lifetime and proof

ExecutableImages stores experimental version 1 authority: Program ID, durable
monotonic establishment sequence, immutable initializer snapshots/history and
current physical-range selection. Program ID plus sequence identifies a declared
lifetime; bytes, CPU PC, Function ID and current ROM fingerprints do not.
Same-byte explicit establishment creates a new generation. Requests must name
the generation and refuse noncurrent generations before fingerprint validation.

The explicit operation validates current ROM snapshot, exact physical destination
and canonical annotation conflicts, copies bounded bytes, and creates a fresh
owned generation snapshot/Function in one cancellable transaction. It retains
historical snapshots and later user edits; it never overwrites old view names.
Physical RAM remains writable. Read-only proof/native callbacks validate current
RAM and snapshot bytes, generation, view/Function binding and proof dependencies.
Source-ROM edits cannot recopy RAM or change historical initializer/generation.
Conservative proof staleness may require explicit proof refresh, separately from
establishment. Current-format reopen must not establish or explicitly refresh.

A byte-mapped decoded RAM view was considered and tested locally. Pinned Ghidra
prevents writes to its backing RAM while mapped decoded instructions exist.
Therefore the selected view is an immutable, generation-bound snapshot through
SoftwareCallExecutionView, with actual RAM FETCH evidence and an explicit image
binding. Snapshot storage does not claim to be canonical physical RAM. Actual
native data inputs/stores lower to checked canonical mutable RAM, not snapshot
or initializer storage. No global volatility or writable ROM is introduced.

## Compatibility and remaining work

Predicate graph and registration experimental formats advance from 3 to 4;
incompatible old authority rejects without migration or record mutation. New
image authority has its own version. Public mapping v2, configured-domain v2,
FarCallEvidence v3, language/compiler/native/SLEIGH formats and dependencies stay
unchanged. This is not G4 migration qualification.

The gate requires both positive native subchecks, alias/interference and FETCH
controls, generation-specific negatives and one separate-process read-only image
reopen. Safe refusals and unit totals alone cannot establish G3 PASS. Broader
banked WRAM/SRAM/VRAM/device/boot/async behavior, general initialization discovery,
self-modifying execution, writer analysis and ordinary-window integration remain
in the retained [plan](../sa/IMPLEMENTATION-PLAN.md).
