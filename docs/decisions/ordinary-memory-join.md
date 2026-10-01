# Ordinary physical RAM must-knowledge joining (N3)

N3 refines the N2 ordinary BankAnalysis worklist, using the incumbent
`SymbolicMemory.State` fact store. It is a bounded SA-03 foundation slice,
not SA-03 completion or a general memory-analysis solution.

## Domain and correlation

A fact is an exact path-written physical WRAM/HRAM byte. Absence means unknown.
Joining retains a byte only when every contributing state establishes the same
exact value. Conflicting, missing and disjoint-only facts disappear. Physical
keys already incorporate aliases and banks; joining does not resolve aliases,
read Program bytes, consult W4 declarations or aggregate candidate values.

The exact join key is the static instruction Address (including execution view),
MapperKnowledge and the complete register-byte map. Different mapper or register
states stay separate. These are all persistent non-memory components of ordinary
Work; instruction-local unique values reset on each instruction. Program inputs
are fixed for the session and checked by the existing fingerprint/modification
guards. There is no independent mapper/register join or new memory representation.

## Worklist and bounds

Every root and successor enters the same joined-state registry. Its first arrival
establishes a snapshot. Later arrivals intersect that snapshot with their facts.
Identical arrivals do nothing. A weakened snapshot is queued even if the key was
processed before. Obsolete pending snapshots are skipped, and full processed
snapshot identity prevents duplicate evaluation. A key can only lose facts after
its first arrival; incoming STOREs cannot restore a fact lost at that key.
Instruction transfer can still establish fresh facts at successor keys.

Address diversity counts distinct processed non-memory keys, rather than memory
revisions. The existing 32-key fallback still replaces incoming mapper, registers
and memory with the conservative unknown state. N3 does not alter its mapper or
register semantics. Each actual evaluation, including reprocessing, consumes the
existing global state budget. Thus finite descending memory revisions improve
convergence while the global bound contains incompatible/expanding execution state.
Budget exhaustion remains explicitly incomplete and publishes no PROVEN result.

Candidate targets from earlier evaluations are retained as observations; reasons
for unknown alternatives remain sticky. Reprocessing with a weakened RAM LOAD
therefore prevents earlier observed selectors from becoming proof. Candidate
observations are never fed back into the memory domain.

## Compatibility and alternatives

Engine `20260930-n3-memory-join-1` rejects N2 results through the existing engine
mechanism. Schema 3 and fingerprint dependencies remain unchanged. Memory
snapshots are transient and are never serialized in AnalysisResult.

Retaining every compatible memory variant was rejected because it spends diversity
on path-local byte differences. Choosing one observed value, frequency-based
retention, or joining independently widened mapper/register fields would be
unsound. Removing the 32-state/global bounds would broaden this task unnecessarily.

## Remaining obligations

N1 immutable ROM authority and N2 eligible backing, write invalidation and call
fact loss remain intact. General symbolic pointers, returning-call composition,
device/asynchronous/interrupt effects, new mapper inference and discovery remain
unsupported. N3 does not prove arbitrary loops or whole-ROM completeness. The next
separately authorized slice is N4 returning-call composition.
