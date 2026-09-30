# Ordinary ROM LOAD values (N1)

Baseline: `preview-m2-ghidra-native`, source
`64f87ed48460dd60985d1e469c6f1ff8e79b7ad5`. The candidate is the bounded
working-tree change, with exact source/artifact hashes in the external receipt.

SA-ROM-VALUE-PROPAGATION adds one bounded foundation for SA-03: ordinary
BankAnalysis can consume immutable physical-ROM scalar values. It does not close
SA-03, SA-01, discovery or static-analysis acceptance.

## Boundary and source authority

An actual raw p-code LOAD in the CPU/default address space evaluates its pointer
through the existing register/unique domain. Each ordered byte uses the existing
ScalarAccess READ resolver and path-local MapperKnowledge, with 16-bit wrapping.
Only established ROM/BOOT physical identities can produce a value. All bytes must
be known; assembly is little-endian and limited to the existing scalar domain's
one-through-eight-byte widths. Internal p-code branches still invalidate outputs.

A direct initialized, readable, non-writable, nonvolatile static source must have
file-source provenance or an explicit loader anchor in the existing ProgramMapping
contract. Every eligible source for the physical identity must have the same
current Program byte. Disagreement or missing authority produces unknown. Source
selection never depends on view order/name. Original FileBytes are provenance,
not the byte-value oracle. Generated execution/presentation prefixes are excluded
in both block and space names, including retired storage.

Byte-mapped views do not independently establish immutability: a read-only alias
may point at writable backing. Their direct physical source remains available for
value resolution without requiring its static offset to equal the CPU offset.
Detached, unanchored snapshots cannot supply authority. Independent self-authored
loader-anchored ROM storage exercises genuine disagreement; duplicate FileBytes
views share their current patches in pinned Ghidra and cannot provide that oracle.
No mapping schema or physical/CPU identity change is required.

Mapping observations are retained independently. Address-valued inputs remain
observations; COPY is never implicitly dereferenced. PcodeConstants remains a
context-free evaluator. The focused compiled `LD A,(HL)` fixture proves LOAD;
this slice does not recognize additional direct-memory p-code representations.

## Compatibility and dependencies

AnalysisResult advances the engine to `20260930-n1-rom-value-4`; schema 3 is
unchanged. Old-engine validation fails before application. Existing fingerprints
already cover current initialized bytes, physical mapping/source provenance,
read/write flags, alias topology and p-code. The additional eligibility component covers only the remaining ROM/BOOT source
gate: volatility and reserved generated-block prefix classification. Arbitrary
block names and RAM/device volatility are not dependencies. Address-space names
and mappedness are already represented by mapping identity/alias topology; neither
is hashed again. Initialized transitions already change the existing memory
component. Final closeout review narrowed this component without changing LOAD
semantics; the original receipt identities remain historical evidence.

The regression oracle independently sets ROM file byte 0200 to 02, expects loaded
A=02, MBC5 low selector=2 and physical successor ROM bank 2 offset 0 (`rom2::4000`).
A current patch to 03 must produce selector=3 and `rom3::4000` while original input
remains 02. Packed save/reopen checks use the existing analysis.latest persistence
mechanism, including currentness and stale-result refusal.

## Alternatives and remaining scope

Implicit address dereference would conflate mapping observations with reads and is
rejected. Evaluating memory in PcodeConstants would erase the physical authority
boundary and is rejected. Selecting one eligible view would conceal disagreement
and is rejected. Treating writable initialized storage as entry knowledge would
invent RAM facts and is rejected.

RAM propagation, memory joins, symbolic memory, interprocedural summaries,
indirect-flow recovery, discovery expansion and native transport changes remain
outside N1. Current execution receipts and exact identities are indexed separately
in the [evidence index](../sa/evidence-index.json); this decision defines the source
policy, not whole-ROM or release qualification.
