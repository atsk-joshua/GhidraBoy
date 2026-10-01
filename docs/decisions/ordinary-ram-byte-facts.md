# Ordinary path-local RAM byte facts (N2)

N3 subsequently refines compatible-state convergence; see the
[ordinary memory join decision](ordinary-memory-join.md). The worklist descriptions
below record the N2 checkpoint. Its byte authority and invalidation contract remain.

SA-RAM-VALUE-FACTS follows N1 on `preview-m2-ghidra-native`, starting at
`901c14d065ce31007dea3f600fb447620c22c76e`. This is a bounded SA-03 foundation,
not general memory analysis or milestone completion.

## Incumbent model and choice

`SymbolicMemory.State` already owns physical-keyed byte facts, copying, exact
`AbstractValues` bytes and symbolic declared inputs for W4 predicate proofs.
`MapperState.Physical` identifies region, bank and offset. `ScalarAccess` owns
ordered byte resolution using path-local `MapperKnowledge`; `ProgramMapping`
owns actual Program backing and aliases. Reuse these abstractions rather than
introduce a CPU-address memory map or a second provenance/mapping model.

W4's existing declaration access policy intentionally limits data to a disjoint
fixed WRAM0/HRAM domain and can seed symbolic inputs. Ordinary analysis instead
starts the same fact store empty and consumes only exact bytes established by
its own writes. Its separate access policy accepts canonical readable, writable,
nonvolatile WRAM/HRAM backing without file provenance. Initialization is not a
premise. W4 declaration, executable-image generation and access semantics remain
unchanged. Extending the W4 declaration domain or seeding ordinary analysis from
Program bytes was rejected because either would change its proof contract.

## Byte and lifetime contract

Each ordered STORE byte resolves with WRITE access before the corresponding
mapper transition. A known byte replaces its physical fact. An unknown byte
removes that physical key, including every CPU spelling of its aliases. A
known disjoint physical byte preserves other facts. Unlocated stores and writes
with unresolved physical destinations drop facts conservatively; unsupported
device writes also drop them. No device effects are inferred.

LOAD resolves each byte with READ access. Every byte must have eligible physical
RAM backing and an exact path-written fact, or the scalar is unknown. Values
assemble little-endian with 16-bit pointer wrapping into the incumbent
register/unique domain. ROM LOAD authority remains N1's current physical-ROM
source policy; there is no RAM storage-byte fallback.

Worklist states carry immutable snapshots of the incumbent fact map in their
identity. Roots start empty. Branches retain separate snapshots, so a merge does
not manufacture a joined value. Known mapper selector changes preserve facts by
physical identity; unknown required bank selection cannot identify a read.
Only existing resolved WRAM banks are supported. Conventional calls and existing
software-call continuations carry no ordinary RAM facts. The incumbent bounded
state-diversity fallback drops all facts; no memory join or widening is added.

## Persistence and compatibility

Facts are transient exploration state, not replayable `AnalysisResult` records.
Schema 3, language, constructors, compiler IDs and mapping schema 2 remain intact.
Engine `20260930-n2-ram-value-1` rejects old-engine reads and application.
The existing mapping fingerprint covers physical anchors, alias topology,
cartridge/hardware classification, permissions and file provenance. Explicit
entry mapper assumptions are already persisted. Only canonical mutable WRAM/HRAM
volatility eligibility needs an added fingerprint component. Runtime byte facts
are never fingerprinted as Program storage. Existing general memory-byte hashing
is retained without adding a new RAM-value dependency.

## Verification and remaining obligations

The independently specified compiled-SLEIGH fixture carries byte 2 through
STORE, LOAD and A into an MBC5 write and physical `rom2::4000` consequence.
`BankAnalysisRamValueTest` covers both echo directions, unknown alias overwrite,
disjoint preservation, poison-initialized RAM, unknown pointers/banks, established
bank separation, ordered word operations, HRAM/device boundaries, branch path
locality, call/diversity fact loss and stale RAM eligibility/old-engine refusal.
Existing scalar mapping oracles remain unchanged; their test adapter passes an
empty incumbent memory state. N1 ROM authority remains independently tested.
Detailed source/dependency identities, commands, outcomes, installed witness and
review are external receipts referenced by the [evidence index](../sa/evidence-index.json).

Memory joins/widening, general symbolic pointers, interprocedural summaries,
device/asynchronous and interrupt effects, broad banked RAM inference and
expanded discovery remain unimplemented. VRAM, SRAM, MBC2 RAM and devices supply
no ordinary RAM values. The next separately authorized task is
SA-MEMORY-JOIN-WIDENING; N2 does not start it.
