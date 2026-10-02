# Ordinary path-local RAM byte facts (N2)

N3 subsequently refines compatible-state convergence; see the
[ordinary memory join decision](ordinary-memory-join.md). The worklist descriptions
below record the N2 checkpoint. Its byte authority remains. CALL-STACK-LIVENESS-2A
adds one bounded invalidation exception: an exact FF43/SCX WRITE resolved as a
device on established GB/CGB hardware preserves ordinary WRAM/HRAM facts in the
incumbent synchronous domain. Known and unknown SCX values have the same RAM
write set. No device value is stored or invented. FF46, FF55, unclassified devices
and unknown-address stores retain conservative invalidation. Physical replacement,
mapper transitions and CALL frame identity checks remain independent.

Blanket FF43 clearing was rejected by the 1A disjoint-write diagnostic. A general
device framework and DMA narrowing remain outside this decision. Schema remains
4; engine `20261001-call-stack-liveness-2a-1` requires recomputation of preceding
`20261001-call-stack-liveness-2b-1` results. No persisted representation changes.
`BankAnalysisScxLivenessTest` promotes the physical-byte/mapper/control cases and
checks old-engine rejection and packed save/reopen. Detailed implementation
receipts are retained in the external `CALL-STACK-LIVENESS-2A-20261001` batch;
this slice does not close the broader CALL-stack campaign or begin WUX-1B.

CALL-STACK-LIVENESS-2D extends only that exact WRITE exception to the finite set
FF26/NR52, FF40/LCDC, FF42/SCY, FF43/SCX, FF4A/WY and FF4B/WX. The independent
1A/2A, WYATT-DEVICE-LIVENESS-1 and dedicated WYATT-LCDC-EFFECT-1 audits establish
value-independent ordinary WRAM/HRAM noninterference in the incumbent synchronous
ROM/ordinary-RAM domain. The LCDC audit supersedes the device audit's pending
FF40 classification only within that domain. No corresponding device value or
old/new PPU/APU state is retained or created; interrupt, timing, video accessibility
and audio behavior are not modeled by this rule.

A single narrowly named internal predicate checks established hardware, WRITE,
exact CPU byte address and device resolution. It does not admit a range, unknown
addresses or unresolved effects. FF41, FF0F, FFFF, FF46, FF55 and other unclassified
writes retain conservative invalidation. Mapper handling (including FF70/FF4F),
physical aliases, stack identities, reads, execution flow, coverage and depth gates
are unchanged. Each constituent STORE byte remains independently resolved before
its existing mapper transition; an adjacent unqualified byte still invalidates.
A general effect framework and a separate FF40 structural refusal were rejected:
the independent LCDC audit establishes no such barrier for this bounded domain.

Engine `20261001-call-stack-liveness-2d-1` advances compatibility once; schema stays
4 because only transient invalidation changes. 2C results require recomputation;
obsolete owned WUX-1A flow may retire but cannot authorize new publication.
`BankAnalysisDeviceLivenessTest` adds independent physical stack/mapper/RET oracles
and finite device controls alongside retained 2A/2B/2C and packed lifecycle tests.
Implementation evidence belongs to external `CALL-STACK-LIVENESS-2D-20261001`.
Final integrated campaign/evidence-index closeout remains open; WUX-1A remains
CLOSED / QUALIFIED and WUX-1B has not begun.

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

LOAD resolves each byte with READ access. CALL-MEMORY-COPY-1 also routes one-byte
COPY storage inputs in the default CPU memory space through the same
`memoryLoad`/ReadOutcome path. The input names contents, not an address literal:
constant/register/unique COPY inputs keep their scalar semantics. Other spaces
and wider storage COPY forms remain unqualified; no language or raw p-code change
is required. The current FA a16 instruction emits this one-byte form for WRAM,
HRAM and banked WRAM. Supported unknown/absent data preserves structural read
coverage; unsupported devices or unresolved physical backing still refuse it.
Engine `20261002-memory-storage-copy-1` requires recomputation of 2D results;
schema stays 4. Obsolete owned WUX-1A flow retains retirement authority only.
Broader CALL-stack qualification and WUX-1B remain separate obligations.

Every byte must have eligible physical
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
