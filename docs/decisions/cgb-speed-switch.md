# Bounded CGB KEY1/STOP continuation

CGB-SPEED-SWITCH-2 interprets the raw architectural `stop` userop in BankAnalysis
without changing SLEIGH or general HALT/STOP execution. The pinned hardware audit
in external batch `CGB-SPEED-SWITCH-1-20261002` establishes the guarded synchronous
speed-switch case; its path-specific laboratory counterfactual is not production
proof authority. Source-derived generic control facts replace that counterfactual.

## Transient relation

Package-private `ControlRegisterFacts` carries active CGB mode, current speed and
switch arm as known true/false or unknown, with partial IE and JOYP selection bits.
It is part of execution/worklist identity, call transport and return meets, and
is discarded by conservative unsupported-call or widening fallback. Nothing is
persisted into Program annotations. IF, IME, button state, DIV and timer values
are not represented.

Hardware selection and active mode are distinct. A GB selection excludes CGB
mode; a CGB console or cartridge capability header does not establish active CGB
mode or initial speed. A consumed KEY1 bit predicate partitions compatible mode/speed
alternatives. Non-CGB reads return the documented FF. CGB reads expose only bit 7
(current speed) and bit 0 (arm) where known; reserved bits remain unknown. Raw
BIT p-code then selects feasible conditional successors independently. A bit-7
clear successor excludes non-CGB and establishes NORMAL; its sibling retains
compatible non-CGB or DOUBLE alternatives. No address-specific rule is used.

Exact KEY1 writes update writable bit 0, including a partially known SET/RES
read-modify-write. Unknown bit 0 weakens arm. Software writes cannot alter the
read-only speed relation. IE writes retain source-derived bit knowledge, with
unknown writes weakening it. JOYP writes retain only selection bits 4/5; they
never establish actual button state.

## Guard and effects

The admitted STOP requires active CGB mode, known NORMAL or DOUBLE speed, armed
KEY1, exact IE=00 and known JOYP selection=30. IE=00 excludes enabled pending
interrupts while IF and IME remain unknown. JOYP selection=30 deselects both input
groups while physical buttons remain unknown. The consumed opcode and second
byte must establish canonical `10 00` in eligible physical ROM, with the second
byte within the supplied exploration restriction.

The summary consumes two bytes, continues at the architectural CPU address +2,
toggles NORMAL/DOUBLE and clears arm. It preserves CPU registers/flags, ordinary
WRAM/HRAM, stack bytes and mapper/physical identity. No represented DIV fact
exists; the hardware DIV reset creates no exact timer value in analysis. Exact
pause duration and asynchronous timer, serial, DMA, audio, video and interrupt
execution are outside this contract. Unarmed, unknown, non-CGB, input-selected,
interrupt-enabled and malformed STOP cases remain incomplete; HALT remains
unsupported.

The ordinary-memory rule adds exact KEY1 to the value-independent finite set on
established hardware. Separately, the preceding audit qualifies only exact IF=00,
IE=00 and known JOYP byte writes with both selection bits one for ordinary-memory
preservation on established hardware. Other values and unknown writes retain
conservative invalidation. Tracking control facts does not itself qualify an
ordinary-memory effect. This does not admit any FF4x range or all control/I/O
registers. DMA and unknown-destination negative controls remain binding.

## Compatibility and qualification boundary

Engine `20261002-cgb-speed-switch-2` advances once from RAW-FLOW-VIEW-1; schema
remains 4 because persisted result shape is unchanged. Old results cannot apply
or publish. Exact obsolete owned stock-flow receipts retain retirement authority;
packed results require recomputation. Mapping provenance, instructions and bytes
already fingerprint the consumed premises, including the STOP second byte.

Self-authored compiled-language fixtures must qualify read/write bit knowledge,
branch-order independence, both speed directions, refusal predicates, ordinary
memory/frame preservation and currentness/reopen. The external production replay
must derive control premises without internal-state seeds. Detailed receipts are
kept in `CGB-SPEED-SWITCH-2-20261002`; focused qualification does not establish
whole-ROM, arbitrary STOP, native STOP decompiler, installation or release support.
The 179-state local budget, global limits, mapper semantics, WUX-1P/WUX-1A and
independent downstream storage/widening frontiers remain unchanged. WUX-1B remains
unstarted.
