# Conditional contract hardening

This local change continues the retained effectful-call work. It does not close
SA-01/02/03, authorize deployment, or replace the roadmap. The stock CALLOTHER,
conditional call semantics, persisted record versions, language and dependencies
remain unchanged.

A copied native capture could previously replace a low-latch write with a
high-latch write and pass because the small ROM's effective bank was unchanged.
The oracle now compares both actual latches and ordered mapper bus effects.
Retained physical reads and writes must respect their source mapper epoch.
Immutable read folding and elimination of the declared disjoint local frame
remain permitted. This relation does not claim physical hardware execution or
require one incidental native graph shape. Storage identity continues to precede
HighGlobal symbol associations.

Deterministic tests also demonstrated source mutation between validation and
install, and unvalidated registration substitution during explanation. An
operation-scoped result now carries one validated registration, lowered operations,
source placements and session revision. Explanation derives text and boundaries
from it; navigation checks the actual Program object and revision on the EDT.
The session revision is not persisted executable identity. Install/refresh check
revision after transaction entry; install rederives after its owned topology writes
before associating the resulting durable fingerprint with the proof.

Ghidra transactions are shared subtransactions, not exclusive writer locks.
The checks establish the tested committed mutation boundaries; they do not assert
atomicity against arbitrary concurrent writers during a shared transaction.
ProgramDB's manager lock does not cover every options write, and DomainObject.lock
cannot be acquired with an active script transaction. Neither forceLock nor a
universal lock/cache framework is introduced. Full concurrent transaction isolation
and complete outstanding-work/Program-switch workflow qualification remain open.

Reference expectations use Gekkio's GB Complete Technical Reference revision 192
(2026-08-16), CPU arithmetic/frame sections, and Pan Docs MBC5 register and memory
map descriptions. The documented MBC5 SRAM-enable upper-bit disagreement is not
resolved here; no SRAM-enable behavior changes. Conditional support remains
explicit synchronous, boot-inactive, low-eight-bit MBC5 with high=0, checked WRAM0/
HRAM storage and physically disjoint bounded frames. DMG/CGB device modes,
interrupts, DMA, banked WRAM, loops and general discovery are not inferred.
