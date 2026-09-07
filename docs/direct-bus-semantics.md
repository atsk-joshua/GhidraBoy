# Direct cartridge bus writes

Decomp3 models encoded `LD (nn),A` and `LD (nn),SP` as addressed bus writes.
With an established cartridge descriptor, bytes targeting CPU 0000h–7FFFh become
visible `gb_cartridge_write8(address,value)` operations. They no longer appear
as writes to immutable ROM bytes or to symbols such as `rst00`. Ordinary memory
writes lower to native STORE operations, preserving normal value propagation
and the original flat/overlay address space.

The decoder retains its original constructors, patterns and operands. New
userops are appended after the existing names, preserving their indices. The
Program-aware `CartridgeBusInjectLibrary` uses Ghidra's supported dynamic
callother injection API. Literal addresses are available at this stage, so the
lowering emits no conditional dispatch branch. Word stores capture both source
bytes, write low then high, and wrap each address at 16 bits.

`BankAnalysis` recognizes the same direct hooks and applies its existing ordered
byte-write logic. Old or unrelated userops are not mistaken for writes. Analysis
engine identity is now `20260905-decomp3`: old serialized previews must be
regenerated because operation indices and semantics changed. Existing ownership
receipts and annotations are preserved; rejecting an old preview does not remove
them.

## Activation and RAW policy

A filename, title or absence of warnings never activates cartridge semantics.
Normal cartridge imports already persist the selected descriptor. A legacy
Program with no descriptor remains a flat CPU Program until explicitly enhanced.
On a backed-up copy, use the existing `LegacyEnhancement.enhance(program,"AUTO",
monitor)` mechanism after verifying the original FileBytes and current exported
ROM identity. This reconstructs metadata without changing topology or student
knowledge. An unrecovered GB/CGB mode can remain UNKNOWN: the demonstrated MBC5
ROM-control ports do not require inventing RAM/I/O hardware state.

An explicit RAW override takes precedence over a supported-looking header.
Unsupported mapper types also remain RAW. These cases retain ordinary STORE
lowering; requesting a cartridge emulation context for them is rejected. The
RAW loader's existing memory permissions remain authoritative for native
readonly diagnostics. No ROM permissions or user references are rewritten.

Legacy WRITE references can still prevent Ghidra from folding a ROM read to a
constant. The corrected bus operation prevents erroneous write-to-read value
forwarding even when such a reference is retained. An unresolved ROM load in C
is preferable to inventing a value, but it remains a readability/analysis limit.

## Bounded p-code execution helper

The language's Ghidra `EmulatorHelper` adapter preserves the established flat
CPU behavior by default. `CartridgeBusEmulation.attach(helper,initialState)`
adds an explicit, bounded validation context for the direct hooks. The initial
mapper state is required; there is no implicit bank-1 assumption. The context
applies the existing `MapperState.write` model and leaves ROM bytes unchanged.

This is not a full cartridge emulator. Reads and instruction fetches still use
the flat emulator image, and device timing, complete I/O behavior and dynamic
banked reads/fetches are outside its scope. While attached, a write-through
memory-bank guard rejects other STORE forms that reach 0000h–7FFFh before
changing any ROM byte. Thus an indirect `LD (HL),A` control write cannot silently
mutate ROM or leave a falsely updated selector. Closing the context restores the
original memory bank and retains completed ordinary RAM writes. GhiGBC/SameBoy
remains the full hardware authority. The validated adapter uses Ghidra's legacy
EmulatorHelper extension API; modern PcodeMachine integration is not claimed.

Diagnostic writes use a bounded ring, default capacity 4096. An overload permits
another positive capacity. `writes()` returns the retained records in execution
order, `droppedWrites()` exposes truncation, and `rejectedControlWrites()` exposes
unsupported attempts. Dropping diagnostic records never drops memory writes or
mapper effects. Close contexts with try-with-resources/use.

## Evidence and remaining gates

Maintained regressions exercise native C and recovered p-code, compiled SLEIGH
execution, mapper state, immutable ROM/export bytes, ordinary RAM and flat/overlay
behavior, RAW overrides, retained user WRITE references, diagnostic overflow,
unsupported control-store rejection, and old-userop compatibility. The existing
501-instruction old-provider save/new-provider reopen check passes. Validation of an existing annotated Program is a separate copy-only gate;
self-authored fixture results do not authorize changing user instructions,
metadata, references or function bodies.

Independent hardware checks are reproducible with
`python3 debugger/tests/verify_direct_bus_native.py --work <new-directory>`.
Four self-authored SameBoy MBC5 fixtures cover a byte selector write, the
2FFFh/3000h low/high-selector boundary, 7FFFh/8000h ROM/VRAM, and FFFFh/0000h wrap.
They execute instructions without register/memory state edits, using a documented
minimal boot bypass. Selector state, flags/SP, full fixed and selected ROM
windows, and input files are checked. The retained result is
`/tmp/ghidraboy-direct-bus-native-independent-v2/results.json`. The GhidraBoy debugger supplies this optional hardware oracle; the static
provider has no emulator runtime dependency.

Native C reconstruction of an *unknown absolute entry SP* remains limited by
Ghidra's abstract stack-base model: byte decomposition may display a low zero
from the abstract base. Ordered raw p-code and concrete CPU SP cases are tested;
this does not establish accurate general absolute-SP C output. No global compiler
model is changed to hide this inherited limit.

Indirect stores, read-modify-write instructions, stack writes into cartridge
control space, bank-dependent reads/fetches and unresolved control flow remain
outside this bounded direct-write improvement. Whole-ROM corpus acceptance must
continue to report those gates; the sample warning reduction is not 100% ROM
acceptance.
