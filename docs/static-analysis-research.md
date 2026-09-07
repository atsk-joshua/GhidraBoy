# Static analysis research and design decisions

Reviewed 2026-09-07 against the current provider and Ghidra 12.1.3 source.
This is a research record supporting the [roadmap](roadmap.md) and
[planned specification](static-analysis-spec.md). Source inspection is distinct
from an executed regression. No architectural candidate below is qualified merely
because the corresponding API exists. Current capabilities remain in
[analysis](analysis.md), [input policy](input-policy.md), and
[compiler support](compiler-support.md).

## Evidence and source quality

The downloaded official distribution matched the project's pinned SHA256
`93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54`.
The inspected `FindNoReturnFunctionsAnalyzer.java` matched the source in that
archive and the local installation. Exact versions and artifact identities matter:
an upstream discussion, a current web manual and a local patched executable are
different evidence. The [reference catalog](references.md#static-analysis-reference-catalog)
links version-pinned Ghidra source and hardware/software sources.

Gekkio's PDF was directly retrieved as **revision 192, 2026-08-16**. Earlier
search results advertised revision 184; use the document itself. Its preface
focuses on pre-CGB models, and its MMM01/TAMA5 chapters are TODOs. A table of
contents is not evidence that a device is fully documented. Pan Docs contains
explicit unknown/speculative sections too. Hardware evidence, emulator behavior
and emulator detection heuristics must remain distinguishable.

## Confirmed implementation gaps

The first three findings below were revalidated and addressed by SA-00; their
original finding/evidence descriptions are retained as provenance. See the
[SA-00 decision](decisions/sa00-integrity.md) and
source checkout receipt `docs/evidence/sa00-20260907/README.md` for the conservative
interpretation policy and remaining unsupported cases. The other findings stay open.


| Finding | Evidence inspected | Required response |
| --- | --- | --- |
| Incomplete result invalidation | `BankAnalysis` consumes `Instruction.getFlows()`; 12.1.3 `InstructionDB` obtains those from stored flow references; `ProgramFingerprint` does not hash those references | SA-00: include consumed flow evidence and reference-only negative tests |
| Mixed raw and modified flow | `Instruction.getPcode()` uses `getPcode(false)`; the analyzer separately consumes stored flow/overrides | SA-00: define and test a coherent interpretation policy |
| Host-language shift semantics | `PcodeConstants` uses Java shifts without Ghidra's width/overshift guards | SA-00: operation conformance; source-level mismatch, not a demonstrated real-ROM failure |
| Missing memory values and call summaries | ROM reads are recorded but not evaluated into constants; call fallthrough clears register/mapper knowledge | SA-03: memory facts, ranges, relational bank effects and summary dependencies |
| Named discovery seeds refused | `FunctionDiscovery` rejects every non-DEFAULT label, including imported labels | SA-04/05: preserve names while allowing justified function creation; do not promote every label |
| Indirect cartridge semantics incomplete | Only encoded direct byte/SP stores have dynamic bus injection; other forms remain outside that improvement | SA-02/03: consistent access-kind semantics and native decompiler checks |
| Compiler identity restricts debugger binding | `BankMappings` requires compiler `default`, despite shipped SDCC IDs | Preserve as an integration obligation when qualifying static ABI changes; do not alter IDs to bypass it |

These findings do not retroactively alter historical PASS receipts. Their missing
cases become new regression obligations. Full-game warning inventories and exact
game-specific repairs remain in their owning studies; they are not generic build
inputs and are not reproduced here as commercial ROM-derived code.

## Ghidra mechanisms and limits

### Software-call semantics

The compiler spec's register strategy is intended for hand-written assembly.
Per-function prototypes, `killedbycall`, `unaffected`, callfixups and callother
injection are supported mechanisms. They still require correct effects.

The 12.1.3 nonreturn analyzer runs after disassembly and explicitly defers to a
target callfixup with fallthrough semantics. A returning software-transfer model
must be available before heuristics damage continuations. Repeatedly clearing
`noReturn` or disabling the analyzer does not supply the missing semantics.
P-code CALL/CALLIND do not themselves push a return address. A fixup must account
for original caller pushes, wrapper frames, adjusted inline-payload returns and
callee cleanup without double-pushing or skipping real effects.

Ordinary supplemental references do not implement mapper memory semantics.
However, primary override references can change p-code calls/jumps; they have
uniqueness and operation restrictions. An unconditional jump override can remove
a condition. Distinguish those from navigation evidence. Upstream issues #889 and
#5747 are related reports about nonreturn reassertion and pushed-return software
calls, not proof that the exact GB case is fixed upstream.

The SA-01 mechanism experiments now execute an explicit callfixup and compare
its real frame effects with raw p-code. A stock nonreturn negative followed by
one repair survives repeated automatic analysis. Cross-overlay native CALL also
succeeds with physical target/symbol identity after resolving the competing
decoded primary reference; an initial expected native failure was disproved.
These are bounded mechanism results, not reusable production integration. See
[the call-model decision](decisions/static-call-model.md) and the source receipt
`docs/evidence/sa01-20260907/README.md` for executed scope and retained failures.

### Banked memory and function flow

The inspected overlay operand resolver uses the instruction's current space;
it does not consult a cartridge mapper state. `FunctionManagerDB` requires a
single address space for a body. Native `Funcdata::startProcessing` bounds flow
to the entry space, and `FlowInfo::newAddress` treats outside destinations as
out of bounds. `DecompInterface.setupEncodeDecode` selects an overlay codec
based on entry. A working cross-reference or a selected single-bank custom
transport therefore does not establish general bank-aware native flow.

Compare these alternatives under SA-02:

| Alternative | Evidence / advantage | Must be proven before selection |
| --- | --- | --- |
| Keep overlays and add explicit context-aware analysis/views | Existing source identity and migration investment; protected codec hook exists | Correct multi-bank intra-function flow and data; normal Decompiler-window integration; no reinterpretation of other-bank reads |
| Wider physical address model plus segment operations | Stock HCS12 combines paging with 16-bit inner addresses | CPU/physical width separation, full fetch/return/wrap semantics, read/write asymmetry and language/Program migration; HCS12 itself contains paging TODOs |
| A scoped Ghidra bank-resolution extension | Upstream discussion #9349 describes the missing contextual resolution | Implementation/API acceptance, all flow and memory consumers, maintenance cost and migration; the RFC is not a shipped capability |

A stored context value at one address cannot silently represent every execution
state reaching it. Preserve alternatives/assumptions or construct explicitly
derived analysis views. No decision may rely solely on a nicer C listing.

### Dispatch and abstract values

JVM and Dalvik use `jumpassist` scripts for case values, target addresses,
defaults and table size. In 12.1.3, `JumpAssisted` requires metadata inputs other
than the switch variable to be constants, creates targets in the indirect
instruction's space, and includes a default target. It is not an unknown-bank
resolver or permission to invent a default or a short table domain.

Native `ValueSetSolver` computes an overapproximation within a function. Its
input construction assigns full ranges to loads, calls, callother and segment
operations. It cannot by itself prove a memory-resident state machine's global
range or a bank-shadow relationship. `SymbolicPropogator` and Ghidra operation
behaviors are relevant reuse candidates; preserve conservative unknown values
and audit their own limits rather than replacing one incomplete model blindly.

The existing native normalized-index and logical-shift fixes have specific
regressions. Retain them as versioned dependencies until a verified replacement
exists. Other indirect-transfer warnings require classification first: pointer
calls, manual-return transfers and actual tables need different treatment.

### Compiler allocation and database integration

12.1.3 parameter model rules include datatype/position filters, stack assignment
and hidden-result handling. Evaluate these before expanding `CompilerAbi`'s
manual packed allocation; support for every SDCC signature is not established.
Ghidra source mappings, typed data, unions, references and analyzer infrastructure
are appropriate integration points for metadata and discovery. Decompiler cache
refresh, analysis ordering and saved-work invalidation are part of correctness.

## How game construction changes the requirements

The linked reconstructed disassemblies provide concrete machine-code patterns;
they do not establish the original developer's build system or source types.

| Pattern and primary example | Static consequence |
| --- | --- |
| Crystal restores a bank while retaining callee flags; Red pushes a continuation then jumps | Model bank and result effects separately; RST number is not a universal ABI |
| LADX's `CopyDataFromBank` selects bank 1 afterward | Do not assume every helper restores its incoming bank |
| GBDK 4.5.0 current register-target and legacy inline banked helpers | Versioned recognition, different payload/frame contracts; legacy helper skips four inline bytes and is call(0)-specific |
| GBDK `FAR_PTR` is a 32-bit offset/segment container; other formats use three bytes | Preserve format and effective mapper selection; no universal far-pointer datatype |
| RGBDS LOAD stores ROM bytes assembled for RAM execution; HRAM DMA routines | Track storage versus execution address, copy provenance and later replacement/self-modification |
| Crystal HRAM UNIONs reuse scratch storage | Type/lifetime hypotheses must allow multiple logical uses of the same bytes |
| Crystal event scripts invoke native callbacks; audio has its own command stream | Distinguish native/script graphs and follow validated script-to-native edges |
| Interrupt code updates ordinary RAM and temporarily changes banks | Shared data and bank restoration need interrupt summaries; marking only I/O volatile is insufficient |
| RGBDS charmaps, graphics data, relocation/source context and linker constraints | Import available metadata and derive data interpretation from consumers; bytes that decode are not necessarily CPU code |

Compiler-generated fixtures must pin toolchain/version/options and retain emitted
assembly. Symbols/maps/object metadata must match the exact image and format
revision. Do not treat labels as proved function boundaries, rebuild-generated
annotations as original source truth, or adjacent plausible words as a table-size
proof. Relevant sources are cataloged in
[game construction and metadata](references.md#game-construction-and-metadata).

## Cartridge requirements

This is an implementation/research matrix, not a supported-mapper announcement.
Current support remains limited by [input policy](input-policy.md).

| Family | Details required by the static model |
| --- | --- |
| ROM-only, MBC1/2/3/5 | Control decode and ordering, zero-bank substitution before disconnected-line masking, MBC1 coupled ROM/RAM wiring, MBC2 address-bit control/nibble RAM, MBC3 RTC selection/latch, MBC5 ninth bank bit/rumble RAM limits |
| MBC1M / MBC30 | Distinct wiring or capacities; evidence-backed detection/override; do not equate header mapper ID with board identity |
| MBC6 | Independent 8 KiB ROM/flash windows and smaller RAM windows; mutable flash/device behavior differs from ordinary ROM patches |
| MMM01 / M161 | Alternate reset/header mapping and one-way configuration; M161 changes the entire 32 KiB window |
| HuC1 / HuC3 | RAM versus IR/RTC/device modes; HuC1 is not simply MBC1; HuC3 command/response and unknown behavior |
| Camera / MBC7 / TAMA5 | Register windows, image transfer, serial EEPROM or nibble/RTC protocols; not flat SRAM |
| Identified unlicensed/multicart boards | Wiring, address/data transforms, latches and detection evidence; emulator title/hash heuristics remain hypotheses |
| All families | Hardware versus operating mode, boot overlay, alias identity, original/current bytes, persistent save state, open-bus uncertainty and reproducible model assumptions |

Source conflicts remain explicit research tasks. For example, the retrieved
GBCTR HuC3 overview describes sixteen 8 KiB RAM banks while the Pan Docs memory
map describes four. Resolve the exact controller/board capability with primary
evidence before claiming the broader geometry. Pan Docs labels EMS behavior as
unverified on authentic hardware. mGBA's device implementations are useful
comparisons, not substitutes for hardware evidence. Unknown required behavior
keeps SA-06 open.

## Decision gates and completion boundary

The research identifies the sources, mechanisms, counterexamples and unknowns
needed to plan the work. The implementation must still pass the three roadmap
prototypes: software-call behavior under normal auto-analysis, full banked
memory/flow representation, and correctly classified dispatch recovery.

Measure raw/injected p-code, native CFG/C, committed listing/bodies and saved
reopen independently. Include mutation-only stale-result tests and fresh/imported
work. Keep remaining semantic and coverage failures alongside warning counts.
No new source inspection, summary or documentation change establishes an
[acceptance gate](static-analysis-spec.md#acceptance-matrix) by itself.
