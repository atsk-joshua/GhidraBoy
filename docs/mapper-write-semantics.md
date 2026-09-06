# Mapper writes and decompiler semantics

Original investigation: the correctness issue below was reproduced with native
Ghidra 12.1.3 on 2026-09-05. Decomp3 now implements the bounded encoded-direct
write remedy; see [direct bus semantics](direct-bus-semantics.md) for current
behavior and acceptance evidence. Indirect writes and other stated limits remain
open. The following reproduction and architectural reasoning preserve the
original diagnosis rather than treating warning-free C as proof of correctness.

## Reproduction and cause

The table below records pre-decomp3 output. Use a preserved baseline provider to
reproduce those exact strings. Under decomp3 this raw, descriptor-free fixture
still selects flat semantics; its warning details can differ because direct
hooks change automatic WRITE-reference discovery. Current cartridge acceptance
uses the descriptor-bound native/CPU fixtures documented above.

`src/test/scripts/MapperStoreDiagnostics.java` creates three self-authored
functions in a disposable raw 32 KiB Program, marks its source block read-only,
and runs the actual decompiler with `Respect readonly flags` enabled. It also
creates writable work RAM. Bytes at 2000h and 2100h are initially 5Ah.

| Fixture | Native result | MBC5 cartridge interpretation |
| --- | --- | --- |
| Direct `LD (2000h),A`, then read 2000h, with A=2 | No warning; writes `DAT_2000=2` and propagates `DAT_c000=2` | Control write selects ROM bank 2; fixed-ROM read remains 5Ah |
| Indirect `LD (HL),A` with HL=2100h, then read 2100h, with A=2 | Read-only-write warning; writes `DAT_2100=2`, retains `DAT_c002=0x5a` | Same control operation; fixed-ROM read remains 5Ah |
| Ordinary write/read of C001h with A=2 | No warning; writes and propagates 2 | Correct writable-memory operation |

This fixture is deliberately a raw Program to isolate the decompiler's static
memory behavior; it does not pretend to emulate a cartridge. The MBC5 comparison
follows the existing `MapperState.write`/`translate` contract: writes at
2000h–2FFFh update the low ROM-bank selector and do not modify fixed ROM bytes.

The difference between direct and indirect diagnostics has a concrete cause.
In pinned Ghidra 12.1.3 `MappedEntry.getMutabilityOfAddress` (SoftwareModeling
source, lines 103–130), a read-only block address becomes `NORMAL` when one of
its first 100 incoming references is a WRITE. The assembler supplies a direct
WRITE reference for the first fixture, while the HL fixture initially has none.
Native `Funcdata::fillinReadOnly` (`funcdata_varnode.cc`, lines 663–683) reports
writes that remain read-only in the IR. Consequently **zero read-only warnings
is not proof that cartridge writes or subsequent ROM reads are correct**.

The fixture neither edits reference metadata to obtain a desired result nor
suppresses diagnostics. Complete local output is retained under
`/tmp/gbw3-semantics-review/mapper-store-indirect-results.txt`; the associated
headless log contains `MAPPER_STORE_DIAGNOSTICS_COMPLETE`. These generated
fixtures contain no commercial ROM bytes.

To reproduce, create a fresh temporary directory and zero-filled 32768-byte
`fixture.bin`, then invoke the selected installation's `support/analyzeHeadless`:

```sh
analyzeHeadless "$WORK/projects" MapperStore \
  -import "$WORK/fixture.bin" -loader BinaryLoader \
  -processor SM83:LE:16:default -cspec default -noanalysis \
  -scriptPath "$GHIDRABOY/src/test/scripts" \
  -postScript MapperStoreDiagnostics.java "$WORK/results.txt"
```

Use a new disposable project, not an existing annotated Program. Each function
has a ten-second decompiler timeout. Check completion/error fields in the output
and the explicit script completion marker, not merely process exit status.
Successful diagnostic execution records the defect; it is not a passing mapper
semantics acceptance result.

## Generic remedy derived from the investigation

The correct IR must distinguish an addressed bus write from a read of immutable
cartridge source bytes. The implemented bounded direction uses an explicit
byte-write hook with defined execution semantics and Program-aware lowering:

1. Append a bus-write userop without renumbering existing userops. Cover every
   store form in architectural byte order; start a private prototype with direct
   `LD (nn),A`, ordinary C000h stores, and flat CPU Programs.
2. Provide real execution semantics: flat CPU Programs write their ordinary
   memory; verified cartridges dispatch mapper/device controls through the
   existing hardware model without changing ROM bytes.
3. Lower proven ordinary-memory writes to normal p-code STOREs. Verified
   cartridge-control writes become visible side effects with their exact CPU
   address/value and established mapper meaning. Unknown mapper/address state
   stays explicit. A no-op fixup or an added marker alongside the old ROM store
   would lose or double behavior.
4. Teach BankAnalysis to consume the same hook and byte ordering. Current
   analysis recognizes STORE/direct-memory COPY, not a bus-write CALLOTHER.
5. Test both real native C and architectural state, immutable bytes, mapper
   selectors, and analysis facts. Extend to indirect mixed-address paths,
   read/modify/write, stack stores and 7FFFh/8000h plus FFFFh/0000h boundaries
   before claiming complete support.

Ghidra's `InjectPayload.getPcode(Program,InjectContext)` can specialize a defined
callother hook using Program metadata and encoded constant operands. It does not
receive general late-stage SSA constants for an unknown HL/BC/DE input. Making
all indirect RAM stores opaque would materially harm normal C recovery; a
production design must address this explicitly. Reads of the switchable ROM
window after a selector change require a corresponding banking model and are
not solved by correcting writes alone.

Current p-code STORE operations have no generic reference-based injection hook.
`InstructionPcodeOverride` supports call/branch/callother/fallthrough changes,
not arbitrary STORE replacement. Thus a small reference-only patch is not a
correct implementation. A new context or address-space model is an alternative,
but requires explicit language-version and annotated-Program migration work.
Do not silently change context/register layout under the current language 1.0.

Changing ROM permissions, adding WRITE references, globally marking ROM
volatile, or disabling warning/readonly options cannot satisfy this issue:
these can hide the incorrect store and compromise constant table reads. Existing
annotations and immutable source/export identities must survive the remedy.

## Bounded context alternative and prototype boundary

An opt-in cartridge-bus context could retain the existing flat semantics for
raw CPU Programs while selecting addressed mapper semantics in verified
cartridge Programs. However the current language has no such context register.
Adding one is a language-layout change, requiring versioned migration, and the
context cannot simply be assumed to describe an indirect address's runtime
value. A cartridge-mode bit identifies the hardware environment; it does not
prove that HL points into ROM control space on every path.

A sound bounded prototype can therefore cover encoded direct stores first:
Program-aware injection sees the literal address, checks cartridge metadata,
and chooses the correct store/control operation without generating a conditional
p-code branch. It must preserve ordinary RAM STOREs and flat CPU semantics and
must explicitly retain indirect/mixed sites as unresolved acceptance work.
Using a separate persistent per-site context to specialize indirect stores
requires proof across all incoming paths, byte/source fingerprints, evidence
invalidation when predecessors change, and preview/save/reopen/rollback tests.
Existing uncertain annotations must not silently become such proof.

This restriction follows the pinned native implementation, not a timing guess:
`FlowInfo::injectUserOp` in `flow.cc` (1196–1223) copies each raw input varnode's
space/offset/size into the injection context during flow construction. An encoded
address is available as a constant; an HL register input is not replaced by the
result of a preceding `LD HL,nn` through this API. Exact decoder-known folding is
possible; general late-SSA address folding is not supplied to the callback.

A runtime `if (address < 0x8000)` dispatch is semantically meaningful in cartridge
mode, but folding that p-code branch at known sites reintroduces the same native
unreachable-block diagnostics identified in POP/DAA. An opaque branchless
bus-write userop avoids the internal CFG, but ordinary memory writes then lose
native STORE-based alias and value propagation unless correctly lowered. An
extra write address space with byte-mapped RAM aliases is not an established
solution either: shared Program bytes do not prove native decompiler SSA aliases
between distinct address spaces. Test read-after-write semantics explicitly.

Further extensions must compare these alternatives using the maintained
three-function diagnostic, expanded with direct 2FFFh/3000h controls and a raw
flat Program. It is **not** ready for production merely because the visible
control write removes a warning. Native C, the actual emulator callback,
BankAnalysis state, ordinary load/store precision, mapper-specific effects, and
unchanged source bytes all need to agree before widening the supported scope.
