# Independent architectural expectations for SA-01

These self-authored fixtures in `SoftwareCallExecutionTest.kt` execute compiled
SM83 SLEIGH through `EmulatorHelper`. They do not attach convention overrides,
callfixups, prototypes or generated call references. Expected words and registers
are derived from the instruction sequence, not from the software-call summary.
The primary receipt records whether each test actually ran and passed.

The initial SP is `c100`. Each real PUSH or hardware CALL/RST stores a little
endian word below SP and subtracts two. RET reads the current word and adds two.
A JP HL transfers control without touching SP. Software CALL p-code must not be
credited with any implicit architectural push.

| Fixture | Independent checkpoints |
| --- | --- |
| Hardware CALL then pushed helper epilogue and JP HL | Target SP=`c0fc`, words `0220` and `0156`; final SP=`c100`, AF=`0090`, BC=`4567` |
| Manual pushed continuation and RET to pushed target | Target SP=`c0fe`, continuation `0180`, consumed target word `0300` at `c0fc`; final BC=`9967`, AF unchanged |
| Inline RST, three or four bytes | Replaced stack continuation `0154`/`0155`, consumed target word `0300`, target SP=`c0fe`; final AF=`0090`, raw selector two |
| Nested wrappers with saved BC and AF | Innermost SP=`c0f6`; outer caller word `0153`, saved BC=`4567`, nested return=`0303`; final BC restored and callee AF=`0090` |
| Recognized register wrapper variants | Restoring target SP=`c0fa`, saved AF=`01b0`; constant target SP=`c0fc`; nonrestoring target SP=`c0fe`; each final F=`90` |
| Raw versus physical bank | Restored MBC3 raw selector zero resolves to effective physical ROM bank one; constant return selector three and nonrestored selector two remain distinct |
| Stale RAM shadow | Entry selector one with shadow three restores three; execution disproves any unconditional physical-restoration claim |
| Conditional return, direct self-loop, discarded caller frame | Separate inputs reach ordinary continuation with SP restored, loop with frame still present, or nonlocal destination after POP discards the frame |

The restoring recognized wrapper restores A from the saved incoming AF and leaves
BC equal to that saved AF; it preserves the callee's result F. The constant-bank
wrapper overwrites A with its constant and leaves BC equal to its pushed helper
return. Nonrestoring JP HL leaves the original hardware caller frame for the
callee RET. None of these facts permits assuming an unknown callee preserves its
frame, returns on all paths, or cannot exit nonlocally.

## Limits that must remain visible

`CartridgeBusEmulation.Context` tracks direct cartridge-control writes but its
memory guard delegates reads and instruction fetch to the original flat backing.
Consequently these execution fixtures place executable callees in fixed ROM and
check bank-selector transitions plus `MapperState.translate` identity separately.
They do **not** establish instruction fetch from different physical switchable
banks, native CFG/C, automatic-analysis behavior, listing payload ownership, stale
evidence rejection or save/reopen. Those need separate tests and the banking
architecture obligation cannot be waived by these frame oracles.

Eight executions of a syntactic `JP` self-loop are a bounded checkpoint, not a
general termination proof. Conditional inputs are explicit premises. The corpus
is generic and contains no commercial ROM bytes or game-specific addresses.
