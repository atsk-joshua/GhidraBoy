# Defined-state cross-backend comparison

Recorded 2026-09-06 against the current production adapters. The authored
fixture compares equal defined registers, CPU/physical RAM and bank identity
at **12 named physical PC boundaries**. Ten of eleven normalized timing
intervals agree. The remaining interval has a real, retained speed-switch
disagreement. This is a bounded ACCURACY-02 comparison result, not full model,
device, Basic Debugging or hardware-accuracy qualification.

Implementation: [compare_backends.py](../../tools/compare_backends.py).
Durable observations, hashes, process commands and classifications:
[m8-cross-backend-evidence.json](m8-cross-backend-evidence.json).
Five verifier tests pass, including a contract assertion preserving the exact
speed-switch reproducer and non-rounding clock normalization. The comparison
command returns **exit 2**, status `DIFFERENCES_RECORDED`; its disagreement is
not converted into a test PASS.

## Normalized scope and provenance

The script generates its own 64 KiB CGB/MBC5 cartridge. After each engine's
startup it executes DI, disables LCD/timer/IE/IF, selects ROM1/WRAM3/VRAM0 and
enabled SRAM2, explicitly initializes 24 compared RAM bytes, sets all compared
registers and synchronizes at physical ROM bank 0 PC `0x0250`. That initial
state must match an independent fixed-value oracle before comparison begins.
All keys remain released. Subsequent samples require exact physical-ROM
execution-breakpoint stops, including **the same CPU PC `0x4000` in ROM banks
1 and 2**. Selected CPU RAM bytes must be known and match the independently
captured physical banks within each engine.

The comparison includes AF/BC/DE/HL/SP/PC, selected bank/control observations,
and 8 bytes each at CPU `0xc000`, `0xd000`, `0xa000` with corresponding WRAM0,
WRAM3 and SRAM2 physical bytes. It measures each interval from its previous
synchronized capture, using ticks divided by that engine's declared frequency;
exact cross multiplication detects disagreements without a tolerance. Startup
tick totals, uninitialized memory, IO, frame/audio output and instruction
counters are excluded explicitly. No instruction count is invented for mGBA.

Engine identities differ and remain visible:

- SameBoy core `208ba4afabffab9edde416f2dbb8ae459e34adb8`, native model CGB-E,
  redistributable boot **image**, 2,304 boot bytes. Native binary SHA256
  `67e39fead16cdddb492cef8b5d978072d32cd4d2d2109aa7efd076bd46ca7cb1`.
- mGBA core `685023e05d90d87050fb357f46f7bd2d907083f5`, native model CGB,
  **engine post-boot** policy, zero boot bytes. Native binary SHA256
  `9c0b84e7bd678e695950bbf5451aa916d6b2d6e7c55f08327d6659ff8ac675cf`.

The evidence preserves adapter, boot, ROM, native binary and build identities.
Initializing the compared state makes this subset comparable; it does not make
these silicon revisions, PPU/APU startup histories or boot policies equal.

## Actual timing disagreement

At the `speed_armed` synchronization point, ROM bank 0 PC `0x0284`, KEY1 is
armed, speed is normal, interrupts are disabled with IE/IF zero, and all keys
are released. The minimal executable case is **`10 00 00` — STOP 00; NOP**.
Both engines eventually reach `0x0287` in double speed with equal compared
registers and RAM. The interval measures:

| Backend | Ticks | Declared frequency |
| --- | ---: | ---: |
| SameBoy | 131,096 | 8,388,608 Hz |
| mGBA | 20 | 8,388,608 Hz |

This is an observed pinned implementation difference. SameBoy's
`Core/sm83_cpu.c:449` assigns `speed_switch_halt_countdown = 0x20008` after
arming its speed transition. Pinned mGBA's `src/gb/gb.c:1095–1100`, `GBStop`,
changes `doubleSpeed` and `tMultiplier` immediately. SameBoy exposes intervening
wait boundaries; mGBA proceeds immediately. The verifier measures through the
following NOP so the delay remains in the interval rather than disappearing
through a synchronization choice. Subsequent double-speed INC and NOP each
take four ticks in both engines; preceding normal NOP takes eight.

Classification is `speed-switch-device-delay-unresolved`. The source paths
explain the implementations; **no physical hardware adjudication was done**.
Cross-core speed-switch timing is unsuitable for equivalence claims and remains
unqualified. This is neither a majority vote nor a reason to relax timing
comparison or silently ignore STOP.

## Intentional data divergence

The negative-control ROM changes only the operand at ROM file offset `0x0252`
from `0x42` to `0x99`, plus its checksum. Starting from physical bank 0 PC
`0x0251`, execute `LD A,$42` versus `LD A,$99` once. At `0x0253`, AF is
`0x4280` versus `0x9980`. The following store produces `0x42` versus `0x99` at
WRAM0 offset 0 / CPU `0xc000`. The verifier requires exactly these three named
field differences across the load/store boundaries and records distinct ROM
hashes. Classification is intentional different ROM input, not an emulator
defect. Both complete generated ROMs and every captured row remain in the
local evidence directory; the durable JSON retains hashes and observations.

## Reproduction and remaining limits

From the GhidraBoy root, with already-built adapters:

```sh
debugger/.venv12/bin/python -m unittest discover \
  -s tools -p test_compare_backends.py -v
debugger/.venv12/bin/python tools/compare_backends.py \
  --output /private/tmp/ghidraboy-cross-backend-new-run
```

The output directory must be fresh. Independent native worker processes have
30-second watchdogs; timeout, missing observation and unexpected stop are
failures. The retained run is
`/private/tmp/ghidraboy-cross-backend-review-final-2`, with five verifier tests
passing and the comparison exiting 2. No native rebuild, production adapter
edit, package update or index operation occurred in this task.

Remaining qualification includes the larger opcode/model/mapper and device
matrix, interrupt-boundary comparison, boot-policy-compatible coverage,
adjudication of timing differences against appropriate independent evidence,
and physical Steam Deck verification when the user resumes it. Agreement of
this defined-state subset is not proof of hardware correctness.
