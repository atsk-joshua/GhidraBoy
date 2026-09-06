# Independent mGBA contract review

Reviewed 2026-09-06. This review made no production edits. The existing 12
`test_mgba.py` tests pass on macOS arm64 with native binary SHA256
`b0ac9a4a15fe61ccad0b42eac234006626c1e4bcd0929b397ea8d1e9d9d4d507`.
These results do not qualify Basic Debugging or platform acceptance.

## Findings requiring integration decisions

1. **CPU memory currently reports physical bytes as known during CPU access
   restrictions.** A self-authored CGB/MBC5 ROM disables LCD, writes `0x5a` to
   VRAM address `0x8000`, enables LCD, then loops on `LD A,($8000); JR`.
   At the thirteenth step (read opcode at `0x015d`), CPU register A becomes
   `0xff`, but the capture CPU address `0x8000` remains `0x5a`, matching the
   physical VRAM bank. That CPU address is absent from `unknown_cpu_ranges`.
   The generic agent publishes it into the `ram` space as known. The descriptor
   documents physical projection, which preserves honesty about the experiment,
   but does not prove the plan's coherent CPU-memory requirement. Preserve
   physical bank observations while implementing a qualified CPU observer or
   marking restricted CPU windows unknown. IO and IE are already unknown.

   Reproducer code at `0x0150` (entry point jumps over the header):
   `3e 00 e0 40 3e 5a ea 00 80 3e 91 e0 40 fa 00 80 18 fb`.
   ROM length is 65536; header bytes `0x143=0x80` and
   `0x147..0x149 = 0x19,0x01,0x00`.

2. **`instructions` differs across backends.** mGBA increments the counter for
   an interrupt dispatch, and its existing interrupt test explicitly expects
   this. SameBoy increments from its opcode retirement callback. The shared
   trace exposes both as `Machine.Instructions`, without this distinction in
   machine-readable metadata. Count retired opcodes consistently or expose
   execution-boundary counts with explicit semantics. The mGBA handoff already
   acknowledges the difference; documentation alone does not remove ambiguity
   for trace consumers.

## Pinned implementation references for the fixes

In pinned `src/gb/memory.c`, `GBLoad8` (lines 246–345) uses
`gb->video.mode`: mode 3 blocks VRAM, and modes 2/3 block OAM. During
`gb->memory.dmaRemaining != 0`, the DMA source bus is selected with
`memory.dmaSource >> 13`. The CGB bus map in successive 8 KiB windows is
`MAIN, MAIN, MAIN, MAIN, VRAM, MAIN, RAM, CPU`. Accesses to the same bus are
blocked unless the DMA bus is CPU; DMA also blocks `0xfe00..0xfeff` regardless
of source. These static tables are private to the core. The adapter may copy
this pinned classification, or conservatively mark CPU memory below HRAM
unknown during DMA. Preserve all physical banks. Public internal fields are
`video.mode` (int), `memory.dmaRemaining` (int), and `memory.dmaSource`
(uint16_t). HDMA uses `gb->cpuBlocked` and `memory.hdmaRemaining`;
`GBProcessEvents` drains its scheduler until `cpuBlocked` clears.

In pinned `src/sm83/sm83.c`, `_SM83Step` dispatches an IRQ when
`executionState` is FETCH or HALT_BUG and `irqPending` is true. Both cases
clear the pending flag, install `_SM83InstructionIRQ`, and disable interrupts
instead of loading an opcode. Sampling `irqPending` before the adapter's
boundary function is insufficient for rigorous attribution: the patched
`SM83TickNoIdle` drains due events before `_SM83TickInternal`, and those events
may raise an IRQ. Record dispatch/opcode provenance after that pre-drain, at
the actual fetch decision. Keep the existing interrupt fixture and update its
instruction-count expectation; additionally test an interrupt that becomes
pending during the pre-fetch event drain.

Minimal lock regression: use the authored ROM above, step until the `LD A`
result is `0xff`, assert physical VRAM bank 0 remains `0x5a`, and assert the
CPU `0x8000` address is unknown while the returned captured mode is 3.
Assert that address becomes known again after the mode leaves 3. Similarly
seed OAM with LCD disabled, enable LCD, and check unknown status during
modes 2/3. Start OAM DMA from a copied HRAM routine to test DMA range coverage
without fetching opcodes from its blocked source bus. These latter OAM/DMA
checks are suggested tests, not executed evidence from this review.

## Checks without a new defect

- The 8,388,608 Hz timebase is correct for this pinned CGB configuration.
  Actual isolated stepping produced JP `+32`, normal NOP `+8`, LD A,immediate
  `+16`, LDH `+24`, speed-switch STOP `+16`, and double-speed NOP `+4` ticks.
  Pinned upstream `_GBCoreTimingFrequency` returns `CGB_SM83_FREQUENCY`, and
  `gm_ticks` uses `mTimingGlobalTime`. Add these delta assertions to retained
  tests; the current suite checks speed selection but not timebase ratios.
- Load failure closes its VFile only when the core has not taken ownership.
  Pinned `GBLoadROM` installs `gb->romVf` before mapping, and teardown closes
  installed files. No adapter double-close defect was found by source review;
  allocator and map failure injection were not executed.
- Python uses copied ABI fields, the actual native model is checked, and
  unsupported edits, watches, checkpoints and special step modes reject through
  descriptor capabilities. Current tests verify immutable capture and multiple
  bank identities.
- Pause writes an atomic flag, while normal native operations use the Session
  lock. Safety against concurrent close relies on Session's explicit owner
  lifecycle rule that close follows worker shutdown. This review did not qualify
  arbitrary close/pause races outside that rule or DMA/HDMA pause latency.
- Plain STOP intentionally cannot wake on input; broader device and STOP
  conformance remains necessary before claiming unrestricted CGB Basic Debugging.

Test invocation:

```sh
PYTHONPATH=debugger/python debugger/.venv12/bin/python -m unittest discover \
  -s debugger/tests -p test_mgba.py -v
```
