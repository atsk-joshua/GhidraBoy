# Experimental mGBA adapter handoff

Evidence date: 2026-09-06. This is a focused executable M8 engineering chunk, **not M8 PASS, Basic Debugging qualification, a default-backend change, or release acceptance**. Physical Steam Deck verification remains deferred by the user until other work is solid.

## Implemented boundary

`debugger/python/ghigbc/backends/mgba.py` implements the existing generic `Session` hooks and immutable snapshot protocol. No mGBA structure is mirrored in Python. The adapter ABI carries one opaque handle, copied fixed-width scalar arrays, and bounded copied memory/frame buffers. Generic agent, profile, mapping and session code need no engine handles. Only pause may cross the execution owner: it writes a C11 atomic flag. Native core calls, capture, input and teardown follow the existing Session lock/owner policy.

The explicitly accepted model is **CGB**, matching native `GB_MODEL_CGB`. `CGB-E`, DMG/SGB, BIOS images, non-CGB cartridges, non-MBC5 mappers and rumble variants are rejected. There is no claim that mGBA distinguishes CGB silicon revisions. ROM header types 0x19–0x1B are accepted; native model/mapper and exact loaded ROM size/content are checked after reset. Both Python and native own copies of the input, and native storage outlives the transferred VFile/core.

Implemented features: bounded run slices, execution-boundary step, urgent pause, register capture, CPU/ROM execution breakpoints, physical memory capture, semantic input, and normalized ARGB8888 frames. Breakpoint capacity is 256; range/ID validation occurs before native mutation. Continue skips the just-hit boundary once. Step ignores execution breakpoints; an interrupt dispatch counts as one execution boundary and stops before its vector opcode. Breakpoints do not trigger while HALTed or before a pending interrupt dispatch. Mapping generation is observed after every execution boundary, including changes that occur between captures.

The immutable capture includes all 8 WRAM banks, both VRAM banks, bounded actual SRAM, OAM and HRAM. CPU ROM/WRAM/VRAM/SRAM windows and WRAM echo are projected from these physical bytes; this is explicitly **physical observation, not a CPU access-lock/open-bus oracle**. IO 0xFF00–0xFF7F, IE, unusable 0xFEA0–0xFEFF, and disabled/unavailable SRAM are marked unknown. The unsafe full-address-space raw-read path is never used. VRAM uses the proven segmented observer rather than copying past the public block pointer's real allocation. Capture at a failed/partial execution boundary is rejected.

Unadvertised capabilities reject through the shared descriptor before writes: physical watches, register/WRAM edits, checkpoint/restore, step-over and step-out. In particular, generic schema-3 checkpoints remain available as an architecture hook but **this adapter does not yet advertise checkpoints**. The private diagnostic serialization used in tests rejects HALT_BUG before upstream `saveState`, which would otherwise execute another opcode. No coercion to FETCH is performed.

Plain STOP remains persistently stopped after the owner callback; subsequent step/run does not execute. There is no qualified STOP input-wake policy. Native instruction counts include interrupt dispatches and exclude idle HALT slices. A later checkpoint implementation must retain the wrapper STOP lifecycle, counters and all core/build/ROM/boot/config identity in the generic envelope, validate state length before loading, and independently qualify replay.

## Independent execution review

Reviewed the pinned native `SM83Tick`, `_SM83TickInternal`, `GBProcessEvents`, `GBHalt`, and the additive patch. The original `SM83Tick(false)` follows its existing two event drains and single native machine cycle. No opcode handlers, interrupt dispatch, device scheduler, clock multiplier or CPU layout change. The new function exits event drains on HALT; the adapter's idle path uses native `earlyExit` and native FETCH normalization. The primitive checks entry/boundary state and fails after eight machine cycles rather than manufacturing a coherent observation.

This does **not** make every native path wall-clock preemptible. `GBProcessEvents` still drains `cpuBlocked` device work before returning and synchronously executes native device callbacks. Adapter slices check a two-millisecond deadline and 10,000-boundary cap **between native calls**. HALT with IME and an enabled non-firing serial interrupt is now bounded in the tested cases. Arbitrary DMA/HDMA/device stalls and external callbacks need separate qualification; the adapter remains experimental.

Reran the execution experiment independently at `/private/tmp/ghidraboy-mgba-adapter-execution-review`: PASS, 998 serialized-state differential ordinary/CB opcode cases plus HALT, interrupt/wake, speed-switch/STOP and halted urgent-pause cases. `receipt.json` retains commands, source/patch/binary hashes and watchdog result. Production and probe primitive/patch copies are byte-equal and checked in the adapter suite; future consolidation must preserve the retained experiment receipt semantics.

## Build and tests

```sh
python3 debugger/scripts/build_mgba.py \
  --source /private/tmp/ghidraboy-integration-20260906/mgba-source \
  --work /private/tmp/ghidraboy-mgba-adapter-rebuild
PYTHONPATH=debugger/python python3 -m unittest discover \
  -s debugger/tests -p test_mgba.py -v
```

The builder rejects dirty/wrong-revision source, archives the exact pinned revision into a new work directory, checks/applies the patch there, and builds the GB-only static mGBA target into the selected shared adapter. It inherits the actual target's compile definitions and transitive link dependencies. SameBoy and its boot assets are not build inputs. Adapter warnings are errors; upstream warnings are retained in build logs. The output is `debugger/build/libghigbc_mgba.dylib` (macOS) or `.so` (Linux), with a mandatory adjacent `.json` receipt. Runtime verifies source revision, patch hash and binary hash; the descriptor configuration includes the receipt hash, covering native source hashes, build definitions and link command. This is component identity, not a whole-project acceptance receipt.

Twelve native Python integration tests cover:

- Immutable, nondestructive repeated capture/frame polling; actual CGB model and explicit unknown ranges.
- Coherent WRAM bank 3, both VRAM banks, SRAM bank 2 and CPU/echo projections against authored ROM operations, with before/after full serialization equality.
- HALT idle/instruction accounting, IME on/off serial-enabled urgent pause, deadline recovery, and mapping changes without intermediate captures.
- HALT_BUG diagnostic serialization rejection without PC/register mutation; interrupt dispatch ending before its vector opcode.
- Persistent plain STOP and a single-boundary CGB speed switch.
- Physical execution breakpoints at the same CPU address in teaching-fixture ROM banks 1 and 2; continue/step ordering, range rejection and unsupported capabilities.
- Semantic RIGHT/B input observed through actual native joypad reads, frame size/format, closed-handle behavior, altered build receipt rejection and primitive/patch identity.

The final executable suite ran in 0.083 seconds on macOS arm64 under a 30-second subprocess watchdog. Its component receipt and test log are `/private/tmp/ghidraboy-mgba-adapter-conformance/{receipt.json,tests.log}`; the final isolated build is `/private/tmp/ghidraboy-mgba-adapter-3/receipt.json`. Native binary SHA256 is `b0ac9a4a15fe61ccad0b42eac234006626c1e4bcd0929b397ea8d1e9d9d4d507`; adjacent build receipt SHA256 is `fa99d8e0fba175f0b2c73e775e1923d2e520c0b352a033a8448a89bc4e003e90`. Python compilation and whitespace checks also pass. No timed-out case is success. Native Linux build, shared backend conformance/Trace RMI publication, packaging/install independence, desktop display acceptance, broader mapper/model support and physical Steam Deck testing remain coordinator-owned follow-up gates.

## Packaging handoff

The selected runtime must carry `backends/mgba/native/patches/0001-sm83-no-idle.patch`, the native binary and its exact adjacent build receipt. Ship pinned mGBA licensing and the corresponding modified upstream source/patch as required by MPL-2.0, retaining upstream notices. New adapter/build/Python sources follow the repository license. Add `mgba` to the lazy backend factory and CLI backend choice with default model `CGB`; a shared explicit `--model CGB-E` must fail for this backend. Keep SameBoy selected by default until independent shared conformance and release gates pass.
