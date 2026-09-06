# Pinned mGBA bounded execution experiment

Evidence date: 2026-09-06. This follows the HALT blocker in [M1 conformance notes](m1-conformance-notes.md). The experiment demonstrates an adapter-local instruction boundary primitive using a small additive native patch. It is not a production adapter, hardware qualification, M8 PASS, or a release decision.

## Cause and implementation

In revision `685023e05d90d87050fb357f46f7bd2d907083f5`, `_GBCoreStep` repeatedly calls `SM83Tick` until `SM83_CORE_FETCH`. `SM83Tick` drains events both before and after a machine cycle. A halted CPU can remain at the next event indefinitely, so that drain never returns. Independently, `GBProcessEvents` can fast-forward while HALTed with IME and IE enabled until an interrupt occurs; an enabled serial interrupt without a transfer need never occur. Checking an atomic flag around `core->step` cannot interrupt either loop.

The experiment consists of [execution.c](../../tools/backend_probes/mgba_execution/execution.c) and [sm83-no-idle.patch](../../tools/backend_probes/mgba_execution/sm83-no-idle.patch). The patch factors the existing `SM83Tick` body into a shared function and adds `SM83TickNoIdle`, whose event drains stop when the CPU is halted. The existing exported `SM83Tick` follows its original path. No instruction table, interrupt dispatch, HALT handler, STOP handler, event scheduler, clock multiplier, or CPU structure layout changes.

The adapter-local primitive calls the new native entry point through one instruction or interrupt dispatch. When halted, it calls the existing native event handler with `GB.earlyExit=true`; this already-supported owner-thread flag bounds halted fast-forward and is consumed/reset by `GBProcessEvents`. The native handler aligns the halted CPU to FETCH. Subsequent halted calls report `GB_PROBE_IDLE`, advancing native device events without claiming an executed instruction. A due event immediately after restore can consume one idle call without advancing time. Instruction execution resumes only on a later call after the native interrupt handler wakes the CPU.

`SM83_CORE_HALT_BUG` is also a boundary: the HALT instruction has completed and the next opcode must fetch without incrementing PC. The public step loop passes through this boundary and consumes that next instruction; the experiment returns before it. A defensive eight-machine-cycle cap reports `GB_PROBE_FAULT` for an unsupported pipeline, without pretending the partial state is a coherent boundary. The owner must reset or fail the session after that fault.

## Verified cases

| Case | Assertion |
| --- | --- |
| Ordinary instructions | 998 full serialized-state comparisons against the original `core->step` path: 243 base opcodes and all 256 CB opcodes, each with flags `0x00` and `0xF0`. This includes both outcomes of conditional branches/calls/returns and memory instructions. HALT, STOP and 11 illegal opcodes are excluded from this differential matrix. |
| HALT, no enabled interrupt | HALT ends at the following PC before `INC B`; 1,000 idle slices preserve PC/registers and advance native devices. |
| HALT, IE set, no pending interrupt | With only serial IRQ enabled and no transfer, 1,000 idle calls each return for IME off and on; CPU remains halted. |
| HALT wake | Setting native IF through the bus wakes the CPU. IME off executes exactly the next instruction; IME on performs exactly the serial interrupt dispatch, saves the post-HALT PC, and stops before the vector opcode. |
| Pending interrupt before HALT | IME off produces the native HALT-bug boundary and the subsequent repeated fetch; IME on dispatches VBlank before HALT is fetched and saves the pre-HALT PC. |
| Halted capture/restore | Public save at the normalized FETCH boundary is nondestructive; the serialized state restores and continues servicing halted events. |
| CGB STOP | Two-byte STOP switches normal → double → normal speed through the unmodified native handler. A following ordinary instruction executes once at double speed. Plain STOP emits exactly one native control callback and returns before the next opcode. |
| Urgent pause while halted | A separate thread writes only the C11 atomic request flag. The owner services halted idle slices with IME and serial IE set, acknowledges before its one-second deadline, and retains the halted PC/register boundary. Measured acknowledgment latency: 0.001 ms in the retained run. |

The test places self-authored instruction sequences in WRAM of the loaded teaching fixture. It changes internal register/IME values only to arrange test preconditions; production must not expose those structs through its ABI. The native STOP control callbacks assert owner-thread execution. The complete probe ran in 0.289 seconds under a 30-second subprocess watchdog; compiler warnings are errors for experiment code.

## Reproduction and identities

```sh
python3 tools/backend_probes/mgba_execution/run.py \
  --source /private/tmp/ghidraboy-integration-20260906/mgba-source \
  --rom /Users/joshuahansen/dev/GhiGBC/build/teaching.gbc \
  --work /private/tmp/ghidraboy-mgba-execution-recheck
```

The runner rejects a different revision or dirty source, archives the pinned checkout into a new work directory, checks/applies the patch to that private copy, and builds GB-only through CMake. The original checkout remains unmodified. The probe inherits the actual mGBA target's compile definitions and link dependencies. The receipt includes every command, compiler/link flags, elapsed time, source and log hashes, and output. A timeout fails the experiment; no timeout is counted as capability success.

| Artifact | SHA256 |
| --- | --- |
| `/private/tmp/ghidraboy-mgba-execution-2/receipt.json` | `9ce0b20f2f3b353e75b185c90c9f8e35fc99964caa49cd5fca24c39c8bbeaa76` |
| `/private/tmp/ghidraboy-mgba-execution-2/build/mgba-execution-probe` | `3e72f3dce253c5962e1fa20e50db35f7fa33be1aa354e4f9046aea261d5f5bdb` |
| `sm83-no-idle.patch` | `bc873a1d5886b070dc8638eb1b6d51b9a7e316a678ba75d8e3d4593a881a2eba` |
| Pinned source archive | `a59017f0dee15f8f9067c5f0638707f81487de595274f6b9e5a3e88f2bb517e9` |
| Fixture ROM | `ee2d9eaa2523526d6f8f254873d0d4c1f7ee999d793985ad6b13e3585a7561b3` |

Host: macOS 26.5.2 arm64; CGB engine post-boot state, no BIOS. These are component identities, not a whole-repository receipt. The patch changes MPL-2.0 upstream files and must retain their license obligations when shipped; adapter experiment sources are MIT.

## Limits and production handoff

- **Checkpoint at HALT_BUG remains unsupported.** Upstream `GBDeserialize` rejects every execution state other than FETCH. Calling public `saveState` at HALT_BUG silently executes the next instruction before serializing. A production wrapper must reject checkpoint capture at this boundary before calling that API, or separately implement and qualify exact HALT-bug serialization. Do not coerce the execution state to FETCH.
- **Plain STOP requires owner control.** The native handler signals sleep/shutdown; it does not create a persistent CPU halted flag. The production owner must stop the run loop in response to that callback. This probe verifies callback delivery, not a complete STOP lifecycle or input wake policy.
- `GB_PROBE_EXECUTED` includes an interrupt dispatch. It is an execution-boundary count, not an exact count of fetched opcodes. Step reason, instruction accounting, debugger hooks, watchpoint completion, breakpoint ordering, and event priority need production integration tests.
- The experiment does not qualify DMA/HDMA stalls, arbitrary peripheral callbacks, DMG/SGB, additional mappers, illegal opcodes, boot ROM execution, hardware timing conformance, live debugger attachment, physical capture, or native crash containment. Native calls still run to completion; the result establishes bounded HALT behavior in these cases, not a hard wall-clock guarantee for every native path.
- Production packaging must identify the original source revision, this patch, build flags, core binary and configuration. The additive API uses internal headers and belongs inside the opaque native adapter. No Python type should mirror `GB` or `SM83Core`.
- Complete independent patch review, implement coherent physical capture and production owner/control integration, then run shared backend and Trace RMI conformance before changing the Basic Debugging gate.

## Consolidated production primitive

After byte-equivalent production/probe checks passed, the probe runner was updated
to compile `debugger/backends/mgba/native/execution.c` and consume its canonical
header/patch directly. The duplicate experimental copies were removed before any
release. Historical receipts retain the original hashes; current receipts include
`executionSources`. Source and packaged adapter checks now verify the same native
inputs against their build receipt.
