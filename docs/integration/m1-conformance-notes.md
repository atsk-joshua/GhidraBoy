# M1 conformance inventory and adapter handoff

Evidence date: 2026-09-06. This inventory extends [backend decisions](backend-decisions.md). It records feasibility checks and limitations; it does not qualify M8 or add a supported backend.

**Decision:** continue engineering an embedded mGBA adapter, but do not freeze its instruction/pause implementation or approve Basic Debugging yet. The public instruction-step call stalls at the fixture's HALT. Owner-thread cancellation works during ordinary instructions but cannot interrupt that native call. This is an observed blocker, not a hypothetical crash concern. Emulicious remains attachment feasibility only; its tested interface cannot establish our required coherent memory or exact loaded-ROM identity.

## Retained evidence

The unmodified mGBA source is `/private/tmp/ghidraboy-integration-20260906/mgba-source`, revision `685023e05d90d87050fb357f46f7bd2d907083f5`. The fixture is the self-authored `GhiGBC/build/teaching.gbc`, SHA256 `ee2d9eaa2523526d6f8f254873d0d4c1f7ee999d793985ad6b13e3585a7561b3`. The host is native macOS 26.5.2 arm64; configuration selects CGB, engine post-boot state, no BIOS. No upstream modifications were made.

| Receipt | SHA256 | Result and scope |
| --- | --- | --- |
| `/private/tmp/ghidraboy-integration-20260906/mgba-conformance-1/receipt.json` | `a37ec4a5eada7b340e3317249820ffb295d0112a065f62b51fe33cbd99d35231` | FAIL: original extended instruction loop timed out at 30 seconds; retained as discovery evidence. |
| `/private/tmp/ghidraboy-integration-20260906/mgba-conformance-4/receipt.json` | `ddb0ba1d02bf663c8abb31f3560ad4d6e4c82b8bc70fdd6c2618add23f4fb0e9` | Normal-run assertions PASS; isolated HALT step TIMED_OUT at 2 seconds, HALT run-loop RETURNED. Watchdog owns and reaps the probe process. |
| `/private/tmp/ghidraboy-integration-20260906/m1-transport-conformance/receipt.json` | `facd5af4d75c913dd898ac50e25f80b8f6f28bdbaae7947245f51b905a448e81` | Seven local DAP transport tests PASS under Python 3.9.6. These are socket-pair tests, not a new live emulator run. |
| `/private/tmp/ghidraboy-integration-linux-20260906/emulicious-results/probe-verified-step/receipt.json` | `0fd789b3f8402e817b63b380e3b6be94b8dc0350f749f0b29a9b307def793c45` | Earlier live Linux attachment/control PASS. This source update did not rerun the live emulator. |

The final mGBA executable SHA256 is `98c3185b81969b1c74f8245fbd728f387c535b5f5a0fb508096666a2b6da136d`. Its receipt records exact probe source hashes, commands, compiler flags, link command, log hashes and elapsed durations. Probe-2 evidence is also retained; probe-3 adds VRAM access, transferred file ownership and shutdown assertions; probe-4 prints the HALT limitations explicitly in the command result. These are component snapshots, not whole-repository identities.

Reproduce with a new work directory:

```sh
python3 tools/backend_probes/run_mgba.py \
  --source /private/tmp/ghidraboy-integration-20260906/mgba-source \
  --rom /Users/joshuahansen/dev/GhidraBoy/debugger/build/teaching.gbc \
  --work /private/tmp/ghidraboy-m1-recheck
python3 -m unittest discover -s tools/backend_probes -p 'test_*.py' -v
```

The runner's overall PASS means the feasibility probe completed and recorded its cases. Always inspect `haltCases` and `limitations`; an expected watchdog timeout does **not** pass the corresponding capability.

## Executed mGBA operations

| Requirement | Observation | Consequence |
| --- | --- | --- |
| Exact owned input/load | Physical ROM block matches every input byte and length; two physical ROM banks differ at the same CPU address. | Hash the immutable bytes actually handed to the core and verify loaded block identity. |
| Instruction step/registers | PC 0x0100 → 0x0101; bank-2 instruction effect and register edit verified. | Ordinary-instruction feasibility passes; this does not cover HALT/STOP/interrupt semantics. |
| Physical breakpoints/watches | Stops at CPU 0x4029 in banks 1 and 2; bank-3 WRAM write at 0xD034 and same-value write both observed. | Public debugger hooks are usable; do not generalize writer/DMA/blocked-access precision beyond the events tested. |
| Owner/callback ordering | Every entered callback runs on the owner thread; custom callbacks match executed ordinary-instruction count. | Keep native execution, register access, capture and edits on one owner. |
| Urgent pause while executing | A separate thread writes only a C11 atomic flag. Owner acknowledges at the next ordinary-instruction boundary; measured 0.028 ms in probe-4. | Viable cross-thread signal during nonhalting execution; this is one measurement, not a latency qualification. |
| Deadline and recovery | Owner stops a JR loop after 20.116 ms, remains paused, and subsequently executes one instruction. | Deadlines belong to the adapter/session. `mDebuggerRunTimeout` does not provide an execution deadline. |
| HALT/native stall | At fixture PC 0x456D, `core->step` does not return within 2 seconds. `core->runLoop` returns at PC 0x456D on the first call. | A returning run-loop is not proof of one-instruction execution. Resolve HALT-safe stepping before Basic Debugging. |
| Paused/shutdown behavior | Polling a paused or shutdown debugger preserves complete serialized state. | Do not execute merely to service paused transport/display work. |
| Safe physical observation | Complete physical block reads and both VRAM bank reads preserve serialized state. Full 64 KiB `rawRead8` inspection changes it. | Whitelist proven safe regions; represent other addresses as unavailable. |
| Public block coverage | CGB VRAM block advertises 32,768 bytes but accessor returns 8,192; IO entry returns no pointer. WRAM accessor returns 32,768; ROM 65,536; OAM 160; HRAM 127. | Validate actual sizes. Never copy the advertised VRAM size from the returned pointer. Physical `rawRead8` segments 0/1 distinguish CGB VRAM banks and a full 16 KiB segmented read is nondestructive in this fixture. |
| State/error behavior | Unknown register read/write and invalid state magic are rejected without changing serialized state. A 32-instruction restore/replay reproduces the complete serialization. | Wrapper must enforce state length and identity before calling `loadState`, which has no length argument. Replay result covers this controlled fixture only. |
| Ownership/close | Successful load transfers its `VFile`; normal core destruction closes it exactly once. Borrowed ROM bytes outlive core destruction. | Keep the backing buffer until close. Match teardown to the actual load path; failed-load ownership requires separate tests. |
| Input/timebase | Native key-mask roundtrip and positive frequency/timing frequency pass (8,388,608 Hz). | Translate shared RIGHT/LEFT/UP/DOWN/A/B/SELECT/START to native bit order A/B/SELECT/START/RIGHT/LEFT/UP/DOWN. Do not infer instruction-cycle units from host time. |

The pinned implementation references are `src/debugger/debugger.c` (`mDebuggerRunTimeout`, `mDebuggerUpdatePaused`), `src/gb/core.c` (`_GBCoreStep`, `_GBGetMemoryBlock`), `src/sm83/sm83.c` (`SM83Tick`, `SM83Run`), `src/gb/gb.c` (`GBProcessEvents`, `GBHalt`, load/unload ownership), and `src/gb/serialize.c` (`GBDeserialize`). The last function only warns on a differing ROM CRC; it is not our checkpoint identity validator.

## External attachment and provisional contract

The retained live Emulicious receipt identifies JAR SHA256 `db185a1ed0af3bdab5ebdeb254612d02d3848bac155dbc89333d1b04e21c371d`; the official archive SHA256 is `6e1c6d511014033bbc2668360a0194389a5bad2bf6c5ffd0fe093b84da33c0fc`, with inspected adapter source revision `172b0b88ae682badfb8b6b6e9b0c480946db2c65`.

Its local DAP connection observed entry/step stops, registers, bank-related hardware scopes and PC 0x0100 → 0x0101. Disconnect with `terminateDebuggee=false` preserved the emulator during the 0.5-second observation. Cleanup then terminated only the process created by the probe. Standard raw-memory reads, instruction breakpoints, data breakpoints and stepping granularity were explicitly unadvertised. Support for conditional/function breakpoints or step-back in the capability response is advertisement, not newly tested parity.

The transport now uses one absolute response/event deadline across fragmented headers and bodies, bounded headers/bodies, preserved interleaved events/replies and explicit EOF/error reporting. The seven tests cover these properties, event cursors, malformed/excessive bodies and a slow peer that cannot continually renew the deadline. After a framing error, EOF or timeout, treat that connection as failed and reconnect with a new `Dap`; these tests do not establish emulator-side cancellation or state recovery.

An external observation may expose stopped registers/scopes with `ticks_per_second=None`, explicit limited coverage and no physical-capture feature. No native type is needed in the generic descriptor or snapshot. However, successive DAP scope requests do not establish an atomic register/memory capture, loaded-ROM fingerprint or protection from another external controller. A future adapter must reject Basic Debugging/Program binding where these requirements are absent. The current `create_backend` rejects Emulicious entirely; no success-shaped snapshot or guessed ROM bytes were added. Shared `BackendDescriptor.require`, `UnsupportedFeature`, `unknown_cpu_ranges` and descriptor coverage can express narrower capability results without exposing either engine's internal types. Actual external capture consistency remains unestablished.

## Smallest production implementation

1. Add one `debugger/backends/mgba/native` adapter owning an opaque handle, `mCore`, debugger/module, copied ROM bytes, bounded event storage, output frame and C11 pause flag. Python sees fixed-width copied values/bytes through that adapter ABI; it never mirrors `mCore` or mGBA structs.
2. Build the pinned GB-only core through CMake (`LIBMGBA_ONLY`, `M_CORE_GB`, `ENABLE_DEBUGGERS`; disable GBA, GDB and scripting). Include source and generated headers, inherit **the actual `mgba` target's `COMPILE_DEFINITIONS`**, and link its target dependencies. In this run they include `ENABLE_DIRECTORIES`, `ENABLE_VFS`, `BUILD_STATIC`, `USE_PTHREADS`, Foundation and libm. The generated `flags.h` alone is insufficient. Do not hardcode this host's full flag list into a portable build.
3. First resolve and regress the HALT instruction primitive. Cover HALT with/without interrupts, STOP/speed switch, ordinary and conditional instructions, pending interrupts and pause while halted. An owner flag around `core->step` is demonstrably insufficient. A reviewed minimal native/core change with its own pinned patch identity is preferable to inventing instruction semantics in Python. Keep any internal-header implementation local to this adapter.
4. Implement the existing `Backend` methods and reuse `Session` ownership, epochs, history, mapping/profile helpers and checkpoint envelope. `pause` only signals atomically; `run_slice` owns execution and honors a short deadline; capture copies all supported banks/registers at a stopped boundary. Validate capture coverage and mapping generation. Keep IO/computed values unavailable until a safe implementation is tested.
5. Start with the proven CGB/MBC5/post-boot fixture configuration and a truthful capability inventory. Reject unsupported models, mappers, over/out, physical-watch precision, edits and checkpoint combinations until their independent tests pass. The existing feasibility probes do not justify advertising all upstream hardware support.
6. Enforce full ROM/boot/core/build/patch/config identity and payload length before checkpoint restore. Normalize frames and semantic input bits; release held input on focus loss. Build/install only this selected runtime without depending on SameBoy's library or assets, then run the unchanged shared conformance/Trace RMI suites.

## Gate disposition for the coordinator

- `SPIKE-01`: expanded executable inventory and exact receipts now exist; missing semantics and the HALT failure are explicit. No upstream patch has been validated.
- `SPIKE-02`: embedding remains the selected engineering direction: direct identity and physical-bank observations are attainable, but HALT-safe pause needs implementation work. DAP has process/lifecycle advantages with a narrower proven observation boundary.
- `SPIKE-03`: descriptor/coverage/error boundaries can represent both probe outcomes without leaking native types. External coherent capture remains unavailable, not passed.
- `SPIKE-04`: **no-go for declaring mGBA Basic Debugging qualified at this snapshot**; conditional go for the adapter engineering above. The next concrete blocker is bounded HALT-safe instruction execution, followed by production coherent CPU memory capture and shared conformance.

Do not convert this inventory into blanket M1, M8 or release PASS. Physical desktop/Steam Deck acceptance and whole-project qualification are separate gates.
