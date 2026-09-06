# Backend feasibility decisions

## mGBA: proceed with an embedded adapter

The pinned `685023e05d90d87050fb357f46f7bd2d907083f5` core passed the retained standalone probe for load, single-instruction stepping, registers, two physical ROM banks at the same CPU PC, WRAM write and same-value watches, save/restore, input, and timebase reporting. The probe is in `tools/backend_probes/`; its source pin, executable hash, commands and limitations are recorded in the work receipts.

Use the native core API through a small adapter. Inherit the exact CMake target compile definitions: this revision's generated flags header alone does not describe the final ABI layout. Keep all mGBA types and any necessary internal-header use inside that adapter.

Do not use a blind full-address-space `rawRead8` sweep for snapshot capture: the probe demonstrated serialized-state mutation. Physical block reads preserved state. Unavailable/computed device values must have explicit coverage until a safe observation method is implemented and tested. mGBA's input order must be translated to the shared semantic `Button` order. The probe's bounded synchronous control is not evidence for full asynchronous pause, crash handling, hardware-model coverage or M8 backend support.

## Emulicious: viable attachment transport, narrower proven observations

The exact official archive has SHA256 `6e1c6d511014033bbc2668360a0194389a5bad2bf6c5ffd0fe093b84da33c0fc`. The official adapter source was inspected at `172b0b88ae682badfb8b6b6e9b0c480946db2c65`. Its DAP connection runs over a local socket; no additional broker is needed for an eventual adapter.

The Linux probe connected, initialized, launched the synthetic ROM, observed an entry stop, read CPU registers and PPU/APU/cartridge/hardware scopes, stepped from PC 0x0100 to 0x0101, and received a new stop. Disconnect with `terminateDebuggee=false` preserved the process for the bounded post-disconnect observation; only subsequent cleanup of the probe-owned process terminated it. The cartridge scope exposed MBC5 and ROM bank 1; hardware scopes exposed VBK/SVBK and mode information.

The tested endpoint did not advertise standard DAP raw-memory reads, instruction breakpoints, data breakpoints or instruction-granularity support. The observed step is evidence for this fixture, not a universal instruction-step guarantee. ROM bytes loaded by the external engine were not independently fingerprinted through DAP. Coherent bulk memory capture and exact Program binding are therefore not established. Do not silently label these capabilities available or replace them with guesses from the input file.

The macOS attempts remain failed environment evidence: first-run update policy blocked startup, and after configuring an isolated fixed-version copy the JVM stalled in native audio initialization. The Linux run resolved the transport/control feasibility question without suppressing these failures. It used a virtual display and establishes no physical GUI acceptance.

## Shared boundary and remaining checks

The initial protocol in `ghigbc.backend` isolates selection, descriptor, timebase, capabilities, normalized capture access and frame/input methods. SameBoy supplies the first implementation. Captures retain immutable identity/precision metadata; legacy imports and trace fields remain compatible. Generic modules must never use native handles or interpret a backend's flattened ABI buffers.

The source now has useful evidence for both embedded and external execution patterns. Complete M1 still requires finishing the explicit probe/conformance inventory, including pause/timeout behavior and external capture consistency. The public adapter contract remains provisional while these checks and the generic session/recovery extraction proceed. A successful probe does not add an emulator to the supported-backend list.
