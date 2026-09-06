# Execution adapter contract — initial version 1

`ghigbc.backend` is a small Python protocol and immutable records. Importing it, the profile API, the agent or the display module does not import an emulator adapter or load its library. Backend selection is explicit through `create_backend`; the only installed implementation currently offered is SameBoy. Unknown names fail before reading ROM inputs. Native bindings and structure layouts remain private to the adapter.

An immutable descriptor identifies the core/configuration/patch, actual hardware model and cartridge operating mode, supported models/mappers, capabilities, observation precision and timebase. A snapshot retains the descriptor that applied when it was captured. Current SameBoy support is CGB-E, including DMG-cartridge compatibility mode; this does not establish native DMG hardware support.

The generic agent consumes `cpu_bytes`, `mutable_banks()`, `unknown_cpu_ranges`, named stop reasons, register/state observations and immutable event records. It never interprets the SameBoy ABI's flattened memory buffer. `ghigbc.native` remains an explicit compatibility import for existing SameBoy callers, including its native test surface and `Capture.memory`; that legacy representation is not part of the new snapshot protocol.

Physical region codes retain existing trace-schema-1 identities. Backends normalize their own region enums into this vocabulary. Event `origin_name` and `precision` describe actual observations; publication does not assign CPU provenance or instruction-final precision to every future backend. Unsupported/unobserved CPU ranges are marked unknown by the adapter's capture coverage.

Ticks have a declared frequency, or an explicitly unavailable timebase. Generic pacing uses that frequency rather than assuming an emulator clock. Traces add `Backend`, `BackendAPI`, `Model`, `HardwareMode`, `Capabilities`, `Ticks` and `TicksPerSecond`; existing paths and schema-1 fields remain readable. The old `Ticks8MHz` field is populated only for a matching timebase. These additive attributes do not change the native ABI or checkpoint payload version.

`Button` defines semantic input order: right, left, up, down, A, B, select, start. An adapter must translate this into its own engine's key order. `key_mask()` uses the same contract order. Frame buffers are immutable ARGB8888 data with explicit dimensions; the SDL presentation layer uses backend methods and owns its own SDL handles. Video and input require declared capabilities.

Execution is serialized by the existing session owner. Native adapter locks remain internal; pause must not wait behind a running execution slice. Close happens after the owner/display workers have stopped. Sequential late pause is harmless, and ordinary reads reject a closed backend. The contract does not authorize concurrent destruction while another caller uses the native machine.

Capabilities are checked before recoverable edits or unsupported step/input/video operations. The agent supplies the selected backend's profile capabilities to `ProfileSession`; a decoder requiring an unavailable capability is not instantiated. Existing profile API callers retain their legacy default capabilities for compatibility.

The current source extraction preserves SameBoy checkpoint schema 2, recoverable edits, command ordering, mapping barriers and profile bounds. Remaining M4 work includes the separate generic session/recovery implementation, completing the native source-directory boundary, broader backend conformance/failure injection and validating all display/focus paths. This initial protocol is not a claim that mGBA or external attachment is fully implemented.
