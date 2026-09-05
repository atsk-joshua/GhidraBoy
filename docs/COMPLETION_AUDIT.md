# Completion audit — 2026-09-05

The original target remains a working student session on Steam Deck desktop mode, Linux x86-64, Ghidra 12.1.2. The implementation and evidence below are on macOS 26.5.2 arm64. The Linux candidate is cross-built and ABI-inspected, not executed on the Deck. The full goal is not complete. SSH host/user and the target installation path have been requested; no target execution evidence has been supplied.

## Handoff acceptance matrix

| ID | Current evidence | Scope / remaining gate |
|---|---|---|
| T01–T02 | RealTraceTest and UiActionTest: bank1/bank2 CPU4029, distinct physical bytes, renamed static block, inactive-bank breakpoint via registered UI action | Verified on Mac; target run required |
| T03–T04 | Native tests and real trace event: WRAM3/4 D034 filtering, arbitrary DirectWriter, original writer PC and physical target | Verified on Mac |
| T05–T06 | Native same-value/change and blocked-VRAM tests; repeated inspector reads preserve full native save state | CPU access and final-byte scope; no DMA watch claim |
| T07 | Real trace register API: AF12B0, BC3456, DE789A, HLBCDE, PC4567, SPCFFE and aliases | Version-matched Ghidra client; Mac evidence |
| T08 | Native ordinary/CB, interrupt, HALT/STOP, conditional CALL/RST and resume bypass tests | Ordinary over/out; GBW3 far-call over/out explicitly unavailable |
| T09 | Real native edge tests: MBC5 bank256, MBC1 ROM0 bank32, SVBK zero, echo and boot identity | Declared ROM-only/MBC1/MBC3/MBC5 scope; RTC-selected bytes unknown |
| T10–T11 | Independent reopened trace checks, old bytes/mappings, captured writer UI selects old snapshot and static address | Exact MappingSnapshot marker prevents inherited readiness |
| T12 | Restored epochs/re-armed breakpoints, parent checkpoint path/state SHA/source metadata, immutable captured parent, independent reopen | Native25 tests and checkpoint-parent-ghidra.log pass |
| T13 | Real launcher, live breakpoint edits, pause/resume, structured termination, disconnect/default pause, actual SDL close and process checks | Mac tests; no target process lifecycle claim |
| T14 | Real remote register/physical-WRAM edits, invalid/running rejection, debugger-origin provenance, full recovery and historical values | Only explicit paused experiment mode; original assets are not edit targets |
| T15 | Exact SHA256 profile gate and writer opcode; generic-ROM event description receives no HP label | Supplied ROM fingerprint only; no unverified new profile |
| T16 | Existing writer label appears in panel; additive bookmark preserves prior text; versioned knowledge export retains symbols/functions/structures/comments | Supplied structures are cartridge headers, with no conflicting live-unit structure supplied; profile does not consume arbitrary user-defined layouts |
| T17 | CLASS2 APC HP10→3, writer rom18::40b5 LD(HL),B, restore/repeat, independent reopen with all100 unit records | Actual map battle on Mac; caller unknown, not inferred |
| T18 | Real SDL play, paused input, seeded held-key release on minimize, integrated close; actual HP button and full cleanup pass | Steam Deck desktop/held-key/clean installation gate still blocked on access |

The event pane now shows epoch and selected-event target/field, CPU addresses, origin, attempted value and precision. Rendering and registered writer/bookmark controls were exercised through CUA; the passing observer log is `ui-actions.log`. Actual HP selection/command/cleanup is independently recorded in `hp-ui.log` and `hp-ui-result.json`. The battle text checks use the original event snapshots in `study-battle-details.log`.

## Architecture, artifacts and contracts

- SameBoy1.0.3 commit, CPU provenance patch, Ghidra12.1.2, GhidraBoy compatibility patch, RGBDS and Gradle inputs are recorded in `dependencies.lock.json`; third-party notices are in `LICENSES/`.
- Native C owns opaque SameBoy state, bounded execution/access storage and copied captures. Python uses a 64-entry owner command queue and one ordered writer; native access storage is64 entries with dropped-count reporting. These bounds are code contracts, not a saturated transport benchmark.
- Matched Trace RMI interfaces and methods expose one process/thread, actual registers/PC, CPU and physical memory, breakpoint/watch controls, checkpoints and explicit edits. Caller/stack reconstruction beyond the observed frame is not invented.
- ROM/boot bytes are loaded from fingerprinted immutable copies. Captures and debugger edits are immutable; edits retain recovery state. Restore source metadata survives later restores and trace reopening.
- `scripts/bootstrap.py`, build scripts, `prepare_runtime.py`, `install.py`, `doctor.py` and rollback are present. Complete versioned runtime install/rollback and copied-runtime launcher were tested. The current installed paths are in `INSTALLATION.json`.
- Doctor checks the selected Ghidra/client, Java, one SM83 definition, native loading, loopback and SDL2 loading/version. `ready_for_desktop_validation` means prerequisites, not proof of rendering/input on a target.
- Source and Linux candidate tarballs, matched extension ZIPs, teaching ROM/symbols and SHA256 sums are under `dist/`. Package checks exclude commercial ROMs, GZF, checkpoints and battery saves. The teaching ROM is built from checked-in assembly.
- QUICKSTART explains installation, launcher, copied GZF export/hash, actual unit selection, HP watch, writer navigation, read-only historical Trace mode, restore/repeat, explicit edits and rollback. STEAM_DECK supplies the next runnable target commands.

## Measured limits

`integrated-growth.json` records250 sequential real Trace RMI stop captures in12.406s after warmup. Agent RSS rose43456→43472KiB (16KiB); Ghidra RSS934592→1112912KiB (178320KiB); saved trace3391488→4587520 bytes (1196032 bytes). Dropped count stayed0. Saved history intentionally grows; this is not a long-duration leak or request-saturation proof.

That run's warm20-sample remote step p95 was37.625ms; pause269.863ms including test settling. Earlier real SDL play measured120.000s wall /119.999s emulated. These meet the stated initial latency targets on the named Mac, not the Deck. Full target measurements remain required.

The first growth attempt failed an immediate restored-register read. Its log is preserved. The observer now explicitly waits for a new completed capture after restore; the rerun completed all assertions and the measurement. Earlier UI/host/cleanup failures are retained under prior/failure names; they are not substituted for final pass evidence.

## Target continuation

From the extracted Linux candidate in a Steam Deck desktop terminal, set the actual Ghidra12.1.2 path and Java21 home, then run `python3 scripts/prepare_runtime.py`, `scripts/test_native.sh`, `scripts/test_ghidra.sh --growth`, and `bash scripts/test_ui_actions.sh`. Run doctor and the playable-window/focus steps from STEAM_DECK, then install with `python3 scripts/install.py`. Retain target logs and version/architecture output. The commercial walkthrough uses a local project copy and matching exported ROM; private assets are not included in the bundle.

Until those target checks run, do not claim that the student is up and running on his Steam Deck.
