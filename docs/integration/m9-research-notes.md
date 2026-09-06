# M9 captured-observation tools

Implemented 2026-09-06 as a bounded source-level research/history slice. This is not a completed M9 gate or release receipt. All reads use the selected Ghidra trace snapshot; no emulator handle, optional game profile, second database, or replay engine is introduced. `GbcActionService` remains compatible.

## Operations

Open **GBC History** with a captured GB/GBC trace. The header identifies the selected captured snapshot, session, epoch, backend, hardware model, and captured running/stopped state. This state describes the observation; it does not assert the target is currently live.

- Filter history with plain literal terms, or exact qualifiers: `region:wram bank:1 offset:0x23 epoch:2 access:write`. Qualifiers also support read/execute/unknown access and other physical regions. The bank qualifier compares the physical bank number, so bank 1 cannot accidentally match bank 10. Invalid filters retain usable controls and show an error. Writer/bookmark actions translate sorted/filtered row indices back to the correct observed event.
- Select the snapshot in Ghidra's Time view, then choose a physical capture range (region, bank, offset, length). **Pin capture** freezes that observation. Change the selected snapshot and use **Compare capture** to compare the same physical range. Comparison identifies both session/epoch/capture contexts, register changes, known-byte changes, bytes that cannot be compared, and differing/unavailable ROM/backend/core/config/model/mode/timebase/capability/coverage/static-mapping settings. It does not compare engine instruction counts as equivalent time.
- **Export capture** saves the selected snapshot/range to a versioned JSON observation. **Reopen observation** validates it, shows a human-readable summary plus complete machine-readable evidence, and pins it for comparison. Reopen requires no running trace, emulator, or profile. It uses the existing Ghidra Java libraries, rather than introducing a separate standalone application. The JSON itself remains readable with ordinary JSON tools.
- Capture commands act on the snapshot shown in the header, not on an older access-event row. An event row's writer/bookmark navigation continues to use that event's observed snapshot. The export includes only access events observed at its selected snapshot; the broader history table retains prior captured events.
- File choosers and cancellation use Swing controls. Capture/export/read work runs off the UI thread; capture loops check interruption. File output replaces the destination only after a complete temporary file is ready. Closing a chooser cancels that choice; **Cancel** interrupts active report work. Keyboard focus labels and report-button mnemonics are supplied; the report-control row can scroll horizontally on small displays.

## Observation contract and limits

Format `ghidraboy-observation`, version 1. An envelope stores a canonical SHA-256 of its observation body. This detects payload corruption or accidental modification; it does not authenticate the author. The reader rejects unsupported versions, payload-hash mismatches, malformed/duplicate/deep/trailing JSON, oversized input, invalid coordinate/length relationships, and fabricated values for UNKNOWN/ERROR bytes. A caller binding an observation to a particular ROM can supply its expected SHA-256; mismatches are rejected. Portable UI reopen deliberately does not bind to whichever Program happens to be open. The displayed source references are explicitly unverified against the current Program, and a subsequent comparison exposes differing ROM hashes/settings.

Each exported observation contains:

- Trace name/path, exact snapshot and captured session/epoch/capture identifiers where recorded. Missing historical metadata stays null.
- ROM SHA-256, backend/core/config/model/mode, time units and optional tick/instruction/execution-boundary counts, capabilities, coverage/memory semantics, selected-bank state, mapper/boot state, and captured checkpoint-parent provenance.
- At most 4096 bytes from one physical region/bank/range, individual trace memory states, and explicit null bytes for unknown/error/unavailable memory. Captured CPU-space lockouts therefore cannot leak underlying raw bytes into a claim about CPU-visible values.
- Persisted static mapping references for each byte: Program URL, static mapping start plus exact displacement, and an explicit current-binding-unverified label. Captured static mapping generation/envelope and mapping issues remain visible. The report does not silently resolve an old mapping against a newly edited Program.
- Captured register values and up to 1000 access events observed at that snapshot, preserving target/writer coordinates, access/origin/precision, validity, and raw before/after/attempt fields. Truncation is explicit. An access event is not proof of a call stack or a causal formula.
- Separate hypotheses (empty for native exports), explicit unknown experiment steps/recorded inputs/boot hash, and a replay-unavailable declaration. Boot/input hashes are not presently persisted by this trace publication path, so the exporter does not invent them. The portable format contains no emulator state payload.

Input files are limited to 4 MiB, nesting to 24 levels and individual arrays to 16384 elements. These limits are independent of unbounded trace history. An observation export is not a checkpoint, reverse-execution recording, controlled experiment recipe, or portable state conversion. Matched settings alone do not prove deterministic reproduction.

## Executable evidence

Run from the GhidraBoy root after building the static provider artifact and self-authored fixture:

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
GHIDRA_INSTALL_DIR=/tmp/ghidraboy-switch-recovery2-mac-final/distribution \
bash debugger/scripts/test_observation_report.sh
```

The runner compiles all current generic extension Java sources and the focused harness, creates a real DBTrace using the real imported synthetic ROM and static mappings, and executes a separate Java process to reopen the resulting JSON without a trace/emulator/profile. It does not modify installed extensions or frozen qualification artifacts.

Latest recorded execution: exit 0, **32 checks passed**, `OBSERVATION_REPORT_TEST_PASSED` and `OBSERVATION_STANDALONE_REOPEN_PASSED`. The harness covers exact filtering, old-snapshot preservation, event selection, static source references, memory-state fidelity, optional instruction counts, setting differences, roundtrip identity, invalid input, limits, and capture cancellation. Three existing Ghidra `AutoImporter`/`LoadResults` deprecation warnings are retained; no compiler errors occurred. The normal Gradle attempt initially encountered sandbox socket denial, so this source compilation used direct javac over the same current generic Java source files rather than claiming a successful Gradle build.

| Input/evidence | SHA-256 |
| --- | --- |
| `debugger/ghidra-extension/src/main/java/ghigbc/ObservationReport.java` | `e533a85c4c54a424492698486695784dea4dacd6835f87b1eadd9d1cf9b146eb` |
| `debugger/ghidra-extension/src/main/java/ghigbc/HistoryFilter.java` | `3ccf518b3d5ceaec68c7663a485fd69aeb6c95dc95d1767d879186b37c6c009a` |
| `debugger/ghidra-extension/src/main/java/ghigbc/StudyProvider.java` | `5fbfde89162ac7452e1cb18f0e078844e0cb12da3e219574281a9e7c5632f56d` |
| `debugger/tests/ghidra/ObservationReportTest.java` | `216f1accf31b9b9b91fbbc73c079ed58bb02ca630c8cc26d9e7b3f8279e3d7f8` |
| `debugger/scripts/test_observation_report.sh` | `470881396691822bcb4a05938fe4574971a0e838c8cc8be6d36c8e251d0692b6` |
| `debugger/build/observation-report-test.log` | `8011cf512f9f08b2ac47b848bdf3412c1531ac48958082d3ca35937c309867be` |

## Remaining qualification

This slice supplies executable prerequisites for history filtering/comparison and portable observation reopen. It does not close TOOL-01/02/03, RESEARCH-01/02, or UI-01. Remaining work includes fresh installed listing/decompiler/breakpoint/watch/navigation operations on both backends; GUI selection/coherence through reconnect/Program switching; real keyboard, scaling, chooser, cancellation and malformed-file interaction; a documented experiment whose conclusion traces to these byte/source references; and controlled restore/repeat reproduction with recorded inputs/clock conditions and explicit backend capability differences. Physical Steam Deck verification is deferred by the user until the other work is solid.
