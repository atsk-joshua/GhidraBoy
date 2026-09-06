# Integration compatibility inventory

This inventory applies to the GhiGBC → GhidraBoy migration, not the earlier suite integration. The source anchor and per-file dispositions are in `ghigbc-import.json`; execution state is in `status.json`. Preserve the interfaces below during Release A. New backend metadata is additive unless a separate migration gate proves otherwise.

| Surface | Current producer / consumer | Preservation and verification |
| --- | --- | --- |
| SM83 language | GhidraBoy `data/languages`; saved Programs and trace registers | Exactly one provider, unchanged language/register/context IDs; old saved instructions versus fresh decoding across 501 valid base/CB encodings |
| Compiler specifications | GhidraBoy and saved per-function ABI choices | Keep existing compiler/prototype IDs, explicit storage and native call-effect fixtures; do not infer conventions from games |
| `GhidraBoy` extension | Root Gradle archive, Ghidra extension loader | Retain extension identity and `fi.gekkio.ghidraboy` classes; build as static-only without debugger dependencies |
| `GhiGBC` extension | Imported Java plugin, launcher, tool configurations | Retain ID and `ghigbc` classes initially; no second provider JAR or language bundled |
| `ProgramMapping` schema 2 | Static provider → `BankMappings` | Preserve identity/coverage, list-valued ambiguous mapping and partial ranges; same-PC/two-bank/split/rename/alias tests |
| `MapperState` | Static provider → debugger mapping adapter | Report unknown/device states; actual backend observations supply live state |
| `GbcActionService` | Generic debugger → GhiBW3 `StudyPlugin` | Keep `watch` and `goWriter`; validate selected trace/session/epoch/capture; preserve user bookmarks |
| `BankMappings.isReady` | Generic debugger → GhiBW3 `StudyProvider` | Keep readiness behavior or a delegating compatible entry point; do not expose partially published mappings |
| `ghigbc.profile` | Generic Python runtime → `ghibw3.profile` | Preserve `ByteRange`/`Field`, profile API 1, bounded copied observations and absent/failing-provider behavior |
| `ghigbc.native.Machine` | Existing test/oracle scripts | Keep a compatibility import when the SameBoy adapter moves; generic agent must eventually use backend selection instead |
| `gc_*` C ABI 1 | SameBoy C adapter → Python binding | Preserve ABI until explicit version change; no private SameBoy layouts cross into Python |
| Native event records | SameBoy CPU patch → native adapter → trace | CPU-origin attempts and instruction-final bytes retain their precision; no inferred DMA writer or committed-write claim |
| `ghigbc.agent` command | Launcher, existing shell/consumer callers | Preserve module entry point and existing supported options; backend selection is additive |
| Launcher/configuration | Packaged `sameboy.sh`, Ghidra launcher registry | Existing launch offers still discover/load; retain known default versus experimental edit behavior |
| Trace schema/paths | `schema.xml` and agent → saved Ghidra traces | Keep `Machine`, registers, events, edits and profile paths readable in separate-process reopen tests |
| Capture/mapping markers | Agent and Java mapping worker | Preserve `CaptureSnapshot`, mapping readiness/generation, save barrier and snapshot-limited lifespans |
| Legacy trace namespaces | Older suite producers → current generic readers | Missing encoding/model metadata remains legacy/unknown; never reinterpret old fields as new precise evidence |
| Profile field batches | Profile API → trace persistence | Preserve `field-batches-v1`, complete counts and provenance within bounded messages |
| Checkpoint schema 2 | SameBoy `Machine` save/restore | Keep core/config/patch/ROM/boot/model checks, opaque `.sbs` payload, parent identity, restored epoch and released input |
| Recoverable edits | Session controls → checkpoint + trace edit records | Preserve paused opt-in, pre-edit recovery and debugger-origin before/requested/actual bytes; no false guest access event |
| `ExportGbcKnowledge.java` | Root static script and legacy debugger entry point | One authoritative `ProgramKnowledge` implementation; same `ghigbc-knowledge-v1` export contract |
| Static public scripts | GhidraBoy tools/import/ABI scripts | Installed discovery, preview/apply/remove, source/ownership lifecycle and preserved annotations |
| Legacy delegates | GhiGBC `legacy/` and `tests/drive_game.py` → external GhiBW3 | Keep thin delegates with explicit `GHIBW3_ROOT`; exclude from generic runtime and avoid copying game implementation |
| Installer journal schemas | Current installer and schema-2 rollback delegate | Retain supported old recovery paths, exact file hashes and user-modification refusal; validate on copied installations |
| Native decompiler marker | Copy-only updater and doctor | Executable and `ghidraboy-native-dependency.json` are one managed pair; preserve exact rollback identity |
| Build/environment overrides | Current scripts and external GhiBW3 | Keep explicit overrides during migration; replace default sibling/datestamped paths with build outputs and manifests |

## Existing checks and destinations

| Current suite | Destination / scope |
| --- | --- |
| Root Gradle unit, exhaustive p-code, ABI and decompiler tests | Remain in root static project; baseline 456 tests includes 168 ordinary sampled external vectors |
| `ExternalVectorTest` comprehensive corpus | Remains opt-in static validation, pinned revision and hashes; baseline checks 21,000 vectors in 21 selected files |
| `tools/installed_smoke.py` | Root installed lifecycle/preservation; now also invokes the existing all-opcode saved-constructor fixture |
| `tools/migration_smoke.py` | Root actual 11.3.1 → 12.1.3 copied database migration |
| GhiGBC `tests/test_*.py` | Imported debugger tests; baseline 46 tests, real native calls plus Python contracts |
| `RealTraceTest`, `MappingContractTest` | Imported real installed Trace RMI/mapping acceptance, independent of GhiBW3 |
| `UiActionTest`, display probes | Imported generic UI/display acceptance; headless success does not pass interactive actions |
| Native semantic oracle scripts | Imported independent SameBoy execution; root static verifiers invoke explicitly selected backend oracle |
| Package/installer/deck tests | Imported and consolidated under root orchestration at M3; platform/device evidence remains separately scoped |
| GhiBW3 pure/static/live/private gates | Stay external; static-only, generic-profile absence/removal and declared public APIs are integration obligations |
| Game-specific GhiGBC Java harnesses | Retain historically; reconcile with existing GhiBW3 consumer tests without importing game assumptions into generic code |

Synthetic Programs/traces/checkpoints created by current baseline runs live under the retained baseline work directory identified in `progress.md`. They are test fixtures, not original user databases. Historical archives retain their original identities; regenerated build output is distinct from preserved rollback artifacts.
