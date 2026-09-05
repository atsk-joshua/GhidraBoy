# GhiGBC implementation and handoff report

**Work period:** September 4–5, 2026, as recorded in the project log.

**Prepared for:** Joshua Hansen and his son.

**Project:** `/Users/joshuahansen/dev/GhiGBC`

**Status:** Implemented, installed and validated on the development Mac. The Steam Deck handoff is ready; actual Steam Deck execution and desktop validation remain pending.

This report consolidates the work, decisions, reasons, validation and remaining responsibilities. It supersedes intermediate “next action” and “pending” notes in the chronological log where later evidence resolved them. It is a record of substantive engineering work, rather than a transcript of every command or temporary process.

Evidence filenames below are relative to `docs/evidence/` in the full repository/source archive. The student ZIP contains a curated software-and-guides package and an empty target evidence directory; it does not preload Mac test logs as Steam Deck results.

## 1. Result delivered

Built GhiGBC: a SameBoy-backed Game Boy Color debugger integrated into Ghidra’s native Debugger through Trace RMI. It provides the execution backend, banked memory, register capture, bank-qualified breakpoints, CPU access watchpoints, checkpoints, explicit recoverable edits, a playable SDL window, and a study panel linked to the student’s static program.

On the development Mac, a real Game Boy Wars 3 CLASS 2 attack was captured through Ghidra. APC slot 50 changed from HP 10 to 3. The captured instruction was `rom18::40b5`, opcode `0x70`, `LD (HL),B`, within the existing `FUN_rom18__40a1` function. Restoring the pre-attack checkpoint and repeating the attack reproduced the result. An independent reopen verified the saved bytes, mappings, events and unit records. Caller attribution remains unknown.

The student deliverable is:

```text
dist/GhiGBC-SteamDeck-Handoff-0.1.0.zip
```

It contains the Linux candidate, both Ghidra extensions, teaching ROM, source, licenses, guides, setup/validation scripts, notes template and a results collector. The user confirmed that SSH is not enabled on the Deck and requested a package his son can run locally. No SSH enablement is required by this handoff.

The full deployment goal remains awaiting those target results. A cross-built Linux library and successful Mac tests do not establish that the student is already up and running on his Deck.

## 2. Starting point and preservation of existing work

Read the goal objective and the supplied Start Here, Codex Prompt and Implementation Plan. The workspace began empty. The handoff supplied research, specifications, the older Live Lab/Study Pack and historical test results, rather than an implemented integrated debugger.

Inventoried the host, installed tools, supplied assets and prior code. The development host was Apple silicon, macOS 26.5.2. The deployment target was initially unknown; the user later identified Steam Deck desktop mode. Kept those two environments distinct throughout the work.

Preserved the prior lab under `legacy/`. Reused its pure ROM/table/unit decoders, COMBAT map and test vectors. Kept its PyBoy commands and semantics separate from the new SameBoy agent, using an isolated legacy Python environment.

### ROM and program identity

| Asset | Finding and action |
|---|---|
| Supplied GZF copies | Both recorded the same SHA256: `0a3da750f238e7a768fca3417c92cfabaedc9d5bc742f095469ecb2617a0fbbf` |
| Earlier standalone ROM | SHA256 `40d78c75a2fa7ba9273476e4651d1adbaf4de98b3c05a12dad4167e53da82708`; it did not match the reviewed profile |
| ROM exported from the annotated program | SHA256 `e779a6b56575a2afafb7e1e99411b23d7400a8fddbda8bd52c660b7903c3b451`; 64 ROM banks, 1 MiB |
| Annotated program audit | 79 memory blocks and 1,792 functions; SM83 language identity preserved |

Used the existing `ExportGBW3ROM.java` inside Ghidra against a copied program. The exact mapped ROM was exported to new files. No custom GZF parser was invented, and the differing standalone ROM was not silently treated as equivalent.

The initial program audit enumerated 2,544 symbols. A later, more inclusive knowledge export enumerated 9,789 symbols, including generated/dynamic symbols, alongside 1,792 functions, three structures and 18 comments. These are different enumeration scopes, not evidence that thousands of student labels were added.

Private copies, experiments and checkpoints stayed under ignored development directories. Commercial ROMs, GZF files, checkpoints and personal saves were excluded from distribution. The teaching ROM is the explicit redistributable exception.

## 3. Major decisions and why they were made

| Decision | Reason and consequence |
|---|---|
| Follow the specified SameBoy/native C/Python/Java architecture | It directly supports a real Ghidra debugger while keeping hot-path emulation outside the JVM. A backend comparison was not needed to implement the supplied design. |
| Pin SameBoy 1.0.3 to an immutable commit | Reproducible source inspection, patches and checkpoint compatibility require a specific core, rather than a moving branch. |
| Keep SameBoy state opaque to Python | Mirroring a private C structure in ctypes would couple Python to compiler/layout details. The adapter returns fixed-width public records and copied buffers. |
| Use a narrow CPU provenance patch | Public memory callbacks alone could not reliably distinguish CPU accesses from interrupt/DMA/inspection activity or identify the original writer. |
| Use Trace RMI and standard Ghidra views | Registers, execution controls, traces and mappings belong in the existing Debugger. No separate web service, emulator, disassembler or production console-text protocol was introduced. |
| Start with an isolated 11.3.1 baseline, then use 12.1.2 | The prior lab documented 11.3.1. The user subsequently selected the existing 12.1.2 installation and reported Apple-silicon problems with 12.1.3. Work followed that correction. |
| Patch GhidraBoy while preserving its language identity | The student’s program depends on `SM83:LE:16:default`, compiler `default`, base space `ram`. Changing identity or installing duplicate definitions would undermine compatibility. |
| Represent physical identity separately from PC | CPU address `0x4029` can refer to different ROM banks. The architectural PC must remain a real 16-bit CPU address. |
| Derive static mappings from actual blocks/file offsets | Students can rename blocks and symbols. Name parsing alone would be brittle and could navigate to the wrong bank. |
| Capture supported mutable memory at stops | Full stopped copies establish correctness and history before dirty-page optimizations. Inspection should not read changing live memory behind an old snapshot. |
| Distinguish access attempts from final physical values | SameBoy’s write callback occurs before commit and blocking checks. An attempted write is not automatically a committed change. |
| Gate GBW3 semantics on the exact ROM hash | Filenames, titles and similar-looking ROMs do not prove identical layouts or balance tables. A mismatch retains generic debugging. |
| Preserve unknown callers and limit far-call over/out | The GBW3 RST inline-argument convention was not sufficiently verified for safe caller reconstruction or stepping over it. Ordinary CALL/RET/RST support was tested separately. |
| Install a complete versioned per-user runtime | Backing up only extension JARs would not restore the matching agent/native/Python combination. The installed launcher must also survive a moved development checkout. |
| Cross-build a Linux candidate with Zig | No accessible Deck or usable local Docker daemon was available during the build work. Cross-compilation produced a deliverable without pretending that Linux execution had occurred. |
| Deliver a manual-run student ZIP | The user confirmed no SSH and asked for a package his son could run. Setup, testing and log collection now work as explicit local steps. |

## 4. Versions and build environment

| Component | Selected or observed value |
|---|---|
| Development host | macOS 26.5.2, arm64, `MacBookPro.localdomain` |
| Deployment target | Steam Deck desktop mode, Linux x86-64 |
| Ghidra | 12.1.2; source revision `c0f584bf229fffba61b36431f3ce30c0c3e4e682` |
| Ghidra location on the Mac | `/Users/joshuahansen/ghidra_12.1.2_PUBLIC` |
| Java used for validation | OpenJDK 21.0.12.1 |
| Python used for validation | 3.14.7; handoff documents Python 3.10–3.14 |
| Trace RMI Python client | `ghidratrace==12.1`, from the selected distribution |
| Protobuf | `6.31.0`, from the distribution’s wheels |
| SameBoy | 1.0.3, commit `208ba4afabffab9edde416f2dbb8ae459e34adb8` |
| GhidraBoy base | Commit `42032f9d97e9e502dc10a14743bdb3d1b9388588`, compatibility patch applied |
| RGBDS | 1.0.1, commit `92bfe5d930c07dd4672b148f811305aa294d6e6f` |
| Gradle | 8.14.3, local pinned installation/cache |
| Mac native compiler | Apple clang 21.0.0 |
| Linux cross-compiler | Zig 0.14.1; target `x86_64-linux-gnu.2.28` |
| SDL2 observed by doctor | 2.32.72 on the development host |
| Preserved legacy backend | PyBoy 2.7.0 in its separate environment |

Dependency commits, download hashes, patch hashes and the cross-compiler archive are recorded in `dependencies.lock.json`. The earlier 11.3.1 downloads remain documented as baseline work; they are not the supported student release version.

The Mac core used upstream release-library rules, with the adapter compiled as C11/O2. RGBDS’s official binaries were used after the local source build encountered the host’s older Bison. The Linux cross-build uses upstream object rules, then directly links the adapter/shared library because Zig does not support the upstream relocatable-link convenience step used there.

## 5. Native execution and capture work

Implemented `native/ghigbc.h` and `native/ghigbc.c`, including machine lifecycle, execution control, registers, memory capture, physical mapping, break/watchpoint management, input/framebuffer access and full-state checkpoints.

The adapter uses a mutex for copied state and an atomic pause request. Python execution calls release the GIL and run bounded slices. CPU access records are bounded to 64 entries and expose a dropped-event count. The Python machine-owner queue is also bounded to 64 entries.

The core patch in `native/patches/0001-cpu-bus-provenance.patch` scopes direct CPU bus operations. It captures instruction-start identity and prevents stale CPU attribution across interrupt, DMA or inspector activity. Normal hot-path execution does not call Python on each instruction/access.

Implemented and tested ordinary/CB stepping, bounded HALT/STOP behavior, interrupt boundaries, ordinary conditional CALL/RET/RST over/out, and execution-breakpoint resume bypass. A step that encounters a wait or interrupt boundary is not falsely described as one retired instruction.

Implemented canonical physical breakpoint identity, independent of the active CPU window. Watches cover CPU read/write/access events, including direct stores outside GBW3 helpers, same-value writes and separate change predicates. Final memory values are observed at a safe instruction boundary; exact per-internal-access commit timing is not claimed.

Captured CPU-visible inspectable memory, eight WRAM banks, two VRAM banks and supported cartridge RAM. Unavailable memory and RTC-selected regions are represented as unknown. Inspector reads were checked for non-interference using complete native save-state comparisons.

Added three important ABI extensions during correctness audits:

- `gc_create_buffers`: loads the immutable ROM/boot bytes that Python fingerprinted, preventing a path replacement between hashing and native loading from changing the actual input.
- `gc_key_mask`: observes held-button state without a guest bus read, enabling paused/focus-loss validation.
- `gc_edit_wram`: edits a specified physical WRAM bank/offset without guest watch callbacks or bank-selection side effects.

These were additive changes under ABI 1. The final Linux ABI inspection records 19 required exported entry points.

## 6. Ghidra integration and bank history

Implemented `python/ghigbc/agent.py` and the version-matched XML schema. The trace models one machine/process, one SM83 thread and an observed frame-zero PC. It exposes the required execution, register, memory, breakpoint, focus and event-thread interfaces.

Implemented real remote methods for resume, interrupt, step-into, supported over/out, break/watchpoint creation/deletion/toggling, checkpoint save/restore, captured-memory/register refresh, explicit experiment edits, trace saving and termination.

Adapted to Ghidra 12.1’s client signature and typed method schema. Used 4 KiB memory chunks to remain below the protocol’s 64 KiB message limit. Batched transactions abort on errors. Registers are transmitted with the client’s big-endian byte encoding even though SM83 memory is little-endian; pair and byte aliases were verified using non-symmetric values.

Implemented Java `BankMappings` and `GbcPlugin`. Physical trace banks map explicitly to the annotated program; CPU windows map to the bank captured at that snapshot. Entries have snapshot-bounded lifespans, preserving earlier bytes and destinations across bank switches.

For example, ROM bank 18 offset `0xB5` corresponds to the usual CPU address `0x40B5`, file offset `0x480B5` and static address `rom18::40b5`. The PC itself does not contain a bank number. ROM0 remapping, boot coverage, SVBK zero, echo aliases and wider bank IDs received separate attention.

Two completion markers now prevent premature navigation:

1. `CaptureSnapshot` is written after all capture bytes and attributes. Java refuses to map inherited fields from an unfinished new snapshot.
2. `MappingSnapshot` records the exact snapshot whose static mappings are complete. It replaced a flipping readiness boolean that triggered duplicate Model-tree nodes. Readers retain compatibility with older boolean-marked saved traces.

## 7. Checkpoints, edits and lifecycle

Checkpoints contain full SameBoy state and metadata identifying the ROM, boot bytes, core, patch/configuration, hardware model, clock/input policy, session, epoch, ticks and state-file SHA256. Production metadata uses schema 2. Early diagnostic schema-1 checkpoints were not silently converted, and PyBoy savestates were not presented as SameBoy states.

Restore validates compatibility and checksum, creates a new epoch, clears stale pending state, reconciles breakpoints and releases keys. Captures now retain an immutable parent-checkpoint path, state fingerprint, source session/epoch and original checkpoint ticks. Later restores cannot rewrite an older capture’s source. A checkpoint created after restore also records its parent.

Register and WRAM edits require explicit experiment mode and a paused machine. Invalid requests are rejected before recovery artifacts are created. Successful edits first create a full recovery checkpoint, write intent, apply the change, then record the actual result—including architectural AF masking.

Debugger edits are recorded under `Machine.Edits`, separately from CPU accesses under `Machine.Events`. They include before/requested/actual-after values, physical target or register, epoch/snapshot and a recovery link/hash. Real remote tests verified edits, rejection while running/default mode, recovery and saved history.

Lifecycle work includes default pause on disconnect, bounded save retry for Ghidra’s active-transaction response, socket shutdown to wake the receiver, and structured termination. The agent publishes termination state, saves the trace and then closes transport. Actual game-window close was verified to preserve TERMINATED state after independent reopen. Final process checks found no owned validation app, agent or selected-version stalled decompiler process.

## 8. Display, profile and study workflow

Implemented `python/ghigbc/display.py` using SDL2, with event pumping on the required main thread even while emulation is paused. Keyboard controls are arrows, Z/X, Enter and Backspace. Very short taps are retained for at least 30 ms so a press/release in one event pump is still visible to the emulated game. Focus loss clears held and pending keys.

Implemented the fingerprinted GBW3 profile using the preserved decoders: 53 unit templates, 33 weapon templates, 100 live-unit slots and the existing WRAM4 COMBAT map. Verified the known writer opcode before enabling that interpretation. Candidate unit rows do not automatically establish that a map battle is active. The old FF80 bank shadow is documented as a game diagnostic; actual mapper state remains authoritative.

The Study panel displays units and write events. It provides the selected-unit HP watch, captured-writer navigation and opt-in bookmark action. Existing Ghidra names are used for writer labels. Bookmarking appends an observation without replacing the existing student note.

Added event epoch and a selected-event detail pane showing physical target/HP field, target CPU address, attempted value, origin, writer CPU address, original snapshot and precision. It reads the event’s historical capture. Generic ROMs receive physical labels without GBW3-specific HP labels.

Historical writer navigation now explicitly activates the event’s trace and changes a present-following Target mode to read-only Trace mode when needed. This fixes Ghidra rejecting an older snapshot while following the live target. Returning to live play uses Control Target mode; viewing history does not restore the machine.

Added read-only `ExportGbcKnowledge.java` for versioned export of symbols, namespaces, functions, block/file mappings, structures and comments. The supplied structures were cartridge-header structures; no conflicting live-unit structure was supplied. The profile does not import arbitrary user-defined structure layouts as emulator truth.

## 9. Actual game experiment and its limits

Early boot/menu and CLASS 1 exploration established navigation and input, but did not prove combat. A GRUNT was created in CLASS 1 and unit data observed. A setup-time HP-clear write was identified as initialization, not an attack. A later VS setup probe was also kept separate from battle evidence.

Moved to a real Ghidra-connected CLASS 2 tutorial battle, using normal game input. The HUMVEE in slot 1 attacked the APC in slot 50. Results were:

| Observation | Verified result |
|---|---|
| Defender | APC slot 50, HP 10 → 3 |
| Attacker | HUMVEE slot 1, HP 10 → 5 |
| Watched target | WRAM bank 3, offset `0x324`, CPU address `0xD324` |
| Writer | ROM bank 18, offset `0xB5`, CPU `0x40B5` |
| Static instruction | `rom18::40b5`, `LD (HL),B`, opcode `0x70` |
| Existing function | `FUN_rom18__40a1` |
| Caller | Unknown; not inferred |

Saved and restored the pre-attack checkpoint, repeated the attack, closed the session and independently reopened the trace. A persistence defect discovered during this process was fixed and the experiment replayed in a fresh session. The final reopened evidence contains all 100 unit records. In the final saved project, the two recorded hits are snapshots 4 and 6, epochs 1 and 2; earlier runs used different snapshot numbers.

Private final evidence project: `build/projects/Battle-1788579290888.gpr`, trace `/New Traces/GBC/student12`. Private continuation checkpoint: `.local/game-evidence/class2-fire-ready`. These are development artifacts and are not included in the student software ZIP.

## 10. Problems found and corrective action

| Problem | Correction / final disposition |
|---|---|
| Supplied standalone ROM differed from the annotated program | Exported the mapped ROM from a copied GZF inside Ghidra and used exact fingerprint gating. |
| GhidraBoy did not directly compile against 12.1.2 | Patched changed loader APIs and removed HashUtilities usage while retaining language identity and attribution. |
| Overlay display syntax differed from mapping serialization | Used API-compatible `space:offset` serialization while preserving Ghidra’s `space::offset` display convention. |
| New snapshots exposed inherited bank fields before capture publication finished | Added the final `CaptureSnapshot` marker and mapping guard. |
| Readiness false→true updates caused Model-tree duplicate nodes | Replaced the handshake with exact numeric `MappingSnapshot`. |
| Long unit/COMBAT JSON was silently truncated on persistence | Ghidra’s string codec used a fixed buffer. Stored UTF-8 byte arrays, warned on older truncated metadata, and replayed/reopened the real battle to verify all records. |
| Hashing input paths and reopening them could identify different ROM/boot bytes | Added immutable buffer loading and replacement/deletion regression tests. |
| Experiment changes lacked trace-level source/recovery evidence | Added immutable debugger-origin edit records and a dedicated physical-WRAM edit API. |
| Restored captures did not retain checkpoint parent identity | Added captured and persisted source path/fingerprint/session/epoch/ticks. |
| Breakpoint edits could alter state/history or reuse identities | Preserved RUNNING state during live edits, retained deleted historical specifications and used monotonic identifiers. |
| SameBoy’s async console reader could consume sidecar stdin | Disabled that reader for the structured agent. |
| Very short keyboard taps were lost within one display pump | Added a short minimum tap lifetime while preserving immediate focus-loss release. |
| Closing transport/window could leave misleading lifecycle state | Added structured termination, bounded save retry and shutdown ordering; verified reopened TERMINATED state. |
| Bare Java app automation and a shell app wrapper were unreliable | Used a dedicated jpackage validation app with a distinct identity and a full Ghidra classpath. The shell-wrapper approach was not retained as the reliable test route. |
| Minimal test tools lacked normal static navigation; the standard template needed a front end | Used Ghidra’s shipped Debugger template with a real FrontEndTool. |
| Right-click injection did not reliably open the context menu | Invoked the same registered bank action through Ghidra’s standard action chooser using actual UI controls. |
| Go to writer could reach a static address but fail to select history in Target mode | Switch to read-only Trace mode for historical coordinates. |
| HP observer saw a trace before its first snapshot existed | Handle the initially empty trace and wait for a completed capture. |
| Front-end disposal exited the JVM before final test reporting | Test-only front-end subclass lets cleanup return so the observer can report its own result. |
| A queued withdrawal event could reactivate a closed fixture trace | Clear the fixture’s active trace before tool disposal. |
| Native Mac decompiler stalled during some attempts | Preserved Java/native diagnostics and stopped a verified owned stuck child during recovery. After the user clarified approval/window timing, retries completed without the stall. No permanent cause or universal decompiler fix is claimed. |
| A growth run failed an immediate restored-register assertion | Preserved the failure, added explicit completed-capture synchronization after restore, and reran successfully. |
| Linux link convenience step was unsupported by Zig | Built upstream core objects and linked the shared adapter directly. |
| Doctor could report generic readiness without checking SDL2 | Added SDL2 load/version checks and a separate desktop-prerequisite result. |

Ghidra/macOS accessibility child-index exceptions and some PTY-close diagnostics occurred in specific runs. Passed assertions and exit status are reported alongside those diagnostics, rather than describing every run as error-free. The final HP session completed its own post-cleanup pass marker with exit 0 and no earlier Swing/activation/mapping assertion.

## 11. Validation performed

| Area | Evidence |
|---|---|
| Native/control correctness | 25 tests passed in `checkpoint-parent-native.log`; representative mapper, access, state, input-identity, edit and checkpoint cases |
| Preserved legacy behavior | 11 integrations plus 256 initiative, 150 damage, eight modifier and three synthetic firing-order cases rerun |
| Real Ghidra APIs and persistence | `checkpoint-parent-ghidra.log`: `REAL_TRACE_TEST_PASSED` |
| Actual registered UI actions | `ui-actions.log`: bank action, native Resume, historical writer and bookmark preservation; `UI_ACTIONS_PASSED`, exit 0 |
| Actual game HP button | `hp-ui.log` / `hp-ui-result.json`: APC selection, WRAM3 HP watch and complete cleanup; `HP_UI_PASSED`, exit 0 |
| Real map battle | `actual-battle.json`, `actual-battle-verification.log`, `study-battle-details.log` |
| Paused desktop/input | `paused-display.json` and `ghidra-desktop-close.log` |
| Versioned install/rollback | Runtime install/rollback/self-rollback evidence and current `INSTALLATION.json` |
| Linux format/ABI | `linux-library.json`, `linux-abi-check.log`; cross-built ELF64 x86-64 with 19 required exports |
| Student handoff helper checks | Two tests passed for wrong-version rejection and result-collector exclusions |
| ZIP integrity and usability checks | Extracted script/help/collector checks, Python/shell syntax, platform guard, member hashes, private-asset exclusions and fresh result-folder check |

Native or remote-method checks were not represented as manual clicks on every corresponding dialog. Direct UI evidence was added for the particular actions listed above. A dummy display was not used as desktop-play evidence.

Legacy logs contain optional PyBoy screenshot/recording warnings about missing Pillow. Passing the numerical and integration checks does not establish that those optional legacy capture plugins work in the isolated environment.

The paused focus-loss test seeded a guest-held key through the native API before minimizing the actual window. A real Z tap also produced the expected key-state transitions. This is useful evidence of paused pumping/release behavior; it is not a physical held-key test on the Steam Deck.

### Performance measurements

| Measurement | Result and scope |
|---|---|
| Real SDL play | 120.000 seconds wall / 119.999 seconds emulated on the Mac |
| Warm remote step p95 | 37.625 ms, 20-sample measurement from the integrated growth run |
| Remote pause | 269.863 ms, including test settling; not pure UI-click latency |
| Integrated growth probe | 250 sequential real Trace RMI stop captures in 12.406 seconds |
| Agent resident memory | 43,456 → 43,472 KiB; increase 16 KiB |
| Ghidra resident memory | 934,592 → 1,112,912 KiB; increase 178,320 KiB |
| Saved trace size | 3,391,488 → 4,587,520 bytes; increase 1,196,032 bytes |
| Dropped events during that probe | 0 |

These satisfy the initial response-time targets on the measured Mac. The probe includes documented wait boundaries and is not a count of 250 guaranteed retired instructions. Saved history intentionally grows. The measurements are not a long-duration leak proof, request-saturation test, or Steam Deck performance result.

## 12. Installation, packaging and delivered files

The installer validates Ghidra 12.1.2, rejects duplicate SM83 definitions, backs up managed extensions and installs a versioned runtime. The runtime includes the agent, native library, matched Python environment, open-source boot asset, required legacy decoder code, notices and rollback utility. Java, Python and SDL2 remain host prerequisites.

Rollback verifies recorded file hashes and confines changes to managed locations. It refuses to discard files modified after installation. Failure rollback and the ability to roll back from the installed runtime were tested.

Current development installation:

```text
/Users/joshuahansen/Library/ghidra/ghidra_12.1.2_PUBLIC/
  Extensions/GhidraBoy
  Extensions/GhiGBC
  GhiGBC-runtime/0.1.0-20260905T011833040074
  GhiGBC-rollback/20260905T011833040074/manifest.json
```

`docs/INSTALLATION.json` records the exact current paths. Earlier versioned runtimes/manifests remain as rollback history; chronological references to those older installations are not the current installation instructions.

### Source orientation for the next maintainer

| Location | Responsibility |
|---|---|
| `native/ghigbc.c`, `native/ghigbc.h`, `native/patches/` | Core bridge, ABI and CPU provenance patch |
| `python/ghigbc/native.py` | Opaque native wrapper, immutable captures, checkpoint/edit metadata |
| `python/ghigbc/agent.py`, `schema.xml` | Trace RMI model, remote methods and ordered publication |
| `python/ghigbc/display.py`, `profile.py` | SDL event loop and exact-ROM game decoding |
| `ghidra-extension/src/main/java/ghigbc/` | Bank mappings, plugin actions and Study panel |
| `ghidra-extension/data/debugger-launchers/` | Ghidra launch integration |
| `scripts/` | Bootstrap, builds, install/rollback, doctor, knowledge export and packaging |
| `scripts/deck_handoff.py`, `scripts/package_deck_handoff.py` | Student setup/validation/collection and curated ZIP generation |
| `tests/ghidra/` | Real integration, UI observers, developer game-session console and saved-battle verifier |
| `tests/fixtures/`, `tests/test_*.py` | Teaching assembly, native/control regression and handoff-helper tests |

The developer game-session console orchestrates real Ghidra remote methods while gameplay input remains in SDL. It was an acceptance harness; normal student use starts through the packaged Ghidra launcher.

| Deliverable | Purpose |
|---|---|
| `dist/GhiGBC-SteamDeck-Handoff-0.1.0.zip` | Student-facing package with START-HERE, Setup, Validate, Collect-results and NOTES |
| Companion `.zip.sha256` and `dist/SHA256SUMS` | Integrity checks; use these rather than an embedded self-referential ZIP hash |
| `dist/GhiGBC-0.1.0-linux-x86_64.tar.gz` | Full Linux candidate payload and source/evidence |
| `dist/GhiGBC-0.1.0-source.tar.gz` | Source, scripts, documentation, preserved legacy work and development evidence |
| GhiGBC and GhidraBoy extension ZIPs | Matched Ghidra 12.1.2 extensions |
| `dist/teaching.gbc` and `dist/teaching.sym` | Self-authored debugger fixture and symbols |
| `docs/QUICKSTART.md` | First-session teaching/game/checkpoint walkthrough |
| `docs/COMPLETION_AUDIT.md` and `docs/ACCEPTANCE.md` | Requirement-to-evidence mapping and limits |

The curated student package deliberately starts with a fresh target log directory. Its manifest hashes every included payload file. Result collection allowlists setup/test logs and visible NOTES.txt, skips symlinks, and excludes ROMs, projects, checkpoints and saves. Logs may contain hostnames and local paths, so the student is told to review them before returning the ZIP.

At report preparation, Git HEAD is `a38824d31dbd799fe32077695ab8eb81b8afed74` (Initial commit, September 5). The working tree also contains later handoff/documentation/helper changes. Distribution archives are built from the working tree; do not assume HEAD alone contains every final handoff change. This reporting task does not commit, merge or publish those changes.

## 13. Rebuild and continuation commands

From the repository/source archive, with the appropriate platform tools available:

```sh
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra_12.1.2_PUBLIC
export JAVA_HOME=/absolute/path/to/jdk-21
python3 scripts/bootstrap.py
scripts/build_native.sh
scripts/build_extension.sh
scripts/test_native.sh
scripts/test_ghidra.sh
```

The Mac-to-Linux cross-build is `scripts/build_linux_cross.sh`, using the pinned Zig compiler. Package the built artifacts with:

```sh
python3 scripts/package.py
python3 scripts/package_deck_handoff.py
```

For the student, extract the handoff ZIP in Desktop Mode and follow START-HERE.md:

```sh
bash Setup.sh
bash Validate.sh
bash Validate.sh --ui
```

Setup remembers the Ghidra/JDK paths, which can be supplied explicitly. Automated validation and the interactive phase are separate, avoiding an unnecessary repeat of the full suite. Complete the actual game-window, pause/focus and close checks, fill in NOTES.txt, then run:

```sh
bash Collect-results.sh
```

The returned results ZIP is the next input needed to finish target acceptance. Private game files remain separate. The student should use a copy of his own annotated GZF and export/check the exact matching ROM before following the GBW3 walkthrough.

## 14. Remaining work and limits

The outstanding deployment work is to run the candidate on the actual Steam Deck: native loading, installed Ghidra/version/client compatibility, clean per-user setup, real window/input/focus behavior, controls, persistence, restore and performance. Then repeat the commercial-game walkthrough on that machine as appropriate and review the returned logs.

The following are explicit first-release limits, not hidden completed features:

- CPU-origin watches only; no DMA/HDMA watch coverage.
- Attempted access plus final physical-byte evidence; not exact commit timing for every internal I/O access.
- Ordinary supported over/out only; GBW3 far-call over/out and verified caller reconstruction remain unavailable.
- One observed frame, without an invented complete stack or authoritative reconstructed C locals.
- Supported mapper subset and tested representative edges; RTC-selected bytes remain unknown and other mapper families are not promised.
- Keyboard controls implemented; Steam Deck controller/Steam Input mapping has not been validated.
- No battery-save import, PyBoy-state conversion, audio output, docked game display or general reverse-execution system.
- Current profile uses the verified ROM layout; arbitrary user structure layouts/new ROM profiles are not automatically trusted.
- Doctor readiness and cross-build inspection do not replace actual target desktop evidence.

The user’s current delivery choice is a local-run package, not SSH access. The project is awaiting the son’s Steam Deck results. Preserve the existing passing development evidence, use returned failures to select the next concrete fix, and do not label target deployment complete until those results support it.
