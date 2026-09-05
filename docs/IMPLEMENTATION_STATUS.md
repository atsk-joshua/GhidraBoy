# Current result — 2026-09-05

- Student handoff: **dist/GhiGBC-SteamDeck-Handoff-0.1.0.zip**. The user confirmed no SSH; his son will run the included local setup/validation and return collected logs.
- Selected version: **Ghidra 12.1.2**. Development host **macOS 26.5.2 arm64**; deployment target **Steam Deck desktop mode, Linux x86-64**.
- Working native SameBoy adapter, real Trace RMI debugger, physical bank mappings, break/watchpoints, standard controls, checkpoints, experiment edits, SDL window, study panel and authoritative writer labels.
- **Real CLASS 2 map battle passed**, twice, then repeated after the persistence fix. APC HP **10→3**, writer **rom18::40b5 / LD(HL),B**, checkpoint restore/repeat and independently reopened trace verified. All **100 unit records** now persist correctly via byte-array metadata. Caller remains unknown.
- **25 native/Python tests pass**; final real Ghidra acceptance passes, including live breakpoint edits, historical breakpoint identity, copied runtime launcher and structured termination. Logs are under `docs/evidence/`. Legacy 11 tests plus 256 initiative /150 damage /8 modifiers /3 order cases rerun unchanged.
- Installer now copies a **versioned complete runtime** and backs up extensions. Full runtime install/rollback and automatic launcher tests against that copied runtime passed.
- **Deployment proof is unavailable, and the completion audit remains open:** no Steam Deck SSH/access details were supplied. A Linux x86-64 library and installable candidate bundle were cross-built and ABI-inspected. Native execution, clean install, held-key/focus and desktop controls on the Deck still must be run using `docs/STEAM_DECK.md`. Do not claim the student is up and running there.
- **Direct teaching-fixture UI sequence passes**: registered physical-bank action through the standard action chooser, native Resume, historical Go to writer, and preservation of an existing bookmark. The test exposed and fixed historical navigation in Target mode. `docs/evidence/ui-actions.log` ends `UI_ACTIONS_PASSED`, process exit 0. The game-profile HP button and complete session cleanup separately pass for APC slot50 (`HP_UI_PASSED`, exit0). Steam Deck execution remains unverified.
- The mapping completion flag now records an exact `MappingSnapshot`; real capture/reopen checks pass without the former Model-tree duplicate-ready assertion. Earlier copied-GBW3 runs exposed a native Mac decompiler stall; the final user-authorized retry completed without that stall or a teardown exception (see `hp-ui-result.json`).
- Known limits: CPU-origin watch coverage only (no DMA/HDMA watches), GBW3 far-call step-over/out disabled, no inferred callers, no battery import, no audio output. Ghidra can log transient active-transaction/PTY-close diagnostics; bounded save retry and structured termination are implemented.

The sections below are the chronological implementation log; earlier blockers/results are superseded by later milestones.

# Implementation status

## Objective and plan
Implement the supplied SameBoy/native C/Python Trace RMI/Java Ghidra design. Gates:
1. Inventory, preserve legacy work, pin tools and extract matching ROM with Ghidra.
2. Native adapter and self-authored RGBDS fixture; prove boundaries and bank identity.
3. Real Ghidra trace, registers, explicit bank mappings and breakpoint translation.
4. Display/input, watchpoints, checkpoints, edits and lifecycle.
5. Fingerprinted GBW3 decoders, study actions and actual battle evidence.
6. Reproducible per-user packaging, rollback, doctor and student walkthrough.

## Inventory (2026-09-04)
- Empty workspace; no existing Git repository or local AGENTS.md. User says no `codex/` branch prefix.
- Build host: macOS 26.5.2 / Darwin 25.5.0, arm64, MacBookPro.localdomain.
- Apple clang 21.0.0; system Python 3.9.6; Homebrew Python 3.14, OpenJDK 21 and SDL2 available. Ghidra not found in Applications/Downloads/dev or Spotlight.
- Actual student deployment platform remains unconfirmed. Build/test on this Mac; do not infer it is the student's machine.
- Preserved supplied Live Lab and Study Pack unchanged in `legacy/`.
- Both downloaded GZF files have SHA256 `0a3da750f238e7a768fca3417c92cfabaedc9d5bc742f095469ecb2617a0fbbf`.
- Standalone ROM SHA256 `40d78c75a2fa7ba9273476e4651d1adbaf4de98b3c05a12dad4167e53da82708` differs from required profile. No semantic profile for that file.
- Expected mapped ROM SHA256 `e779a6b56575a2afafb7e1e99411b23d7400a8fddbda8bd52c660b7903c3b451`; use original exporter against copied GZF.
- SameBoy v1.0.3 resolves to commit `208ba4afabffab9edde416f2dbb8ae459e34adb8` (annotated tag `5104c0429df2a73cfccea8c5034d5cb72c13c5f2`).
- Selected initial Ghidra compatibility lane: 11.3.1, isolated installation; no existing installation to overwrite.

## Validation
- `git ls-remote https://github.com/LIJI32/SameBoy.git refs/tags/v1.0.3 'refs/tags/v1.0.3^{}'`: resolved above after network permission escalation.
- `shasum -a 256` on commercial inputs: fingerprints above. Originals untouched.
- Legacy historical results not rerun yet. No new native/Ghidra/desktop/battle gate passed.

## Next action
Finish pinned local tool acquisition, inspect SameBoy API, build native library and fixture. Install isolated Ghidra 11.3.1/GhidraBoy to export the annotated ROM and run real integration checks.

## Milestone: native control and copied program (2026-09-04)
- RGBDS v1.0.1 at `92bfe5d930c07dd4672b148f811305aa294d6e6f`; official universal macOS binaries used after source configure rejected system Bison 2.3.
- SameBoy built with upstream `make -j8 lib CONF=release`, clang arm64, O3/LTO; boot ROMs built from upstream source with RGBDS. Adapter uses C11/O2 and links the static core.
- Narrow CPU-bus patch in `native/patches/0001-cpu-bus-provenance.patch`: direct CPU operations distinct from interrupt/DMA/inspector traffic; attempts captured before commits. No Python hot-path callbacks.
- `PYTHONPATH=python .venv/bin/python -m unittest discover -s tests -v`: **9 passed**; details and native-only latency in `docs/evidence/native-tests.log`. Includes same-PC bank 1/2, inactive-bank breakpoints, bank 3/4 writes, original writer PC, same/change distinction, register values, CB, HALT wait, interrupt boundary, echo/SVBK zero, immutable capture bytes, checkpoint/edit recovery, non-invasive inspector.
- Tests do not yet prove blocked writes, STOP, wider MBC bank IDs, real trace history or desktop controls; those remain open.
- Ghidra 11.3.1 + GhidraBoy 20250830 imported `.local/student-copy.gzf` with no analysis and ran unchanged `ExportGBW3ROM.java`. Output `.local/experiments/student.gbc` **matches expected SHA256**. Original inputs untouched. Log: `docs/evidence/ghidra-export.log`.
- Isolated venv: Python 3.14.7, distribution-matched `ghidratrace==11.3`, `protobuf==3.20.3` installed offline from Ghidra wheels. Legacy PyBoy remains separate and has not been rerun.
- Next: real Trace RMI schema/controls, connect GUI, verify registers and physical banks in real Ghidra before extending UI.

## Milestone: real Trace RMI proof
- Deployment clarified by user: **Steam Deck desktop mode, Linux x86-64, "latest Ghidra"**. Exact installed version not yet observed. Official current release API resolves to **12.1.3 (20260817)**. This is a new compatibility lane using a project copy; macOS 11.3.1 is the working development baseline, not target proof.
- `tests/ghidra/RealTraceTest.java` compiles against the distribution and launches an actual Ghidra tool with Trace RMI, Registers, Threads, Time and Model plugins. It creates a disposable Ghidra project, starts the real native agent and invokes Ghidra RemoteMethods over loopback.
- `docs/evidence/real-ghidra-test.log`: **REAL_TRACE_TEST_PASSED**, CPU bank 1 bytes, inactive physical bank 2 bytes, genuine remote Step PC=$402B, inactive-bank stop in bank 2, historical CPU memory, AF/BC/DE/HL/PC/SP and A/F/B/C values all verified by Ghidra's trace register API. Trace saved at `/New Traces/GBC/teaching` within the disposable project.
- This does not yet prove explicit static mappings, reopened history or UI button clicks. CUA lists the running Ghidra Java app but cannot resolve its app handle; no screenshots claimed.
- Native schema + single owner/writer + bounded command queue in `python/ghigbc/agent.py`; CPU and physical memory fully copied at stops, immutable ROM recorded once. Historical refresh methods do not read live state.
- SDL2 main-thread display/input implementation added but not yet desktop-validated.
- Next: explicit static mapping service, real history/reopen and reverse breakpoint checks; then remaining execution/UX and Steam Deck packaging.

## Version correction from user
+ User explicitly selected **Ghidra 12.1.2**, installed at `/Users/joshuahansen/ghidra_12.1.2_PUBLIC`; reports 12.1.3 issues on Apple silicon. Stop the 12.1.3 lane. Inspect and use 12.1.2 with a project copy and its own Python client. Steam Deck remains the deployment target.

## Milestone: selected Ghidra 12.1.2 passes real integration
- Patched GhidraBoy release commit `42032f9d97e9e502dc10a14743bdb3d1b9388588` for changed 12.1.2 loader signatures and removed HashUtilities, preserving language identity, source attribution and loader semantics. Patch checked in under `ghidra-extension/patches/`.
- Upstream GhidraBoy Gradle `assemble` and Ghidra-supported extension `buildExtension`: **BUILD SUCCESSFUL** (`docs/evidence/ghidraboy12-build.log`, `extension12-build.log`). Gradle 8.14.3; user-local cache. Rebuilt extensions installed only under isolated `.local/user12`, not the user's actual Ghidra settings.
- Adapted 12.1 Trace RMI `extra` parameter, typed object method schemas/decorator and 64 KiB message limit. Memory writes are 4 KiB chunks; capture transactions abort on errors.
- `docs/evidence/real-ghidra12-test.log`: **REAL_TRACE_TEST_PASSED**. Real Ghidra 12.1.2 tool + server + native agent. Bank 1/2 CPU bytes, inactive-bank breakpoint, remote step, all pair/byte-alias values verified. Explicit static mappings follow renamed bank 2 block. Old snapshot mappings persist after switches. A separately opened persisted trace retains old bytes and mappings. Student label `StudentBankTwo` preserved.
- Native suite now **11 tests pass** including blocked VRAM attempts and STOP wait. Native-only step p95 ~0.244 ms, pause ~0.004 ms; these are not UI latency claims.
- Profile reuses original `inspect_rom`, `decode_unit` and COMBAT map without modifying legacy code; exact ROM hash + known LD(HL),B opcode verified, 53 unit/33 weapon tables decoded.
- GBC Study panel, physical static breakpoint action, HP watch, captured-writer navigation and opt-in bookmark action implemented and compiling; end-to-end UI action validation still pending.
- Bootstrap, build, doctor, rollback installer and student guide added; clean installer/launcher checks still pending. Do not claim all gates complete.
- Current next actions: ordinary step-over/out tests; build/install final 12.1.2 extension, expand real server checks for watches/checkpoints/latency, validate display and finish packaging. Steam Deck target execution and actual map battle remain unproved.

## Milestone: live plugin, controls, latency and installer
- Real 12.1.2 test expanded to enable **GbcPlugin** and open the imported static fixture. This exposed and fixed double-colon overlay address serialization: Ghidra's mapping conflict parser needs `space:offset`, even though UI overlay addresses display `space::offset`.
- Latest `real-ghidra12-test.log`: **REAL_TRACE_TEST_PASSED** with live mapping/study plugin, remote checkpoints, restore epoch/register checks, saved/reopened bytes/mappings, preserved labels. **Remote step p95 35.604 ms**, **pause 133.154 ms** on MacBookPro.localdomain arm64; pause includes 100 ms conservative test settling. Not Steam Deck measurements or UI click latency.
- Native ordinary CALL/RET and conditional CALL/RST step-over/out now use SameBoy's observed call-depth hooks; bounded and cancellable. Step Out refuses when no observed frame exists after restore. GBW3 far-call over/out deliberately disabled pending verification. Native suite **13 tests passed**; extra mapper suite **3 tests passed** (MBC5 bank 256, MBC1 ROM0 bank 32, MBC3 RTC selector unknown, boot identity, CPU read watch).
- Disabled SameBoy's default async console input explicitly after native gameplay probe revealed it could consume sidecar stdin even with debugger disabled.
- Original legacy code unchanged: **11 tests rerun passed**, plus 256 initiative, 150 damage, 8 modifier, 3 synthetic order cases passed (`legacy-tests.log`, `legacy-routines.json`). Python 3.14.7/PyBoy 2.7.0 isolated in `.venv-legacy`; not the old historical Python 3.12 environment.
- Per-user installer test in `.local/install-test` succeeded for GhidraBoy/GhiGBC and rollback removed only recorded installed files. Result `install-test.json`; actual user's settings not yet changed.
- Native commercial-ROM gameplay probe booted to main menu, saved `.local/game-evidence/main-menu` checkpoint, entered New Game/data selection. Current driver running in PTY session **32634**, accepts one JSON command per call. Its in-memory native library predates disabling async stdin, so do NOT queue multiple input lines in one call. Recent framebuffer `.local/game-evidence/frame-010.png`. This is a native diagnostic, not a Ghidra/Steam Deck battle or desktop proof.
- Next: continue actual gameplay capture; test automatic launcher and actual installed plugin; source package with licenses/rollback/diagnostics; target build if SSH available. Remaining battle/desktop gates must stay explicit.

## Additional delivery progress / current live state
- Automatic Ghidra launch service **discovers GBC / SameBoy and launches native agent**, verified through actual TraceRmiLauncherService using the installed JAR in a fresh profile. Test extended to wait for a complete saved initial capture before closing; rerun currently paused at **Ghidra's first-run user agreement**. User asked to review/accept in the open window. Current test JVM PID **22312**, shell session **89867**, profile `.local/clean-launch12`. Do not silently accept the agreement or bypass it.
- Clean source/bootstrap acquisition now verifies official SHA256 archives for RGBDS Linux x86-64/macOS and Gradle; local idempotent bootstrap test passed. Source pins, patches, archive URLs and hashes recorded in `dependencies.lock.json`.
- Added explicit experiment-mode remote WRAM/register actions and launcher toggle. Checkpoints now use metadata schema 2 including adapter config and core-patch checksum; old metadata intentionally rejected.
- Sidecar Python must load its platform-native library (`.dylib` macOS, `.so` Linux). Linux executable build still needs Steam Deck/SSH or a Linux build host; Docker CLI exists here but no daemon. User asked about SSH, response pending.
- Task-owned stale failed test JVM **18840** and obsolete 11.3.1 desktop **13620** were stopped after process inspection. Active native game driver PID **20852**, PTY session **32634** retained.
- Native game probe reached first **CLASS 1** training map. Frame `.local/game-evidence/frame-024.png` showed map loading, no units yet. Start (not A) on NEXT MAP began mission. Driver still uses original metadata schema 1 in memory; its main-menu checkpoint is diagnostic-only and incompatible with new production schema 2. Do not silently migrate it.
- Latest native suite is being rerun for metadata/edit changes; legacy tests already passed and need not rerun absent changes.

## Desktop access retried after user approval
- User said "Try again i just allowed". CUA now successfully selects the Python.app SDL window by its full app path. Ghidra's bare-Java app still returns Invalid app by both bundle ID and display name.
- Real SDL window screenshots were observed inline in the task: game title, intro, then main menu after Start keyboard input. Fixed very short key taps being pressed/released in one event pump by retaining taps for 30 ms; focus loss still clears all held/pending keys immediately.
- `desktop-probe.log`: **120.00014 wall seconds / 119.99936 emulated seconds** on this Mac. Actual SDL driver/window, no dummy driver. Keyboard Start verified visually. Focus-loss while held and integrated paused-window interactions remain to be proven; do not extrapolate to Steam Deck.
- Latest combined native suite **16 tests pass** after checkpoint schema/edit updates.
- Source archive and extension archives created in `dist/` with teaching ROM and SHA256SUMS. These are **development artifacts**, not a validated Linux binary release. Rebuild/repackage after remaining code/docs changes.
- Native game probe current frame `.local/game-evidence/frame-031.png` after CLASS 1/Red Star day 1; still no plausible decoded units. Need inspect visible tutorial and advance normally; do not fake RAM or call game helper routines to claim a battle.

## Latest gameplay and hardening
- Real gameplay built a GRUNT through the game UI in CLASS 1, slot **0**, coordinates **(7,9)**, HP **10**, fuel 99, ammo 9. Diagnostic checkpoint `.local/game-evidence/class1-unit0`; bank-3 HP watchpoint armed on offset 4. No actual attack/HP delta yet. Current framebuffer `frame-035.png`; advancing normally with native joypad commands.
- Captured writer navigation now verifies the open static program matches the mapping URL; asynchronous mapping updates drain pending events to avoid missing a capture. Sidecar shutdown unblocks transport before freeing its machine.
- Experiment-mode launcher option and metadata schema 2 are implemented; latest native suite remains 16 passing. Extension rebuild after UI/mapping hardening in progress (session 67754).
- Ghidra clean-profile test remains at the user's first-run agreement (not a code hang); requests for agreement review and Steam Deck SSH details are pending. No bypass performed. Bare Java application cannot be addressed by CUA even after desktop access was granted; Python SDL application can.
- Read-only 12.1.2 copied-program audit: **79 blocks, 1,792 functions, 2,544 symbols**, SM83 language retained. Re-exported ROM matches exact expected hash (`ghidra12-student-import.log`, `student12-audit.log`).
- CLASS 1 end-turn advanced normally; unit 0 refreshed its action flags without HP change. This training scenario has not supplied combat evidence. Returning the native diagnostic to its menu checkpoint to select a battle-capable scenario. Do not label it an actual battle.

## Actual per-user install and Ghidra desktop access
- Installed to `/Users/joshuahansen/Library/ghidra/ghidra_12.1.2_PUBLIC/Extensions/{GhidraBoy,GhiGBC}`. Exact rollback manifest: `/Users/joshuahansen/Library/ghidra/ghidra_12.1.2_PUBLIC/GhiGBC-rollback/20260904T185808077412/manifest.json`. Evidence `installed-mac12.json`.
- Doctor outside sandbox: `ready_for_generic_tests: true`, ghidratrace 12.1 / protobuf 6.31.0, one SM83 language definition, native arm64 library and loopback available, exact ROM hash.
- Created a tiny local `.local/Ghidra.app` wrapper so CUA can resolve the existing bare-Java app. CUA finally returned the actual Ghidra User Agreement window, but its getApp call stalled for **1396 seconds** despite a 30-second requested timeout. Avoid repeating app discovery. Persistent CUA binding `ghidra` now exists.
- Visible agreement is Apache 2.0/as-is/lawful-use notice, buttons OK and Cancel. User explicitly asked via async tool whether OK may be pressed; **approval pending**. Do not accept before response.
- Native game diagnostic session 32634 remains active in VS → MAN (hand-around-the-GB) selection, choosing a battle-capable scenario. Still no actual attack captured.

## Clean-profile launcher gate passed
- User explicitly approved accepting the Ghidra agreement. Clicked OK via CUA; clean-profile validation resumed and completed.
- `clean-ghidra12-test.log`: **REAL_TRACE_TEST_PASSED**, including actual installed JAR, matching bank maps, aliases, checkpoints, persistence, and **automatic launcher publishes and saves a complete initial capture**. Latest remote step p95 **39.164 ms**, pause **125.328 ms** (includes test settling). Ghidra emits terminal bad-file-descriptor/socket-close diagnostics during test teardown; no sidecar remains in process inspection.
- Actual desktop Ghidra main window is accessible through the wrapper, although menu/shortcut automation has been unreliable. Closed only the task-created empty manager PID 51052 and launched the latest packaged integration test with `--keep-open` for direct window verification. Session **14795**, log `final-ghidra12-test.log`, existing approved `.local/clean-launch12` profile; it will hold its restored register test state for 120 seconds then clean up.
- Steam Deck SSH details still not supplied. Native battle diagnostic session 32634 now VS → MAN → STANDARD; no attack captured yet.
- The held-open GUI test exposed a Ghidra Registers renderer exception after its extra launcher trace was closed directly. Adjusted harness to close that trace through DebuggerTraceManagerService first; added study-panel close guards. This is being rebuilt/retested; previous pass markers do not establish that final teardown issue is resolved yet.
- VS setup HP-clear watch event: original physical WRAM3 + 4, writer unbanked `$3B7B`, old uninitialized byte to 0. Explicitly **initialization, not combat**. No battle HP-change claim.

## Important race fixes under validation
- Real WRAM watchpoint tests passed: final byte 0x35, exact arbitrary writer, study panel uses renamed `StudentHPWriter`, breakpoint edits preserve the event's original snapshot.
- Repeated real tests exposed a snapshot publication race: Java received snapshot-added before batched bank fields, and mapped inherited WRAM1 into a snapshot later captured in WRAM3. Added **CaptureSnapshot** marker written after all capture bytes/attributes; BankMappings now requires marker == requested snapshot before reading banks or adding mappings. Tests wait for it too. This is a correctness fix, not a timing sleep.
- Added structured remote `kill`: pause, publish terminated state, save, then close transport and exit. Save retries only the structured "active transaction" error for up to 3 seconds while Java mappings settle. Socket is shut down before close to wake receiver. Lifecycle and mapping-race fixes are being tested; do not count latest incomplete run as passing.
- The final test pass marker now prints only after owned-sidecar exit and truthful TERMINATED-state checks.

## Complete-capture and lifecycle retest passed
- Latest `final-ghidra12-test.log` ends **REAL_TRACE_TEST_PASSED after all assertions**, including real WRAM event/label/history checks, complete-capture mapping guard, checkpoints, saved/reopened traces, automatic launcher initial capture/save, **owned sidecar exits after structured termination**, and **trace retains TERMINATED state**.
- No wrong-bank conflict or closed-trace renderer exception in this latest run. Ghidra's terminal implementation still logs a bad-file-descriptor diagnostic while its owned PTY closes; report it as a known teardown diagnostic rather than hiding it.
- SDL close now queues the same structured termination path; avoids abruptly closing transport while the machine remains represented as live. This small follow-up still needs the final UI close validation.
- Pending external gate: Steam Deck access/build/run/desktop evidence. Actual commercial battle remains unverified; current VS preview has no units yet. Source package and on-Deck commands exist but do not claim Linux binaries or battle completion.

## Real game acceptance session
- Preserved old native-only VS probe at `.local/game-evidence/vs-preview-continuation` and closed its process/session 32634. It never produced a combat claim.
- Opened **GameSession.java** using latest installed JARs, real Ghidra 12.1.2 tool (native control/listing/register/thread windows + GbcPlugin), a newly imported copy of the annotated GZF, real Trace RMI and SDL game window. PTY session **93747**. Commands: `run`, `pause`, `watch SLOT`, `save NEW_DIRECTORY`, `restore DIRECTORY`, `summary`, `trace`, `quit`. Game input must use normal SDL controls; no RAM edits to manufacture battle state.
- Full-state checkpoints created in this new session use production metadata schema 2 and are suitable for normal agent restore. Legacy diagnostic checkpoints remain schema 1 and are not silently migrated.
- Gameplay reference consulted: GameFAQs tutorial FAQ by Juigi, https://gamefaqs.gamespot.com/gbc/582119-game-boy-wars-3/faqs/33526 . It identifies tutorial map 2 as a normal combat scenario with opposing units. This is navigation context, not evidence that our battle passed.
- Actual Ghidra-connected SDL session progressed normally through title → New Game → empty DATA1 → commander name → mode selection. Selected Beginner mode via observed SDL screenshots. No experiment edits; goal is tutorial map 2 with opposing units. The native-only probe is closed; use session 93747 for real Trace RMI controls.

## Actual map battle verified, persistence fix pending replay
- In the real Ghidra-connected CLASS 2 mission, used normal SDL input to move HUMVEE and fire on APC. APC HP **10→3**; HUMVEE HP **10→5**. Watchpoint stopped at ROM bank 18. Saved `class2-after-attack`, restored production checkpoint **class2-fire-ready**, repeated the same action, obtained the same result. Trace events at snapshots **5 and 7**, epochs **0 and 1**, restored HP10 at snap6.
- Closed session 93747 and independently reopened project **Battle-1788577000775** / trace `/New Traces/GBC/student12`. `actual-battle-verification.log` reports **ACTUAL_GHIDRA_MAP_BATTLE_PASSED**: exact ROM fingerprint, target WRAM3 offset0x324/CPU D324 (slot50 HP), **writer rom18::40b5 / opcode0x70 / LD(HL),B**, function `FUN_rom18__40a1`; caller remains unknown. Old physical memory and mappings survived save/reopen and restore/repeat.
- Reopen exposed a Ghidra 12.1.2 codec bug: VariantDBFieldCodec allocates 1024 bytes; STRING encoder ignores overflow, silently truncating long values. Raw banked memory/events are intact. Changed UnitsData/CombatData to UTF-8 **byte arrays** (byte codec grows buffer on overflow). New reader warns for old truncated metadata rather than presenting false rows. Original battle evidence reconstructs relevant unit fields from captured WRAM; it labels that recovery explicitly.
- Need replay the saved Fire-ready checkpoint in a fresh session using the byte-array fields, then reopen and verify all 100 unit records persist.
- Added canonical event physical writer/target fields and correct physical overlay address for ROM0 remapping/echo execution. Native/Python test confirms ROM32 CPU $002B maps to rom32:$402B, and echo CPU $F002 maps to wram1:$D002. Duplicate canonical execution breakpoints now resume past the instruction once. Latest native suite passes.
- Started fresh replay session **47985** with byte-array unit/COMBAT attributes and latest installed JARs; restored production checkpoint `class2-fire-ready`, armed slot50 HP, resumed. Current new project name is in the session's GAME_SESSION_READY output. Need Fire/confirm twice across restore, then export/reopen evidence with ExportBattleEvidence.java to verify all100 unit records survive.
- Versioned runtime installer/rollback passed, and real automatic launcher test used that copied runtime successfully. This fixes the earlier limitation where rollback restored only extension JARs while the agent/native library remained in the mutable development checkout.
- Knowledge export passed: 9,789 symbols (including generated/dynamic entries), 1,792 functions, 3 structures, 18 comments. Read-only output `build/experiments/student.knowledge.json` is excluded from distribution.
- Checking a pinned Zig cross-compiler as a bounded attempt to produce a Linux x86-64 library on this Mac. Actual Steam Deck execution/desktop remains unverified regardless of cross-build outcome.

## Final handoff state
- Final real Ghidra test: **REAL_TRACE_TEST_PASSED**; RMI step p95 **34.037 ms**, pause **143.069 ms** including test settling, on the named Mac. Live breakpoint edits preserve RUNNING state; deleted specs remain historical; IDs do not reuse earlier identities.
- **ACTUAL_GHIDRA_MAP_BATTLE_PASSED** after independent reopen, including all100 unit records, exact writer, physical memory, mappings and checkpoint replay.
- Installed-runtime self-rollback passed. Doctor run from the actual installed runtime returns `ready_for_generic_tests: true`. Process audit found **no owned test/agent processes**.
- Linux `.so` is ELF64 x86-64, all16 ABI exports verified, GNU libc target2.28. **Not executed on Linux/Steam Deck.** Bundle includes software + self-authored teaching ROM only; commercial assets excluded.
- Final Mac runtime: `/Users/joshuahansen/Library/ghidra/ghidra_12.1.2_PUBLIC/GhiGBC-runtime/0.1.0-20260904T222610375078`.
- Final rollback manifest: `/Users/joshuahansen/Library/ghidra/ghidra_12.1.2_PUBLIC/GhiGBC-rollback/20260904T222610375078/manifest.json`.
- Deliverables: `dist/GhiGBC-0.1.0-linux-x86_64.tar.gz`, `dist/GhiGBC-0.1.0-source.tar.gz`, extension ZIPs, teaching ROM and `dist/SHA256SUMS`.
- Next required action: execute the candidate on the Steam Deck using `docs/STEAM_DECK.md`, or supply SSH user/host and Ghidra path. The student-on-Deck gate remains unverified; do not mark the full deployment objective complete.

## Goal continuation — immutable input identity

- Previous goal turn classified as **progress**: implementation, installed runtime, cross-build and real battle evidence changed authoritative state. This continuation also made progress; it is not a blocked/no-progress turn.
- Completion audit found a local correctness gap: Python fingerprinted a ROM before the C core reopened its path, and checkpoint/trace boot metadata reread the boot file later. A replacement between reads could make metadata describe bytes other than those loaded.
- Added two deterministic tests using the real native library and controlled file replacement. Both failed on the previous implementation (`input-identity-before.log`) and now pass (`input-identity-after.log`).
- Added the backward-compatible ABI-1 `gc_create_buffers` entry point. The production agent supplies its immutable ROM and 2304-byte CGB boot copies; SameBoy copies both before returning. Trace boot content and checkpoint boot fingerprints use the loaded copy, not the current path. Existing matching checkpoints remain compatible.
- `scripts/test_native.sh`: **21 tests passed**. `input-identity-ghidra.log`: **REAL_TRACE_TEST_PASSED**, including the copied-runtime launcher, trace history and structured shutdown. macOS and Linux libraries rebuilt; Linux ELF inspection confirms the additional export. Linux execution remains unverified.
- The earlier top-level claim that only deployment proof remained was too broad: paused/focus-loss desktop behavior and direct UI-action/remote-edit evidence still need explicit completion-audit coverage. Next local action is to close those acceptance gaps; Steam Deck access is still required for its platform gate.

- Updated Mac runtime: `/Users/joshuahansen/Library/ghidra/ghidra_12.1.2_PUBLIC/GhiGBC-runtime/0.1.0-20260904T224937492315`. Rollback: `/Users/joshuahansen/Library/ghidra/ghidra_12.1.2_PUBLIC/GhiGBC-rollback/20260904T224937492315/manifest.json`.

## Goal continuation — paused desktop input and close

- Previous goal turn classified as **progress** (immutable input loading fix and verified rebuilds). This turn also made progress by obtaining missing desktop evidence.
- Added additive ABI-1 `gc_key_mask`, a locked read of native held-button state without guest bus reads. It lets the acceptance probe observe actual input state while the emulator is paused.
- Ran `tests/paused_display_probe.py` with the real SameBoy machine and SDL desktop window. CUA keyboard Z produced A-key transitions 0→16→0. Seeded a guest-held A through the native API, then used the actual window minimize button: key mask became0. Seeded it again and closed the actual window: close callback observed mask0, display returned, process exited0. **All observations retained tick26171648**, so input/event processing did not resume the emulator. Evidence: `paused-display.json`; no dummy driver. Initial held state was seeded through the ABI, not a physical held keyboard event.
- Added `--display-close` to the real Ghidra test. Actual CUA close of its launched paused SDL window passed: connection closed, trace reported TERMINATED, and independently reopened trace retained TERMINATED. Full test ended **REAL_TRACE_TEST_PASSED** (`ghidra-desktop-close.log`). CUA reported the app quitting; the exact process handle independently returned exit0.
- Native suite remains **21 passing tests**. Both libraries rebuilt, with Linux ABI inspection updated for the new read-only export; Linux execution still unverified.
- Steam Deck target input/focus/desktop gate remains open. Next local audit item: strengthen evidence for explicit remote experiment edits and capture provenance, without treating native-only edit tests as full UI proof.

- Refreshed installed runtime: `/Users/joshuahansen/Library/ghidra/ghidra_12.1.2_PUBLIC/GhiGBC-runtime/0.1.0-20260904T230437459516`; rollback manifest `/Users/joshuahansen/Library/ghidra/ghidra_12.1.2_PUBLIC/GhiGBC-rollback/20260904T230437459516/manifest.json`.

## Goal continuation — experiment edits and provenance

- Previous goal turn classified as **progress**: real paused input, focus-loss and integrated close evidence. This continuation also made concrete progress.
- Audit found that edits only left a local `edit.json`; the trace did not identify debugger-origin changes or link them to recovery. Added immutable edit records under `Machine.Edits`, with snapshot/epoch, before/requested/actual-after, physical target or register, recovery path and state SHA256. They are separate from guest CPU access events.
- WRAM edits now use a narrow native physical-bank write API, bypassing guest bus restrictions/watch hooks and clearing stale writer/call state. Input is validated before checkpoint creation. Intent is written before mutation, actual result afterward; AF masking is recorded accurately.
- Native edit tests pass for refusal/no artifacts, normalized register result, recovery, echo-to-physical-bank identity and absence of guest watch events. Full native suite: **24 tests pass**.
- `experiment-ghidra.log` ends **REAL_TRACE_TEST_PASSED**: real remote BC edit/readback/recovery, physical WRAM edit/recovery, preserved older values, debugger-origin records and recovery fingerprints after independent reopen, default-mode/running-mode rejection. These are real Ghidra remote-method checks, not claims that every edit dialog was clicked manually.
- Both native libraries rebuilt; Linux ABI inspection includes `gc_edit_wram`. Linux/Steam Deck execution remains unverified. Next completion-audit item is direct bank-aware UI navigation/action evidence and remaining deployment checks.

- Updated runtime: `/Users/joshuahansen/Library/ghidra/ghidra_12.1.2_PUBLIC/GhiGBC-runtime/0.1.0-20260904T232556585170`. Rollback manifest: `/Users/joshuahansen/Library/ghidra/ghidra_12.1.2_PUBLIC/GhiGBC-rollback/20260904T232556585170/manifest.json`.

## Goal continuation — standard Debugger UI fixture (2026-09-05)

- This continuation made progress: fixed the interactive harness initialization, started the shipped Debugger template with a real FrontEndTool, and added a reproducible interactive acceptance command. Previous turns also made progress; this is not a third consecutive no-progress turn.
- `tests/ghidra/UiActionTest.java` prepares a fresh teaching project, renamed bank block, student labels and an existing bookmark, then observes actual registered actions. It requires a canonical bank-2 breakpoint, native Resume stops, historical writer navigation and preserved bookmark text. It does not invoke those UI actions itself.
- The initial minimal tool lacked ordinary static navigation. Loading the standard template first failed because the IDE plugins require an active Ghidra front end. Creating the normal FrontEndTool before the Debugger tool resolved that concrete fixture failure.
- Real 12.1.2 standard tool and agent reached `PASS initial capture mappings ready`. CUA zoomed the off-screen saved layout and opened Navigation > Go To. Subsequent desktop calls repeatedly returned `noWindowsAvailable`/`timeoutReached`. Thread dump `docs/evidence/ui-action-thread-dump.txt` showed the Java UI thread waiting for events and the test waiting for the first action. This is incomplete interactive evidence, not a product pass or proof of a product deadlock.
- A dedicated macOS jpackage app was used to distinguish the fixture from other Java applications. The portable continuation is `bash scripts/test_ui_actions.sh`; it builds and starts the same observer in a separate user profile. `bash -n scripts/test_ui_actions.sh` and compilation against installed Ghidra 12.1.2 JARs pass (only upstream deprecated importer warnings).
- Production binaries and installed runtime did not change in this continuation. Steam Deck access/execution is still unavailable. Next concrete gate: finish the observed UI actions on a controllable desktop, then execute the Linux candidate and desktop checks on the Deck. No new broad native suite was run for this harness/documentation-only change.
- End-of-turn process check found neither the owned validation PID nor any `ghigbc.agent` process. The log contains no `UI_ACTIONS_PASSED` marker; the last recorded phase remains `bank_breakpoint`. Packages were refreshed and checked for valid SHA256 sums, inclusion of interactive continuation files, and exclusion of commercial ROM/project/save artifacts.

## Goal continuation — historical writer UI fixed and verified

- Previous turn classified as **progress** (standard-tool fixture and continuation command). This turn made concrete product progress and obtained actual UI evidence.
- Retried with the owned jpackage app under a tracked process handle. Normal Ghidra Go To worked using paste into the focused field; right-click injection did not expose the menu reliably, so used the installed standard action chooser (Cmd+3), selected the same registered physical-bank action, and clicked OK. This is a real UI action, not an API substitute.
- Before-fix UI sequence proved bank-qualified action and native Resume, then exposed a product error: Go to writer attempted snapshot5 from snapshot8 while Control Target mode follows the present. Ghidra refused time navigation. Evidence retained in `ui-actions-before-navigation-fix.log` and the observed status message.
- GbcPlugin now uses read-only Trace mode for historical writer navigation when the current control mode follows the present. It explicitly activates the event's trace before the snapshot and checks closed trace/program handles. This changes observation coordinates only; it does not restore the emulator. QUICKSTART explains returning to Target mode.
- Extension rebuild `ui-navigation-build.log`: BUILD SUCCESSFUL. Reinstalled into isolated profile and repeated the same actual UI sequence. `ui-actions.log`: **UI_ACTIONS_PASSED**, owned process session37704 exit0. Observer verifies canonical ROM bank2 breakpoint, native Resume stops, event from WRAM3, later PC4567, exact static writer and historical snapshot, read-only Trace mode, and preserved existing bookmark text. No direct game-profile HP-button claim.
- The passing full-tool run logs a Ghidra `ObjectTreeModel` duplicate MappingReady node assertion, plus macOS JMenu accessibility child-index exceptions. The UI sequence completes, but the Model-tree symptom remains a concrete follow-up; do not describe this as a diagnostic-free run.
- Installed verified fix into actual per-user runtime `/Users/joshuahansen/Library/ghidra/ghidra_12.1.2_PUBLIC/GhiGBC-runtime/0.1.0-20260905T001524387505`; rollback manifest in the matching `GhiGBC-rollback/20260905T001524387505/manifest.json`. Authoritative copied JSON: `docs/INSTALLATION.json`.
- No native changes, so no repeated broad native suite. Next local checks are the Model-tree diagnostic and actual HP-panel command; Steam Deck deployment still needs target access. Goal remains active with meaningful progress.

## Goal continuation — exact mapping marker and real HP-panel action

- Previous goal turn classified as progress (historical-navigation fix and actual registered UI proof). This turn made further concrete progress; no blocked-threshold claim.
- Inspected installed ObjectTreeModel listener/node bytecode. The ready boolean alternated false→true, causing same-value lifespan merging and duplicate child insertion in the Model tree. Replaced the handshake with Java-owned numeric `MappingSnapshot`, written with the completed mapping transaction. Readers require exact snapshot equality; old saved traces retain boolean fallback support. The agent no longer resets the boolean on every publication.
- `mapping-marker-build.log`: BUILD SUCCESSFUL. `mapping-marker-ghidra.log`: REAL_TRACE_TEST_PASSED / process exit0, including exact marker, rejection for an uncaptured future, historical reopen, bank mappings, edits, copied runtime launcher and termination. Remote step p95 33.558ms; pause130.44ms including the test's settling delay. No duplicate-ready assertion recorded in this run. No native changes or redundant native-suite rerun.
- Added `HpWatchUiTest` / `scripts/test_ui_actions.sh --hp`. The initial trace can exist before its first snapshot; fixed a concrete observer null-unboxing race and preserved its before-fix error. The fixture imports the private annotated GZF copy and restores the real pre-attack checkpoint without fabricating RAM/state.
- Actual CUA selection of APC slot50 (HP10) and Watch selected HP verified physical WRAM3 offset0x324 / WRITE in the real trace. Saved evidence: `hp-ui-result.json`, `hp-ui.log`. This proves the actual game-panel command, not a new full attack replay.
- The standard tool's native Mac decompiler stalled before startup, sampled at `_dyld_start`; its Java wrapper held a monitor needed by the UI. Evidence: `hp-ui-restored-threads.log`, `mac-decompiler-stall.log`. Its binary is arm64 and retains Chrome quarantine metadata, but cause is not established. System Settings Privacy & Security showed no pending Open Anyway approval. Stopping the verified owned native child released the UI for the HP action. Ghidra attempted decompilation again and cleanup stalled; final process exit1. This is not a clean session pass. Fixed premature HP_UI_PASSED placement in the test so that future full-pass markers require completed cleanup.
- Installed matched new agent/extension runtime `/Users/joshuahansen/Library/ghidra/ghidra_12.1.2_PUBLIC/GhiGBC-runtime/0.1.0-20260905T003458559941`; rollback uses the matching timestamp directory. `docs/INSTALLATION.json` is current.
- Next concrete work: resolve or establish the native Mac decompiler limitation without weakening OS protections; then complete the remaining deployment audit. Steam Deck execution/desktop access is still unavailable. Actual button proof does not substitute for target desktop evidence.

## User-authorized retry — HP session and cleanup passed

- User reported possibly closing the window before approving computer use and asked to retry. Reused the approved desktop scope; did not modify OS security settings or native decompiler binaries.
- The retried real Ghidra session restored the verified pre-attack checkpoint, displayed the real APC slot50 HP10 row, and the actual Watch selected HP button created WRAM3 offset0x324 WRITE. The native decompiler stall did not recur.
- Fixed two observer cleanup issues found during the retry: ordinary FrontEndTool.dispose calls System.exit(0), which could mask errors/skip the observer's final report; test-only TestFrontEnd now lets cleanup return. Clearing the active trace before disposal also prevents a queued target-withdrawal event from trying to reactivate a closed trace. These changes affect acceptance fixtures, not the installed plugin.
- Final owned process session21511: **exit0**. `hp-ui.log` ends **HP_UI_PASSED**, after agent shutdown, tool/front-end disposal, imported-program release and project close. No ERROR, Exception, or duplicate node assertion appears in the final log. `hp-ui-result.json` supersedes the earlier action-only/failed-teardown result. Previous logs retained under explicit prior/failure names.
- Production runtime remains the verified 20260905T003458559941 version. Source/Linux candidate bundles refreshed with current source, test and evidence. The remaining platform gate is actual Steam Deck execution/desktop validation; the complete objective still requires its final audit and target evidence.


## Completion audit and student handoff

- Previous goal turn classified as progress: real HP command and full cleanup passed. This continuation also made concrete implementation and delivery progress.
- Audited the expanded handoff and T01–T18 against current source/evidence. Added the missing event-panel epoch and detail view for physical target/HP field, CPU addresses, attempted value, access origin and precision. Data always comes from the event's original snapshot. Real trace checks reject game field labels on generic ROMs; independent actual-battle reopen checks identify slot50 HP and its original epochs. CUA rendered/read the detail pane and completed writer/bookmark actions; UI_ACTIONS_PASSED / exit0. Mac accessibility menu diagnostics remain in that run's log, separately from passed assertions.
- Doctor now verifies SDL2 loading/version and distinguishes desktop prerequisites from actual desktop proof. `doctor-audit-mac.json` passes the readiness checks.
- Added and ran a bounded250-stop integrated growth measurement. `integrated-growth.json`: agent RSS +16KiB, Ghidra RSS +178320KiB, saved trace +1196032 bytes, dropped0, 12.406s. Warm step p95 37.625ms / pause269.863ms including settling. History intentionally grows; no long-term leak or saturation proof claimed. An initial restore-read assertion failure was retained, and the observer now explicitly waits for completed restored captures; the rerun passes all assertions.
- Restored captures now retain immutable checkpoint-source path/SHA/session/epoch/ticks; subsequent checkpoints carry their parent. `checkpoint-parent-native.log`:25 native/control tests pass. `checkpoint-parent-ghidra.log`: REAL_TRACE_TEST_PASSED, including source links/fingerprints after independent reopen. No C ABI/native library change was needed.
- Installed final matched runtime `0.1.0-20260905T011833040074`; `docs/INSTALLATION.json` is synchronized with the installer result.
- User confirmed his son's Steam Deck has no SSH enabled and requested an offline handoff. Created a curated ZIP with START-HERE/README, Setup.sh, Validate.sh, Collect-results.sh, visible NOTES.txt, the Linux library, both extension archives, teaching ROM, source, licenses and portable guides. Setup remembers target Ghidra/JDK paths, checks the selected version/platform and uses the existing offline installer. Validation separates automated and interactive phases. Collection allowlists logs/notes and excludes symlinks and private game files; failures are retained with timestamps.
- `deck-handoff-tests.log`:2 handoff helper tests pass (wrong-version rejection and collector exclusions). Extracted ZIP entry points/help, Python/shell syntax, manifest hashes, archive integrity, native/teaching payload selection and result collection verified locally. This is packaging/orchestration validation, not Linux execution. Mac development logs are not preloaded into target result folders.
- Target desktop execution has remained unavailable across the prior UI, HP and audit continuations. All current local implementation/handoff work is complete; actual Steam Deck acceptance now requires his local run and returned results. Do not request SSH again or claim the student is up and running before those results arrive.

## Full engineering handoff report

- At the user's request, consolidated the entire implementation history into `docs/HANDOFF_REPORT.md`: starting assets, preservation, version changes, architecture decisions and reasons, native/Trace RMI/UI work, checkpoint/edit provenance, actual battle evidence, failed approaches and fixes, validation scopes, performance, installation/rollback, deliverables, repository state and remaining target work.
- Checked the report against the chronological log, current installation manifest, dependency pins, actual-battle data, growth/doctor results and repository HEAD. It distinguishes the inclusive symbol-export count from the earlier audit count and retains the limits of desktop, cross-build and test evidence.
- Included the report in the student handoff ZIP and linked it from START-HERE. Updated source/Linux archives and checksums. No emulator or debugger behavior changed for this reporting request, and no new Steam Deck execution is claimed.
