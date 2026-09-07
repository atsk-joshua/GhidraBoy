# Generated integration qualification report

**INCOMPLETE** — Local qualification only. Physical Steam Deck deferred. No publication or archival.

Source commit: `baead1028bdee1ad122afd4e2fd6237e14e5d2dc`. Receipt and archive hashes are in the adjacent JSON.

| Original gate | Status | Requirement |
| --- | --- | --- |
| BASE-01 | PASS | exact source/dirty-file and binary manifests exist; original checkouts, private assets and rollback archives remain unchanged. |
| BASE-02 | PASS | every current public workflow/test suite has a destination and baseline status. Existing failures have reproductions and an explicit disposition; migration-caused failures cannot be hidden among them. |
| BASE-03 | PASS | saved annotated Program fixtures cover historical upstream and current provider formats, including the persisted POP constructor regression. Trace fixtures cover legacy/current mappings, profiles, edits and checkpoints. |
| BASE-04 | PASS | one compatibility table lists extension/class names, scripts, Python imports, C ABI, schemas, launchers, GhiBW3 dependencies and supported upgrade paths. |
| SPIKE-01 | PASS | executable probes and result receipts identify tested versions, exact operations, observed semantics, missing capabilities and any required upstream patches. |
| SPIKE-02 | PASS | compare cost of native embedding versus remote attachment, including pause safety, safe peeks and identity verification; select mGBA integration mode based on evidence. |
| SPIKE-03 | PASS | provisional contract covers both probes without exposing either engine's internal types. Unsupported external coherence is rejected or explicitly graded; never fabricated. |
| SPIKE-04 | PASS | record a go/no-go decision for mGBA Basic Debugging. If it cannot meet the minimum, Release A may continue; Release B remains incomplete until an evidence-backed second backend is selected and passes M8. Do not add more candidates without resolving the failed requirement. |
| MOVE-01 | PASS | source history is reachable or explicitly retained in the source bundle; every imported supported file matches the source hash before subsequent edits. |
| MOVE-02 | PASS | all exclusions/relocations have recorded reasons and license provenance. No duplicate SM83 language or study implementation appears. |
| MOVE-03 | PASS | original static build and imported component tests run from their documented paths. No unexplained behavioral difference from M0. |
| BUILD-01 | PASS | clean static checkout builds/tests without emulator binaries, Python runtime setup, SDL, native compiler or debugger project dependency downloads. |
| BUILD-02 | PASS | clean full checkout builds without neighboring GhiGBC/GhiBW3 repositories, absolute developer paths, stale build outputs or manually selected provider JAR filenames. |
| BUILD-03 | PASS | packages contain one static provider, no bundled compile-only provider copy, correct notices, no private assets, and a deterministic source/dependency manifest. |
| BUILD-04 | PASS | root commands are documented and exercised from a fresh checkout and paths containing spaces. Existing public commands either work through thin delegates or have tested migration guidance. |
| BUILD-05 | PASS | packaging identifies stock versus patched native decompiler requirements; the doctor detects mismatches and never silently overwrites an active Ghidra distribution. |
| BACKEND-01 | PASS | structural checks find no SameBoy headers/private fields outside its adapter, and no native handle/API access from generic agent/UI/display/profile code. Compatibility readers and labeled provenance may mention SameBoy. |
| BACKEND-02 | PASS | run identical self-authored fixtures through the pre-extraction and new SameBoy paths; compare defined registers, physical bytes, stop reasons, event order/precision, bank mappings, edits and restore semantics. |
| BACKEND-03 | IN_PROGRESS | pause during run/queue saturation, timed-out requests, disconnect/reconnect, target exit, callback ordering, event overflow and shutdown have bounded behavior with visible error/loss reporting. |
| BACKEND-04 | IN_PROGRESS | display input, focus loss, minimized/paused pumping, frame copying and close work through the abstraction without stale held keys or lock inversion. |
| BACKEND-05 | PASS | startup and action requests reject unsupported model/mapper/capability combinations explicitly; capability enforcement does not rely on disabled UI controls alone. |
| COMPAT-01 | PASS | copied old Programs reopen with preserved constructor identity, comments, symbols, types, functions, overrides and ownership receipts; removal never deletes later user work. |
| COMPAT-02 | PASS | legacy and new traces reopen in separate processes with no emulator runtime loaded and no optional study profile; raw memory, old paths, historical mappings, writer precision and edit/parent-checkpoint evidence remain inspectable. |
| COMPAT-03 | PASS | schema-2 SameBoy checkpoints restore only with compatible identities. Wrong engine/core/patch/ROM/boot/model, corrupt payloads and unsupported schema versions fail before mutation. |
| MAP-01 | PASS | renamed/split/partial blocks, overlays, alias ambiguity, current patches, detached sources, view selection and conflicting user mappings retain existing correctness and ownership behavior. |
| MAP-02 | PASS | capture/save/mapping barriers survive rapid stepping, Program switching, save/close/reopen and reconnect; historical selections never silently follow or modify the current target. |
| PROFILE-01 | PASS | GhiBW3 static-only, live, missing/failing/wrong-revision profile and profile-removal/reopen cases pass. Generic package class loading and startup require no study code. |
| PROFILE-02 | PASS | stale session/epoch/capture actions, oversized declarations and failed decodes are rejected with preserved raw controls/history; field batches retain complete provenance and counts. |
| A-STATIC | PASS | all current SLEIGH, static analysis, mapper, compiler ABI, generated-C/native decompiler, ownership, schema and actual database migration gates pass for the selected dependency tuple. |
| A-RUNTIME | IN_PROGRESS | native/Python and real installed Trace RMI gates pass, including 250-stop growth, paused display, edits/checkpoints/reopen and shutdown error scanning. |
| A-INSTALL | PASS | clean install, upgrade, interrupted install/recovery, altered-user-file preservation, component removal and rollback pass on macOS arm64 and Linux x86-64 using extracted packages without source/build tools. |
| A-GUI | IN_PROGRESS | identify the exact installed candidate and use real Ghidra actions for import, launch, step, physical breakpoint/watch, historical navigation, bookmark, save/reopen, cancel and close. Headless harnesses alone do not pass this gate. |
| A-PERF | PASS | comparable baseline/candidate runs meet the performance checks in section 6. No unexplained unbounded queue, memory or thread growth. |
| A-RELEASE | NOT_RUN | reproducible artifacts and complete provenance exist; an installed end-to-end debugging smoke test passes with a self-authored fixture; each support claim points to a passing gate. Platform-specific blocked gates prevent claiming that platform supported. |
| HW-01 | PASS | boot/model selection and actual reported configuration agree; reject incompatible boot images and silent model fallback. Exercise true DMG and both CGB modes independently. |
| HW-02 | PASS | ROM-only/MBC1/MBC2/MBC3/MBC5 advertised geometries pass selector/alias/boundary tests, including MBC2 nibble/mirror behavior, MBC5 bank 256, MBC1 lower-window changes, SVBK zero and echo RAM. Unimplemented wiring remains unknown/unsupported. |
| CPU-01 | PASS | preserve all existing exhaustive arithmetic/CB/stack/control-flow regressions and pinned external vectors; inventory all base/CB encodings and expand missing families. Report actual cases, undefined opcodes, masks and exclusions, not “100% CPU accuracy” from an opcode count. |
| HW-03 | PASS | applicable hardware ROM suites exercise timers, interrupts/EI delay, HALT/STOP, bus restrictions, boot unmapping, CGB speed switching and DMA/HDMA behavior. A correct engine result does not prove the debugger's event attribution is correct; check those separately. |
| ACCURACY-01 | PASS | a debug-instrumented run matches a pristine-core run for comparable defined state/output; nondestructive inspection leaves engine state unchanged; instrumentation patches cannot validate themselves solely through their own event output. |
| ACCURACY-02 | PASS | cross-backend fixtures normalize model/boot/clock/input and compare defined registers/memory at explicit synchronization boundaries. Differences produce minimal reproducers and classified explanations, never majority-vote correctness or blanket suppression. |
| HW-04 | PASS | distinguish collected physical-hardware evidence from published test expectations and emulator results. Unavailable hardware stays unverified, with model/revision and retrieval provenance recorded for external evidence. |
| MGBA-01 | PASS | all Basic Debugging conformance tests pass on its declared DMG/CGB modes and mapper set, including identical CPU PCs in different banks and clean detach/close behavior. |
| MGBA-02 | IN_PROGRESS | physical watches, edits, checkpoint/restore and over/out are either independently tested with declared precision or rejected as unsupported. Backend capabilities and actual UI/API behavior agree. |
| MGBA-03 | PASS | common static mapping, selected-capture, save/reopen and synthetic-profile tests run unchanged against both real backends. Tests parameterize capabilities; a blanket skip cannot pass a required tier. |
| MGBA-04 | PASS | install only mGBA with SameBoy absent and vice versa; neither selected backend relies on the other's shared library, boot asset or metadata. Recorded traces remain readable after removing either runtime. |
| MGBA-05 | PASS | mismatch fixtures compare the two cores without demanding identical undefined startup memory, wall-clock RTC or backend-private state formats. At least one disagreement fixture proves the diagnostic path works. |
| MGBA-06 | IN_PROGRESS | both backends run from extracted platform packages and pass resource, failure and cleanup gates. Mark experimental until its required tier passes on the named platform. |
| TOOL-01 | IN_PROGRESS | from a fresh installation, import a banked fixture, launch either supported backend, set a physical breakpoint from the listing and navigate the resulting capture back to the correct static bank. No manual address conversion or developer-only command is required; ambiguity uses the supported view selector. |
| TOOL-02 | IN_PROGRESS | register/memory inspection, watch setup, history filtering, capture comparison and checkpoint/edit operations have executable checks plus real GUI acceptance. Actions operate on the selected session/capture, and unavailable capabilities fail with a specific reason. |
| TOOL-03 | FAIL | listing, decompiler, memory and history views retain coherent selection and useful state through stepping, Program/session switching, reconnect and reopen. Long operations remain cancellable; malformed inputs and backend failures leave usable controls and diagnostics. |
| RESEARCH-01 | PASS | a synthetic experiment can be exported, reopened without the emulator, and traced from a conclusion to exact observed bytes and source locations. Invalid/stale Program bindings remain visible. |
| RESEARCH-02 | PASS | restore/repeat under controlled conditions reproduces declared results; divergent settings and missing replay capabilities are detected. A bookmark naming a writer never becomes proof of a caller or damage formula. |
| UI-01 | IN_PROGRESS | keyboard navigation, readable labels/statuses, cancellation, capability-disabled actions, display scaling and historical/live selection are checked on claimed platforms. Routine operation requires no knowledge of internal ABI/schema names. |
| B-RELEASE | NOT_RUN | M7–M9 and the refreshed Release A gates pass for every claimed release configuration. Backend-specific research differences are published; universal parity is not implied. |
| DEVICE-01 | NOT_RUN | actual Steam Deck installation, input/focus, pause/close, readable UI, real Trace RMI, save/reopen and performance pass before advertising Deck acceptance. A virtual display/container cannot substitute. Windows is a separate future platform gate, not inherited from an emulator's platform support. |
| CUTOVER-01 | PASS | a fresh contributor needs only GhidraBoy for generic builds and only the additional GhiBW3 checkout for game-specific work; no generic ledger, fixture or release operation depends on the old GhiGBC checkout. |
| CUTOVER-02 | PASS | The standalone checkout is removed. Current ownership and command paths are documented in ../repository-ownership.md; no separate compatibility checkout or archive is required. |
| CUTOVER-03 | PASS | Standalone-checkout retention is superseded by the two-repository cutover. Keep extension/package identifiers and saved-work readers inside GhidraBoy; household commands live in GhiBW3. See ../repository-ownership.md. |
