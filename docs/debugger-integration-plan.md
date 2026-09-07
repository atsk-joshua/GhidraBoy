# GhiGBC → GhidraBoy integration plan

Status: implementation in progress; executed checks and remaining gates are tracked in the [execution ledger](integration/progress.md) and [gate status](integration/status.json). Prepared 2026-09-05 against the local checkouts below. Requirements below do not themselves establish completion. Milestone IDs in this document are independent of the earlier GhiBW3 suite integration milestones.

### Execution checkpoint — documentation-only pause after GUI failures

Runtime code remains `1fce58f`; latest prior documentation commit is `baead10`.
Read the current [handoff](integration/agent-handoff.md),
[state](integration/handoff-state.json), [58-gate register](integration/status.json),
and [full-tool teardown investigation](integration/gui-teardown-investigation.md).
The user stopped CUA execution and asked for this documentation refresh.
**Neither release nor the non-Deck outcome is fully qualified.**

- Scoped final Mac/Linux component checks, reproducible packages/source archive,
  static/hardware/shared-profile/research/private-consumer checks, both30-minute
  soaks and controlled/all-retained latency budgets passed on their recorded
  exact inputs. Preserve all earlier failures and scope limits.
- The original register-renderer repair and uncaught collector are implemented.
  Later full shipped-tool disposal exposed different errors: stale current trace
  coordinates, an observed uncaught activation error, and logged logical-breakpoint
  failures despite exit0/empty uncaught queues. Exact original stack not independently
  reproduced; proposed orderly-teardown barrier is unimplemented/unqualified.
- Broad lifecycle acceptance is reopened; physical GUI workflows remain incomplete.
  Repeated fresh/timed launches caused first-run dialogs and CUA confusion. The user
  confirmed all open Ghidra sessions were assistant-created and requires one
  persistent configured session, without concurrent native GUI probes.
- The last OS inventory found intended patched12.1.3 and unintended old12.1.2
  JVMs; the user subsequently reports killing them. Generic Java CUA selection is ambiguous; no further target assumptions.
  VNC is stopped, Chrome connection concern is unresolved, and the old
  license-approval-only blocker is stale.
- GhiGBC cutover `65e1208`/`413a971` and private GhiBW3 `99802e0`/`29145f8` remain
  committed. Histories, artifacts, rollback inputs, delegates and unrelated files
  remain preserved. Physical Steam Deck is explicitly deferred; no publication
  or remote archival is authorized. Original requirements below are unchanged.

## 1. Outcome and release boundaries

Make GhidraBoy a first-class environment for Game Boy and Game Boy Color analysis, debugging and research: import and preserve a ROM, analyze code and data, inspect hardware state, control execution precisely, conduct repeatable experiments, and retain evidence that another researcher can inspect.

Teaching workflows, lessons, curricula and guided educational exercises are outside the product scope. Hardware understanding comes from accurate inspection, integrated analysis and reproducible evidence. Documentation supports installation, operation, API contracts and troubleshooting; synthetic ROMs are regression fixtures. Prioritize correctness, debugger capability, usability and reliability when evaluating milestones.

Integrate GhiGBC into the maintained GhidraBoy repository as an optional debugger module. Keep one static SM83 provider, one generic debugger implementation, and small emulator adapters. Keep GhiBW3 as an external, optional example of game-specific research tooling. Reuse Ghidra's debugger, listing, decompiler, navigation and persistence rather than building a second IDE.

Deliver in two independently useful increments:

- **Release A — integrated SameBoy parity:** one checkout, coordinated builds and installation, backend boundary, preserved static/runtime behavior, compatible saved work, and verified end-to-end debugger operation. Requires M0–M6. This is a migration release, with its current hardware and debugger limitations stated.
- **Release B — multiple backends and broader GB/GBC coverage:** real DMG/CGB model selection, expanded accuracy evidence, supported mGBA baseline, capability-aware analysis and research tools, and final installed acceptance. Requires M7–M10 as well as Release A's gates. An mGBA prototype alone does not qualify.

“Full support” means preserving all existing supported behavior and completing the declared release matrix. It does not mean every cartridge controller, hardware revision, peripheral, emulator, or debugging feature is already implemented. The long-term ambition is broad coverage; each additional claim requires a testable contract and evidence.

## 2. Inspected baseline and immediate issues

| Repository | Inspected HEAD | Relevant ownership |
| --- | --- | --- |
| GhidraBoy | `53df8b29287d2211fe54597cb989f6cba82f5811` | SM83, loader, physical/static mapping, conservative analysis, compiler conventions, native decompiler fixes |
| GhiGBC | `c1cfeef2140a48302f4bcccffd4464df5349d98c` | SameBoy adapter, session execution, Trace RMI, captured history, installation and generic profile API |
| GhiBW3 | `c7241685da724e5701e93a41ed19ab192ff34ebf` | Optional exact-revision static/live study tools and legacy PyBoy research |

These are planning anchors, not frozen migration inputs. M0 must record new heads, dirty files, artifact identities and active worktrees before implementation. Observed untracked materials include GhidraBoy's changes report and GhiGBC's student guide/output directory; they must not be accidentally imported, deleted or packaged.

Findings that determine the design:

1. GhiGBC already compiles against the separate GhidraBoy provider and packages both extensions. Build/package scripts still name `GhidraBoy-20260905-suite1.jar`, while the current provider build declares `20260905-decomp3`. Eliminate path/version guessing through build outputs, not another fallback filename.
2. The existing C ABI uses owned handles and copied fixed-width records. Preserve that useful encapsulation. The C implementation nevertheless uses `GB_INTERNAL` and a CPU-bus instrumentation patch; those belong entirely to the SameBoy adapter.
3. The Python agent and display directly call `machine.lib`/`machine.handle`. The agent embeds SameBoy identity, event coverage, and an 8 MHz timebase. An abstract class alone would not remove these dependencies.
4. The native implementation selects `GB_MODEL_CGB_E`; Python accepts a 0x900-byte CGB boot image. The existing DMG test changes the cartridge header while using this same machine. True DMG model coverage needs separate work and evidence.
5. Runtime mapper support is ROM-only/MBC1/MBC3/MBC5; static mapping also models MBC2. RTC-selected/device bytes are unresolved at runtime. CPU access watches report attempts and final instruction-boundary bytes; DMA/HDMA attribution is unclaimed.
6. Saved traces, mapping generations, recoverable edits, ordered callbacks, queue limits, profile isolation and annotation ownership already have substantial tests. These are migration requirements, not candidates for simplification away.
7. `ghigbc.StudyProvider` is now generic history UI despite its name. GhiBW3 directly consumes `GbcActionService`, `BankMappings.isReady`, and Python `ghigbc.profile` types. Preserve those compatibility surfaces while replacing internal coupling.
8. Evidence is distributed across all three repositories, and some reports describe 12.1.2 or older 12.1.3 artifacts. None proves acceptance of the current combined heads. Reconcile evidence by exact source/toolchain/artifact tuple.
9. GhidraBoy's patched native decompiler is a separate, versioned dependency with copy-based install/rollback. Integration must retain its identity and regressions; an extension ZIP alone cannot establish that those fixes are installed.

Baseline references: [static contract](static-contract.md), [analysis ownership](analysis.md), [CPU validation](cpu-validation.md), [compiler support](compiler-support.md), [input policy](input-policy.md), [native dependency](native-decompiler/build-and-rollback.md), and the source inventory in section 12.

## 3. Architecture: a few strong boundaries

### Repository and build layout

Keep GhidraBoy's existing root source layout to minimize unrelated churn. Move GhiGBC first as a traceable subtree, then organize only the imported debugger code:

```text
GhidraBoy/
  src/                       existing static provider and its tests
  data/                      sole SM83 language and hardware reference assets
  ghidra_scripts/             static workflows and compatible script entry points
  debugger/
    ghidra-extension/        trace mapping, history UI, generic action service
    python/ghigbc/
      backend.py             small protocol and immutable shared records
      session.py             owner queue, lifecycle and capture/epoch policy
      agent.py               Trace RMI publication and command translation
      mapping.py             static snapshot transport
      profile.py             bounded optional decoders
      display.py             presentation through backend-neutral methods
      backends/
        sameboy/             Python binding and native implementation/patches
        mgba/                added only after feasibility gate
    tests/                   backend contracts, native tests, real RMI tests
  tests/fixtures/             shared self-authored source fixtures and manifests
  tools/                     coordinated build, package, validation, dependency tools
  docs/
    contracts/               runtime, trace, profile and compatibility contracts
    workflows/               task-oriented usage and troubleshooting reference
    releases/                versioned support matrices and concise receipts
```

This is a target organization, not permission to move all files in one changeset. Keep ordinary static tests where they are. Shared fixtures need no separate library. Preserve `fi.gekkio.ghidraboy`, the `ghigbc` package and public entry points during Release A. Product labels may say “GhidraBoy Debugger” without renaming persisted identities.

Use the existing root Gradle wrapper and a debugger subproject for Java artifacts. Resolve the debugger's compile-only provider dependency from the root project output. Keep native build tools and Python testing appropriate to those languages; expose a small set of root commands that orchestrate them. The default static build must neither configure a required native toolchain nor fetch/build emulator dependencies. Consolidate dependency identities into one canonical manifest with consumed/generated views as necessary; never hand-maintain competing version lists.

Ship one product with two installation choices: **Static** and **Static + Debugger**, with optional backend runtime payloads. Initially retain the `GhidraBoy` and `GhiGBC` Ghidra extension IDs and one copy of each JAR. A repository merger does not require an extension/class/schema rename. A later extension consolidation needs its own measured benefit and upgrade test.

### Responsibility and dependency rules

| Boundary | Owns | Must not own |
| --- | --- | --- |
| Static provider | Instruction semantics, import, static evidence, mapping candidates, compiler conventions, user-owned annotations | Emulator lifecycle, live bank guesses, required Python/native emulator dependency |
| Generic debugger/session | Command ordering, identity checks, epochs, immutable observations, recovery policy, trace publication, capability enforcement | SameBoy structures/constants, game offsets, a second CPU interpreter |
| Backend adapter | Actual engine control, hardware observations, safe inspection, event precision, backend state payloads, engine-specific stepping support | Ghidra Programs/transactions, bookmarks, research conclusions |
| Ghidra debugger UI | Current versus historical selection, navigation, evidence presentation, enabled actions | Direct native calls, inferred missing hardware state |
| Research profile | Pure decoding from bounded copied observations, declared capabilities and exact recognition | Machine handles, execution ownership, arbitrary live reads or automatic code downloads |

Dependency direction is static provider → consumed by debugger → consumed by optional GhiBW3. Static tests may invoke independent hardware oracles as an explicitly selected validation tier; that is not a production dependency. No circular runtime dependency and no separate generic plugin framework.

### The backend contract

Start with a small Python protocol and immutable dataclasses/records. Keep native ABIs private to each adapter unless a second implementation demonstrates that sharing them reduces work. No universal RPC layer, service process per component, or cross-language code generator is required.

The contract must express:

- **Descriptor and session configuration:** backend/core/build/patch identity, protocol version, supported hardware models and revisions, mapper scope, boot policy, clock policy, capabilities and limits. Selected and actually applied settings must both be recorded. ROM and boot identity come from the bytes actually loaded; external attachment must establish equivalent evidence or mark exact identity unavailable.
- **Lifecycle:** load/start, bounded run, instruction step, interrupt request, coherent capture, detach/close. Pausing must remain possible while run commands are pending. External attachment has explicit ownership: detaching must not terminate an emulator the session does not own.
- **Inspection:** 16-bit CPU registers, banked physical regions, mapping state, valid/unknown/device coverage and immutable copied memory. No bank-zero defaults for missing state. CPU inspection and physical storage are different views.
- **Events:** target CPU and physical coordinates, origin, attempted access versus committed change, optional writer, boundary/precision, ordering and dropped-event count. Unknown fields remain absent or explicitly unknown. Never turn instruction-final bytes into per-access commit evidence.
- **Time:** an engine timebase with an exact conversion where known; separate emulated time, wall time, session sequence and checkpoint timeline. Do not retain a universal `Ticks8MHz` assertion for engines that cannot provide it. Preserve legacy fields only when their values have defined semantics.
- **Optional operations:** physical watches, register/WRAM edits, checkpoint/restore, over/out, input, video, device capture and later audio. Negotiated support is enforced by both API and UI. Unsupported operations return structured reasons before mutating state.

Capabilities are structured and session-specific, not a single `supports_debugging` flag. Examples include coherent instruction-boundary capture; CPU execute breakpoints; physical bank breakpoints; CPU read/write attempts; writer attribution; DMA observation; nondestructive inspection; checkpoint compatibility; and supported step-over/out conventions. Mappers/models and validity ranges are part of the capability result.

Define **Basic Debugging** as load or verified attach, pause/resume, instruction stepping, coherent CPU registers/memory, stop reasons, executable breakpoints, bank identity for declared banked support, and reopening recorded observations. **Research capabilities** add physical watch provenance, safe edits, checkpoints/replay, device observations and stronger timing. SameBoy must keep every currently supported capability. Another backend may pass Basic Debugging while advertising narrower research capabilities, clearly visible in the launcher and resulting trace.

The session owner serializes machine operations. Native adapter locks remain internal. Replace display/agent raw handle access with methods and an explicit thread-safe input/frame path; do not route urgent pause behind execution work. Contract tests enforce ordering, shutdown, cancellation and snapshot atomicity.

### Persisted data and static/live integration

Keep static mapping schema, backend protocol, native ABI, trace observation schema, checkpoint envelope and profile API independently versioned. Define supported producer/consumer ranges, rejection behavior, and reader fixtures for each; do not bump every version because files moved.

New captures record backend identity, actual model/mode, ROM/boot fingerprints, capability/precision metadata, session/epoch/capture, coverage, timebase and mapping generation. Backend IDs are metadata rather than trace-tree path names. Reopen raw history without loading an emulator or game profile. Retain old trace paths and interpret missing metadata conservatively.

Use an engine-neutral checkpoint envelope containing an opaque engine payload. Preserve existing schema-2 SameBoy readers and their exact identity checks. Any portable state import is a separately validated conversion producing a new session/provenance record, not permission to resume arbitrary foreign checkpoints. Trace snapshot selection remains observation, not reverse execution.

Preserve `ProgramMapping` as the static authority and the backend as the live hardware authority. Bind exact live bytes to current exported Program bytes only when hash and coverage support it. Keep original versus patched identity distinct. Ambiguous aliases, renamed/split blocks, device selections and uncovered regions remain explicit. Keep snapshot-limited mappings and user mapping preservation.

Retain selected-capture validation and profile budgets: currently 64 declared ranges/64 KiB, 4096 fields, and bounded 48000-byte serialized batches. Keep FIFO Trace RMI reply correlation, bounded queues, stale-session cancellation, mapping-save barriers and completed-capture publication. Change limits only with measurement and new acceptance evidence.

## 4. Milestones and exit gates

Gates were initialized as **NOT RUN**; current results are recorded in the execution checkpoint and linked gate status. A milestone completes only when all its required gates pass for the named candidate. `BLOCKED`, `FAIL`, `NOT RUN`, and documented `NOT APPLICABLE` are distinct; skips do not count as passes. Each implementation changeset should address one boundary and be independently reviewable/revertible.

| Milestone | Depends on | Deliverable |
| --- | --- | --- |
| M0 | — | Verified baseline, ownership inventory, compatibility fixtures |
| M1 | M0 | mGBA and external-attachment feasibility receipts; provisional contract |
| M2 | M0 | History-preserving source migration |
| M3 | M2 | Single build, dependency and package entry points |
| M4 | M1, M3 | Backend-neutral session with SameBoy parity |
| M5 | M4 | Persisted compatibility, mapping and external profile integration |
| M6 | M3–M5 | Release A acceptance and reproducible packages |
| M7 | M6 | Explicit hardware models and accuracy/coverage expansion |
| M8 | M1, M4, M5 | Real mGBA backend and common conformance |
| M9 | M5; M7/M8 for model/backend coverage | Integrated analysis, debugger usability and research tools |
| M10 | M6–M9 | Release B qualification and repository cutover |

M1 and M2 are independent after M0; M7 and M8 can advance independently against the agreed contract. These dependencies describe work order, not a requirement to use multiple agents. No new backend may drive generic schema changes without a conformance example and a compatibility check.

### M0 — Establish what must survive

**Work:** inventory tracked files, active worktrees, untracked work, source licenses, dependency locks, actual binaries, installed identities, API consumers and historical artifacts. Classify each source path as migrate, retain externally, compatibility shim, historical evidence, or generated/private exclusion. Preserve a Git bundle of each source history and checksummed relevant artifacts. Use a fresh migration branch such as `integrate-ghigbc`; do not rewrite existing refs or prefix it with `codex/`.

Rerun current provider and debugger tests against one explicit 12.1.3/JDK 21 tuple, including the actual selected native decompiler. Record current failures rather than attributing them to the merger later. Capture comparable latency/growth measurements and a capability inventory. Distinguish historical GUI/Deck results from current ones.

**Exit checks:**

- `BASE-01`: exact source/dirty-file and binary manifests exist; original checkouts, private assets and rollback archives remain unchanged.
- `BASE-02`: every current public workflow/test suite has a destination and baseline status. Existing failures have reproductions and an explicit disposition; migration-caused failures cannot be hidden among them.
- `BASE-03`: saved annotated Program fixtures cover historical upstream and current provider formats, including the persisted POP constructor regression. Trace fixtures cover legacy/current mappings, profiles, edits and checkpoints.
- `BASE-04`: one compatibility table lists extension/class names, scripts, Python imports, C ABI, schemas, launchers, GhiBW3 dependencies and supported upgrade paths.

### M1 — Test the abstraction before freezing it

**Work:** build bounded standalone probes using pinned mGBA sources and a minimal Emulicious remote connection. For mGBA, verify load, pause, instruction step, register reads, physical/banked memory, a breakpoint in two banks at the same CPU PC, event hooks, coherent snapshots and state save/load. For Emulicious, establish protocol, connection/lifecycle ownership, bank/register visibility, stop callbacks and attainable capture consistency. It is a feasibility probe, not a third supported backend commitment.

mGBA exposes core and debugger APIs, making it a plausible native adapter; suitability is still an inference until these probes pass. Its core/debugger headers are the implementation references. Emulicious advertises remote debugging, but that does not establish parity with our required observations. [mGBA core API](https://github.com/mgba-emu/mgba/blob/master/include/mgba/core/core.h), [debugger API](https://github.com/mgba-emu/mgba/blob/master/include/mgba/debugger/debugger.h), [Emulicious features](https://emulicious.net/).

**Exit checks:**

- `SPIKE-01`: executable probes and result receipts identify tested versions, exact operations, observed semantics, missing capabilities and any required upstream patches.
- `SPIKE-02`: compare cost of native embedding versus remote attachment, including pause safety, safe peeks and identity verification; select mGBA integration mode based on evidence.
- `SPIKE-03`: provisional contract covers both probes without exposing either engine's internal types. Unsupported external coherence is rejected or explicitly graded; never fabricated.
- `SPIKE-04`: record a go/no-go decision for mGBA Basic Debugging. If it cannot meet the minimum, Release A may continue; Release B remains incomplete until an evidence-backed second backend is selected and passes M8. Do not add more candidates without resolving the failed requirement.

### M2 — Import source with provenance and minimal behavior change

**Work:** import GhiGBC under `debugger/` using an unsquashed history-preserving subtree merge or equivalent two-parent import that retains the original commits. Keep a source-path/hash manifest and audit excluded files. Import useful source and tests; do not copy `.deps`, venvs, builds, private game assets or output directories. Preserve original upstream and contributor notices per component. Legacy game-specific implementations stay in GhiBW3; retain only justified delegates with documented removal conditions.

Keep the first import mechanically reviewable. Separate relocation/path corrections from semantic refactoring, formatting, version updates and bug fixes. Keep old repositories usable until final cutover.

**Exit checks:**

- `MOVE-01`: source history is reachable or explicitly retained in the source bundle; every imported supported file matches the source hash before subsequent edits.
- `MOVE-02`: all exclusions/relocations have recorded reasons and license provenance. No duplicate SM83 language or study implementation appears.
- `MOVE-03`: original static build and imported component tests run from their documented paths. No unexplained behavioral difference from M0.

### M3 — Unify build, dependencies and distribution

**Work:** wire Java projects through the existing wrapper, remove sibling checkout assumptions and dated JAR names, and introduce root build/check/package commands. Keep backend dependencies lazy and independently selectable. Reuse the installer's existing staged validation, journals, recovery and rollback; consolidate orchestration around it rather than replacing it wholesale.

Create product manifests for Static, Debugger + SameBoy, and later Debugger + mGBA. A combined distribution may offer backend selection while shipping separately verifiable payloads. Consolidate generic suite receipts into GhidraBoy; GhiBW3 retains only its own consumer evidence plus references to provider artifacts. Keep native decompiler identity and copy-only updater separate from emulator runtime identity.

**Exit checks:**

- `BUILD-01`: clean static checkout builds/tests without emulator binaries, Python runtime setup, SDL, native compiler or debugger project dependency downloads.
- `BUILD-02`: clean full checkout builds without neighboring GhiGBC/GhiBW3 repositories, absolute developer paths, stale build outputs or manually selected provider JAR filenames.
- `BUILD-03`: packages contain one static provider, no bundled compile-only provider copy, correct notices, no private assets, and a deterministic source/dependency manifest.
- `BUILD-04`: root commands are documented and exercised from a fresh checkout and paths containing spaces. Existing public commands either work through thin delegates or have tested migration guidance.
- `BUILD-05`: packaging identifies stock versus patched native decompiler requirements; the doctor detects mismatches and never silently overwrites an active Ghidra distribution.

### M4 — Extract the backend boundary with full SameBoy parity

**Work:** wrap the current native implementation in a SameBoy adapter. Move opaque handles, constants, fixed memory layouts, boot defaults, patched core fields and state-file encoding behind it. Move session/epoch policy, command ownership and immutable normalized observations into the generic layer. Keep engine-specific call tracking and low-level watches in the adapter. Replace every agent/display native-handle access.

Keep current execution slicing and Trace RMI ordering guarantees. Use dependency injection and explicit local backend selection, with lazy import so a missing unused backend does not break launch or history browsing. A small test backend may exercise failure/order behavior but cannot establish emulator support or hardware correctness.

**Exit checks:**

- `BACKEND-01`: structural checks find no SameBoy headers/private fields outside its adapter, and no native handle/API access from generic agent/UI/display/profile code. Compatibility readers and labeled provenance may mention SameBoy.
- `BACKEND-02`: run identical self-authored fixtures through the pre-extraction and new SameBoy paths; compare defined registers, physical bytes, stop reasons, event order/precision, bank mappings, edits and restore semantics.
- `BACKEND-03`: pause during run/queue saturation, timed-out requests, disconnect/reconnect, target exit, callback ordering, event overflow and shutdown have bounded behavior with visible error/loss reporting.
- `BACKEND-04`: display input, focus loss, minimized/paused pumping, frame copying and close work through the abstraction without stale held keys or lock inversion.
- `BACKEND-05`: startup and action requests reject unsupported model/mapper/capability combinations explicitly; capability enforcement does not rely on disabled UI controls alone.

### M5 — Preserve saved work and external research integration

**Work:** add backend/model/capability metadata without rewriting existing observations. Preserve API names or provide tested delegates. Make GhiBW3 resolve artifacts from the new build/manifest; keep its static component independent. Replace reliance on `BankMappings.isReady` internals with a small supported readiness API only if needed, retaining a compatibility delegate.

Define upgrade and rollback separately for extension files, runtime payloads, Ghidra distributions and user databases. A downgraded reader must reject unsupported new data cleanly; restored installation files do not magically downgrade a saved database. Never modify original projects to test migration.

**Exit checks:**

- `COMPAT-01`: copied old Programs reopen with preserved constructor identity, comments, symbols, types, functions, overrides and ownership receipts; removal never deletes later user work.
- `COMPAT-02`: legacy and new traces reopen in separate processes with no emulator runtime loaded and no optional study profile; raw memory, old paths, historical mappings, writer precision and edit/parent-checkpoint evidence remain inspectable.
- `COMPAT-03`: schema-2 SameBoy checkpoints restore only with compatible identities. Wrong engine/core/patch/ROM/boot/model, corrupt payloads and unsupported schema versions fail before mutation.
- `MAP-01`: renamed/split/partial blocks, overlays, alias ambiguity, current patches, detached sources, view selection and conflicting user mappings retain existing correctness and ownership behavior.
- `MAP-02`: capture/save/mapping barriers survive rapid stepping, Program switching, save/close/reopen and reconnect; historical selections never silently follow or modify the current target.
- `PROFILE-01`: GhiBW3 static-only, live, missing/failing/wrong-revision profile and profile-removal/reopen cases pass. Generic package class loading and startup require no study code.
- `PROFILE-02`: stale session/epoch/capture actions, oversized declarations and failed decodes are rejected with preserved raw controls/history; field batches retain complete provenance and counts.

### M6 — Qualify Release A

**Work:** run the combined acceptance matrix on built and installed packages. Preserve existing debugger operations and static analysis functionality. Generate a single versioned support report from receipts, replacing contradictory current-facing documentation with links to historical records.

**Exit checks:**

- `A-STATIC`: all current SLEIGH, static analysis, mapper, compiler ABI, generated-C/native decompiler, ownership, schema and actual database migration gates pass for the selected dependency tuple.
- `A-RUNTIME`: native/Python and real installed Trace RMI gates pass, including 250-stop growth, paused display, edits/checkpoints/reopen and shutdown error scanning.
- `A-INSTALL`: clean install, upgrade, interrupted install/recovery, altered-user-file preservation, component removal and rollback pass on macOS arm64 and Linux x86-64 using extracted packages without source/build tools.
- `A-GUI`: identify the exact installed candidate and use real Ghidra actions for import, launch, step, physical breakpoint/watch, historical navigation, bookmark, save/reopen, cancel and close. Headless harnesses alone do not pass this gate.
- `A-PERF`: comparable baseline/candidate runs meet the performance checks in section 6. No unexplained unbounded queue, memory or thread growth.
- `A-RELEASE`: reproducible artifacts and complete provenance exist; an installed end-to-end debugging smoke test passes with a self-authored fixture; each support claim points to a passing gate. Platform-specific blocked gates prevent claiming that platform supported.

This completes repository integration and SameBoy parity. It does not complete Release B, native DMG support, a second backend, or physical Steam Deck acceptance if that device has not been tested.

### M7 — Expand hardware coverage and independent accuracy evidence

**Work:** replace implicit CGB-E assumptions with explicit selected/actual model, hardware revision and operating mode. Support at least a named native DMG configuration, CGB running a DMG cartridge, and CGB running a CGB cartridge; include boot execution versus validated post-boot initialization as separate policies. Establish correct model-dependent memory/device availability, speed/timebase and input behavior. Add MBC2 runtime support on the reference backend rather than treating static MBC2 modeling as runtime evidence.

Maintain a coverage matrix by hardware/model, mapper, subsystem, operation and backend. Use compiled SLEIGH tests for static semantics, independent pinned vector corpora, source-based native/generated-C regressions, hardware-targeted ROM tests and normalized cross-backend experiments. Expectations identify origin and applicable hardware revisions. Mooneye explicitly separates hardware models/revisions and acceptance/manual tests; preserve those distinctions. [Mooneye suite](https://github.com/Gekkio/mooneye-test-suite). Existing external vectors must retain their pinned revision/provenance rather than inheriting the description of today's upstream branch. [SM83 vectors](https://github.com/SingleStepTests/sm83).

**Exit checks:**

- `HW-01`: boot/model selection and actual reported configuration agree; reject incompatible boot images and silent model fallback. Exercise true DMG and both CGB modes independently.
- `HW-02`: ROM-only/MBC1/MBC2/MBC3/MBC5 advertised geometries pass selector/alias/boundary tests, including MBC2 nibble/mirror behavior, MBC5 bank 256, MBC1 lower-window changes, SVBK zero and echo RAM. Unimplemented wiring remains unknown/unsupported.
- `CPU-01`: preserve all existing exhaustive arithmetic/CB/stack/control-flow regressions and pinned external vectors; inventory all base/CB encodings and expand missing families. Report actual cases, undefined opcodes, masks and exclusions, not “100% CPU accuracy” from an opcode count.
- `HW-03`: applicable hardware ROM suites exercise timers, interrupts/EI delay, HALT/STOP, bus restrictions, boot unmapping, CGB speed switching and DMA/HDMA behavior. A correct engine result does not prove the debugger's event attribution is correct; check those separately.
- `ACCURACY-01`: a debug-instrumented run matches a pristine-core run for comparable defined state/output; nondestructive inspection leaves engine state unchanged; instrumentation patches cannot validate themselves solely through their own event output.
- `ACCURACY-02`: cross-backend fixtures normalize model/boot/clock/input and compare defined registers/memory at explicit synchronization boundaries. Differences produce minimal reproducers and classified explanations, never majority-vote correctness or blanket suppression.
- `HW-04`: distinguish collected physical-hardware evidence from published test expectations and emulator results. Unavailable hardware stays unverified, with model/revision and retrieval provenance recorded for external evidence.

### M8 — Implement and qualify mGBA

**Work:** implement the M1-selected adapter against a pinned mGBA core. Reuse the existing session, mappings, profiles, history UI and installer. Support explicit backend selection, independent optional installation and different backend sessions without hidden global state. Start with Basic Debugging, then add research features where the adapter can prove the required semantics.

**Exit checks:**

- `MGBA-01`: all Basic Debugging conformance tests pass on its declared DMG/CGB modes and mapper set, including identical CPU PCs in different banks and clean detach/close behavior.
- `MGBA-02`: physical watches, edits, checkpoint/restore and over/out are either independently tested with declared precision or rejected as unsupported. Backend capabilities and actual UI/API behavior agree.
- `MGBA-03`: common static mapping, selected-capture, save/reopen and synthetic-profile tests run unchanged against both real backends. Tests parameterize capabilities; a blanket skip cannot pass a required tier.
- `MGBA-04`: install only mGBA with SameBoy absent and vice versa; neither selected backend relies on the other's shared library, boot asset or metadata. Recorded traces remain readable after removing either runtime.
- `MGBA-05`: mismatch fixtures compare the two cores without demanding identical undefined startup memory, wall-clock RTC or backend-private state formats. At least one disagreement fixture proves the diagnostic path works.
- `MGBA-06`: both backends run from extracted platform packages and pass resource, failure and cleanup gates. Mark experimental until its required tier passes on the named platform.

### M9 — Deliver integrated analysis, debugger usability and research tools

**Work:** make static analysis, execution control and captured evidence work together without manual address translation or backend-specific UI paths. Prefer improvements to native Ghidra views plus one focused hardware/history inspector. Present CPU and physical addresses together, distinguish live from captured state, and expose actual hardware mode, event precision and uncertain mappings at the point of use.

Required operations: navigate listing/decompiler locations to verified runtime banks and back; set bank-specific breakpoints and watches from native views; inspect registers, flags, physical memory and captured access events; filter/search history by physical location, event kind and epoch; compare selected captures; inspect observed call state without fabricating stack frames; perform recoverable edits/checkpoint restoration; and compare backend observations under matched settings. Reuse native Ghidra functionality where it meets these requirements. Keep actionable errors, keyboard access and responsive cancellation consistent across backends. Self-authored ROMs serve as regression fixtures. Documentation covers operation, capabilities and troubleshooting.

Research exports use a versioned machine-readable observation format and a concise human-readable report: source/input hashes, settings, timebase, capabilities, selected captures, mapping identity, applied hypotheses, differences and experiment steps. Keep raw, decoded and inferred findings distinguishable. Prefer existing JSON and Ghidra persistence; avoid adding a new database. Reproducible replay requires recorded inputs at a defined emulated boundary, controlled clock/nondeterminism and a compatible checkpoint; do not promise replay where those conditions are unavailable.

**Exit checks:**

- `TOOL-01`: from a fresh installation, import a banked fixture, launch either supported backend, set a physical breakpoint from the listing and navigate the resulting capture back to the correct static bank. No manual address conversion or developer-only command is required; ambiguity uses the supported view selector.
- `TOOL-02`: register/memory inspection, watch setup, history filtering, capture comparison and checkpoint/edit operations have executable checks plus real GUI acceptance. Actions operate on the selected session/capture, and unavailable capabilities fail with a specific reason.
- `TOOL-03`: listing, decompiler, memory and history views retain coherent selection and useful state through stepping, Program/session switching, reconnect and reopen. Long operations remain cancellable; malformed inputs and backend failures leave usable controls and diagnostics.
- `RESEARCH-01`: a synthetic experiment can be exported, reopened without the emulator, and traced from a conclusion to exact observed bytes and source locations. Invalid/stale Program bindings remain visible.
- `RESEARCH-02`: restore/repeat under controlled conditions reproduces declared results; divergent settings and missing replay capabilities are detected. A bookmark naming a writer never becomes proof of a caller or damage formula.
- `UI-01`: keyboard navigation, readable labels/statuses, cancellation, capability-disabled actions, display scaling and historical/live selection are checked on claimed platforms. Routine operation requires no knowledge of internal ABI/schema names.

### M10 — Qualify Release B and finish cutover

**Work:** rerun Release A's full installed matrix for the final combined sources, both backend payloads, new hardware models and integrated analysis/research operations. Produce release-specific supported/degraded/experimental matrices, source archives and evidence links. Update GhiBW3 and old GhiGBC contributor entry points to the new artifact locations. Keep a migration guide with exact upgrade and rollback paths.

**Exit checks:**

- `B-RELEASE`: M7–M9 and the refreshed Release A gates pass for every claimed release configuration. Backend-specific research differences are published; universal parity is not implied.
- `DEVICE-01`: actual Steam Deck installation, input/focus, pause/close, readable UI, real Trace RMI, save/reopen and performance pass before advertising Deck acceptance. A virtual display/container cannot substitute. Windows is a separate future platform gate, not inherited from an emulator's platform support.
- `CUTOVER-01`: a fresh contributor needs only GhidraBoy for generic builds and only the additional GhiBW3 checkout for game-specific work; no generic ledger, fixture or release operation depends on the old GhiGBC checkout.
- `CUTOVER-02`: update old-repository documentation/redirects and preserve history/releases. Archival/publication are explicit execution actions after qualification, not part of preparing this plan. Do not delete old tags, artifacts, checkpoints or rollback distributions.
- `CUTOVER-03`: compatibility delegates stay for at least two supported release cycles and until known GhiBW3/guide callers migrate; remove them only through a documented incompatible change with reader/migration tests. Do not grow permanent duplicate implementations.

## 5. Accuracy and support matrix

The matrix separates what the engine emulates from what the debugger observes or explains. The combined product never inherits all upstream emulator capabilities automatically.

| Area | Release A requirement | Release B requirement | Further expansion gate |
| --- | --- | --- | --- |
| Static SM83/decompiler | Preserve semantics, native fixes, ABI/ownership and database compatibility | Expand audited instruction-family coverage and shared fixtures | New compiler conventions only from emitted-code fixtures |
| Hardware identity | Accurately declare current CGB-E configuration and compatibility mode | True DMG, CGB compatibility and CGB native modes with named revisions | MGB/other revisions/SGB/AGB compatibility each need model evidence |
| Cartridge banking | Preserve current static/runtime sets and explicit unknowns | Reference backend adds MBC2; other backend advertises its verified matrix | MBC1M/MBC30/exotic controllers/peripherals need dedicated topology and hardware tests |
| Watches | Preserve CPU-origin access/attempt/change distinctions | Capability-graded cross-backend watches and provenance | DMA/HDMA and exact internal commit timing require new events/fixtures |
| PPU/APU/timers/serial | Preserve engine operation and safe existing inspection; no new UI claims | Model-aware device status, explicit inspection coverage and applicable accuracy tests | Rich PPU/APU inspectors, audio output and serial/link workflows each require capture/lifecycle tests |
| Call analysis/stepping | Preserve current ordinary-call guarantees and explicit unknown callers | Same guarantee by backend capability; static hypothesis kept distinct | Game/compiler-specific far calls require independently proven adapters |
| Saved work | Programs, traces, checkpoints and recoverable edits retained | Engine-neutral history; engine-specific checkpoint resume | Reverse execution and portable state conversion need separate replay contracts |
| Research | Existing bounded profiles and exact identities | Reproducible synthetic experiments and portable observation reports | Battery-save import/export, richer instrumentation and input replay require identity/time tests |

“Best in class” acceptance is demonstrated by precise explanations, preserved work, trustworthy evidence, responsive workflows and easy reproduction. More settings or backends are not substitutes for those properties.

## 6. Test execution, performance and release evidence

### CI tiers

| Tier | When | Required contents |
| --- | --- | --- |
| Fast component | Each relevant change | Static unit/contract tests; Python ordering/profile/compatibility tests; native adapter fixtures; structural dependency checks |
| Real integration | Changes to mapping/session/backend/schema/build or public APIs | Installed Ghidra + real Trace RMI, lifecycle/reopen, same-PC/two-bank, stale actions, synthetic profiles, native decompiler fixtures where affected |
| Comprehensive | Scheduled/explicit candidate validation | Full existing exhaustive SLEIGH gates and pinned vectors; hardware ROM matrix; both real backends; differential fixtures; instrumented/pristine comparisons |
| Release/platform | Every release candidate | Clean extracted-package install/recovery/rollback, reproducibility, GUI, resource soak, integrated tool operations, actual claimed-device acceptance |

Retain existing test runners initially and orchestrate them; retire redundant runners after parity is demonstrated. Do not create tests that merely mirror renamed paths. Artifact/schema/build changes invalidate dependent installation and reopen evidence even when source-only unit tests pass. Fetch dependencies in a separate verified preparation step so actual installed-runtime acceptance runs offline without development tools. Do not turn a missing comprehensive input or native executable into a successful release run.

### Performance and resilience gates

At M0, record host/architecture, native versus virtual execution, Ghidra/JDK/Python, backend/model, fixture hashes, render mode and test settings. Use at least three comparable warm runs; report sample counts, median and p95 for step, pause and capture publication, plus RSS, thread/handle counts and trace bytes per capture.

For migration parity, predeclare a regression threshold: flag a median-of-run-p95 increase above `max(20% of baseline, 10 ms)` on the same host/configuration. Diagnose noise with additional paired runs only when needed. This is a proposed gate to calibrate at M0, not a claim about current performance. Preserve responsive pause under queue saturation and add a two-second end-to-end pause timeout on named native release hosts; virtual environments have separately declared budgets before measurement.

Keep the existing 250-stop check and add a 30-minute bounded-capture soak with repeated pause/resume, session replacement and at least 100 checkpoint/restore cycles for checkpoint-capable backends. Separate expected trace-history growth from leaks: measure repeated fixed-size batches after warmup, queue bounds, post-close process/resources and idle memory trends. Finalize an explicit per-host steady-memory and per-capture storage envelope at M0. A stable total RSS snapshot alone is insufficient.

Force failures: truncated/corrupt state, wrong ROM/boot/backend, missing SDL/library, backend crash during a pending command, stalled pause, RMI disconnect mid-publication, save-lock contention, full queues, dropped events, stale callbacks, corrupted package, interrupted install and user-modified managed files. Each must preserve existing work, terminate or recover within a named bound, and leave a diagnostic rather than a false completed capture.

### Evidence format and promotion

Each gate receipt includes gate ID, status/reason, exact source tree identity (including relevant dirty files), command/parameters, dependency and binary hashes, host/hardware model, selected backend/capabilities, input fixture hashes, time/clock policy, logs, assertions/case counts, duration and artifact identity. GUI/device receipts add actual observations. Expected failures name a known issue and limited scope; they do not pass a feature that requires that behavior.

Use one generated release report and machine-readable support matrix. Store compact fixture manifests and curated receipts in source; keep bulky logs/build outputs in versioned artifacts with stable hashes/links. Historical reports remain historical. Do not package evidence containing the package's own final hash and create a self-referential reproducibility problem.

Promote a candidate only if required gates pass on its actual packaged bytes. When a component changes, reuse unrelated receipts only with explicit dependency/identity matching; rerun affected tests. Do not rerun expensive unrelated suites solely to produce a larger test count.

## 7. Installation and compatibility policy

- Preserve Ghidra 12.1.3/JDK 21 as the migration tuple. Ghidra upgrades, native dependency upgrades and repository restructuring are separate changes. The current supported Python floor is 3.9; use an existing suitable interpreter or explicit user selection, capability checks and an isolated runtime. Do not manage or pin the user's system Python or require a previously tested patch version.
- Static installation requires no emulator runtime. Debugger history readers remain available without a selected backend. Install/remove/update backends independently, with old checkpoint compatibility discoverable from their envelopes.
- Keep prebuilt Mac arm64/Linux x86-64 runtime packages, hash-verified dependencies, component notices and offline installation. Build reproducibility is assessed within the same pinned platform/toolchain, not by requiring unlike native platforms to produce identical binaries.
- Preserve one installed SM83 provider and legacy GhiGBC extension identity initially. Installer validation must detect collisions before changing files. Restart requirements and incompatible active sessions are explicit.
- Keep install journals and exact rollback bytes; changed user files are preserved. Native decompiler executable and identity marker move/roll back together in a copied distribution.
- Commercial ROMs, original boot ROMs, Programs, saves and private checkpoints are excluded from public artifacts. Use self-authored/redistributable fixtures with provenance. Private GhiBW3 checks remain an opt-in consumer gate and cannot be required for generic contributor CI.

## 8. Lean implementation rules and explicit deferrals

Keep Java for Ghidra integration, Python for session/profile orchestration, and C/C++ bindings where the selected engines require them. Do not add a new implementation language, web UI, generic distributed bus, package registry or plugin discovery ecosystem during migration. Keep the current queue/ownership model unless a demonstrated failure justifies changing it. Refactor only at real dependency boundaries.

Keep hardware/static mapping semantics in one authoritative static module; adapters report actual hardware state without reimplementing SLEIGH. Shared normalization may describe GB/GBC regions, but must not compute unobserved live bank state by guessing from a game. Keep per-function calling conventions and conservative analysis independent of emulator choice.

Do not implement Emulicious, BizHawk, PyBoy, BGB and Gambatte simultaneously. After mGBA, select the next adapter from an unmet workflow: Emulicious for attachment, BizHawk for TAS/replay, PyBoy for Python automation. Require the same feasibility/conformance gates. Existing GhiBW3 PyBoy tools remain usable externally while that decision is deferred.

Beyond Release B, prioritize by analysis/debugging/research value: richer bank/device inspectors, input/clock-controlled replay, battery-save workflows, PPU/APU inspection and audio, serial/link experiments, DMA attribution, broader mapper/revision support and proven far-call conventions. Each is a small capability milestone with source fixtures, observer semantics, installed/UI checks and evidence; none is silently included in a blanket “full support” claim.

## 9. Main risks and mitigations

| Risk | Concrete mitigation |
| --- | --- |
| Merger obscures existing failures | Freeze source/artifact baseline and keep old/new results separately identified |
| Abstraction leaks or becomes too broad | Two real feasibility probes; one small protocol; forbid generic raw handles; review every added method against a tested use |
| Loss of annotations or old traces | Copied persisted fixtures, separate-process reopen, constructor/ownership regression gates, additive readers |
| Native patch subtly changes emulation | Pinned patch/source identity; pristine versus instrumented comparison; independent expectations |
| Engine agreement mistaken for hardware truth | Model-specific hardware tests and documented independent provenance; classify divergences |
| Build/install complexity grows | Existing wrapper, one artifact manifest, lazy backend dependencies, two user installation choices |
| Apparent DMG or mapper support exceeds implementation | Actual model/capability reporting and matrix tests; no inference from file extension/header alone |
| Performance degrades behind correct unit tests | Paired baseline measurements, real RMI and long-run lifecycle/resource gates |
| Game-specific code returns to generic core | External GhiBW3 consumer tests, no-profile install, dependency boundary checks |
| Endless migration scope | Release A parity first; Release B has explicit models/backends; later hardware/features get separate gates |

## 10. Suggested changeset sequence

1. Baseline and compatibility fixtures; source/disposition manifests.
2. Standalone backend feasibility probes and provisional contract decision.
3. History-preserving GhiGBC import with attribution and no semantic edits.
4. Path/build dependency correction and canonical artifact/lock resolution.
5. Packaging/installer orchestration with preserved IDs and runtime optionality.
6. Shared records/protocol; SameBoy adapter extraction and direct-handle removal.
7. Session/display ownership and capability enforcement, retaining ordered RMI behavior.
8. Trace metadata/readers, checkpoints and mapping/history compatibility.
9. External GhiBW3 build/API migration and no-profile acceptance.
10. Release A validation, operational documentation and packaged debugger parity.
11. Explicit hardware model/boot configuration and MBC2 runtime coverage.
12. Independent accuracy harness expansion and observer/pristine comparisons.
13. mGBA implementation plus common conformance and platform packages.
14. Integrated navigation/inspection, research exports and usability fixes.
15. Release B qualification, migration guide and old-repository cutover.

Fixes exposed by a gate get separate changesets with their own reproducer; do not disguise correctness changes as mechanical migration. No phase requires rewriting published history. Do not commit other ongoing work just to make the tree appear clean.

## 11. Completion checklist

- [ ] One checkout builds generic static and debugger products, with no sibling-repository assumptions.
- [ ] Static-only users acquire no emulator/Python/SDL dependency.
- [ ] SameBoy retains every currently supported feature and precision guarantee.
- [ ] Real mGBA passes the declared shared tier; optional capabilities match actual behavior.
- [ ] Generic code has no backend handles/private types or engine-specific time/memory assumptions.
- [ ] Exact ROM/boot/model identity, physical banks, uncertainty, time and event provenance survive capture and reopen.
- [ ] Old annotated Programs, trace schemas, profiles and compatible checkpoints remain usable through tested paths.
- [ ] True DMG and both CGB modes have separate evidence; mapper/observer limits remain visible.
- [ ] SLEIGH/decompiler/native/runtime correctness and independent accuracy gates all retain provenance.
- [ ] Installed artifacts pass isolation, recovery, rollback, performance, GUI and every claimed device gate.
- [ ] Listing/decompiler navigation, physical breakpoints, inspection, history search/comparison and recoverable experiments work coherently through the installed UI.
- [ ] Another researcher can reopen an experiment and distinguish bytes, observations and hypotheses.
- [ ] Generic documentation/evidence resides in GhidraBoy; GhiBW3 stays optional; old repository history is preserved.

## 12. Source inventory used for this plan

Paths below identify the inspected source checkouts; M2 must replace live cross-repository references with migrated paths or immutable historical provenance.

| Source | Planning evidence |
| --- | --- |
| GhidraBoy `build.gradle.kts`, `settings.gradle.kts`, `.github/workflows/ci.yml` | Root provider build, version, wrapper and CI |
| GhidraBoy `docs/static-contract.md`, `docs/analysis.md`, `docs/input-policy.md` | Mapping, ownership, hardware/input semantics |
| GhidraBoy `docs/cpu-validation.md`, `docs/compiler-support.md`, `docs/native-decompiler/build-and-rollback.md` | Existing CPU, ABI, native dependency and preservation gates |
| GhiGBC `README.md`, `docs/SUPPORT.md`, `docs/NATIVE_CONTRACT.md` | Current boundaries, limitations and copied observation semantics |
| GhiGBC `native/ghigbc.c`, `native/ghigbc.h`, `native/patches/0001-cpu-bus-provenance.patch` | C ABI, private SameBoy coupling, model choice and instrumentation |
| GhiGBC `python/ghigbc/native.py`, `agent.py`, `display.py`, `dispatch.py`, `profile.py` | Runtime coupling, checkpoint identity, ordering and profile bounds |
| GhiGBC `ghidra-extension/src/main/java/ghigbc/` | Generic history, mapping and public action surface |
| GhiGBC `scripts/build_extension.sh`, `scripts/package_candidate.py`, `dependencies.lock.json` | Sibling paths, stale provider names and package dependencies |
| GhiGBC `tests/test_dmg.py`, `scripts/build_native.sh` | DMG-header fixture does not select a native DMG machine |
| GhiGBC `docs/contracts/`, `tests/ghidra/` | Mapping/profile contracts and installed regression coverage |
| GhiBW3 `live-extension/build.gradle`, `StudyPlugin.java`, `StudyProvider.java`, `python/ghibw3/profile.py` | External compile/runtime API consumers |
| GhiBW3 `docs/integration/LEDGER.md`, `ACCEPTANCE_REPORT.md`, `ownership.md` | Historical integration evidence, ownership and known deferred gates |

External feasibility/test-suite references in M1/M7 were checked during planning. Pin exact implementation and test revisions in M0/M1; moving branch links are discovery references, not release dependency locks.
