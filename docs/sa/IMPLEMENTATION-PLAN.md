# GhidraBoy static accuracy and Ghidra compatibility implementation plan

Current source authority is the Git-managed repository. Read [IMPLEMENTATION-STATUS.md](IMPLEMENTATION-STATUS.md) for accepted checkpoints and current gate state. The planning baseline, proposals, first-slice instructions and evidence descriptions below retain their original 2026-09-08 meaning; they are not new work orders. W1/L and the scheduled W2 foundation are accepted; W3a/G2 and bounded W3b are accepted. Remaining requirements and package ownership are unchanged.

**Selected workspace:** `/private/tmp/GhidraBoy-EX0205-20260908-180109/workspace`<br>
**Selected source:** `/private/tmp/GhidraBoy-EX0205-20260908-180109/workspace/source`<br>
**Selected runtime:** `/private/tmp/GhidraBoy-EX0205-20260908-180109/workspace/runtime`<br>
**Planning date:** 2026-09-08, America/Phoenix. This document proposes future work; no experiment or implementation was executed to produce it.

| Identity | Reconciled value |
| --- | --- |
| Experimental source manifest, 1,800 files | `c98babd0b7d27134517ce5e008345abf608c10562afe80238ab64595835e6fd0` |
| Experimental extension | `ccd6f873dd0e8743c354d501b33ceae86ad1d89fa72c1cb9501d03b5778fc613` |
| Native companion | `d60be1dd82b660b4123adbe2a8c7c3353a7974e856d4298208f8dc68490db871` |
| Compiled SLA | `02f52cc6eeb44ebc94cfda1d24e58e73b27b8585e729ea30dff1807a0a994a2a` |
| Ghidra authority | NSA/Ghidra `Ghidra_12.1.3_build`, commit `8b4c91d4d5bd1549622bfbade0df199585b98365`, plus retained switch-recovery and state-entry patches |
| Recorded build environment | Ghidra 12.1.3, JDK 21.0.12.1, checked-in Gradle 9.0.0 wrapper |
| Authoritative checkout, inspected separately | `/Users/joshuahansen/dev/GhidraBoy`, `integrate-ghigbc`, `5ffc32f65bbd3254c9694d4f33c4fb21039d3fa1`, clean |

**Read-only reconciliation:** all 1,800 selected source hashes/modes match; no additional files were found in the inspected source scopes (`src`, `data`, `docs`, `tools`). The three executable-artifact hashes above match. No recovery from an archive was necessary. The existing [sealed EX-02-05 archive][sealed] remains the transferable source/evidence recovery anchor; resolve these local source citations under its `EX0205/run/` tree on another machine. Clean repository HEAD was not substituted for the experimental source. See the [source manifest][manifest], [reconstruction receipt][reconstruction] and [EX-02-05 report][report]. No new EX-09-01 result is assumed or claimed; this coordinator had no unfinished command from the completed EX-02-05 run to resume.

Labels used below: **Source finding** means inspected implementation; **Reused evidence** means an existing execution receipt, not a new run; **Proposal** means a recommended implementation change; **Conditional** identifies a G1–G4 dependency. All work packages and acceptance commands are future work, requiring implementation authorization.

## 1. Recommended direction and what can start now

Retain the existing mapper and physical-storage model, state-qualified graphs, derived execution views and narrow pre-flow native protocol as the **provisional baseline**. Consolidate their duplicated proof and interpretation logic, then generalize values, accesses, control flow and memory through shared provider boundaries. Add ordinary Ghidra integration around that service. Do not replace the address model or build a second whole emulator merely because the ordinary-entry adapter is currently narrow.

Start **W1a: behavior-preserving ordinary proof-boundary extraction and self-contained regression inputs**, defined in section 9. It can proceed before every decision gate closes. W2's typed value/access contracts, W4's hardware/result contracts, W5's migration inventory design and W6's compiler fixture inventory can follow without a GUI witness. Unresolved GUI infrastructure blocks normal-window qualification, not these implementations.

Use seven packages plus a separate mechanical lint task. G1–G4 are small decision checkpoints embedded in their owning packages, not four new handoff campaigns. The missing witnesses, bounds, consequences and fallbacks are in [DECISION-GATES.md](DECISION-GATES.md). There is no dependency requiring “all experiments complete” before implementation.

## 2. Established behavior and its boundaries

| Capability | Source finding and reused execution evidence | What remains unproved or unimplemented |
| --- | --- | --- |
| CPU/storage foundation | `MapperState`, `MapperKnowledge` and `ProgramMapping` separate 16-bit CPU addresses, physical region/bank/offset, file offsets and static aliases. SLEIGH is the architectural instruction source. [Mapping][mapping], [mapper][mapper], [specification][spec] | General controller/device geometry, access-master/timing distinctions and executable-image generations are not represented completely. |
| Ordinary immutable-ROM bridge | `OrdinaryEntryAccess` proves and installs conditional aliases, rechecks dependencies and rederives serialized proofs at native invocation. Reused T2/A and EX-02-05 baseline/retained controls prove transport, stale refusal, refresh and current-candidate reopen. [Ordinary bridge][ordinary], [retained controls][retained] | The original canonical route's bank-sensitive data identity failure is not repaired merely by alias success. The bridge requires its declared synchronous domain and rejects unsupported routines. |
| Bank-changing fetch | `BankAnalysis.previewFetch` records physical bytes and ordered writes from its worklist; the ordinary adapter orders only a proved unique path. Reused EX-03-03/C controls show a bank-changing fetched sequence transported through segmented views. [Fetch analysis][bank], [EX-03-03 report][fetch-report], [retained C checker][retained] | A visitation trace is not a CFG. `orderedFetch` rejects multiple states at one instruction. Split decode/wrap and general branching need explicit support. |
| Unknown selector/pointer safety | EX-02-03 deliberately removes the relevant selector or pointer producer. The provider refuses read-only; known controls succeed. [EX-02-03 report][unknown-report] | This establishes no-fabrication safety, not general unknown-memory capability; the original U_PTR requirement remains open. |
| Finite input dependence | `FiniteEntryProducer` preserves unknown entry bytes as full byte domains and carries selector provenance. EX-02-04/05 capture checking establishes B/D-dependent reads, physical source associations and ordered mapper effects in one static artifact per request. [Finite producer][finite], [final checker result][checker] | Two-selector byte lowering, straight-line ROM0, exact pointers, bounded MBC5 geometry and fixed-WRAM effects are restrictions, not the final capability target. Missing knowledge safely refuses; original U_PTR remains required and open. |
| State-qualified calls and graphs | `SoftwareCallEffects`/`SoftwareCallContinuationView` already retain state, physical fetch/data identities, live call frames, local graph edges and typed transport vetoes. Existing tests cover repeated CPU PCs, later/nested calls, return variants and selected exact flag contexts. [Call graphs][effects], [graph lowering][continuation], [state tests][state-tests], [call decision][call-decision] | These exact-context successes do not prove a single unknown-input branching graph, joins/widening, arbitrary caller summaries or multiple configured domains at one physical software-transfer site. G2 targets that delta. |
| Program/entry isolation | EX-02-05 reuses the unchanged finite provider: simultaneous P/Q, legally bound persistent interfaces, Q-only stale/refresh, close/reopen, headless display selection, B0150/D0250 alternation, foreign/twin/serialized proof negatives. [Report][report], [ownership review][review] | Different entry PCs are not competing physical identities at the same CPU PC. A controller/window cache is a separate ownership layer. |
| Ownership and saved work | `AnalysisOwnership`, application reviews and registry validation retain original fields and preserve later user edits; actual registry-4 material exists. Reused current finite reopen passes. [Ownership][ownership], [application][application], [migration capture][old-capture] | Current-candidate reopen is not an old-provider migration. Broad annotation repair and downgrade/rollback require W5/G4. |
| Verification and operability | Reused final receipt: **684 tests, 65 fresh XML classes, zero failures/errors/skips**; focused six-class selection: 39 tests. Combined Gradle command fails on **169 unchanged lint findings**. [Full receipt][full], [lint comparison][lint] | Actual normal-window qualification remains blocked by the recorded AWT launch crash. No later GUI pass was identified in the selected evidence. [GUI record][gui] |

**Precise ordinary-proof baseline:** the positive ordinary path assumes boot bypass, no asynchronous interrupt/DMA or untracked mutation, an exact full ordinary MBC5 image with at most 256 banks, unknown canonical incoming CPU register context and no software-call registry. It proves immutable ROM reads and only supported mapper/fixed-WRAM effects. The ROM0 body is contiguous, at most 1,024 bytes, straight-line and ends at its actual C9; SP-changing body instructions are refused, with a symbolic fixed-WRAM return-frame domain SP C000–CFFD. The banked-fetch variant additionally requires a physical ROMX invocation justified by a fixed-ROM driver's actual call and a unique fetched sequence. These are source admission limits; the executed EX-02-04/05 witnesses specifically use the supplied four-bank fixtures, not every admitted image. These restrictions describe reused evidence and present guards, **not final acceptance exclusions**; section 5 assigns their generalization. [Ordinary bridge][ordinary], [EX-03-03 report][fetch-report]

Older decision documents contain registry-5/6 failures; inspected source is registry **7**, injection **5**, state-continuation **2**, ordinary-record **3-finite**. Current full-test success includes `SoftwareCallAutomaticAnalysisTest`; do not relabel an older failing test as a current failure. Conversely, those tests do not close the whole installed/window campaign. The handoff's prospective `static-dispatch-model.md` and `sa01-integration-20260907` receipt links are absent in this selected source; treat them as documentation gaps, not unseen evidence. [Bank decision][bank-decision], [automatic-analysis test][automatic-test]

## 3. Decisions to adopt, with explicit reconsideration conditions

| Decision | Recommendation and support | Required correction/generalization | Remaining uncertainty and concrete counterexample |
| --- | --- | --- | --- |
| D1 — Storage and execution representation | Retain physical backing plus derived views and state-qualified graph identity. Keep CPU pointers, PC/SP arithmetic and return words 16-bit. Existing graph/native tests are positive evidence; the retained widened-address candidate had failures. [Bank decision][bank-decision] | Add explicit image generation and predicate/invocation identity; separate graph nodes from Ghidra Function/listing extents. Never union incompatible bytes into one unconditional body. | **G2:** if a correctly derived two-path graph and physical calls cannot survive native flow/function recovery with existing transport, revise only the failing view/lowering/native boundary. Producer refusal alone is not evidence against representation. |
| D2 — Native transport | Keep the optional `__ghidraboy_state_entry_v1` pre-flow protocol and exact dependency checks. Keep ordinary non-protocol behavior intact. [Entry injection][entry], [native patch][native-patch] | Feed one shared validated graph/access representation into the existing bridge and software-call adapters; preserve raw operations and explicit effects. Add native capabilities only when a specific lowering cannot express its contract. | **G2/G3:** lost branch target, frame effect or symbolic memory dependency after correct payload admission forces a bounded protocol/lowering change. A missing companion must remain a clear capability refusal, never stock “success” with wrong constants. |
| D3 — Proof and ownership authority | Program-scoped live sessions; durable records identified by Program, image, domain, entry, engine and dependencies, rederived before use. No name/address-only cache. Preserve live-preview versus durable-authority distinction. [Ordinary bridge][ordinary], [fingerprints][fingerprint], EX-02-05 | Consolidate currently different fingerprint and registry policies. Initially retain conservative hashes; later narrow consumed dependencies with paired mutation tests and a versioned policy. Separate topology setup from display selection. | A byte-identical foreign live proof accepted, a restored edit escaping a live revision guard, or a consumed untracked reference/type change producing accepted stale output invalidates the policy. Persistent-ID reuse on legitimate reopen does not. |
| D4 — Abstract knowledge and effects | Preserve concrete mapper semantics as the leaf implementation; add a shared typed abstract layer with exact values, finite alternatives, bit constraints, symbolic values and explicit unresolved reasons. | Replace expression-string equality as the eventual semantic identity with typed expression/provenance nodes; keep correlations needed by selector pairs and call outcomes. Add ordered byte-access/effect records. Do not equate TOP with a hardware default or COMPLETE with closed-world proof. | **G2/G3:** unsupported correlation or mutable-memory behavior first requires value/effect-model work. If bounded joins lose mandatory target precision, introduce partitioning/relational facts locally; do not globally raise caps or silently drop alternatives. |
| D5 — Ordinary Ghidra integration | Add a thin provider service and user-facing actions for review/apply/refresh/navigation; use the stock window and Program event lifecycle. Existing Tools exposes software-call contexts, not a durable ordinary-bridge workflow. [Tools][tools] | Explicitly label conditional results. Only proven caller edges route to their contexts. Canonical entries may use an unconditional summary only when all declared entry conditions justify it; otherwise retain unresolved canonical behavior and expose reviewed contexts. | **G1:** pinned stock listener already schedules refresh for Program changes and resets on block add/remove/restore. A provider event or controller integration fix is conditional on observing stale owned window output. Do not assume public `DecompInterface` cache flushing reaches the window's controller cache. |
| D6 — Saved work and external contracts | Stage explicit, previewable migrations; preserve schema-v2 mapping and `ghigbc-knowledge-v1` adapters until a versioned successor is necessary. Keep old files immutable. [Knowledge export][knowledge], [consumer adapter][consumer] | Separate decoder, topology, executable proof, annotation and compiler migrations. Remove only unchanged owned replacements. Retain edited/uncertain views as nonexecuting or unresolved rather than claiming destructive authority. | **G4:** a genuine old Program loses a user edit, changes physical identity, or cannot be rolled back/reopened safely. Then ship read-only inspection/safe rejection for that old format until an explicit migrator exists; do not auto-upgrade it. |

**Pinned window source finding:** the runtime's `Decompiler-src.zip` contains `DecompilerProgramListener.domainObjectChanged`, which resets on `MEMORY_BLOCK_ADDED`, `MEMORY_BLOCK_REMOVED`, `RESTORED` and certain spec changes, then schedules the updater for all received events. `DecompilerController.refreshDisplay` clears its cache; `display` can reuse cached Function results; the provider's `doRefresh` calls `refreshDisplay`. This argues for testing event delivery and actual window ownership before adding another cache or patch. These are source findings, not GUI execution evidence. G1 must inspect the current window result passively before any Debug/Refresh action, because the built-in debug action also clears the controller cache. [Pinned runtime source archive][decompiler-src], [pinned DecompInterface][decomp-interface]

### Proposed shared contracts

These names are **proposed internal interfaces**, not claims that these Java classes already exist. Introduce them behind existing entry points before changing public/persisted formats.

| Proposed boundary | Required content/invariants | Current owner to adapt |
| --- | --- | --- |
| `ProgramAnalysisSession` / `ProofEnvelope` | Live Program token and revision guard; durable Program/image/domain/entry/engine identity; canonical versus derived entry; consumed dependency policy; complete/partial/unresolved scope; no result-chosen assumptions. | `OrdinaryEntryAccess`, `SoftwareCallRegistry`, `ProgramFingerprint` |
| `AccessRequest` / `AccessOutcome` | CPU address/width, read/write/fetch, master/phase, state-before; ordered per-byte sources and state-after; exact/finite/partial/symbolic value; mapped/disabled/device/blocked/open-bus/unknown status and reason. Written value, latch, effective mapping and readback are distinct. | `MapperState`, `MapperKnowledge`, `CartridgeBus`, `BankAnalysis`, both producers |
| `ExecutionStateKey` / graph | CPU PC + physical instruction/image identity + abstract domain/predicate + relevant memory/mapper state + invocation/live-frame identity. Stable edges and matched returns; joining values never merges different code images. | `SoftwareCallEffects`, `BankAnalysis`, `SoftwareCallContinuationView` |
| `EffectSummary` / `ImageIdentity` | Read/write/kill/ordering sets, return variants, asynchronous interference policy; original file versus patched ROM versus copied RAM bytes, generation and initializer provenance. Observed trace epochs do not prove all writers. | `SoftwareCallEffects`, `ProgramMapping`, future mutable-memory layer |
| `ReviewedChangeSet` | Baseline fingerprint, precise owned edits and preserved edits, source/provenance, vetoes, cancellation and reverse operations; transactional recheck before apply. | `AnalysisApplication`, `SoftwareCallApplication`, `AnalysisOwnership`, `FunctionDiscovery` |

Do not create a grand replacement IR before the first useful adapter. W1 preserves behavior; W2 makes access/value types useful to existing producers; W3 and W4 extend graph/effect content; W5 consumes these contracts. Source findings of disagreement between paths become localized corrections with tests, not silent selection of whichever path produces cleaner C.

## 4. Dependency-ordered work packages

Effort is relative engineering size, not a calendar promise: S = localized, M = several coordinated changes, L = cross-cutting, XL = several incremental deliveries. Gate uncertainty is stated separately from known implementation volume. One coordinator owns interfaces and integration. Parallel work requires nonoverlapping files and separate test outputs/Programs.

### W1 — Consolidate the working provider and its regression inputs

**Objective/gap:** turn the verified experimental baseline into maintainable source boundaries without changing its admitted domain. The ordinary bridge currently combines admission, fingerprints, persistence, alias setup and lowering; finite records depend directly on its nested source-byte records. Tests/captures also depend on handoff paths.

**Existing boundaries:** [OrdinaryEntryAccess][ordinary], [FiniteEntryProducer][finite], `SoftwareCallStateEntryInjection`, `SoftwareCallExecutionView`; `OrdinaryEntryAccessTest`, `OrdinaryFiniteAccessTest`, `OrdinaryBankedEntryTest`, `OrdinaryUnknownAccessTest`, `OrdinaryIsolationAccessTest`, `BankAnalysisFetchTest`. [Isolation tests][isolation-tests]

**Changes:** extract package-private dependency/admission and storage/lowering helpers in small stages, retaining public entry points and exact record fields. Remove duplicated plumbing only after equivalence. Place self-authored fixtures and pure checkers in durable test/tool locations with provenance and portable explicit paths. Keep an independent oracle separate from production transfer code. Add one evidence index referencing immutable past results and small new deltas; stop nesting predecessor archives. Repair documentation authority links, clearly identifying missing prospective docs and old-version receipts. Do not mark milestones complete.

**Dependencies/ownership:** no gate prerequisite. W1 owns ordinary-bridge refactoring and test resource migration; keep `ProgramFingerprint`, software-call schemas and mapper policy unchanged in W1a. L may run separately once file ownership is agreed.

**Acceptance/DoD:** the six actual focused classes are present in fresh XML; all prior supported payload semantics, rejected domains, Program/twin/entry isolation, ordered effects and current-record save/reopen survive. Refactoring must not change serialized schema, dependency digests for equivalent Programs, canonical annotations or native/SLA identity. Run broader provider validation at integration. Done when test inputs no longer require an attachment layout and each extracted boundary has one owner; preserved historical failures remain queryable.

**Compatibility/rollback:** same identifiers and record readers; revert the refactor without migrating Programs. New extension/JAR identities still receive a new receipt. **Effort M, risk low–medium**; risk is accidental serialization/fingerprint drift, not representation uncertainty.

### W2 — Program-scoped authority, abstract values and ordered access resolution

**Objective/gap:** unify scalar mapper knowledge, constant propagation and finite projection without erasing their distinctions. Current `MapperKnowledge` uses known/null registers, `BankAnalysis` stores known register bytes, `FiniteEntryProducer` uses bounded Cartesian sets, and each proof path hashes dependencies differently.

**Existing boundaries:** [MapperState][mapper], [MapperKnowledge][mapper-knowledge], [ProgramMapping][mapping], [BankAnalysis][bank], `PcodeConstants`, `InstructionInterpretation`, `CartridgeBus`, `AnalysisResult`, [ProgramFingerprint][fingerprint], `SoftwareCallRegistry.semanticDependencies`.

**Changes:** implement the proposed value/access envelopes with legacy adapters. Preserve byte overlap, signedness, 16-bit wrap and distinct physical sources for every byte; distinguish read/write/fetch before mapping. Generalize finite selector lowering beyond two alternatives using exhaustive guarded alternatives with an explicit unresolved/default path when coverage is incomplete. Retain original selector computation and effect order. Introduce relational selector facts only where independent sets lose required relationships. Define partial-value masks and endpoint outcomes instead of guessing bytes. Keep global hashes first; narrow to consumed code/data/context/reference/prototype/fixup/permission/image/summary dependencies only after proving exclusion safe. Add live revision race guards and Program-scoped lifetime/eviction; do not cache proofs solely by persistent ID or alias. Preserve generated-reference exclusion only where the analysis truly does not consume those references.

**Dependencies/ownership:** follows W1 interfaces. W3 may design graph adapters once value/access types stabilize. W4 owns new hardware semantics after this core adapter is integrated; do not concurrently edit `MapperState` or mapping schemas.

**Acceptance/DoD:** raw compiled p-code versus abstract inclusion and emitted behavior; direct/indirect/word/stack/RMW access ordering; split operands across mapped boundaries and FFFF→0000; exact, finite, partial and unresolved outcomes; correlated versus independent selectors and over-budget frontiers. Pair each narrowed dependency with consumed and irrelevant mutations, including reference-primary, nested datatype/prototype, permissions, aliases and change-then-restore races. Keep P/Q warm isolation and byte-identical foreign live-proof rejection. Done when all existing consumers use the common access contract and mandatory missing knowledge is reported structurally without fabricated precision.

**Compatibility/rollback:** internal adapters initially preserve mapping v2 and AnalysisResult schema. New persisted value/proof/dependency semantics require explicit versions and W5 migration/read-only rejection; old records never inherit new proof authority. **Effort L, risk high** from soundness and dependency completeness. G2/G3 constrain later extensions, not basic typed contracts.

### W3 — General control flow, invocation summaries and rooted discovery

**Objective/gap:** combine the existing exact-state graph/call mechanism with unknown-input finite analysis. Avoid rebuilding the call model from scratch or flattening state identity to a CPU address.

**Existing boundaries:** [SoftwareCallEffects][effects], [SoftwareCallModel][call-model], `SoftwareCallValidation`, `SoftwareCallConfiguration`, [SoftwareCallRegistry][registry], [SoftwareCallContinuationView][continuation], `SoftwareCallInjection`, `SoftwareCallMayReturnInjection`, `BankAnalysis`, `FunctionDiscovery`, `SoftwareCallInstructionDiscovery`.

**Changes:** partition branches with predicates, introduce sound joins and bounded loop convergence, retain unresolved successors after widening/budget exhaustion, and distinguish matched return, may-return, nonreturn and nonlocal outcomes. Preserve real hardware/software pushes, wrapper cleanup, flags, bank restoration and continuation words; a p-code CALL adds no implicit push. Key reusable summaries by invocation/domain and effects, not one physical configured site. Reuse exact-context summaries as proven specializations, not general ABIs. Lower the validated graph through existing state-entry transport with stable entry/projection labels. Separate pointer calls from actual tables; derive target sets/defaults from producers and relevant writers, then choose native recovery or a validated override/jumpassist only for its proper contract. Alternate discovery and summaries from justified roots until stable or explicitly incomplete; payloads/data remain reserved and speculative decode does not commit itself.

**Dependencies/ownership:** W2 access/value core; **G2 before accepting unknown-input multi-path native lowering**. W3 owns graph, registry invocation identity and summary semantics. W5 owns application/UI, using a frozen interface rather than concurrent registry edits. Basic root discovery work can precede G2; native multi-state completeness cannot.

**Acceptance/DoD:** extend existing state-path/callee/continuation/automatic-analysis tests with one unknown-domain diamond, same-CPU physical alternatives, call/return and backwards edges. Then add loops, nested/restoring/constant/nonrestoring/manual transfers, multiple domains at one configured site, zero/default/wrap dispatch and unknown writer/callee controls. Assert graph reachability and physical target/continuation mapping, SP/register/flag/memory effects and native results independently. Every unresolved required edge remains in denominators. Done when the required ordinary/call/dispatch/discovery families compose without per-fixture configuration or silent path loss; a safe refusal is safety evidence, not capability completion.

**Compatibility/rollback:** version changed graph/registry/summary records; preserve original body/override/fixup receipts and old readers' safe-rejection behavior through W5. **Effort XL, risk high**; G2 localizes producer, graph, lowering or native representation failure before broad generalization.

### W4 — Mutable memory, executable-image lifetime and hardware breadth

**Objective/gap:** preserve symbolic mutable-memory behavior and hardware effects beyond immutable-ROM substitution. Existing exact-state memory maps and scalar mapper/device results are useful foundations, not an asynchronous bus model.

**Existing boundaries:** `SoftwareCallEffects.Machine`/access ledger, `MapperState`, `MapperKnowledge`, `ProgramMapping.identifyRam`, `Cartridge`, `CartridgeLayout`, `MapperTopology`, `CartridgeBus`, `HardwareReference`, SLEIGH `data/languages/` when a demonstrated instruction-effect correction is required. [Hardware contract][input-policy]

**Changes:** add symbolic RAM inputs, precise alias-aware stores/read-after-write, unknown-store kill sets and effect summaries that preserve disjoint memory. Define executable image IDs and generation lifetimes independently from source-ROM patches and physical RAM storage. Track copy/decompression initialization and later replacement; invalidate decode, views and summaries on generation change. Model asynchronous/device boundaries with conservative read/write/interference summaries, per-data volatility where justified, and visible unresolved timing/flow obligations. Distinguish CPU, DMA and other access masters; preserve delayed EI, interrupt/RETI, HALT/STOP, timers, OAM/IDU non-target effects and transfer lifetime. Separate controller, board wiring, geometry, raw control latch, effective selection and device/readback. Extend ordinary controllers and uncommon topologies deliberately; enum additions alone cannot express MBC6 flash/windows or unusual reset/header mapping.

**Dependencies/ownership:** W2 first; **G3 before qualifying mutable native effects and replacement-image support**. W3 call summaries and W4 interference summaries must share effect identities. Hardware source-conflict resolution is targeted implementation evidence within this package, not a fifth general architecture survey.

**Acceptance/DoD:** G3 minimal pair, then SRAM/WRAM/VRAM/echo aliases, bank shadows, save-derived state and unknown stores; copied code versus replaced code and stale views; boot overlays and split fetch; disabled/device/blocked/open-bus/partial read outcomes; controller/wiring matrix including MBC1M, MBC30, MBC6/7, MMM01, M161, HuC1/HuC3, Camera, TAMA5 and identified unlicensed variants. Keep unresolved hardware conflicts explicit. Hardware-backed expectations plus self-authored/static checks are primary; emulator agreement is supplementary. Incremental deliveries may retain explicit unresolved rows, but W4 is capability-complete only when its required declared hardware matrix passes. Unresolved required rows remain W4 implementation backlog and prevent SA-06/07 closure.

**Compatibility/rollback:** new image/mapping identities require adapters and separate migration from listing repair; constructor/context changes require language migration tests. No ROM-writable or global-volatile workaround. **Effort XL, risk high**, driven by device semantics and temporal provenance; G3 is a contract witness, not a complete device emulator.

### W5 — Ordinary Ghidra workflow, annotation repair and saved-work compatibility

**Objective/gap:** turn conditional mechanisms into trustworthy ordinary analysis/navigation/decompilation, and preserve existing Programs and consumers during adoption.

**Existing boundaries:** [GhidraBoyTools][tools], [AnalysisApplication][analysis-application], [SoftwareCallApplication][application], [AnalysisOwnership][ownership], `ProgramKnowledge`, `FunctionDiscovery`, `SymbolService`, entry injection, existing migration scripts; proposed thin Ghidra plugin/controller-facing service. The root remains the sole SM83 provider; [BankMappings][consumer] currently explicitly requires mapping v2/default compiler.

**Changes:** expose preview, explain-unresolved, apply, refresh, remove and canonical/context navigation through ordinary Ghidra services. Distinguish selecting a view from changing invocation facts. Route proven calls to their own contexts; do not silently give unknown canonical callers a selected-context result. Eventually repair canonical semantics for the declared unconditional domain using shared analysis, retaining explicit conditional views wherever no unconditional summary exists. Use real Program events and stock controller invalidation; **G1 determines whether any additional event/controller integration is needed**. Quarantine stale executable proofs promptly; expensive refresh occurs in a cancellable background analysis/review transaction, never a mutating native callback.

Implement typed review changesets and field-level ownership comparisons. Inventory and adjudicate incorrect boundaries, references, functions/thunks, signatures and inline data; keep original/repaired denominators and provenance. Separate record/decoder/topology/annotation/ABI transitions. For old Programs, default to inspection and explicit migration or explicit non-destructive rejection. Preserve later user edits and uncertain historical ownership. Remove or retire only unchanged owned derived artifacts, including the existing caution about removing the last overlay block while consumers retain addresses.

**Dependencies/ownership:** service/action shell and inventories may start after W1; W2 proof contracts and W3/W4 capabilities integrate incrementally. **G1 gates normal-window claims; G4 gates enabling old-work migration by default.** W5 owns application/ownership/UI and adapters; no unreviewed changes to consumer repositories or active installations.

**Acceptance/DoD:** actual window-owned results/events (G1), fresh full automatic analysis including temporary UndefinedFunctions/projection entries, normal navigation and decompilation after byte/context/prototype changes; cancel during review/apply, change between preview/apply, partial failure rollback, user edits after apply and removal; genuine old Program inventory/migrate/rollback/separate-process reopen (G4). Add save/reopen for each new persisted behavior and compatibility tests for mapping/knowledge consumers. Done when supported ordinary workflows are usable without capture scripts and old formats have explicit safe dispositions. GUI absence does not justify declaring the feature qualified.

**Compatibility/rollback:** stage on copied projects/distributions; immutable pre-migration export and old runtime retained; reject unknown versions; downgrade via restored copy or a proven reverse migration, never assume an old provider understands new executable records. **Effort L, risk high**, mostly ownership and event/lifecycle integration.

### W6 — Compiler/metadata contracts and later consumer-linked analyzers

**Objective/gap:** expand existing ABI/symbol support and eventually recover typed data/assets from proven consumers, after memory and flow foundations can support it.

**Existing boundaries:** `CompilerAbi`, `FarCallConvention`, `SymbolFile`, `SymbolService`, `DataTypes`, `ProgramKnowledge`, compiler `.cspec` files, `src/test/resources/compiler/`, `FunctionDiscovery`. [Compiler support][compiler-doc]

**Changes:** retain assembly default; verify versioned current/legacy compiler storage rules, packed/aggregate/variadic results, flags, cleanup and far-pointer layouts against emitted code. Prefer supported Ghidra parameter-allocation rules when they express the ABI. Add metadata import adapters with exact image/toolchain/relocation/line provenance (RGBDS, SDCC, WLA-DX as required). Define data-consumer APIs for reads, extents, native/script callbacks and storage lifetime. Only after W3 discovery and W4 memory/image contracts stabilize, implement pointer/table/script/text/graphics/map/compression classification and bounded asset interpretation from verified metadata or consumers. Byte patterns, entropy and valid 2bpp decoding remain hypotheses, not automatic data annotations.

**Dependencies/ownership:** compiler fixture inventory and metadata parsing contracts can run early in separate files. Semantic ABI changes integrate with W3 call summaries/W5 migration. **No asset analyzer rollout before W3/W4 foundations and W5 reviewed application are ready.**

**Acceptance/DoD:** exact versioned compiler fixtures and imported source identity; relocation versus execution addresses, scratch lifetimes, alternate far pointers, native-versus-script control; false-positive 2bpp/compression/metadata controls and dual code/data roles. One vertical consumer-to-memory-to-typed-result example precedes broad analyzers. Done when required formats and consumer families have tested positive capability and sensitive negatives without guessing compiler origin.

**Compatibility/rollback:** version compiler profiles/import formats; preview annotation placements and preserve previous symbols/types/source maps. Never propagate an assumed ABI to unknown routines. **Effort L, risk medium–high**, dominated by version coverage and consumer completeness.

### W7 — Integrated accuracy, performance, operability and release qualification

**Objective/gap:** qualify the composed system on exact artifacts, not a sum of isolated passes.

**Existing boundaries:** `tools/check.py`, build/packaging scripts, dependency pins and companion installers, `tools/run_validation.py`, migration tooling, `docs/validation.md`, `docs/integration/status.json`, debugger support/packaging and consumer adapter tests. [Validation][validation], [retained milestones][roadmap]

**Changes:** one evidence index with immutable historical records and per-integration source/dependency/domain deltas. Automated compact summaries distinguish safety, positive capability, precision and qualification. Add request/worklist budgets, cancellation latency and bounded caching only after correct Program/entry/image/summary keys exist. Test lifecycle cleanup and support matrices for stock/missing/mismatched/qualified companion, each supported platform/compiler/schema tuple. Keep static-only builds independent of Python, SDL and emulator/private repositories. Retain notices and patch provenance. Integrate broader shared-semantics regressions at checkpoints rather than rerunning all historical campaigns after every edit.

**Dependencies/acceptance/DoD:** progressively consumes W1–W6; final required claims depend on G1–G4 and applicable SA acceptance rows. Raw instruction semantics, abstract inclusion, emitted operations, native HighFunction/C, saved database state and actual normal window are separate oracles. Use self-authored cases, pinned compiler builds and reconstructed public patterns; optional private corpora remain outside generic distribution. Keep warnings/failures and original function/case denominators. Qualify process/service close, error logs, cancellation, memory/time budgets, migration/recovery, consumer compatibility and package rollback on exact artifacts. Any required unresolved capability or blocked required platform keeps its release gate open. **Effort L ongoing, risk medium–high** from composition and operational coverage.

**Rollback:** packages and native dependencies remain independently identifiable and revertible; installation/publishing requires separate authorization. No release or milestone completion is asserted by this plan.

### L — Mechanical baseline lint cleanup

Fix the 169 baseline diagnostics in a separate mechanical change with its own diff and receipt. Do not mix with W1/W2 semantics or reinterpret lint failure as a semantic defect. Preserve tests and generated/persisted behavior; run the affected formatting checks, focused tests if source structure changes, and full checkpoint validation when integrated. Nonoverlapping file ownership or serialized integration prevents collision with W1/W3. **Effort S, risk low**. No cleanup was performed in this planning task.

## 5. Temporary restrictions and their disposition

**Final-target rule, incorporating the updated prompt:** the small proof domains were chosen to isolate testing questions. They are not the final product specification. The completed implementation must not require two selectors, straight-line code, one exact configured invocation, immutable-ROM-only reads, fixed-WRAM-only effects, a single terminal C9, or blanket boot/interrupt/DMA exclusions for all analysis. W2–W6 own their generalization. Narrow current paths may survive as optimizations with proved preconditions, but broader required cases must reach the general service rather than be rejected solely by the old experimental guards.

W1 intentionally preserves behavior only during consolidation; it does not freeze these restrictions for release. Keep the old bounded fixtures as regressions and add successor capability tests that exceed each temporary limit. Resource/time budgets remain necessary operational controls, but exhaustion produces an explicit incomplete result and cannot waive a required acceptance case. Execution conditions remain truthful attributes of individual claims; a simplified test premise must never silently become an application-wide entry fact. Final SA/FX acceptance continues to require the broader memory, flow, hardware and saved-work scope mapped below.

| Current restriction | Planned disposition |
| --- | --- |
| Straight-line, terminal C9, bounded ROM0; banked adapter requires a uniquely ordered physical path | Replace the linear adapter's role with W3 graph lowering after G2. Keep a simple fast path and explicit unsupported frontier; never truncate a Function to qualify it. |
| At most two finite selector alternatives; finite native read lowering is byte-only | Generalize in W2 to guarded finite/partial results and ordered multi-byte reads. Retain finite resource budgets as honest operational limits, not “all required values exhausted” proof. |
| 1,024-byte/4,096-operation/256-value/expression-length limits and Cartesian may-domain | Version/document budgets; replace string expressions with typed provenance, add partitioning/joins/widening in W2/W3. Preserve uncertainty when limits are hit; test required precision separately from sound overapproximation. |
| Ordinary MBC5 geometry, at most 256 banks; low-selector finite path | Generalize through W2 byte ordering and W4 controller/wiring contracts, including correlated MBC5 high/low effects. Do not globally alter hardware behavior by raising one constant. |
| Exact immutable-ROM reads; fixed-WRAM writes; constrained symbolic return frame | Retain immutable-ROM optimization; add W4 symbolic mutable memory and image lifetime after G3. The frame domain is an explicit current premise, not a general stack rule. U_PTR stays open until general pointer/endpoint behavior is implemented. |
| Ordinary bridge rejects presence of the software-call registry and unknown/partial call domains | W2/W3 reconcile proof authority and compositional summaries before removing the veto. Removing a guard alone is not integration. |
| Exact-state calls/flags and one configuration per physical software-transfer site | Generalize invocation keys and summaries in W3; retain exact specializations with truthful domains. Existing two-context tests do not establish one unknown-input CFG. |
| Whole-Program/block/function hashes stale unrelated same-Program setup | Keep conservatism initially. W2 introduces audited consumed dependency sets; W5 separates semantic changes, topology changes and selection events. Never skip hashes simply to keep a view current. |
| Conditional aliases, experimental record names, custom capture scripts | W1 consolidates code/tooling; W5 supplies ordinary UI/controller integration and versioned durable records. Retire superseded duplicate mechanisms only after equivalent tests/migration. Keep old receipt interpreters as read-only compatibility tools. |
| Synchronous/no boot/no interrupt/DMA/untracked mutation; limited devices | Retain as labeled support boundaries for current optimizations. W4 expands required domains with explicit effects; these limitations do not become permanent optional omissions. |
| Optional pinned native companion; current-candidate reopen only | Retain dependency identity checks, support matrix and explicit failures. W5/G4 establishes old-work policy; W7 qualifies installations/platforms. No SLEIGH/public schema redesign without a separately evidenced necessity. |

## 6. Requirement routing without deleting scope

This mapping assigns ownership, not completion. The [specification][spec], [roadmap][roadmap] and original [FX/amendment crosswalk][crosswalk] remain the authorities. Catalog cases become implementation acceptance discriminators under their existing IDs; they are not queued tasks.

| Existing IDs | Owning packages / qualification |
| --- | --- |
| SA-00; S-01–S-04; A-CPU, A-DEPENDENCIES | Maintain through W1/W2; W5 transactions and W7 composition. SA-00's historical completion is not reset or expanded. |
| SA-01; S-08; A-CALL | W3; W5 ordinary analysis; G2 and W7 |
| SA-02; S-05–S-06; A-BUS, A-GHIDRA | W2/W3/W4/W5; G1–G3 |
| SA-03; S-02, S-05–S-09; A-STATE, A-FLOW | W2/W3/W4; G2/G3; W7 |
| SA-04; S-10, S-13; A-DISCOVERY, A-MIGRATION | W3/W5; W6 consumer classification; G4 |
| SA-05; S-11; A-ABI-DATA | W6, W3 ABI summaries, W5 migration |
| SA-06; S-07, S-12; A-CART | W4/W2; W7 hardware matrix |
| SA-07; A-CORPUS and every applicable A gate | W7, consuming W1–W6 and G1–G4 |
| FX-01, FX-25 | W3 discovery/projection entries + W5 automatic analysis; G1 |
| FX-02–FX-07, FX-33 | W3 invocation/backedges/nested/frame coverage; G2 |
| FX-08–FX-10 | W2 access kind/data-vs-code/ordered controls + W3; G2/G3 |
| FX-11–FX-17 | W4 controller/wiring/bank/blocked/boot coverage + W2; A-CART/A-BUS |
| FX-18–FX-19 | W4 shared RAM and replacement images + W5 persisted invalidation; G3 |
| FX-20 | W6 compiler/banked ABI + W3/W5 |
| FX-21 | W2 dependencies + W5 events/transactions; G1/G4 |
| FX-22–FX-23 | W5 genuine migration and preserve-later-edits; G4 |
| FX-24, FX-26, FX-34 | W5/W7 dependency matrix, normal navigation, full-tool orderly close/logged errors; G1 |
| FX-27–FX-29, FX-31–FX-32 | W6 metadata, graphics false positives, bounded compression, contextual roles, consumer vertical slice; W3/W4/W5 prerequisites |
| FX-30 | W3 dispatch domain/default semantics + W6 consumer contracts |
| M0, M2, M3 | W1/W5/W7 identity, source migration, build/package ownership |
| M5, M6, M10 | W5/W7 persisted compatibility, release/recovery/cutover; G1/G4 |
| M7, M9 | W4 hardware and W3/W6 analysis/research integration; W7 qualification |
| M1, M4, M8 | Retain debugger/backend feasibility, parity and conformance in their existing backlog; W4/W5 contract changes trigger adapter checks; W7 must not claim these completed through static tests. |

**Amendment mapping:** the retained crosswalk supplies 20 exact topic labels and explicitly says original FA IDs were not recovered. A targeted filename search did not locate `additional-fixture-families.yaml`; no IDs are invented. Preserve these labels and restore original IDs if that specific artifact is later found. This documentation gap does not block W1 or create a fifth experiment gate.

| Retained amendment topics (exact labels) | Owners |
| --- | --- |
| MBC2 partial values; Written value, latch, effective mapping and readback | W2/W4 |
| MBC5 source conflict; MBC6 and writable flash; Uncommon controller scope | W4 |
| OAM/IDU effects; DMA masters; HBlank transfer lifetime; CPU control transitions; Timer writes; Model-specific unusable space; Boot provenance | W4, W2 access contract, W7 coverage |
| Split fetch and wrap; CPU/p-code coverage | W2/W3, W7 |
| Abstract soundness and budgets; Native versus custom effects | W2/W3/W4, G2/G3, W7 |
| Warm decompiler lifecycle; Snapshot scope; Transactional application | W2/W5/W7, G1/G4 |
| Foundational consumer contracts | W6 after W3/W4/W5 |

## 7. Integration, migration and acceptance policy

Implementation proceeds with focused tests on changed code, broader regression when a shared semantic/dependency boundary changes, and full validation at integration checkpoints. Verify each requested class appears in fresh XML. Do not add focused totals to full totals. Keep child exits, skipped facilities and known baseline lint separate.

For each new capability require: a declared domain and independent expected result; a positive native or ordinary-workflow witness where appropriate; a sensitive negative for wrong physical/source/owner/effect behavior; and a clear unresolved frontier. Unit refusal alone is insufficient. Reuse unchanged source/dependency/domain evidence by reference; rerun only affected or newly composed assumptions. Maintain raw SLEIGH, overridden/injected p-code, firstpass, optimized HighFunction/C, persisted Program and window-owned evidence as separate layers. Firstpass is not raw input; debug replay is not packed wire capture.

Persisted changes need preview, conflict inventory, atomic revalidation/apply and cancellation rollback. Preserve original bytes, patched bytes and RAM images separately. A migration must record what is retained, rederived, retired, rejected and corrected, including disproven annotations; preservation is not a requirement to keep known errors indefinitely. Keep an immutable copy for rollback and test reopening it under the identified old runtime. Current persistent-ID reuse is valid only alongside the appropriate durable rederivation and dependency contract, never as an authorization shortcut.

Do not broaden production claims while G1's facility is unavailable, but continue non-GUI work. G2/G3 failures are localized by comparing graph/access proof, emitted payload, native result and database identity. G4 may legitimately establish safe rejection rather than migration capability. If another independent architecture blocker appears, name it, explain why G1–G4 cannot answer it, and request separate authorization for investigation; do not silently extend the campaign.

## 8. Execution order and parallel ownership

| Stage | Work that can proceed | Wait condition |
| --- | --- | --- |
| First integration | W1a, then remaining W1; L as an isolated mechanical change | No G gate |
| Foundation | W2 value/access/proof adapters; W4 contract/geometry design; W5 inventory/action-service design; W6 compiler/metadata inventory in separate files | Freeze shared interfaces before parallel implementations |
| Generalization | W3 branching/summaries with G2; W4 mutable effects/images with G3; W5 actual window event witness G1 on a usable facility | Only dependent capability acceptance waits on its gate |
| User workflow | W5 transactional application and G4 migration; compose W2–W4 into canonical/conditional workflow | Do not enable unqualified migration or claim normal-window success |
| Higher consumers | W6 data/asset analyzers, after required flow/memory/lifetime and review boundaries | W3/W4/W5 foundations |
| Qualification | W7 integration checkpoints throughout; final matrix at completion | All applicable required capability/compatibility/operability gates |

One coordinator owns integration and shared contract revisions. Future implementation workers may split independent boundaries, but no concurrent edits to a shared registry/mapper/ownership file, no tests racing one Program or native interface, and no installations racing shared output directories. Reviews focus on new risk and changed assumptions. Existing evidence remains immutable in one index; small deltas replace recursive handoffs.

## 9. First implementation slice safe to authorize: W1a

**Exact scope:** in a new implementation checkout based on this selected source, extract only `OrdinaryEntryAccess.fingerprint` and its dependency-validation plumbing into one package-private helper (proposed `OrdinaryProofDependencies`), leaving the public `Proof`/registration types, serialized fields/order, version strings, live-instance semantics, mapper logic, domains, alias naming and emitted operations unchanged. Keep it private to the ordinary path initially; do not unify the software-call hash policy in this slice. Move the existing self-authored ordinary/finite/isolation fixture inputs into durable test resources, retaining their exact hashes/provenance and the independent checker separation. Update the relevant source/test entry documentation without advancing milestone status.

**Tests:** the six existing focused classes listed in W1, including `OrdinaryIsolationAccessTest`; dependency mutation/restoration and byte-identical twin negatives; compare equivalent pre/post-refactor proof fingerprints and emitted p-code; current-version save/reopen and unchanged canonical annotations. Then the standard full provider checkpoint and build-input suite on the new artifact, with L's 169 baseline findings reported independently if L is not yet merged. Reuse existing native captures as the semantic baseline; a changed shared native path requires the focused retained controls, not a fresh catalog campaign.

**Done/stop:** finish when the extraction is behavior-preserving and fixtures are self-contained, with actual focused XML membership and a new integration receipt. Stop and preserve a failing variant if equivalence requires changing proof authority, schema, finite domain, native/SLEIGH behavior or canonical semantics. Those changes belong in W2/W3/W5 under their own acceptance criteria. Do not automatically run G1–G4 or EX-09-01 as part of W1a.

**Inputs missing:** no source/runtime prerequisite prevents this slice or this plan. Only the original amendment FA-ID catalog was not located; the exact 20 retained topics are mapped above. G1 infrastructure remains an explicit qualification blocker. G4's genuine old Program and identified old runtime are present; see the gate document.

**Planning review:** one targeted independent reviewer inspected the draft decisions, first slice, gate boundaries and selected source contracts. The G1 passive-observation rule above incorporates its cache-clearing concern. Reference/path and requirement-routing checks are document checks only; no Gradle/native/GUI/emulator campaign ran during planning.

## Source and evidence references

[manifest]: evidence-index.json#historical-reference-manifest
[reconstruction]: evidence-index.json#historical-reference-reconstruction
[report]: evidence-index.json#historical-reference-report
[retained]: evidence-index.json#historical-reference-retained
[checker]: evidence-index.json#historical-reference-checker
[review]: evidence-index.json#historical-reference-review
[full]: evidence-index.json#historical-reference-full
[lint]: evidence-index.json#historical-reference-lint
[gui]: evidence-index.json#historical-reference-gui
[spec]: ../static-analysis-spec.md
[roadmap]: ../roadmap.md
[crosswalk]: evidence-index.json#historical-reference-crosswalk
[ordinary]: evidence-index.json#maintained-source-ordinary
[finite]: evidence-index.json#maintained-source-finite
[bank]: evidence-index.json#maintained-source-bank
[mapping]: evidence-index.json#maintained-source-mapping
[mapper]: evidence-index.json#maintained-source-mapper
[mapper-knowledge]: evidence-index.json#maintained-source-mapper-knowledge
[effects]: evidence-index.json#maintained-source-effects
[continuation]: evidence-index.json#maintained-source-continuation
[call-model]: evidence-index.json#maintained-source-call-model
[registry]: evidence-index.json#maintained-source-registry
[fingerprint]: evidence-index.json#maintained-source-fingerprint
[entry]: evidence-index.json#maintained-source-entry
[native-patch]: evidence-index.json#maintained-source-native-patch
[ownership]: evidence-index.json#maintained-source-ownership
[application]: evidence-index.json#maintained-source-application
[analysis-application]: evidence-index.json#maintained-source-analysis-application
[tools]: evidence-index.json#maintained-source-tools
[knowledge]: evidence-index.json#maintained-source-knowledge
[consumer]: evidence-index.json#maintained-source-consumer
[state-tests]: evidence-index.json#maintained-source-state-tests
[automatic-test]: evidence-index.json#maintained-source-automatic-test
[isolation-tests]: evidence-index.json#maintained-source-isolation-tests
[bank-decision]: ../decisions/static-bank-model.md
[call-decision]: ../decisions/static-call-model.md
[old-capture]: evidence-index.json#historical-reference-old-capture
[decompiler-src]: evidence-index.json#historical-reference-decompiler-src
[decomp-interface]: evidence-index.json#historical-reference-decomp-interface
[input-policy]: ../input-policy.md
[compiler-doc]: ../compiler-support.md
[validation]: evidence-index.json#maintained-source-validation

[sealed]: evidence-index.json#historical-reference-sealed

[unknown-report]: evidence-index.json#historical-reference-unknown-report
[fetch-report]: evidence-index.json#historical-reference-fetch-report
