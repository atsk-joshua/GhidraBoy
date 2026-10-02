# Implementation status

## CGB-SPEED-SWITCH-2 — bounded implementation candidate

BankAnalysis implements the [bounded KEY1/STOP control relation](../decisions/cgb-speed-switch.md).
Transient active-mode, current-speed, arm, IE and JOYP-selection facts support
partial KEY1 reads and source-derived raw BIT/SET effects. CGB hardware/header
capability alone does not establish active mode. Only tested compatible mode/speed/arm
alternatives split and stay separate through conditional exploration and meet conservatively
at returning calls. Software cannot change KEY1's read-only speed bit.

Only canonical two-byte STOP with active CGB, known speed, armed KEY1, IE=00 and
both JOYP input groups deselected toggles speed, clears arm and continues at CPU
address +2. Ordinary RAM, real return frames and mapper state survive; no timer,
IF, IME, actual input or asynchronous execution state is invented. Other STOP and
HALT behavior remains incomplete. Exact KEY1 joins the finite ordinary-memory
noninterference set; IF=00, IE=00 and known JOYP deselection writes have separately
value-qualified preservation guards. DMA, unknown writes and other control values
retain conservatism.

Engine `20261002-cgb-speed-switch-2` retains schema 4. RAW-FLOW-VIEW-1 results
require recomputation and cannot authorize publication; obsolete exact owned stock
flow retains retirement authority. SLEIGH, mapper semantics, the 179-state local
budget and global/depth limits remain unchanged. WUX-1P and WUX-1A remain CLOSED /
QUALIFIED; WUX-1B has not begun. Detailed qualification belongs to external batch
`CGB-SPEED-SWITCH-2-20261002`. Full-provider aggregate, installation and release
qualification remain separate obligations.

Focused qualification passes 518 JUnit cases across 41 reports, including 43
self-authored control cases, with no failures/errors/skips; lint, extension,
build-input and documentation/package checks pass. Separate-process old-engine
rejection, current recomputation, speed-switch save/reopen and isolated STOP
second-byte invalidation pass. Independent source review has no blocking findings.
The unseeded public 02B1 replay preserves the four/eight loops, rom4 matched
return, timer liveness, HRAM helper and raw 02DF JP beneath CALL_RETURN. It derives
CGB NORMAL on the KEY1 bit-clear path, arms KEY1, establishes IE=00/JOYP=30 and
resumes STOP at 15C7 as DOUBLE/unarmed with all 99 ordinary facts preserved.
The 15B3 callee returns compatibly; 1571 resumes at 1574 with SP=D000.

The next independent frontier is 1574 -> 0618 -> 06BC: unresolved storage,
32-key widening at 06D0..06D4 and the unchanged 179-state refusal at 06D6.
The unrestricted 571-state witness suppresses all final proof authority after
that incomplete callee. An explicitly restricted unseeded prefix ending before
1574 retains current exact 37F3 and 1571 certificates. Later 1577 preserves
CALL_RETURN presentation and raw RST word 1578; SP is unknown after the 1574
refusal. No storage/widening repair, state-limit change or WUX-1B work is included.

## RAW-FLOW-VIEW-1 — bounded implementation candidate

BankAnalysis uses the [architectural instruction view](../decisions/raw-flow-view.md)
for raw p-code and prototype/context flow type, targets and fallthrough beneath
saved Ghidra FlowOverride presentation. All enum classes remain presentation
state. Same-target ordinary stock retyping is permitted by the separate raw gate;
foreign targets, explicit reference overrides, length/fallthrough changes and
unsupported fixups or unsafe conventions remain unresolved. Shared stock-flow
publication validators retain their strict representation contract.

Engine `20261002-raw-flow-view-1` retains schema 4. TIMER-WRITE-LIVENESS-1 results
require recomputation; exact obsolete owned physical CALL receipts retain only
retirement authority. Presentation dependencies remain fingerprinted and
unowned overrides are preserved. Loop semantics, mapper/stack checks, timer
qualification, depth and the 179-state invocation budget remain unchanged.

Focused generic tests and separate-process self-authored stock Shared Return
Calls save/reopen qualify this boundary. The unseeded public Wyatt witness
retains exact four/eight loops and the 179-evaluation rom4 invocation, timer
frame and HRAM-copy return. Saved 02DF CALL_RETURN remains present while raw JP
follows 156D with SP=D000 and no push. The next independent frontier is the
1571 CALL to 15B3: volatile KEY1/FF4D reads and the STOP arm prevent a complete
matched-return proof. Later 1577 retains its unknown-provenance CALL_RETURN and
raw RST push/continuation, but incoming SP is already unknown after the refused
call; no concrete stack addresses are claimed there.

The unrestricted replay conservatively suppresses all published proof authority
after downstream incomplete callee exploration. A separately declared finite
prefix ending at that call boundary revalidates the exact 37F3 physical CALL
certificate. Neither witness publishes into or saves the private Program.
Evidence is indexed under `RAW-FLOW-VIEW-1-20261002`; the next frontier remains
outside scope. Full-provider aggregate, installation and release qualification
remain open; WUX-1B has not begun.

## TIMER-WRITE-LIVENESS-1 — bounded implementation candidate

The [ordinary RAM contract](../decisions/ordinary-ram-byte-facts.md) adds only
exact FF06/TMA and FF07/TAC to the finite qualified ordinary-memory write set.
Known and unknown bytes preserve existing ordinary WRAM/HRAM facts without
creating timer facts or modeling asynchronous interrupts. FF04/DIV and FF05/TIMA
remain unqualified. Engine `20261002-timer-write-liveness-1` retains schema 4;
LOCAL-STATE-3 authority requires recomputation and obsolete owned flow retains
retirement authority only. Loop semantics and the 179-state invocation budget
remain unchanged.

Focused qualification, packed lifecycle and unseeded public Wyatt progression
are recorded externally in `TIMER-WRITE-LIVENESS-1-20261002`. Its then-retained 02DF
CALL_RETURN frontier is now traversable under RAW-FLOW-VIEW-1 above.
The earlier 37F3 invocation can receive a bounded certificate; that does not
establish whole-session completion beyond the independent frontier. Full-provider aggregate, installed and release qualification remain
open; WUX-1B has not begun.

## LOCAL-STATE-3 — bounded resource candidate

The [local invocation resource contract](../decisions/local-analysis-budget.md)
raises the internal per-invocation evaluation guard from 128 to exactly 179,
without headroom. Engine `20261002-local-state-3` retains schema 4; LOCAL-LOOP-1
results require recomputation, while known obsolete owned flow retains retirement
authority only. Loop/flag/predicate semantics, cycle admission, widening, global
budgets, depth, recursion and cancellation remain unchanged.

Focused qualification and the unseeded public witness are recorded externally in
`LOCAL-STATE-3-20261002`. The downstream timer frontier remains outside scope.
This is an intermediate candidate; full-provider, installed and release
qualification remain open. WUX-1B has not begun.

## LOCAL-LOOP-1 — focused implementation candidate

The [finite conditional-loop contract](../decisions/finite-conditional-loops.md)
adds pure raw CBRANCH predicate selection, transient partial F-bit precision and
ordinary-invocation JoinKey graph termination checks. Self-authored public CALL
fixtures establish four INC/CP iterations and eight DEC/copy iterations with exact
counter/pointer exits, unknown-predicate alternatives, returned flag meets,
branch-order invariance and stable/wraparound/unknown-state refusals. RAM meets,
physical/frame/mapper guards, recursion/depth, cancellation, global budget,
128-state invocation limit and 32-key widening remain unchanged.

Engine `20261002-local-loop-1` retains schema 4. Prior-engine results require
recomputation; obsolete owned physical CALL flow has retirement authority only.
Focused validation passes 422 tests across 35 JUnit reports with zero failures,
errors or skips, plus lint and extension build. Packed currentness/reopen and
retirement controls include the preceding 2F engine. Independent semantic review
and raw compiled instruction evidence are in external batch
`LOCAL-LOOP-1-20261002`. The original N6 test expecting both known-condition JR
arms is superseded by hardware truth-table assertions; its failed run is retained.

This is a focused candidate only. Unseeded Wyatt source-path, integrated Linux
qualification and WYATT-GAP-2 remain open gates. A hardware-finite invocation may
still exceed the retained resource budget. No whole-ROM, arbitrary-loop, installed,
headed, Steam Deck, Wyatt workflow or release acceptance is claimed. WUX-1A remains
CLOSED / QUALIFIED; WUX-1B has not begun.

## CALL-STACK-LIVENESS-2F — bounded implementation

The exact ordinary-memory noninterference set adds FF25/NR51 only: FF24, FF25,
FF26, FF40, FF42, FF43, FF4A and FF4B. Known and unknown NR51 writes preserve
existing ordinary WRAM/HRAM facts without creating APU state in the supported
synchronous domain. See the [RAM contract](../decisions/ordinary-ram-byte-facts.md).
Engine `20261002-call-stack-liveness-2f-1` retains schema 4; 2E results require
recomputation and obsolete owned flow retains retirement authority only. COPY,
depth and resource bounds remain unchanged. Focused validation and bounded Wyatt
replay are recorded externally in `CALL-STACK-LIVENESS-2F-20261002`. Final campaign/
evidence-index closeout remains open; WUX-1A remains CLOSED / QUALIFIED and
WUX-1B has not begun. No full-provider, installed or release qualification is claimed.

## CALL-STACK-LIVENESS-2E — bounded implementation

The exact ordinary-memory noninterference set adds FF24/NR50 only: FF24, FF26,
FF40, FF42, FF43, FF4A and FF4B. Known and unknown NR50 writes preserve existing
ordinary WRAM/HRAM facts in the supported synchronous domain without creating
APU state. FF25 remained unqualified at that checkpoint. See the [RAM contract](../decisions/ordinary-ram-byte-facts.md).
Engine `20261002-call-stack-liveness-2e-1` retains schema 4; prior engine results
require recomputation and obsolete owned flow retains retirement authority only.
Memory-storage COPY, depth and resource bounds remain unchanged. Focused tests
and bounded Wyatt replay are recorded externally in `CALL-STACK-LIVENESS-2E-20261002`.
Final campaign/evidence-index closeout remains open; WUX-1A remains CLOSED /
QUALIFIED and WUX-1B has not begun. No full-provider, installed or release
qualification is claimed.

## CALL-MEMORY-COPY-1 — bounded implementation

BankAnalysis now interprets a one-byte default CPU memory-storage COPY input
through the existing mapper/physical read and SymbolicMemory/ReadOutcome path.
Constants, registers and unique temporaries retain scalar COPY semantics.
Supported reads with unknown or absent contents remain structurally supported;
unsupported/unresolved physical effects still refuse callee composition. Other
spaces and multi-byte storage COPY are unqualified. Language and raw p-code are
unchanged. See the [RAM contract](../decisions/ordinary-ram-byte-facts.md).

Engine `20261002-memory-storage-copy-1` retains schema 4; 2D results require
recomputation and obsolete owned CALL flow retains retirement authority only.
Focused validation and bounded Wyatt replay are recorded in external batch
`CALL-MEMORY-COPY-1-20261002`. The supported C100 read may remain unknown while
preserving coverage. Broader CALL-stack campaign closeout remains open, WUX-1A
remains CLOSED / QUALIFIED and WUX-1B has not begun. No whole-ROM, full-provider,
installed/native/GUI or release qualification is claimed.

## CALL-STACK-LIVENESS-2D — bounded implementation

The ordinary-memory exception now covers exactly FF26, FF40, FF42, FF43, FF4A
and FF4B on established GB/CGB hardware. Known and unknown written byte values
preserve existing physical WRAM/HRAM facts only; no device state, interrupt,
timing, PPU or APU completeness is established. See the
[RAM contract](../decisions/ordinary-ram-byte-facts.md). Mapper/bank handling,
reads, structural/value coverage, frame identity and maximum depth three remain
independent. FF41/FF0F/FFFF, DMA triggers, unclassified and unresolved writes
retain conservatism. Engine `20261001-call-stack-liveness-2d-1` retains schema 4;
2C results require recomputation and obsolete owned flow retains retirement
authority only.

Focused device, retained 2A/2B/2C, mapper and WUX currentness/packed lifecycle
validation and bounded source-derived Wyatt replay are recorded in external batch
`CALL-STACK-LIVENESS-2D-20261001`. This bounded step leaves final integrated
campaign/evidence-index closeout open. WUX-1A remains CLOSED / QUALIFIED; WUX-1B
has not begun. No whole-ROM, installed/native/GUI or release qualification is
claimed. The replay frontier is recorded in the batch without repair.

## CALL-STACK-LIVENESS-2C — bounded implementation

The internal ordinary-call maximum advances from two to three active invocations
under the [2C contract](../decisions/three-level-ordinary-call.md). Fourth calls,
recursion, cycles, incomplete paths, unsafe frames/mapper identities and resource
limits remain refused. Device-write handling and 2B read semantics are unchanged.
Engine `20261001-call-stack-liveness-2c-1` retains schema 4; pre-2C saved results
require recomputation and obsolete owned flow retains retirement authority only.

Focused depth, retained N4–N7, WUX-1P/WUX-1A, 2A/2B and packed lifecycle checks
qualify this bounded implementation. Detailed receipts stay in external batch
`CALL-STACK-LIVENESS-2C-20261001`; final integrated campaign/evidence-index closeout
remain open. WUX-1A remains CLOSED / QUALIFIED. WUX-1B has not begun. Broader
Wyatt composition, device frontiers, whole-ROM, installed/native/GUI and release
qualification are not established by this step.

## WUX-1A — CLOSED / QUALIFIED

WUX-1A qualifies bounded ordinary unconditional returning direct-CALL stock flow
from exact current typed WUX-1P proof. Conditional CALL and software-call behavior
are unchanged. JP HL / WUX-1B remains separate and has not begun. Bounded fixture
evidence does not establish whole-ROM completeness or headed, Steam Deck, Wyatt,
debugger or release qualification.

The implementation commits are `fa2fc684329291bf499155ffe8894cc00162d8ac`
and lifecycle hardening `3a092c82f565e32d3a422739f89dd708b7fb654b`.
Q1 tested the latter plus the test-only oracle repair, tree
`763142ff4c9fc6539fcf64d3f4a1cdb9a8562f35`. The distinct Q1 test-oracle
closeout commit is `9c3e584930df2f84e2d6697191de1c6c7306d914`, tree
`aa443cd5e51af64ea63243179dbb957768b71657`; PQ1-D2, Q2A and Q2B qualify
that exact candidate. The final WUX-1A-CLOSE commit containing this status is a
separate documentation/evidence-only child of that Q1 closeout. Its post-commit
HEAD/tree is recorded in the external closure batch's `commit-identity.json`,
avoiding a self-referential commit hash. Production manifest remains
`42034e687d457f5e6510a023db5a4c70d85e623ed4ded6f8834de6029148896b`.

Q1-R1 passes the complete pinned Linux Ghidra 12.1.3 / JDK 21 aggregate:
1,130 PASS across 108 JUnit XML reports, zero failures, errors or skips. Actual
native CALL has sole target `rom2::4100`; raw architectural p-code equivalence,
inherited mapper-store native lifecycle, lint, build and static checks pass.
The inherited one-byte `c9` debug acquisition is a WUX-1P oracle erratum;
semantic missing-state-entry rejection remained correct, with no production regression.

PQ1-D2 is **HARNESS_ORDERING**: legitimate fingerprint invalidation and stale
retirement preceded the external harness's late creation of its independent
`0150` root. There was no contemporaneous physical-high-pcode / CPU-native
mismatch. Normal external-entry stock analysis converges to physical native CALL;
no production repair was indicated.

Q2A **PASS** establishes separate-process A/B publication, save/reopen, durable
receipt/flow and normalized currentness without transient cache state. C mutates
a consumed RET dependency: analysis retires stale authority before incomplete
recomputation, restores exact CPU DEFAULT and issues no new certificate/physical
flow. D independently reopens and confirms durable retirement, stale-result
rejection and preserved user/Function work. The unrelated incomplete invocation
control retains still-current authority through fresh reopen. Raw p-code is unchanged.

Q2B is **RECREATED_BUT_USER_SAFE**. Untouched generated/owned Functions may be
removed by `AnalysisOwnership.remove("functions")` and recreated by
FunctionDiscovery; stable numeric Function IDs are not a product contract.
Qualifying user edits engage existing ownership safeguards: names, comments,
tags, signature annotations, body and user work survive repeated analysis and
fresh-process reopen. Receipt-free DEFAULT Functions and unrelated user Functions
survive; no duplicate or false CPU callee appears. All seven native checks target
`rom2::4100`, proof fingerprints remain current, and no production repair is indicated.

Durable receipts/report hashes and closure lineage are in the
[evidence index](evidence-index.json). The next roadmap step is a master decision:
whether JP HL / WUX-1B is necessary before broader normal Wyatt workflow work.
Neither path is authorized by this closeout.

## WUX-1A-Q1 — CLOSED / QUALIFIED

The resumed Q1 qualification passes on pinned Linux Ghidra 12.1.3 / JDK
21.0.12.1: 1,130 provider tests across 108 JUnit XML reports, zero failures,
errors or skips. `ktlintCheck`, `buildExtension`, build-input and diff checks pass.
The focused run passes all 24 `StockRouteFaultTest` cases and both native controls.
The ordinary CALL native target is exactly `rom2::4100`; the inherited mapper-store
native lifecycle and raw architectural p-code equivalence tests execute and pass.
The tested candidate is frozen `3a092c82f565e32d3a422739f89dd708b7fb654b` plus the
four-line test-oracle repair, tree `763142ff4c9fc6539fcf64d3f4a1cdb9a8562f35`.
The local closeout adds only qualification/status documentation to that test tree.

Q1-D1 classified the legacy state-entry discrepancy as **INHERITED_ORACLE**:
the qualified WUX-1P checkpoint and all later comparison points record the same
one-byte `c9` presentation carrier while correctly rejecting missing registry
authority. Pinned upstream records instruction/load-image acquisition before
upon-entry injection evaluation; bytechunk count is not semantic acceptance.
Q1-R1 removes only the zero-bytechunk assertion. Completion/HighFunction/C/error
rejection assertions, fixture preconditions and unrelated strict carrier assertions
remain unchanged. No production, state-entry, ordinary CALL or language change
was made. Historical Q1 failure and D1 evidence remain preserved.

This closes the original aggregate/native Q1 scope only. Separate-JVM/large
persistence, installed/headed, release, Steam Deck, debugger, Wyatt and whole-ROM
qualification remain outside this result. At the Q1 checkpoint, Q2 and WUX-1B
had not begun; the closure above now records Q2A/Q2B. Commands,
identities, native witnesses and the historical WUX-1P test-oracle qualification
erratum are linked from the [evidence index](evidence-index.json).

## WUX-1A implementation checkpoint — historical bounded verification

The [stock flow contract](../decisions/ordinary-call-stock-flow.md) derives one
primary operand-matched physical CALL only from current WUX-1P certificates,
with exact DEFAULT displacement/restoration and separate versioned ownership.
Result-only flow normalization prevents circular invalidation; edited/independent
flow remains visible. Stale unchanged artifacts retire before preview, including
incomplete previews; a current original basis survives smaller incomplete runs.
Targeted stock scheduling discovers the physical Function in the same session
and consumes unchanged publication feedback without another relational pass.

Focused Java flow/ownership/currentness, incumbent scheduling and packed save/reopen
checks pass: 78 selected tests, 77 PASS and one native availability skip. Lint and
diff checks pass. The existing native AnalysisLifecycle test was separately
excluded after confirming the pinned distribution lacks macOS arm64 `decompile`.
At that implementation checkpoint, native C execution, separate-JVM/large
persistence, full provider, installed/headed, Docker, release, Steam Deck and Wyatt
qualification remained unrun; Q1 above now supplies the aggregate/native result. WUX-1P evaluator,
schema/engine, shared fingerprints, SLEIGH and JP HL behavior remain unchanged.
Ownership envelope 6 reads older receipts without granting displacement authority.
Detailed source/dependency identities and commands are in the [evidence index](evidence-index.json).

That checkpoint closed the authorized implementation slice only. Q1 above now
closes its native-capable execution and aggregate obligation; WUX-1B is not begun.


WUX-1A-R1 hardens this candidate before qualification: known obsolete-engine
v1 receipts retain only exact retirement/restoration authority; normalized capture
indexes receipts once and architectural checks reuse a revision-bound basis;
notification preparation stays inside the rollback-capable apply transaction.
Focused repair/affected checks pass with 87 selected tests, 86 PASS and one native
availability skip; the inherited native lifecycle method remains excluded for the
same missing executable. Deterministic cache reuse, open-transaction edits,
rollback, obsolete-engine packed reopen and commit-boundary cancellation pass.
Independent source review, lint and diff checks pass. Pinned scheduler coalescing
and conservative partition behavior need no representation change. At that repair
checkpoint broader qualification remained unrun; Q1 above supplies the bounded
aggregate/native result. Repair evidence is indexed under WUX-1A-R1.


## WUX-1P ordinary returning-call certificate — CLOSED

The [certificate contract](../decisions/ordinary-call-proof-certificate.md) adds a
structured durable assertion from successful incumbent unconditional CD
matched-return composition. Source, target and continuation retain exact static
Program and physical ROM identities. Every evaluated source encounter must succeed
compatibly; conflicting identities or outgoing mapper state, failed encounters,
generated execution storage and incomplete callee exploration suppress authority.
Nested/sequential N4–N7 semantics remain unchanged. Conditional and software calls
cannot issue this certificate. Generic Findings remain observations.

Schema 4 / engine `20261001-wux1p-ordinary-call-proof-1` requires recomputation of
preceding N8/WUX-0 results. Ownership remains unchanged. Saved output cannot
bootstrap fresh proof; current fingerprint validation remains mandatory.

WUX-1P qualification is complete. The implementation is
`83cc5a621ea379fec7c474f3f5650c3facf72d04`; the qualified checkpoint after a
test-only native fault-oracle correction is
`3bff09e4a4afeb1d486d4dd08b44845db9b209f9`
(tree `43059ddb0a9641345bf6f721d751e69434857e6c`). Focused qualification passes
178 tests. Three separate JVM persistence/currentness phases pass. Final provider
validation passes 1,098 tests across 105 JUnit reports with zero failures, errors
or skips; `ktlintCheck` and `buildExtension` pass.

**Test-oracle qualification erratum.** The WUX-1P test-only correction retained
an incorrect zero-byte assumption for legacy state-entry rejection. Q1-D1's pinned
Linux comparison reproduces one `c9` bytechunk at this qualified checkpoint and
all later WUX-1A points, while missing-registry semantic rejection remains correct.
The historical aggregate receipt is preserved; it does not establish zero-byte
ordering on Linux. Q1-R1 removes only that non-semantic assertion and retains the
semantic rejection and unrelated strict carrier checks. WUX-1P production
semantics are not reopened and production native behavior was not changed.

WUX-1A native CALL lowering, DEFAULT displacement/restoration, generated-flow
non-evidence handling and production convergence were separate WUX-1P obligations;
the CLOSED / QUALIFIED WUX-1A integration above now addresses them.
No native-flow or Wyatt workflow improvement is claimed by WUX-1P itself. Exact
qualification details are in the [evidence index](evidence-index.json).

## WUX-0 stock-flow integration — investigation complete; WUX-1 deferred

Pinned stock reference, p-code, block, Function, scheduler and native experiments
identify the [ownership/invalidation decision](../decisions/proven-stock-flow-integration.md)
required before production lowering. Physical primary CALL changes high/native
p-code but leaves an extra DEFAULT CPU-space flow edge. COMPUTED_JUMP adds Java
CFG flow while native cross-overlay JP HL remains unresolved. Raw architecture
is unchanged. Separate-process persistence passes for the experimental artifacts;
incumbent analyzer feedback and production lifecycle are unqualified. No production
capability PASS is claimed. Exact receipts are in the [evidence index](evidence-index.json).

## SA-FINITE-POINTER-SUCCESSOR — bounded N8 CLOSED

The accepted N8 checkpoint admits exact ordinary E9 JP HL under the
[finite-pointer contract](../decisions/finite-pointer-successor.md). Both HL bytes,
mapper-qualified physical identity and one defined immutable executable ROM view
are required. The jump preserves architectural state and active call frames; it
creates no call, fallthrough, Function or native flow transport.

The newer implementation and evidence commits supersede the earlier N7-only
current checkpoint. Engine `20260930-n8-finite-pointer-successor-1` retains schema 3;
N7 results require recomputation. Accepted focused/affected, package, independent
review and persistence evidence remains in the [evidence index](evidence-index.json).
General pointer sets/tables, indirect calls, discovery, whole-ROM and SA-03/SA-04/
SA-07 remain open. No N9 begins here.

## SA-SEQUENTIAL-RETURNING-CALL-COMPOSITION — bounded N7 CLOSED

N7 admits multiple sequential direct returning calls within one invocation:
caller → A → B → A continuation → C → A continuation → caller. Admission uses
the active immutable frame chain rather than encountered sites; maximum active
ordinary depth remains two. Each call establishes a fresh frame from actual
current SP, physical stack bytes and mapper state. B's returned register/flag,
RAM and mapper state feeds C; A retains its original physical frame across both
returns. See the [N7 contract](../decisions/sequential-returning-call.md).

Incomplete first or later callees cannot authorize the containing return.
Physical recursion and third active levels remain refused. N6's one conditional
site per invocation, the 128-state local limit, shared global budget, cancellation,
widening and N3 must-fact joins remain unchanged. Engine
`20260930-n7-sequential-returning-call-1` retains schema 3 and fingerprint
dependencies; preceding N6 results require recomputation. Frames remain transient.

Fresh N4/N5/N6 baseline, focused N7 and scoped affected regressions, independent
semantic review, lint/build and build-input/package integrity pass. One disposable
pinned Ghidra Docker witness demonstrates physical B → C → A → caller state
dependency and separate frames; separate JVM save/reopen accepts N7, agrees with
recomputation and rejects preceding N6 read/application. Exact identities, counts,
commands and retained initial test-oracle failure are in the
[evidence index](evidence-index.json).

Only bounded sequential composition is closed. Arbitrary depth, recursion,
indirect calls, RST/RETI, summaries, ABI inference, interrupts/devices, RAM code,
general interprocedural/conditional flow, discovery and whole-ROM closure remain
open, as do SA-01/SA-03/SA-07. Full historical/native, headed target/Steam Deck,
debugger, migration, corpus, fuzzing and hardware campaigns are NOT RUN for N7.
No main change, PR, release or persistent installation occurred in N7. Its original
stop after N7 is superseded by the accepted N8 checkpoint above.

## SA-CONDITIONAL-CALL-RET-MICROFLOW — bounded N6 CLOSED

Ordinary BankAnalysis now interprets CALL NZ/Z/NC/C and RET NZ/Z/NC/C through
validated instruction-local raw p-code guards. Conditions use the incumbent F
byte (Z bit 7, C bit 4); known conditions select one architectural outcome and
unknown conditions preserve both. False paths have no push/pop or frame change.
True paths execute actual stack effects and retain N4/N5 physical frame,
returned PC/SP and outgoing mapper/continuation validation. See the
[N6 contract](../decisions/conditional-call-ret-microflow.md).

Each invocation admits one conditional transfer site; reprocessing the same site
for N3 memory weakening does not spend another. Depth remains two, with N5's
separate one-nested-site bound. Known-false recursive/third-level calls are not
executed; reachable taken refusals preserve false exploration and invalidate the
containing invocation. Incomplete alternate paths cannot publish returned proof.
Compatible returns retain existing register/flag and physical RAM meets;
incompatible mapper/continuation identities refuse composition. The 128-state
local cap and single global budget remain unchanged.

Focused N6 and retained N4/N5 tests, the scoped affected analysis/scalar/topology/
boundary regressions, independent review, lint, static packaging and build-input
checks pass. One disposable Ghidra 12.1.3 Linux amd64 / JDK 21.0.12.1 Docker
witness proves taken CALL with actual return bytes and caller continuation,
unknown RET with both outcomes and conservative returned-state meeting, and
known-false CALL without callee execution or stores. Separate-JVM save/reopen
accepts current N6, agrees on recomputation and rejects N5 read/apply. Exact
commands, identities and counts are in the [evidence index](evidence-index.json).

Engine `20260930-n6-conditional-call-ret-1` retains schema 3 and unchanged
fingerprint dependencies. Frames, site sets and condition/path state remain
transient. Global COMPLETE still means a drained session worklist, not completed
invocation composition; unsupported paths retain frontiers and unknown caller
state. SLEIGH, ordinary conditional JP/JR, mapper/graph/native/software-call
contracts and discovery are unchanged.

This closes only bounded N6. General conditional flow, arbitrary-depth or
recursive solving, indirect-call recovery, RST/RETI, RAM code, general summaries,
software-call/ABI inference, device/interrupt effects, discovery and whole-ROM
qualification remain open, as do SA-01/SA-03/SA-07. Full provider and historical
installed campaigns, run_validation.py, headed GUI, final target/Steam Deck,
debugger, migration, corpus, fuzzing, hardware and final SA-07 were intentionally
unrun. No main merge, PR or N7/N8 begins here. STOP after N6.

## SA-NESTED-RETURNING-CALL-COMPOSITION — bounded N5 CLOSED

The historical N5 checkpoint admitted exactly two active invocations: caller → A
→ B, B RET → A continuation, A RET → caller continuation. Both frames retain
actual pushed physical-byte identity and restored PC/SP checks. B receives A's
actual post-CALL state; A executes its remaining instructions with B's returned
register/flag, mapper and unchanged N3 RAM state before returning to the caller.
Compatible returns use the existing exact/unknown meets; incompatible mapper or
continuation identities and any incomplete nested path invalidate the containing
invocation. See the [N5 contract](../decisions/nested-returning-call.md).

One nested site per invocation is admitted. Third active levels, recursion,
indirect/conditional calls or returns, RST/RETI, software helpers inside the chain
and RAM code remain unsupported. Each invocation retains the 128-state local cap
and every evaluation consumes the single global budget. Frames remain transient;
engine `20260930-n5-nested-returning-call-1` retains schema 3 and unchanged
fingerprint components. Old N4 results require recomputation.

Focused nested and retained call regressions, affected analysis/evaluator/topology
and call-consumer suites, independent review, lint, static packaging and build-input
checks pass. One disposable installed Ghidra 12.1.3 Docker witness proves nested
RAM/mapper composition with actual A post-return effects, conflicting nested RAM
and third-level refusal. Separate JVM save/reopen accepts current N5 results,
agrees on recomputation and rejects N4 read/apply. Exact commands, identities,
test accounting and receipts are in the [evidence index](evidence-index.json).

This closes only bounded N5. General summaries/interprocedural analysis,
arbitrary depth, recursive solving, indirect-call recovery, ABI/software-call
inference, interrupt/device summaries, discovery and whole-ROM closure remain
open, together with SA-01/SA-03/SA-07. Full provider/historical installed campaigns,
headed GUI, Steam Deck, debugger, broad migration, corpus, fuzzing, hardware and
final SA-07 were intentionally unrun. No main merge, PR or N6 begins here.

## SA-RETURNING-CALL-COMPOSITION — bounded N4 CLOSED

Ordinary unconditional direct CALL (CD) now executes its actual architectural
push, analyzes one bounded callee with the incumbent evaluator and composes state
only after complete matching unconditional RET (C9) proofs. Exact SP and both
physical frame-byte identities are required, together with defined executable ROM
and unique physical target/continuation views. Compatible returns meet exact
register/flag bytes and unchanged N3 physical RAM must-facts; the outgoing mapper
comes from actual callee effects. Different mapper/continuation identities or any
incomplete path retain the conservative unknown continuation. See the
[contract](../decisions/ordinary-returning-call.md).

The 128-state callee cap also consumes the shared global budget. Nested/recursive,
conditional and computed calls, guarded returns, RST/RETI, RAM code and general
summaries remain unsupported. Engine `20260930-n4-returning-call-1` retains schema
3 and existing fingerprint components; no frame or RAM snapshot is persisted.
Independent review corrected physical-stack matching and closed its findings.
Focused N4 and affected N3/evaluator/topology/boundary/call-consumer tests, lint and
static packaging pass. One disposable installed Ghidra 12.1.3 Docker witness
proves returned RAM selects ROM2 and conflicting return facts remain unknown.
Separate JVM save/reopen accepts current N4 results and rejects N3 read/apply.
Exact commands, identities and outcomes are in the [evidence index](evidence-index.json).

This closes only N4. General interprocedural analysis, whole-ROM call closure,
SA-01/SA-03/SA-07, discovery, interrupt/device summaries and broad qualification
remain open. Headed GUI, Steam Deck, debugger, full provider/historical installed,
migration, corpus/fuzzing/hardware and final SA-07 campaigns were not run. The next
bounded extension requires separate authorization; none begins here.

## SA-MEMORY-JOIN-WIDENING — bounded N3 CLOSED

Ordinary BankAnalysis joins transient physical RAM must-facts only at identical
static address, MapperKnowledge and register state. Changed joined snapshots are
reprocessed; conflicting/missing facts become unknown. Compatible memory revisions
converge without spending address diversity, while the existing incompatible-state
fallback and global budget remain conservative. See the
[join contract](../decisions/ordinary-memory-join.md) and
[evidence index](evidence-index.json).

Focused join/RAM and affected analysis, scalar/mapping, lifecycle/fingerprint
regressions, formatting, extension packaging, independent review and one disposable
Ghidra 12.1.3 Linux Docker witness pass. Common RAM retains a proved physical
successor; conflicting RAM does not. Separate-process save/reopen preserves N3
identity and rejects N2. Schema 3 and fingerprint dependencies remain unchanged.
This closes only N3; general memory analysis and SA-03 remain open. N4 returning-call
composition is the next separately authorized task and has not begun.

## PREVIEW-M2 native Ghidra workflow — local/headless PASS; intended target headed workflow NOT_RUN

The PREVIEW-M2 source candidate adds a stock-discovered low-priority instruction
analyzer, normal Program Status/legacy-preparation actions, physical-entry partial
mapper premises, bounded loop-state widening, session-wide scheduler-batch
accumulation, integrated justified Function discovery and an outer v1-to-v2 primacy
migration launcher. Mapping schema v2, SM83 language v2, constructors, compiler IDs,
16-bit pointer semantics and the compiled SLA remain unchanged.

Focused preparation/migration/analyzer/bank regressions pass. The native-capable
provider baseline immediately before the bounded batch-accumulation/widening correction
passes 901 tests in 93 classes with zero failures/errors/skips, plus `ktlintCheck`
and `buildExtension`; the final bounded correction has focused analyzer/bank tests,
lint and build only because of user closeout. Its broader full rerun is UNRUN.
Build-inputs pass 7, and tools pass 146 with one explicit optional dependency skip. A fresh private
target migration preserves all 456 USER_DEFINED reference booleans (436 primary,
20 non-primary), all accepted Program inventories and the immutable source GZF.
Separate-process reopen reports ROM0-63, VRAM0-1, WRAM0-7, SRAM0 only and HRAM;
OAM/I/O/IE remain explicit device regions. Normal full-target Auto Analysis completes
with one accumulated result (2,402 states / 143 roots in the first saved run), remains
current after separate-process reopen, and a saved rerun completes safely while
preserving all user-reference states. The unfinished third confirmation was cancelled
at user closeout and is not acceptance evidence.

The actual intended Linux/Steam Deck headed CodeBrowser → Auto Analyze → Decompiler
→ save/close/separate-JVM workflow was not reachable and was not fabricated. The
local disposable runtime also lacked its macOS native decompiler, so local target
evidence is headless analysis/migration only. Final source/artifact identities and the
external evidence root are recorded in the completion response and evidence index.

`PREVIEW-M2-MIGRATION = PASS`

`PREVIEW-M2-AUTO-ANALYSIS = PASS` (generic + private headless; headed target pending)

`PREVIEW-M2-TARGET-WORKFLOW = NOT_RUN`

`ENGINEERING-PREVIEW = NOT_READY`

## V1 exact-candidate aggregate public-operations lifecycle — PASS

The exact AUTH-R3 extension
`54fc048798025691789da706508d9c5fd674c2655b8192152a65eb146899e07c`
passes the complete scoped public-operations lifecycle gate on pinned Ghidra 12.1.3.
The final aggregate checker reports PASS for H0/H1, H2, I1, W1, W2, W3, W4, W5,
W6 and V. All twelve maintained sensitive controls make aggregate acceptance refuse
for the intended row while the checker verifies every unrelated row remains PASS.

Visual acceptance uses actual `java.awt.Robot` desktop captures. The first/reopen
lifecycle sessions captured the chooser, normal baseline, passive stale refusal,
recovery, ordinary Decompiler Refresh, removal refusal and immutable second-JVM first
use. The aggregate W2 session required one bounded user click to activate the
disposable Ghidra window; its pre-refresh new-domain result, domain reversal and both
physical navigation destinations are visibly unobstructed. Fresh independent review
inspected twelve desktop screenshots and reports PASS per row, control and closure
obligation.

All four positive lanes bind to the same candidate. The accepted JVMs are service PID
`77838`, first lifecycle PID `78649`, immutable reopen PID `84661`, and aggregate W2
PID `41971` with observer PID `41978`. Programs close with zero consumers, W2 closes
with `active_requests=0`, and no unrelated Ghidra process was disturbed. All 65 frozen
production files remain byte-identical; the combined production identity is
`e3cb9178d51923f7e5db1ec40f1ca8029f0e8e12f0765d6a0ec6815fa658bc8d`.

Final aggregate receipt SHA-256:
`cbf4f44e2ad8d449caf0cb31ccced77abf72ca7f5b5a0fd36d23241f7601670f`.
Acceptance manifest SHA-256:
`0a5afa5f0bf2f9c75382926b94b3c6fa4b88d42fc8c0cbfdffe20c02829ef27f`.
Independent review SHA-256:
`90d099c30c28ff9aaf37e6ad35d0f636bdc18aa9edef83d8fcf1f80b936314ef`.

REL-0A preserves the W2-R3 raw evidence, V1 raw and derived evidence, the exact
accepted candidate and required supporting corpora under the external SA workspace.
The durable paths and preservation controls are recorded in the
[evidence index](evidence-index.json); the original temp paths remain historical
receipt inputs rather than the only surviving copies.

`PUBLIC-OPERATIONS-LIFECYCLE` is PASS only for its scoped contract. This is not Wyatt
release readiness and does not close hardware/schema, migration, package/install/
recovery or whole-ROM correctness obligations. This checkpoint itself did not
authorize installation, publication, merge, deployment or remote action. The exact
next task is PREVIEW-P1/P2: target-specific compatibility audit and copied-Program
rehearsal.

## W2-R3 AUTH-R3 bounded headed/native qualification — PASS; V/lifecycle blocked

The exact AUTH-R3 extension
`54fc048798025691789da706508d9c5fd674c2655b8192152a65eb146899e07c`
passes the candidate-specific bounded normal-CodeBrowser/PrimaryDecompilerProvider
qualification on a disposable pinned Ghidra 12.1.3 runtime. The pre-run frozen
worktree identity is
`529467d7f3f1a4e4874a2ed9b956f8a4aca54e58758374b01227c1ccccce17c9`;
all 65 frozen production files remain byte-identical and no production correction was
made.

The labeled `Options.getString(physicalAddress, null)` control creates only a cache
entry at unchanged Program revision. Production ownership and both stock/companion
registration families remain absent. Normal native use succeeds at the physical target
and continuation before and after genuine carrier use; the genuine carrier remains
owned, current and structurally valid. The retained creation sequence classifies
`native-6` as provisional old-domain work, `native-7` as old stale authority, and
`native-8` as the first actual new-domain native execution; `native-8` succeeds before
any refresh/reapply/reset. No PRE_NATIVE_CANCELLED request occurred in this accepted
timing, and no invocation was dropped.

A separately launched immutable JVM uses the same candidate, reproduces the saved
authority and succeeds on its first initiated normal stock request without mutation or
rescue. Both JVMs close with zero consumers and zero active native requests. The
maintained semantic kernel passes 49,152 cases across genuine carrier, topology first
use, saved-current use and immutable first use. Focused support tests pass 21/21.
Fresh narrow independent review answers all nine required questions PASS after exact
postprocessor and consumed-input provenance was added. Final machine receipt SHA-256:
`7de9197812788d0a1d78e2f230a00eac621589ab11e05ca9ff4dc708e0fd0e9c`.

Candidate-specific W2 is PASS. Visual V remains UNOBSERVED; complete aggregate
sensitivity, installation/publication and release authorization remain open, so the
aggregate lifecycle remains BLOCKED. STOP after W2-R3; the exact next action is a
separately authorized visual V task.

## AUTH-R3 authority atomicity and paired classification — source-qualified candidate

AUTH-R2 rejects the AUTH-R1 local candidate
`2e6d0f7e350d4bd83ec5fcf549e19a1e5fddffdfa8c8c05ee52fb9b2d60c5c7b`.
AUTH-R1 checked the current value, called `setString`, and only then verified the
result. With genuine persisted `Y` and cached non-null default `X`, writing `X` removed
the database property before refusal. A caller could catch that refusal and commit its
outer transaction. AUTH-R1 also left shallow predicated, ordinary-entry and software
registry predicates that could return after examining only one family.

AUTH-R3 uses one public-API-only endpoint classifier and one shared stock/companion
classifier with `ABSENT`, `STOCK`, `COMPANION`, `CONFLICT` and `AMBIGUOUS` states. Both
endpoints are evaluated before any positive membership or transport selection.
Conflict, genuine-one-plus-ambiguous-opposite, ambiguous-one-plus-absent-opposite and
both-ambiguous states refuse. Creation and replacement reject null, ambiguity,
implicit family conversion and any proposed value equal to a non-null cached default
before mutation. Removal requires the exact family and refuses before mutation when a
cached non-null default would make absence unprovable. Successful writes/removals
verify the full paired postcondition. No record version, schema, language/compiler ID
or persisted semantic version changes.

Real `ProgramDB` regressions cover the destructive Case M with caught refusal,
committed outer transaction and packed reopen retaining `Y`; both paired ambiguity
orientations for `PredicatedCalls`, `OrdinaryEntryAccess` and
`SoftwareCallRegistry`; exact-equal refusal followed by clean-reopen recovery; and
genuine removal followed by reopen absence. The independent negative control performs
the rejected mutate-then-verify order and proves the row disappears after commit and
reopen. Existing absence, pollution, valid-record, malformed/version, genuine-conflict,
physical-ROM ownership and W2 observer regressions remain green.

Full local qualification passes 889 tests in 90 classes with zero failures, errors or
skips, plus `ktlintCheck` and `buildExtension`; build-input checks pass 7 tests and
tools pass 143 tests with one existing optional dependency skip. The artifact identity
is recorded in the AUTH-R3 completion response to avoid a
packaged-document self-reference. It is an **AUTH-R3 source-qualified and
candidate-specific W2-qualified candidate**, not installed, pushed or release-approved. Historical bounded W2 on
`20676c780740dd57d7920c3d1c4bc82b7881a8a2` remains PASS. Candidate-specific bounded
W2 is `PASS`; V remains `UNOBSERVED`; aggregate lifecycle remains blocked.
Fresh independent adversarial review reports no remaining authority finding and
separately reruns the seven focused real-Program regressions successfully.

## W2-R2 root-cause follow-up — W2 PASS; V/lifecycle remain BLOCKED

The exact R3 production extension remains
`21aff1832389fa28ae049cbfb82d9f279344056f79e75623da2e9aed63ca3732`.
The final w2-13 `native-3` call is `PRE_NATIVE_CANCELLED`: the monitor changes from
not-cancelled to cancelled and the call returns at pinned Ghidra 12.1.3 bytecode index
61, before callback setup or native command execution. The checker retains that call
but excludes it from actual-native-use ordering. `native-4` is the first actual native
execution for the committed new authority and succeeds before explicit coherence
refresh.

The physical refusal was support-observer contamination, classification P7. At each
`decompileFunction` entry the observer called typed `Options.getString(address, null)`
without first checking `contains`. Ghidra's `AbstractOptions.getOption` installs an
unregistered typed option in the in-memory option map. `StockEntryInjection.owned()`
therefore changed from false to true for ordinary physical ROM at the same Program
revision, and the deliberately fail-closed stock guard rejected that ROM as carrier
storage. Neither the physical `UndefinedFunction` nor its default `__asm` convention,
context, block, or stored Function topology was damaged.

The support lookup now checks `contains` before `getString`. A bounded replay on the
same Program/candidate records ordinary physical `UndefinedFunction` objects, no
stored Function, `unknown`/`__asm`, no fixup/thunk/inline/no-return/custom storage,
`gb_analysis_entry=0`, no stock ownership, and ordinary initialized read/execute ROM
blocks. The native callback requests `__asm@@inject_uponentry` (`CALLMECHANISM`, type
3). `rom2::5210` completes and displays as the fresh pre-carrier control; after a
valid stock-carrier request, both `rom2::5210` and `rom1::4301` complete and display
normally. The carrier alone retains stock convention, ownership, carrier comment and
`gb_analysis_entry=1`.

Retained w2-13 semantics remain 61,440 passing raw/emitted/native cases across five
captures. Focused support tests and the cancellation receipt checker pass; no
production suite was rerun. Retained H0/H1/H2/I1/W1/W3/bounded-W4/W5/W6 remain
unchanged. W2 is accepted within that bounded scope. Actual desktop visual review is
still UNOBSERVED, the complete positive V sensitivity roster is not accepted, and
aggregate lifecycle status remains BLOCKED. Hardware/schema, migration, ownership,
installation/recovery and Wyatt release obligations remain open.

## PUBLIC-OPERATIONS-LIFECYCLE R3 — PARTIAL; scope frozen; STOP for master review

The attended R3 run exercised a real normal CodeBrowser and analysis-enabled service
lane. The tested executable checkpoint is `20676c780740dd57d7920c3d1c4bc82b7881a8a2`;
extension SHA-256 `21aff1832389fa28ae049cbfb82d9f279344056f79e75623da2e9aed63ca3732`.
The clean checkpoint passed **882 instances in 89 classes**, retaining all **878**
starting instances, with zero failures/errors/skips, plus lint/package. Native and
SLA bytes are unchanged. Scoped Mac/Linux/private native captures and immutable
reopen ran on that candidate; private originals and prepared inputs were preserved.

The service records actual scheduled worker execution, provisional tool-owned
commit/abort, foreground shared edits, busy deferral, and cancellation after commit
with a separately committed later edit preserved. Real no-argument Script Manager
chooser/cancellation/recovery, normal-window stale/refresh, domain reversal,
supersession, accepted-close cancellation, removal and a separate immutable normal
JVM have executed receipts. These are bounded observations, not aggregate lifecycle
acceptance or release approval.

**Open:** transient stale-registration injection errors during carrier creation are
not fully attributed. The driver refreshed domain coherence before its later domain
captures, so first native use of the new topology before that refresh remains
unverified. The user froze scope. The just-started first-use capture and stricter
checker changes are preserved externally as an uncompiled/unexecuted parked patch;
they are excluded from the tested candidate and maintained execution path. No further
repair or GUI run was authorized at closeout. Full independent aggregate sensitivity
and visual acceptance remain incomplete. See the external R3 report and parked patch
through the [evidence index](evidence-index.json).

The explanation revalidation and hosted task-monitor completion boundaries are in
the [operation contract](../public-operations.md) and
[decision](../decisions/public-operations-attended-completion.md). Remaining caller,
hardware/schema, compatibility, packaging/installation/recovery and release work is
unchanged. STOP for master review; no automatic next batch or installation.


## CORE-CONTRACT-HARDENING-OVERNIGHT — PARTIAL; STOP for master review

The supplied mapper-oracle false acceptance is reproduced and corrected with
actual latch, ordered bus-effect and retained physical-use checks. Deterministic
Program mutations also reproduce and close validation/install and
validation/explanation gaps. Explanation, navigation and source placements consume
one validated operation snapshot; install/refresh recheck the tested transaction
entry boundary. The stock mechanism and persisted conditional meaning are unchanged.

The corrected clean checkpoint passes **859 instances in 87 classes**, retaining
all **852 baseline identities and multiplicities**, with no failures/errors/skips.
The first clean attempt's fragile loop-forgery row selection is preserved and
corrected without removing its obligation. Exact Mac and isolated Docker/Rosetta
Linux native checks, full primary generic/private replay, copied-private
preservation and first immutable second-JVM use pass their bounded rows.

Arbitrary concurrent shared-subtransaction publication/joint rollback, the complete
outstanding-work lifecycle and actual normal-window workflow remain unqualified.
Computer Use access was not approved; **GUI_UNRUN** is not headless success.
The complete overnight task is not PASS, and broader hardware/discovery/device
requirements remain open. See the [decision](../decisions/core-contract-hardening.md)
and [evidence index](evidence-index.json). No release or installation is authorized.
STOP for master review; no automatic next batch.

## EFFECTFUL-CALL-CONTINUATION — scoped local PASS; STOP for master review

Revision 2 implements conditional instruction-site derivation in the incumbent
graph and stock CALLOTHER transport. Symbolic registers/valid flags, constrained
affine SP, checked physical memory and mapper/shadow premises flow through real
helper/callee/cleanup effects into the matched outgoing-state continuation.
Faithful bounded inlining preserves the live effects without the ordinary byte-A
call ABI. A native view ends at an actual source return; a following slice remains
a linked explanation with an explicit unanalysed tail. Canonical interpretations
are preserved, and the exact concrete software-call API remains unchanged.

The independent nonconstant/flag-sensitive carry, relocated and indirect-alias
family and the private conditional case pass full raw/emitted/native replay.
Public apply, actual stale refusal/explicit changed-result refresh, owned removal,
real-write cancellation/later-edit controls, immutable second-JVM current-record
reopen and bounded normal-window navigation pass. Preparation and existing
canonical knowledge are separately inventoried. The final clean checkpoint passes
**852 instances in 86 classes**, retaining all **839 baseline identities and
multiplicities**, with no failures/errors/skips. The final tooling requalification
passes 118 tests with one retained optional skip; build-inputs passes seven.

The qualified provider source is `52215b3`; extension SHA-256 is
`967ab05134feaec49c1557081f3797facb261ef10d8ffbb1b21c4110b4f37ddc`.
Pristine Mac and local Docker/Rosetta official Linux native checks pass on those
bytes, along with selected incumbent physical-read/call/memory regressions.
A subsequent checker-only partial-symbol ordering correction is separately tested;
provider bytes are unchanged. New conditional records are version 3; earlier
experimental forms remain quarantined. The original partial report is preserved.
General summaries, looping helpers, wider devices/interference, migration,
canonical repair, deployment equivalence and release qualification remain open.
See the [decision](../decisions/effectful-call-continuation.md) and
[evidence index](evidence-index.json). STOP for master review; no next batch.

## STOCK-FINITE-DISPATCH — scoped local PASS; STOP for master review

Source-derived guarded immutable reads and finite physical indirect-jump edges use
one maintained graph and the stock carrier. Normalized FF80/default and nibble
128-entry/sixteen-target witnesses pass raw/emitted/native replay across all 256
inputs and three frame/carry contexts. Two fixed nibble pointers include C7FF→C800.
Relocation/permutation, physical-bank identity, zero/shift, incomplete authority,
actual stale native refusal, explicit public refresh and first immutable separate-JVM
current-record reopen pass. Source and qualified return storage, original return
bytes, canonical mutable LOAD binding and unsupported returned flags are checked.

The final clean checkpoint passes **838 instances in 84 classes**, retaining all
820 baseline identities/multiplicities with no failures/errors/skips. Mac and local
Docker/Rosetta Linux positives/lifecycle, affected conditional-call/cyclic/alias/image
witnesses and maintained installed/migration workflow regressions pass on the exact
qualified extension. The final source commit is `7a6807f`; the extension SHA-256 is
`0240e40577a0af12df39a0e1c260d9f998113eee57d441f8cad964942e4d0272`.
Final documentation/checker receipts are separate from those executable bytes.

Canonical automatic recovery still overpublishes targets; public normalized
override still fails inputs 3/4/5. No upstream, general W3/W4, migration or stock-release
claim is made. Native terminal provenance is qualified for the retained distinct-RET
witnesses, not arbitrary optimizer restructuring. Proof JSON remains verbose.
See the [dispatch decision](../decisions/static-dispatch-model.md) and
[evidence index](evidence-index.json). G1 archive review and prior accepted semantic/
language scope are unchanged. STOP for master review; no automatic next batch.

## SM83-V1-V2-COMPATIBILITY — scoped local PASS; master review pending

The installed simple translator upgrades genuine final-language-1 annotated work
and the complete 501-instruction corpus to unchanged canonical language-2 semantics.
Core-only observation, save/exit, first immutable second-process use and cancellation
with restored-original recovery pass. Genuine registry-4 and one later-edit variant
retain complete knowledge and raw authority, while public operations and actual
native use refuse unsupported execution/removal without conversion.

The clean stock checkpoint retains all 819 baseline instances and adds one corrupt
record case: 820 pass, with zero failures/errors/skips, plus lint/build. Mac and
Docker/Rosetta Linux installed and actual 11.3.1 migration workflows pass on the same
ZIP. Historical ADC and wrapping-stack corrections remain explicit. This is local
execution evidence, not hosted Actions success, general old-proof migration, full
G4 closure or stock-release qualification. G1 remains reported complete with master
archive review pending; no G1 campaign was rerun. See the
[decision](../decisions/sm83-v1-v2-compatibility.md) and [evidence index](evidence-index.json).
STOP for master review; no next batch.

## G1-WINDOW-HARNESS-COMPLETION — scoped workflow PASS; master review pending

The source-qualified event/commit protocol and bounded transaction-aware settlement
now traverse the complete P/Q/switching/negative/save/close workflow and a genuine
second-JVM immutable reopen. All 819 default instances remain passing. Twenty final
phase captures, actual P3 Refresh, all-input/six-case relations, complete authority
comparison and 28 rejecting sensitivity controls support the scoped result.
The first post-build run's occluded screenshots remain nonqualifying; the reviewed
launcher-only visibility correction has a fresh complete confirmation on unchanged
product bytes. No production correction or new gate allowance was used.
See [completion](G1-WINDOW-HARNESS-COMPLETION.md) and the [evidence index](evidence-index.json).
STOP for master review. Stock release, migration, switches and broader work remain open.

## G1-STOCK-NORMAL-WINDOW-CONTINUATION — HARNESS_OR_CHECKER_BLOCKED

The consolidated candidate executes natural post-proof recovery and actual ordinary
Refresh in the same visible CodeBrowser; both displayed results satisfy the E4
all-input relation. Canonical isolation, Q I1 and passive physical-replacement
refusal are captured. The driver stops at Q2 navigation because its immediate
transaction guard finds an open transaction after generation-2 topology creation.
No settled Q2 result or production lifecycle defect is demonstrated.

The current initial/full checker also rejects the captured P event ordering: the
real revision-4 event arrived just before the commit receipt. Per-record integrity,
specific refusals and disaggregated semantic replay pass; whole-workflow acceptance
does not. All 819 default instances remain passing, with lint/build and tooling.
Missing-registration branches, qualified closure and second-JVM read-only reopen
remain unrun. See the [continuation disposition](G1-STOCK-NORMAL-WINDOW-CONTINUATION.md).
STOP for master review; no further GUI retry or automatic next batch.

## G1-STOCK-NORMAL-WINDOW — BLOCKED; STOP for master review

Genuine visible stock CodeBrowser access is verified. Current-language P0/P1
window-owned results pass the 256-input oracle; the consumed E000 D3→E4 edit
retains old registration and passively produces a visible stale-registration
refusal with no HighFunction/C. The shipped explicit proof actions execute.
Ordinary Refresh was disabled at the immediate post-proof check in the bounded
confirming run; its Program event arrived afterward. No P3, Q/window topology,
Program switching or qualified current-format reopen result was captured.

This is a driver active-action sequencing boundary, not a demonstrated product
semantic defect. The final ready-runner event wait is compile-only. The clean
stock checkpoint preserves all 819 cases, with lint/build and tooling checks
passing. See the [dated G1 disposition](G1-STOCK-NORMAL-WINDOW.md). G1 and the
scoped workflow are not PASS. No automatic retry, migration or next batch.

## STOCK-ROUTE-COMPLETION — PASS for the scoped local task; STOP for master review

Normal public creation and the shipped Tools/application path now select stock.
One-byte presentation carriers and integrity guards across shipped conventions
retain source, physical and image-generation authority separately. Earlier stock
and companion records remain intact without implicit conversion. See the
[compatibility decision](../decisions/stock-route-completion.md).

The exact candidate `346305b` passes the clean default stock checkpoint: **819
instances in 82 classes, zero failures/errors/skips**, plus lint/build, 7 build-input
checks and 86 tooling passes (one existing optional debugger-package skip).
All 795 baseline obligations are accounted for: 793 remain stock semantic tests;
two explicitly optional private canonical-selection protocol cases retain their
implementation and have passing stock lifecycle replacements. There are 26 added
default cases. All 100 transport-neutral cases among the original 102 failures pass.

Actual native controls reject invalid results with no HighFunction/no C. The
21 unit faults include every shipped convention, default/unknown resolution and
mapped-backing replacement. Installed conditional and cyclic fixtures each pass
nine faults with an observed one-byte recovery footprint. Public ordinary/refresh,
physical calls, cyclic graphs, exact continuation order, configured domains,
symbolic RAM/poisoned fills and image generation/source independence pass their
maintained independent checks. The shipped Tools apply action is exercised.
Current image/domain Programs save, exit and reopen in separate read-only processes
without authority or Program-data changes; two exact project backup housekeeping
differences are recorded separately. Focused Linux x86-64 G2 and carrier refusal
pass under Docker/Rosetta, not as a native-host or broad Linux qualification.

The independent integrated review is resolved. Detailed receipts, all intermediate
failures, the per-instance ledger and exact runtime/payload identities remain
external through the [evidence index](evidence-index.json). Final documentation
packaging is distinguished from the tested executable candidate by payload equality.
This is **not stock release qualification**. Genuine language-1-to-2 migration,
normal-window acceptance, switch proof/lowering, broader platform/hosted CI and
inactive-source retirement remain separately open. No new batch starts automatically.

## STOCK-GHIDRA-TRANSPORT — PARTIAL; STOP for master review

The experimental stock transport and its one bounded integrity correction are
implemented. The [decision](../decisions/stock-ghidra-transport.md) supersedes
companion-as-deployment direction, while preserving historical G2/G3 acceptance
on their original runtime. No core Java or production native patch is included.

The exact corrected Mac artifact passes assigned headless ordinary, physical-call,
cyclic, exact-continuation, same-site/two-domain, symbolic-RAM and image-generation
relations and sensitive controls. Current image and domain authority reopen in
separate read-only processes with unchanged Program data; two exact project backup
index/journal changes are recorded separately. Linux x86-64 G2 and native refusal
pass under Docker/Rosetta with actual executable mappings and identities recorded.

Overall stock product qualification **does not pass**. The clean stock checkpoint
runs all 789 accepted cases plus six stock tests: 693 pass, 102 fail, zero skips.
The 102 cases still invoke companion-dependent routes; their obligations remain
untransitioned, not converted to unsupported passes. Lint/build and inexpensive
checks pass. Public normalized-switch override returns wrong values at inputs
3/4/5; nibble recovery has extra targets, and two direct stock range tests fail.
Normal-window execution is GUI_BLOCKED by inability to attach computer-use control
to the launched Java application. The maintained window script compiled but was
not executed. No GUI, CI-green, full migration or complete stock workflow claim
is made.

Language 2.0 adds the nonflowing analysis context. Stock transport version 2 has
separate registration keys and retains old authority without automatic conversion.
The initial carrier-mode-removal failure is retained; a straight-line uponentry
integrity guard now rejects its actual invalid native result without adding CPU
or memory effects. No materialization fallback or third candidate was started.
See the [evidence index](evidence-index.json) for report, artifacts and limitations.
Stop for master review; no W4b, CI repair, debugger/consumer work or publication.

The following sections are historical accepted checkpoints and retained failures,
not qualification of the new stock artifact.

## W4-MEMORY-IMAGE-G3 — G3 PASS; STOP for master review

**G3 PASS — SYMBOLIC RAM EFFECTS AND EXECUTABLE-IMAGE LIFETIME.**
The bounded [memory/image contract](../decisions/symbolic-memory-executable-images.md)
is implemented and verified. Broader W4 and G1/G4 qualification remain open.

One production unknown-memory declaration retains the C060/E060 physical input,
ordered alias effects and `(U, U+1 mod 256)` through raw/emitted/native checks for
all 256 U values, three return/frame cases and both carry states. Two poisoned
fills retain the relation. Twelve actual-artifact negative controls pass per
artifact. A production may-write weakens current data knowledge; the same physical
footprint refuses dependent image FETCH at E201/C201 while a disjoint C062 write
preserves it. Hypothetical effects leave persistent image authority unchanged.

Explicit initialization establishes distinct durable generations at WRAM0 C200.
I1 produces 31 and I2 produces A7; physical replacement refuses old native use.
Source-ROM edits preserve initializer history, RAM bytes and generation. Same-byte
re-establishment rejects an explicitly requested old generation and admits the
current generation. A separate-process first read-only current-image reopen
preserves Program database bytes and serialized authority without establishment
or explicit refresh. Two project backup index/journal changes are individually
classified in the external receipt; no Program mutation is hidden by exclusions.

The corrected exact provider passes 789 tests in 80 classes, retaining every one
of the 782 accepted case instances with seven additions and no failures/errors/
skips. Lint/build, seven build-input checks, and tooling (86 passes, one existing
optional skip) pass. Fresh installed cyclic, same-site domain and active
continuation-order regressions pass. One read-only review was resolved, and the
one localized null-default history-reader correction was fully requalified.
Original failures and both candidate identities remain external.

Image authority is experimental version 1; predicate graph/registration version
4 rejects incompatible earlier records. Public mapping v2, configured-domain v2,
FarCallEvidence v3, compiler/language/native/SLEIGH identities remain unchanged.
This does not qualify general old-provider migration or normal-window events.

The predecessor at `e242dc4b0eaad741c85a2abae5a13a460fc6f767` remains master
accepted. Remote CI remains failed: the supplied exact-head artifact localizes
100 failures to the missing/non-regular companion marker. No CI repair or Linux
companion qualification is claimed. See the [evidence index](evidence-index.json).

**INTEGRATED; RETIREMENT BLOCKED by unverified independent backup.**
STOP for master review. Do not begin another batch automatically.

## REPO-CUTOVER-DOMAIN-PERSISTENCE-FIX — INTEGRATED; RETIREMENT BLOCKED

The bounded saved-domain workflow passes. Same-traversal diagnostics first
reproduced the uncorrected rejection: exactly six dynamic-symbol IDs changed
among 412 complete dependency fields. Registration and pre-save bytes matched;
all other fields and all eight ProgramFingerprint components matched on the
first reopened production check. The correction retains dynamic semantic
identity while preserving stored symbol IDs, reference bindings, Function,
thunk, parameter, context, ownership and permission dependencies. See the
[compatibility decision](../decisions/configured-domain-dependency-identity.md).

Configured-domain authority is v2 and FarCallEvidence is v3. Saved v1 authority
rejects before semantic use without rewriting records. No general migration,
native, SLEIGH or public mapping-schema change is included. The accepted
[discovery-order correction](../decisions/configured-domain-discovery-order.md)
and all five cutover commits remain intact.

The final clean checkpoint passes 782 tests in 79 classes, retaining all 776
accepted identities with six additions and no failures, errors or skips.
Lint/build and build-inputs7 pass; tooling passes79 with one existing optional
skip. Both fresh canonical and anti-canonical Programs pass forward/reverse,
save/process exit, first read-only reopen, proof/view/native and wrong-domain
checks. Complete production preimages match byte-for-byte; stale mutation and
native refusal pass on separate writable copies. Cyclic persistence and active
continuation-order installed regressions pass on the exact final provider.

The [evidence index](evidence-index.json) retains the original failures and links
new captures, independent comparisons, final identities and the report. The
supplemental project-directory assertion exposed only Ghidra backup-index/journal
housekeeping; actual Program database/properties and production preimages remain
unchanged. Exact differences and their source-backed classification are retained.

REPO is the sole active source. The inactive source remains read-only recovery.
Validation is complete; independent backup remains unverified and blocks
destructive retirement. History cleanup is not an implementation prerequisite.
**STOP for master review.** No W4/G3 planning or implementation, W3c, broader
qualification or source retirement begins automatically.

Accepted predecessor checkpoint: **W3b-CFG-CONVERGENCE PASS**. W3 FOUNDATIONAL GRAPH/CALL CONTRACT SUFFICIENT TO BEGIN W4 / G3.

Report/result/coverage: evidence/batches/W3b-CFG-CONVERGENCE/. All three bounded checkpoints pass; full773/78, lint/build, build-inputs7, new native relationships and cyclic separate-process persistence pass. Source `ad023bf61f5273b9d1466c5292f09aa738cd6911cfb89bb2aaf4d48cc3bcc06e`; extension `de7b17963d8f009ce2dabfb1fe2090e7dd3ab29000c20cd26b8b632bd81e00ed`. Native/SLA unchanged. No active implementation or unresolved bounded blocker.

This does not close the remaining W3 dispatch, discovery, richer return/frame, nested-entry or broader invocation families. Those remain tracked W3 backlog and may proceed later where required by composition or qualification. W2 remains frozen. W4/G3 and another W3 package were not started.

## Accepted predecessor record


Current checkpoint: **W3a-PREDICATED-CALLS / embedded G2 PASS**, bounded repeated ordinary invocation **PASS**. Report: `evidence/batches/W3-OVERNIGHT/REPORT-W3-OVERNIGHT.md`; coverage/result alongside it.

One unknown-input graph preserves predicate-qualified physical instruction identities, real CALL/matched RET/frame behavior and native child Functions. Repeated same-target calls retain current byte-register inputs and distinct continuations. Full759 tests/75 fresh classes, lint/build and7 build-input tests pass; focused13 are subsets. Primary/inverted and reuse all256 B x3 witnesses pass raw/emitted/native checks, including mutation/stale rejection. Actual saved graph v2 reopens in a separate process without reimport/analysis/reapply/explicit refresh. One reviewer closed all findings.

Source `36c6bc533c6b4c66a47c640464f37730d96f649321159878239fd1ea474287d9`; installed extension `71a98c98c88ea0ae731d28b0119baa7c07bc7a2f7d30e1ba7c356ffab6f0b0d4`. Native/SLA unchanged. Explicit separate predicated registryv1->v2; oldv1 rejects non-destructively; ordinary W2v5 unchanged. Domain and limitations are in the report and source decision note. Primary758 checkpoint retained before optional work; no later incomplete delta remains.

**W2 FOUNDATION REMAINS FROZEN.** W3/G2's bounded ordinary-call witness is accepted; allW3, W2/SA requirements and product qualification are not complete. No further feature started. Broader graphs, call/flag contracts, mutable/device/async memory and dependency precision retain existing W3/W4/W5 ownership in IMPLEMENTATION-PLAN.md and DECISION-GATES.md. No W2h.

The accepted W2g predecessor source is `665e6e7050b680da923c47f5f8d7285e65f45bdd1119731b10cbaa759ec1cc80` (746 historical tests), extension55459d8df67f3804677a696472164839ad0e0de4649d2267878f24e7d90a655d. Its report and earlier W1/W2 reports/receipts remain unchanged. No recursive predecessor replay or archive reconstruction occurred.

## Repository authority and cutover review

The cumulative accepted SA implementation is reconciled into the normal Git checkout on `integrate-ghigbc`. The [original plan](IMPLEMENTATION-PLAN.md) and [decision gates](DECISION-GATES.md) retain all requirements, backlog and ownership; their dated proposals do not override this status. The [evidence index](evidence-index.json) distinguishes accepted W3b evidence from new cutover validation. G2 is accepted within W3a’s bounded domain; G1, G3 and G4 remain open. Predicate v3 rejects incompatible earlier envelopes; configured-domain v2 rejects v1 and does not establish G4 migration.

Bounded finite relational convergence is not general scalability. Native HighFunction observations do not prove architectural SP/PC or write counts. Two configured domains at one site do not establish automatic discovery. Broader W3 dispatch, discovery, frame, nested-entry and invocation qualification remain open; W2’s scheduled foundation stays frozen.

REPO-CUTOVER awaits the coordinating master’s review. No W3c, W4/G3 or other semantic work starts automatically. Local recovery is verified; independent backup has not been verified, so old-source retirement cannot be claimed complete. See [cutover policy](REPO-CUTOVER.md).

## Original REPO-CUTOVER checkpoint — historical failure

The maintained tree at `d7027eaafa86f8b76e362044841b69a8c3ec3ea9` (tree `dbf5cf1b547455bfbebb0b3894eb72fa3d8a777b`) passed one fresh clean full build/lint checkpoint with all 773 accepted tests in 78 classes, no failures/errors/skips. Build-inputs7, tooling64 pass/one accepted optional skip, debugger-pure15, changed capture Java compilation and source/package link checks passed. Cyclic setup/reopen and active production continuation order installed checks passed.

**Cutover acceptance is BLOCKED:** the fresh same-site/two-domain capture throws `Domain discovery differs from rooted proof` at the initial discovery equality guard in `SoftwareCallDomains.current`, before domain installation/native requests. Headless exit zero does not override the script exception and missing completion marker. The source fixture, capture script, provider JAR, native and SLA match accepted identities; the cause is not established. Preserve the capture and stop for master review. No guard/checker was weakened, no semantic correction or favorable retry was attempted, and W3b’s original acceptance remains attached to its original execution.

The former workspace source is isolated read-only, with no compatibility symlink. Retirement remains blocked by this validation failure and unverified independent backup. The normal checkout remains the sole active development authority; further work requires master authorization. See the exact artifact/recovery/report references in [the evidence index](evidence-index.json).
