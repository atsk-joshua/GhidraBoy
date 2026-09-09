# Static analysis implementation handoff

This retained implementation guide describes the original SA requirement decomposition. Start with [current SA status](sa/IMPLEMENTATION-STATUS.md), the [implementation plan](sa/IMPLEMENTATION-PLAN.md), and [decision gates](sa/DECISION-GATES.md). Dated campaign instructions below are historical; they do not authorize replay or supersede accepted W3b. Original SA/FX/M scope remains required.

This guide makes the [roadmap](roadmap.md) executable; it does not replace any
roadmap item, the [requirements](static-analysis-spec.md), or existing gates.
SA-00 implementation and executed evidence are recorded in the
source checkout receipt `docs/evidence/sa00-20260907/README.md` and
[decision](decisions/sa00-integrity.md). SA-01 through SA-07 remain open.

## Read order and authority

1. Read current task instructions and repository instructions; preserve unrelated
   working-tree changes. Branch names must not use the `codex/` prefix.
2. Read the [roadmap](roadmap.md), then
   [S-01 through S-13 and acceptance gates](static-analysis-spec.md).
3. Read [current analysis behavior](analysis.md),
   [mapping contract](static-contract.md), [input policy](input-policy.md), and
   [compiler support](compiler-support.md).
4. Use [research](static-analysis-research.md) for findings and design alternatives,
   and [references](references.md#static-analysis-reference-catalog) for primary
   sources. Revalidate source-dependent findings against the current checkout.
5. In the source checkout, use `docs/building.md` and `docs/validation.md` for
   environment setup and broader campaigns. Historical integration handoffs are
   evidence, not current execution instructions. Do not resume an old process or
   campaign solely because a document says it was running.

The executable language/schema files describe implemented behavior. The written
static-accuracy specification describes the required future behavior. Do not
change language IDs, versions, constructors, schemas, or compiler IDs merely to
make them resemble the planned architecture.

## Original SA-00 implementation requirements

First inspect `ProgramFingerprint`, `BankAnalysis`, `PcodeConstants`,
`AnalysisApplication`, `AnalysisOwnership`, and `AnalysisResult` under
`src/main/java/fi/gekkio/ghidraboy/`. These are the initial implementation targets;
no emulator backend or private game checkout is needed.

### SA-00a: flow evidence and invalidation

Create a small self-authored banked Program using the existing IntegrationTest
and CartridgeLayout helpers. Reproduce reference-only changes to a followed
flow: target, reference type, primary status, addition and removal. Keep ROM,
instructions, data, mapper assumptions and ordinary flow overrides fixed so the
test isolates the missing dependency. Show which changes alter traversal and
which saved results currently remain accepted.

Then define the consumed-flow policy before changing the hash. Separate decoded
flow, validated overrides, external annotations, and owned supplemental
references. Every consumed dependency must be fingerprinted or otherwise checked.
Excluding an owned reference from hashing is valid only if it cannot influence
the analysis input. Do not blindly hash all references and break apply/reapply:
the current application creates references, and its own output must not become
circular proof or make a saved result unexpectedly unusable.

Required regression cases: stale apply and discovery rejection, reference-only
mutation during preview, independent rerun equivalence, apply/remove/reapply,
later user edits, cancellation, and save/reopen. Preserve existing ownership
receipts. Decide whether the analysis engine identity/result format must advance;
do not silently accept previews produced under the old dependency policy.

Existing test homes: `AnalysisLifecycleTest`, `AuditRegressionTest`,
`AnalysisHardeningTest`, `FunctionOwnershipTest`, and installed lifecycle scripts.

### SA-00b: coherent instruction interpretation

Record the intended relationship between `getPcode(false)`,
`getPcode(true)`, `getDefaultFlows()`, `getFlows()`, fallthrough overrides and
callfixups. These APIs describe different views. Reproduce at least a modified
call/branch, a conditional transfer, and an inline-payload continuation. Assert
both effects and destinations; switching every call to `getPcode(true)` is not
an accepted fix without checking injected/override effects and stack behavior.

Where a convention or override cannot be interpreted faithfully, return an
explicit unresolved result rather than mixing incompatible effects with flow.
Do not convert a conditional branch to an unconditional one merely to attach a
banked target. Extend dependency coverage for the selected interpretation.

### SA-00c: evaluator conformance and baseline

Use Ghidra's operation behaviors or implement width-correct abstract operations
with independent conformance tests. Cover zero, boundary and oversized shifts,
sign/zero extension, truncation, arithmetic wrap and overlapping register writes.
Unsupported operations must invalidate dependent values. `PcodeConstantsTest` supplements the existing boundary/hardening tests;
`PcodeConstantsSleighTest` separately checks compiled instruction behavior. Include compiled-SLEIGH cases to establish
real instruction reachability separately from evaluator contract edge cases.

Capture a baseline per input: defined physical code/data bytes, unresolved bytes,
roots, functions/bodies, indirect edges, semantic failures and warning categories.
Keep annotated and fresh-import inventories separate. Use generic fixtures first;
optional private studies own their corpus tooling and exact-game evidence.

SA-00 is complete only with regressions for its findings, preserved lifecycle
behavior, an updated engine/invalidation policy and evidence for the changed
code. A source-level finding or passing preexisting tests is insufficient.

## Work-package map

Java names below are in `src/main/java/fi/gekkio/ghidraboy/` unless stated otherwise.
Test names refer to existing Kotlin suites under `src/test/kotlin/fi/gekkio/ghidraboy/`.
Add self-authored fixtures where the existing suites do not cover the requirement.

| Work | Starting implementation surfaces | Tests / concrete deliverable |
| --- | --- | --- |
| SA-01 | `FarCallConvention`, `CartridgeBusInjectLibrary`, `CompilerAbi`, `AnalysisApplication`; relevant `.cspec`/`.pspec` files | `BankAnalysisTest`, `AnalysisLifecycleTest`, `CompilerAbiTest`, `decompiler/DecompilerTest`; returning/restoring and nonrestoring software-call fixtures, frame/effect summary and ordinary-auto-analysis continuation regression |
| SA-02 | `CartridgeLayout`, `MapperTopology`, `ProgramMapping`, `MapperState`; language files and Ghidra transport only as required | `MapperTopologyTest`, `CartridgeBusTest`, `AnalysisBoundaryTest`, native decompiler scripts; comparable representation prototypes and a selected architecture/migration decision |
| SA-03 | `MapperKnowledge`, `PcodeConstants`, `BankAnalysis`, `AnalysisCandidates`, `AnalysisResult`, `ProgramFingerprint` | `AnalysisHardeningTest`, `AnalysisBoundaryTest`, `BankAnalysisTest`; memory/range/summary model, join/unknown policy, dependency closure and counterexample fixtures |
| SA-04 | `FunctionDiscovery`, `AnalysisOwnership`, `AnalysisApplication`, `SymbolService`, loader seeds | `FunctionOwnershipTest`, `SymbolOwnershipTest`, `CartridgeEntryTest`, lifecycle scripts; rooted discovery, label-preserving promotion, repair previews, exact disposition and rollback inventories |
| SA-05 | `CompilerAbi`, `.cspec` files, `DataTypes`, `SymbolFile`, `SymbolService`, `ProgramKnowledge`; new format readers when justified | `CompilerAbiTest`, `CompilerSpecTest`, `SymbolBoundaryTest`; versioned emitted-code and metadata fixtures, source mappings, typed data and lifetime evidence |
| SA-06 | `Cartridge`, `MapperState`, `MapperKnowledge`, `MapperTopology`, `CartridgeLayout`, `ProgramMapping`, `HardwareReference` | `CartridgeTest`, `MapperTopologyTest`, `CartridgeBusTest`; controller/board/device matrix and regressions; schema migration proposal before changing window geometry |
| SA-07 | Source validation tooling, installed scripts, public workflows and normal Ghidra integration | All specification gates on exact artifacts; fresh and annotated results, actual migration/reopen, normal-window evidence and documented unresolved failures |

Required integration follow-through includes the debugger's
`BankMappings.java` default-compiler restriction and consumers of any mapping or
language change. Preserve the static-only build. General changes remain here;
private ROMs, game-specific addresses and private conventions stay in the owning
study repository. Public reconstructed patterns must be pinned and translated
into self-authored generic fixtures before becoming generic qualification inputs.

## Architecture decision deliverables

Create source decision records under `docs/decisions/` as work proceeds.
`static-call-model.md` now records the partial SA-01 model and mechanism evidence.
`static-bank-model.md` now records the scoped continuation candidate and its
qualification failures; `static-dispatch-model.md` remains a future deliverable.
Each record must include:

- requirement IDs and exact candidate/source revisions;
- tested alternatives, fixture identities, commands and raw result locations;
- architectural effects, native CFG/C and committed Program behavior;
- selected approach, rejected approaches with evidence, and residual limitations;
- language/schema/consumer migration, invalidation and ownership implications;
- remaining gates and follow-up work IDs.

For calls, test nested software frames, flag results, payload adjustment,
conditional/nonlocal exits and repeated normal auto-analysis. For banking, test
both execution windows, two bank changes within a function, banked data reads,
16-bit arithmetic/stack/fetch wrapping and unknown bank state. For dispatch,
test plain pointer calls separately from indexed tables, duplicate/default/zero
cases, memory-derived bounds and physical target identity. Existing successful
single-bank or helper-specific experiments are supporting cases, not substitutes.

These are implementation tasks with measurable exits, not questions that require
the user to choose an architecture without evidence. Continue independent work
while a decision is unresolved. Do not broaden an unqualified choice across the
provider simply because it passes one example.

## Commands and environment

Use JDK 21 and the pinned Ghidra 12.1.3 binary distribution. Set `JAVA_HOME` and
`GHIDRA_INSTALL_DIR` to explicit installations. Inventory any native companion;
stock 12.1.3 and `12.1.3+ghidraboy.switch-recovery.2` are different test tuples.
Follow [native dependency build instructions](native-decompiler/build-and-rollback.md)
when a changed native dependency is required. Do not patch an active installation.

Run from the source repository root. Start with the relevant focused suites:

```sh
python3 tools/check.py --suite build-inputs
./gradlew test --tests '*AnalysisLifecycleTest' --tests '*AnalysisBoundaryTest' --tests '*AnalysisHardeningTest' --tests '*AuditRegressionTest'
```

Include newly added test classes explicitly in focused runs. Then run the full
provider checks after the implementation change is ready:

```sh
./gradlew test ktlintCheck buildExtension
```

Use `python3 tools/run_validation.py --help` to configure installed/migration
campaigns against fresh disposable distributions. The source checkout's
`docs/validation.md` lists the suites; [CPU validation](cpu-validation.md) and
[instruction compatibility](instruction-compatibility.md) explain their limits.
Ordinary selected vector samples do not establish full opcode or hardware
coverage. The [GUI checklist](gui-validation.md) is an additional gate, not a
reason to launch unscheduled old GUI campaigns. Follow current session/platform
authorization and the existing device deferrals.

Commands in this guide are instructions for implementation, not claims they ran
during the documentation update. Record baseline failures before attributing
new failures to a change; do not erase them or count skips as passes.

## Evidence and handoff after each change

Use a fresh evidence directory selected for the run, with a manifest recording
work/requirement/gate IDs, source commit and dirty-file hashes, exact dependencies,
fixture hashes and provenance, assumptions, commands, exit codes, results,
expected versus actual behavior and unresolved obligations. Proposed manifest
fields are not a new runtime/public JSON schema. Keep private artifacts out of
generic evidence and distributions.

Update the roadmap status only for the scope actually proved. Include a concise
next action and the matching decision/evidence links. Record replacements as
old ID to new IDs plus residual scope; retain every original M0–M10 and SA item.
Never overwrite historical receipts to make them describe current code.

An implementation handoff is complete when another agent can reproduce the
relevant failure/fix, locate every changed contract and required check, and see
which milestone obligations remain. SA-07 requires the entire specification
matrix; a completed SA-00 or a warning-free sample is not milestone completion.


## SA-01 preceding checkpoint

The earlier finite-model and legacy-annotation checkpoint is preserved in
`docs/evidence/sa01-20260907/` and its independent review. Its
`tools/sa01_persistence.py` campaign qualifies legacy annotations only. The
production workflow and executable persistence driver follow below; do not
relabel the preceding experiment or its 502-test receipt as their evidence.

## Production SA-01 integration checkpoint

The follow-through lives in `SoftwareCallRegistry`, `SoftwareCallInjection`,
`SoftwareCallEffects`, `SoftwareCallApplication` and `SoftwareCallExecutionView`.
`GhidraBoyTools` exposes `software-call-preview`, `software-call-apply` and
`software-call-remove`; all compiler definitions install the dynamic payload.
Keep the earlier SA-01 receipt intact and use the new source evidence directory
`docs/evidence/sa01-production-20260907/` for current results and the requirement
completion audit. The implementation now includes banked inline payload reads,
explicit nested conventions, native compatibility vetoes and reviewed physical
continuation views. Do not confuse raw proof completion with native compatibility.

Focused selections must include all `*SoftwareCall*` tests, `FarCallReviewTest`
and `ReferenceOwnershipTest`. `SoftwareCallAnalysisTest` checks concrete incoming
premises; `SoftwareCallTypeDependencyTest` checks same-size native type mutation.
The installed campaign is `tools/sa01_production_persistence.py`; it uses a copied
standard extension, the packaged tools script, ordinary automatic analysis and
separate-process native checks. Its final edited phase intentionally verifies a
stale-contract rejection; logs distinguish that expected error from unexpected
analyzer failures. No analyzer is disabled or repeatedly undone.

Clean removed execution views retain their real shared mappings as non-executable
retired spaces after owned listing/function removal. This preserves address-space
identity for queued stock analysis work. Do not reintroduce deletion of their last
block during ordinary analysis: the installed campaign exposed queued-address
failures from that deletion. Edited views remain intact. General same-CPU
multi-state native execution and unsupported callee memory/flow transport remain
SA-02 obligations; inspect the bank decision and final audit before any milestone
status change.

## State-qualified integration successor

The historical state-qualified campaign is preserved through [the evidence index](sa/evidence-index.json). Current implementation and qualification routing comes from the tracked SA authority. The integration now
uses `SoftwareCallEffects` state graphs, `SoftwareCallContinuationView`, rooted
`SoftwareCallInstructionDiscovery`, and optional `SoftwareCallStateEntryInjection`.
See the latest sections of the call/bank decisions for the explicit compatibility
transition and selected-context domain. Do not treat a native mechanism probe or
an architectural trace as full native semantic qualification.

Run the new focused classes as well as the retained finite regressions, then
`./gradlew test ktlintCheck buildExtension`, build-input/tool suites and both
installed production and state/discovery campaigns. State-qualified callee tests
require the exact optional native companion; absence is not evidence of success.
Normal GUI comparisons must use a separately identified disposable Program and
installation. The original SA-01/SA-02 requirement audit remains authoritative
for completion; broader SA-03/04/06/07 scope is retained.
