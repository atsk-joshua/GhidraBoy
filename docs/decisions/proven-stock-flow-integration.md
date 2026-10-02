# Proven facts and stock Ghidra flow (WUX-0)

Historical WUX-0 status: bounded investigation complete; production WUX-1 deferred for an explicit
flow ownership and invalidation decision. This is not product-capability PASS.
The incumbent LOW_PRIORITY analyzer and production behavior remain unchanged.

Current disposition: [WUX-1A](ordinary-call-stock-flow.md) now qualifies the
bounded ordinary CALL lifecycle. The WUX-0 observations and next-step proposal
below retain their historical meaning; JP HL remains separate.

## Baseline and boundary

The audit starts from the clean N8 checkpoint recorded in the
[evidence index](../sa/evidence-index.json). N8 is accepted; the older N7-only
status text does not reopen it. This campaign adds mechanism tests and documentation,
not another analyzer, evaluator, language, graph or debugger capability.

| Existing fact | Applied artifact | Normal stock consumption |
| --- | --- | --- |
| Immutable ROM read | Owned READ reference and bookmark | Listing/References/navigation; architectural LOAD unchanged |
| Physical WRAM/HRAM access | Owned READ/WRITE/READ_WRITE and bookmark | Same; transient RAM facts are not installed runtime bytes |
| Proven physical CALL | Owned DATA reference and bookmark | Navigation; separate FunctionDiscovery creates justified Functions |
| N8 singleton JP HL | Owned DATA reference and bookmark | Navigation; no intentional native flow lowering or Function creation |
| Incomplete/ambiguous transfer | No confident reference | Explicit apply may publish diagnostic bookmarks; normal analyzer refuses incomplete publication |
| Returned register/flag/RAM/mapper facts | Transient evaluator state | May establish later findings; no ProgramContext or summary installation |
| Named user/imported target | Existing symbol retained | FunctionDiscovery declines automatic promotion of non-DEFAULT labels |
| Existing flow override or conflicting flow reference | Architectural interpretation refuses | User work retained; no new proof established at that source |

Bank-analysis receipts record reference identity, source, type, operand, symbol and
primary state. Only unchanged ANALYSIS additions are removable; historical receipts
without primary evidence and later user edits are preserved. Supplemental references
survive save/reopen and do not affect raw or high p-code. Existing flow references
are different: InstructionInterpretation consults them and ProgramFingerprint hashes
them, including primary/source changes.

## Pinned stock mechanisms

The experiment uses Ghidra 12.1.3 source archives and the official Linux native
helper, each fingerprinted in the external receipt. Relevant source locations are:

- AbstractAnalyzer, AnalyzerType and AnalysisPriority establish the incumbent late
  instruction-analyzer contract. AutoAnalysisManager `codeDefined` and
  AnalysisScheduler coalesce enabled instruction notifications and execute work
  newly queued at an earlier priority in the current session.
- FunctionAnalyzer (Subroutine References) consumes CALL references and schedules
  missing Functions through the normal manager.
- ReferenceDBManager selects primacy per operand. InstructionPcodeOverride selects
  the first primary CALL across all operands. A primary mnemonic reference does
  not automatically displace a primary operand reference.
- InstructionDB `getFlows` consumes non-indirection flow references regardless of
  primary status. RefType.COMPUTED_JUMP is computed flow, not INDIRECTION.
- PcodeEmit substitutes the selected primary CALL target in overridden p-code;
  raw `getPcode(false)` excludes that lowering. Ordinary computed references do
  not replace BRANCHIND. The direct jump override path handles BRANCH/CBRANCH,
  not an architectural HL BRANCHIND.
- SimpleDestReferenceIterator exposes computed-jump block edges. CreateFunctionCmd
  uses single-address-space FollowFlow. Native funcdata/flow bounds traversal to
  the function entry space; DecompileCallback exports overridden p-code rather
  than ordinary computed-reference targets as a branch transport.

Exact source member locations, hashes, fixture bytes, commands and native output
are retained through the [evidence index](../sa/evidence-index.json), rather than
embedding machine-local receipts here.

## Controlled results

Both specimens independently establish CPU 4100 as physical ROM bank 2 offset
0100 and static `rom2::4100`. The CD specimen initializes SP=D000 before actual
architectural pushes. Fixtures are self-authored MBC5 images.

**CALL.** DATA adds navigation without changing flows or p-code. A normal physical
CALL reference adds a stock block edge. Explicitly selecting it and demoting
competing DEFAULT primaries changes overridden/native CALL to the physical target,
while raw instructions, all non-CALL p-code operations, stack writes and CPU
continuation remain unchanged. Native C calls the physical Function. Primary
selection is semantic lowering, not merely an xref decoration.

However, demotion leaves the DEFAULT CPU-space CALL in `getFlows` and block
relationships: the witness has both `4100` and `rom2::4100`. This does not qualify a
truthful singleton relationship across stock consumers. Removal or retargeting of
the DEFAULT edge needs an explicit reversible ownership contract; existing primary
receipts do not record a displaced reference's restoration. Mere reference addition
also invalidates the original fingerprint and fails architectural reanalysis.

**JP HL.** COMPUTED_JUMP adds the physical instruction/block destination while
both raw and overridden p-code retain exactly BRANCHIND of two-byte HL. It adds
no push, call or fallthrough. The stock Function body excludes the cross-overlay
target. Native decompilation completes but reports missing CPU-space instruction
data and truncated control flow; completion is not semantic success. In the installed
witness an additional stock ANALYSIS computed edge to CPU `4100` also appears.
No direct jump override, jump-table override or new transport was installed.

**Scheduling.** A disposable late producer publishes the CALL and invokes
`codeDefined` on only its source. Earlier stock analysis creates the physical
Function in that same manager session. A repeated producer invocation sends no new
notification. The incumbent GhidraBoy analyzer is disabled for this isolated stock
consumer experiment: production feedback, accumulated roots and avoidance of a
second relational pass remain unqualified. The evidence does not justify changing
its priority or splitting it.

**Lifecycle and admission.** Experimental references, primary selection, raw/high
p-code and Functions persist through actual project save and a separate headless
JVM reopen. The pre-lowering result is rejected by the current fingerprint.
A consumed mapper-selector byte mutation rejects the old result. Another control
shows STATE_LIMIT leaves an existing receipt-owned native reference in place.
Stock AutoAnalysisManager does not provide arbitrary dependency-edit retirement
of these persistent references.

A two-root E9 control is COMPLETE and contains both a PROVEN singleton JUMP and
an UNKNOWN same-source FLOW finding. The durable Finding has no explicit N8
provenance; direct jumps share its access and coordinate fields. Therefore
COMPLETE + PROVEN + singleton + the string "jump" is insufficient admission.
Software-call summaries and ordinary/conditional calls also share "call"; ordinary
CD admission must independently distinguish its architectural contract.

## Decision and next obligation

Do not promote the experimental references into production yet. The combined
DEFAULT-edge displacement, proof exclusion, primary restoration, dependency
retirement and feedback obligations do not constitute a demonstrated low-blast-radius
slice. This stops at the task's architecture-sensitive decision boundary; adding
another receipt field alone is not the reason for deferral.

The next bounded task is an ordinary-CD lifecycle design/prototype: choose exact
DEFAULT displacement/restoration and dependency retirement contracts, keep generated
lowering out of proof inputs without ignoring user edits, and qualify singleton
stock flows, physical native CALL, rollback/removal/reapply, consumed-dependency
mutation followed by incomplete analysis, real incumbent scheduler feedback and
separate-process reopen. Obtain an explicit persisted compatibility decision before
production adoption. Preserve imported/user references and Functions throughout.

JP HL remains separate: first add compatible structured admission provenance that
accounts for unresolved same-source alternatives; then decide whether Java CFG-only
integration is a sufficient bounded product contract or a different cross-overlay
native transport is required. Do not turn the architectural indirect transfer into a
direct jump for prettier C.

Normal Wyatt-style users gain no production workflow improvement from WUX-0.
The experiments narrow the next integration decision. Headed/private-target,
Steam Deck, debugger, migration, corpus, fuzz, hardware, release and whole-ROM
qualification remain unrun. No remote mutation or persistent installation occurs.
