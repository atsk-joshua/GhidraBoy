# Independent supplementary-fragment investigation

This is source inspection and independently authored regression work for the
2026-09-07 integration task. It does not claim a build, installed qualification,
Program migration or GUI result. The primary agent owns production integration
and serialized execution. Historical registry4, registry5 and loose registry6
artifacts remain distinct as recorded in the preceding handoff.

## Causal path

The retained failing JUnit output at
`../sa01-state-20260907/handoff-focused-3-junit/TEST-fi.gekkio.ghidraboy.SoftwareCallAutomaticAnalysisTest.xml`
reports native decompilation of `gb_call_view_291_4500_state1::4501` attempting to
fetch unmapped `4507`. This is independently significant from the canonical/alias
thunk and fixup drift. The exact self-authored continuation bytes are
`cd40023c38023e00ea00c2c9`: CALL 0240, INC A, JR C,+2, the untaken LD A,0,
LD (c200),A, RET. Callee 0240 is `3e5a37c9`: LD A,5a, SCF, RET.
The declared execution therefore writes 5b to c200. The proved conditional path
skips 4507–4508. Those bytes exist in canonical ROM but are intentionally not
part of the proof's observed instruction ranges.

`SoftwareCallContinuationView.fragments` groups graph instruction ranges by
physical source address space, retaining holes and both physical bank identities.
`SoftwareCallApplication.apply` materializes these as shared executable blocks
and disassembles every `#state` and `#native_` fragment. The current
`nativeEntryGraphs` function includes root CALLEE graphs and eligible nested
invocations, but excludes the root CONTINUATION graph. Thus a supplementary
continuation listing can have raw conditional flow into its holes and no
Function with a complete pre-flow graph.

The pinned stock `DecompilerSwitchAnalyzer` explains why ordinary analysis
opens this partial listing. In its `findLocations` (line 237), every instruction
in the submitted set is considered (line 246). A call to any Function with a
callfixup qualifies through `isCallFixup` (lines 377–389). The supplementary CALL
0240 qualifies because the callee has a returning-witness fixup. When there is
no containing saved Function, `FindFunctionCallback.process` explicitly uses
`UndefinedFunction.findFunctionUsingSimpleBlockModel` (line 444). It then runs
native decompilation on undefined as well as saved Functions (line 122).
The native decoder follows the raw conditional fallthrough to absent 4507.

This means the warning does **not** establish creation of a persisted Function
at 4501. A temporary UndefinedFunction is sufficient; comparing only saved
Function inventories would miss this entry path. The analyzer's instruction
scan does not consult block execute permissions, so simply marking already
disassembled fragments non-executable does not close this path.

The registry5 annotation diff independently shows normal DATA-to-WRITE
refinements at real stores and logical CPU READ references from derived views.
Those are not evidence that the continuation actually executed the newly named
logical read endpoint, and are not the cause of raw 4507 becoming a decode
candidate. They must remain separate from helper thunk/fixup inheritance.

## Minimal correction constraints

For the reproduced 4501 entry, the complete validated continuation graph already
exists. Registering that graph on an explicit owned supplementary Function can
prevent raw native flow recovery without changing original bytes, padding the
hole, erasing the fragment, or changing the architectural conditional branch.
The graph registry currently also excludes root CONTINUATION in `entryGraph`;
application and resolution must agree if this correction is selected. Domain,
annotation, configuration, source, companion and ownership checks must continue
to protect the new entry.

This is not automatically a solution for every supplementary fragment. A fragment
whose first instruction occurs only after a bank change needs a proof-backed
entry at that actual state. A literal sublist of later trace steps is insufficient:
loop successors can target earlier global step IDs, and a fragment may begin
inside an outstanding native/software frame. A sound slice must close all local
successor edges, retain nested invocation and nonlocal outcomes, preserve live
stack semantics and untyped vetoes, and fingerprint the full prerequisite graph.
If the same physical entry is revisited in different states, one arbitrary chosen
slice cannot represent both domains. These checks are the next obligation for a
general supplementary-entry correction; the simple fixture does not waive them.

## Independent regressions

`SoftwareCallDerivedFlowIntegrityTest.kt` was added without running a build:

- Independently opens the supplementary 4501 entry through a saved Function or
  the same UndefinedFunction finder used by stock analysis, and requires CALL
  0240, RETURN and c200=5b with no bad-data/truncated-flow diagnostic. It asserts
  the actual canonical branch bytes and retained proved destination fragment.
- Runs full ordinary analysis twice, preserves all existing shared fragment
  block mappings, reopens the supplementary continuation and decompiles every
  saved Function in a generated view. Strict campaign log accounting is still
  required because errors from temporary UndefinedFunctions are not necessarily
  reflected in the final saved Program or process exit code.

These are required-behavior tests, not evidence of passing implementation.
Build/format/Program mutation was deliberately left to the primary agent.

## Read-time identities

The source inspection began at git HEAD
`16752093dce0147afd28762a2f8918144ec571c2` with extensive pre-existing staged,
unstaged and untracked work. The following SHA256 values describe the inspected
checkpoint, not any later integrated artifact:

| Input | SHA256 |
| --- | --- |
| SoftwareCallApplication.java | 6c80c5754a39188e7d01938b2740addb906018697c21f80dfc59830ae16cb8fe |
| SoftwareCallContinuationView.java | c997b4b96b726869422b0e805369b133fdee35ebcb95e363afb75fbf1f929c65 |
| SoftwareCallRegistry.java | 6ebffdda4fd2b5fc57735e11c73a77d66b2950ca1c89e57159da98a29cb81d10 |
| Historical automatic-analysis JUnit XML | a098d826387e9e46e26fbf63a6d52a5d30d68837d7dba051658eb3cc4ceb992d |
| Pinned Decompiler-src.zip | c33a0ea114a425131c45ffc7ddd6172142c403813cc271ddece9b324fc78382b |
| Pinned Base-src.zip | a18a8650132670230cd12fdcfaa3e20605a1e1d24c07d033d20986fea2cff2d2 |

The source archives were read directly from
`/private/tmp/ghidraboy-sa00/ghidra_12.1.3_PUBLIC/Ghidra/Features/{Decompiler,Base}/lib/`.
The primary environment inventory must verify their corresponding runtime copy
before treating a source-level mechanism as exact executed runtime attribution.
No active installation, original captured project or private input was changed.

## Full-graph selected-entry alternative

A smaller alternative to slicing was proposed to the primary integrator after
the independent regression reproduced the fragment failure: retain the complete
validated invocation graph and its dependency/veto set, and lower an explicit
initial local branch to the actual selected depth-zero node. All graph anchors
remain present. This avoids dropping a loop backedge to an earlier trace index,
losing prerequisite-call evidence, or accidentally changing the graph's external
return/nonlocal boundary. The selected node must be part of the registered
invocation and its exact incoming state must be visible in the entry receipt.

A fragment containing only deeper invocation instructions must use that
invocation's existing rebased callee graph. It cannot branch directly into a
nonzero-depth node of the enclosing graph, because the lowering intentionally
omits those nodes in favor of actual CALL operations. Function bodies should
retain every mapped depth-zero source instruction for their owning invocation
within the fragment. Distinct invocation bodies must not overlap silently.
Repeated physical roots require an explicit selected domain with separate
available context aliases or a preview-time ambiguity rejection; they cannot
be silently treated as one state.

The registry must distinguish source graph identity from selected entry-node
identity, even if this can be derived deterministically without new fields.
The full proof hash and selected node/state must be consumed. This proposal
requires native tests for the initial local branch, removal of unreachable
prefix operations without diagnostics, earlier-loop successors, nested calls,
nonlocal frame behavior and saved/reopened entry metadata. It is not yet
recorded here as the chosen or qualified production implementation.

## Projection implementation review follow-up

The primary integrator requested an independent read-only review after adding
`entryStep` distinct from `graphEntry`, owned projection Functions, and traversal
of the selected depth-zero successor graph. The review found:

- Native fragment provenance must use the exact invocation graph encoded in the
  `#native_<kind>_<graphEntry>` key. Scanning all graphs of the source first can
  attach a later-bank fragment to a different repeated invocation of the same
  physical routine. The primary reported correcting that lookup. A new test
  invokes bank2:4200 twice with Z=1 then Z=0; both switch to the same physical
  bank3:4205 branch, whose selected writes must remain c210=22 and c210=33 in
  their respective independently opened projections.
- A new later-fragment loop regression selects bank3:4105 after bank2:4100,
  then returns through bank2:410a to the earlier root state. It checks that
  traversal retains the backward graph edge and creates no synthetic RETURN.
- Nested configured software-helper prelude/epilogue steps are retained by
  fragment construction but are intentionally outside balanced callee invocation
  slices. Their nonzero-depth Instructions need coverage review: source-depth0
  plus callee-depth0 projections alone do not establish that every saved fragment
  Instruction has a containing validated Function. A final coverage invariant
  and a nested software-wrapper regression were recommended. No assertion that
  this outstanding path is fixed is made here.
- Both the previous emitter and the newly factored successor walker searched
  only forward trace indices for a matched CALL's `afterCall` state. An exact
  call loop can resume an earlier observed state without creating a later node.
  This remains a distinct potential rejection case; the simple mapper loop
  regression does not establish general repeated-call-loop support.

The test additions were not built or formatted by this worker. The primary
owns the exact outcomes and artifact identity. The renewed review did not find
relaxed dependency checks: the source proof is rederived, all original transport
vetoes remain checked, registry configuration identity includes projection and
selected-node fields, and paired ownership checks remain required.
