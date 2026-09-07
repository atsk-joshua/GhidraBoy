# Installed lifecycle follow-up investigation

This bounded follow-up owns the production persistence driver and installed test
script. It does not independently certify those newly authored checks or close
SA-01/SA-02. The primary integration receipt owns the current artifact identities,
serialized installed executions and final requirement audit.

The investigation began on branch `integrate-ghigbc` with the extensive existing
staged, unstaged and untracked inventory preserved. Initial SHA256 identities for
`AnalysisOwnership.java` and `SoftwareCallExecutionView.java` matched the handoff:
`fe733f887df84ea3395fab1c0c14d17023a78de770a4ed46e426caa184403cb2` and
`282f4a9fbd3ebe1a73b1847addf9e89bf1330a308120a531182ae894a2340b2a`.
The initial script and driver identities likewise matched the handoff's recorded
`2bc7f14ae5ecd229ad848a669d0efbded86a7dd2b0c9425c73bd42f51f775358` and
`6ba07379951041597f32b0d94f6628532f20a1aec5d8b25d8ac0f447607e1844`.

## Findings and executable follow-through

1. The former last phase removed owned state and asserted preservation inside
   that process, then exited. No subsequent process observed the final saved
   user edits and retired mappings. The driver now has a sixth `removed-reopen`
   phase with ordinary analysis still enabled. Both removal and final reopen
   check saved continuation/comment, absence of executable ownership, retained
   mapped/non-executable blocks, no decoded retired instructions or Functions,
   and an identical saved retired-address-space inventory.
2. Earlier installed native checks selected only execution-view Functions for
   banked cases. The installed script now independently decompiles canonical
   banked register/inline/constant roots and companion entries through ordinary
   `DecompInterface`, requiring their actual physical CALL endpoints. These
   assertions intentionally require the primary canonical-root correction;
   they are not weakened to accept alias-only decompilation.
3. The installed fixture now includes an independent restoring banked return,
   constant-bank return to a third bank, true deterministic nonreturning loop,
   and known nonlocal stack-frame rewrite. It preserves the preceding two-site,
   ordered inline payload, nested restoring and user-edit cases. Raw return
   snapshots check SP, physical continuation and register/flag results; native
   checks require physical target and terminal/nonlocal control behavior.
4. The prepare phase explicitly observes the absence of helper instructions and
   saves the resulting public-preview rejection before manually preparing the
   lifecycle fixture. This makes missing-instruction discovery distinguishable
   from prepared application. It does not claim an automatic-discovery fix.
5. Retirement source retains actual shared backing and address-space identity,
   clears unchanged owned listing and removes execution permission. Its
   view-ownership inventory includes user comments, symbols, mapping, functions
   and non-generated references. This is the necessary source correction for
   the recorded deleted-address-space failure, but only a new full installed
   campaign can establish queued-analysis compatibility.

The driver continues to reject every logged ERROR except the exact deliberately
stale `0150` annotation rejection during edited-reopen. PASS markers and process
exit zero remain insufficient when other errors occur. Every new run requires a
new work directory and a fresh temporary Ghidra copy; previous failed receipts,
active installations and private originals remain intact. The driver additionally
records its own hash and the exact installation/JDK/property/native identities.

## Verification status

`python3 tools/sa01_production_persistence.py --help` passed after the driver edit.
No build, formatter, installed Program mutation or GUI session was run by this
investigation before the primary's build/installation coordination. Actual
campaign results must be appended with the new run location and exact artifacts.

## Coordinated preparation follow-through

The primary authorized a new disposable copy at
`/private/tmp/ghidraboy-sa01-resume-install-1/ghidra_12.1.3_PUBLIC`, copied from
`/private/tmp/ghidraboy-sa00/ghidra_12.1.3_PUBLIC`. The source was not changed;
neither location contained a `Ghidra/Extensions/GhidraBoy` directory at copy
completion. Source/copy application-properties SHA256 matched
`fb9b6292c801e4a18b7c20829437d3b18b2241b273aea9b1cbdebdf3e5d0dc15`, and native
Decompiler SHA256 matched
`5b736c3e9236667d35a732f226c99f0014736b9fe506147886a7f15ccb94939a`.
No Program was opened and no driver run began during preparation.

The fixture additionally calls a fixed-ROM ordinary `NOP; RET` callee from the
nested software target. Reapply deliberately introduces false noReturn on that
ordinary callee and CALL_RETURN at its callsite. Every native verification phase
requires the precise annotations repaired and an actual physical ordinary CALL.
The installed script writes only the public Configuration-array input; it does
not parse preview output, so the new sites/nestedRepairs/executionViews review
object is compatible. Updated Python syntax passed. Java and lifecycle checks
remain for the coordinated installed campaign on the new artifact.

## Installed resume campaigns 1–3

All three campaigns used the frozen product archive SHA256
`e14553e37e280212c17406d78c5405624bc6eac0bc3b76189419dbbd35deee67` and
fresh installation/work directories named `ghidraboy-sa01-resume-install-N`
and `ghidraboy-sa01-resume-run-N` under `/private/tmp`. Raw logs, manifests,
fixture/script snapshots and available native output are retained separately in
`installed-runs/resume-run-N/`.

Run 1 failed phase 0 because the newly added test-script physical-address helper
omitted its checked IOException declaration. Neither prepare nor verify loaded;
headless exit zero was correctly rejected. The script signature was corrected.
This was a test-harness defect and does not implicate product behavior.

Runs 2 and 3 compiled, applied through packaged public Tools and passed existing
fixed-site, canonical/alias banked and inline native checks, nested ordinary calls,
and the new restoring-bank caller. Both failed on the constant-bank canonical
entry because its required execution alias no longer passed ownership validation.
The canonical source's own raw annotation receipt remained current. No milestone
or installed phase is passed on the strength of these partial assertions.

Public pre/post snapshots in run 3 isolate the change: the decoder's DEFAULT,
primary, non-flow DATA reference from execution-view CPU4803 to WRAM c103 is
removed/refined by ordinary analysis. The ownership view hash includes that
DEFAULT reference but excludes ANALYSIS non-flow references. Every other captured
view field stayed equal, including function signature, stack frame, body,
instructions, mapping and flow overrides. The other two execution-view snapshots
were identical. This is a concrete ownership false-invalidation finding for the
primary owner; dropping all reference checks or accepting user edits is not a
justified correction.

A read-only inspection of the already failed run-2 saved Program used `-readOnly
-noanalysis` solely to observe failure state without rerunning queues; this was
not a qualification campaign and did not save changes. All driver phases continue
to run ordinary automatic analysis. No analyzer was disabled in a campaign.

Both runs also retained WARN-level injection failures: one Program-modified
callee-derivation rejection and multiple missing-current-return-witness warnings.
The driver now classifies these as campaign failures, alongside ERROR lines;
only the exact deliberately stale0150 annotation rejection in edited-reopen is
expected. Native unreachable-block diagnostics have a separate retained category.
Synthetic classification checks pass for valid stale rejection, wrong phase/site,
unresolved returning markers, ordinary native unreachable blocks and address-space
errors. The transient derivation warnings remain a separate primary integration
obligation; this investigation does not waive them as harmless logging.

## Installed resume campaign 4

Run4 used new artifact SHA256
`e259fac6154e86abca2b58ce8bdc9f789e06d4bc82047c1924fca3e24abc9937`, with
another fresh disposable installation/work pair. The script now explicitly
checks the selected canonical representation: CALL_RETURN/null listing
fallthrough, intact raw architectural CALL, and ordinary mapped alias continuation.
Its native expected values and physical endpoints were not changed.

Phase0 reached both PREPARE_PASS and VERIFY_PASS, including the new constant-bank,
terminal and known-nonlocal checks. Nevertheless the campaign correctly failed:
ordinary constant propagation logged one unresolved returning-target warning for
`rom2::4400`, whose rejected witness reported Program modification during proof.
This warning remains a product lifecycle failure; no later phases or GUI project
snapshot were produced. The source already retries the entire neutral injection
request up to four attempts. No missing outer retry is asserted here; the actual
warning shows that the bounded mechanism did not obtain an accepted witness in
this installed run. View-state refinement and canonical transport failures from
runs2–3 did not recur. All raw run4 artifacts remain in its separate receipt.

## Installed resume campaign 5: complete finite lifecycle pass

All six separate-process phases passed on the next exact artifact:

- Extension SHA256: `0bbea54f5c497c3c586d55987e001dcdb61a8bdc1b06546ec1c9cdeb3d4719e3`.
- Packaged provider JAR SHA256: `f7502b8a0c7d80c0e171b5f77ca51f08e9f4f190e680217c1c99e40923c8f9f7`.
- Installed script SHA256: `e002e88c9812846ab5dd044d676512bd7a3efbb9f3f5240dd9083a0db1865c79`.
- Driver SHA256: `218314ba3d73c3e321f45584a7fa17e5a525b9f78e1f5d84f4aeeb2df1019426`.
- Self-authored ROM SHA256: `b7e0403c9c8c6cfb182be91bb771016b4c588f4793e8e271c330f57f988bd5b8`.

The runtime remains pinned Ghidra12.1.3/JDK21.0.12.1 and the previously identified
native companion. Exact commands and installation/runtime hashes are recorded in
`installed-runs/resume-run-5/run.json`. Every process exited zero. There were no
unexpected errors, unexpected injection/analysis warnings, or other warning lines.
Edited-reopen recorded exactly four expected stale0150 annotation-rejection lines;
the final removed-reopen process logged none.

The completed phases are prepared public application/ordinary analysis/native
verification; separate saved reopen/native verification; explicit annotated repair
and reapplication/native verification; separate reopen of the saved nested-repair
inventory and user edit/save; edited reopen/rejection/removal; and final saved
removal/user-edit/retirement reopen. The nested ordinary repair inventory records
the original false noReturn and CALL_RETURN-to-NONE migration with the actual
matched-return witness and physical target0360. Both reapply analysis and the
subsequent separate process preserve that exact inventory.

Final reopen preserves the user continuation015a and payload comment. Six retired
execution address spaces from initial/reapplied views remain backed by mapped,
non-executable blocks, with no retired instructions or Functions. Their saved
address-space inventory is identical after reopen. Ordinary analysis stayed
enabled throughout; no queue cancellation or suppression supplied the pass.

A disconnected post-repair project snapshot is available at
`/private/tmp/ghidraboy-sa01-resume-run-5/gui-projects/sa01-production.gpr` for
the primary's normal-window verification. The headless driver used the separate
`projects` directory and has completed. This worker has not performed GUI checks.

This pass qualifies the executed finite prepared-fixture lifecycle matrix on the
identified artifact. The explicitly recorded unprepared missing-instruction
rejection still does not prove automatic helper/callee discovery. General same-CPU
multi-bank paths and other original SA-01/SA-02 obligations remain for the primary
requirement audit; neither milestone is certified complete by this campaign.

## Installed resume campaign 6: final archive confirmation

The primary's final package updates two documentation members while retaining the
same provider JAR. A fresh six-phase campaign was nevertheless executed against
that exact final ZIP:
`a0dc7a04ca7468b458fefc75af77c510ec4481d1a87420a9c4341bed42a9c841`.
Installation/work paths are the new `ghidraboy-sa01-resume-install-6` and
`ghidraboy-sa01-resume-run-6` directories under `/private/tmp`.

All six phases again passed with zero unexpected errors or warning lines. The
four exact stale0150 rejections occurred only in edited-reopen; final saved
removal/user-edit/retirement reopen was clean. The driver, script and fixture
identities remain those recorded for run5; no assertions were weakened or scripts
changed between these passing campaigns. Exact process commands/outcomes and raw
logs are preserved in `installed-runs/resume-run-6/`.

The final-artifact post-repair GUI project copy is
`/private/tmp/ghidraboy-sa01-resume-run-6/gui-projects/sa01-production.gpr`.
It is separate from the headless driver project. The driver has completed; normal
window verification and any GUI process identity belong to the primary receipt.
All finite-coverage and incomplete automatic-discovery/general-banking limits
stated for run5 remain unchanged.
