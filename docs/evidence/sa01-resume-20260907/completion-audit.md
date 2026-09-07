# Original SA-01 requirement audit

**SA-01 incomplete. SA-02 incomplete.** This audit retains the original requirements.
Successful finite tests and installed lifecycle checks are not general architecture,
fresh-discovery or whole-ROM completion. Nothing replaces or removes an SA/M item.

Current qualification: 94/94 focused tests and 567/567 full provider tests, with
lint/build passing. Build-input checks pass. Tooling reports 41 tests, one explicit
unconfigured Java-companion test skip; it is not a 41-pass claim. Installed resumed
campaign 7 passes all six phases with zero unexpected warnings/errors. Its four
phase-4 rejection lines (three WARN and one ERROR) are the explicitly asserted 0150 stale-annotation rejection.
The final saved removal/user-edit state is independently reopened in phase 5.

Exact package: SHA256
`a18bc013d93c2815d4e929e814e9ec18248eb357c7c185f060ac1ffbed5cdd98`.
Packaged JAR: SHA256
`f7502b8a0c7d80c0e171b5f77ca51f08e9f4f190e680217c1c99e40923c8f9f7`.
All 55 installed package members match that ZIP. See qualification-manifest.json,
environment.json, full-4 XML, focused-9 XML and retained installed run 7.
Earlier 531-test and resumed 563/566-test passes remain tied to their own revisions.

| Original requested outcome | Current evidence and remaining requirement |
| --- | --- |
| Reproduce actual canonical root failure | Exact missing-site failure reproduced at unchanged canonicalResult assertion; baseline log/XML retained. All starting source/artifact identities matched handoff. |
| Supported normal canonical and execution entry paths | Installed dynamic fixup supports both. Registry explicitly pairs identities; either path rejects either member's drift. Canonical full continuation uses local CFG anchors and owned terminal representation, while alias follows mapped listing. No custom decompile script or reflection required. |
| Physical target/continuation, stack/register/flags | Native CALL endpoints checked; raw-vs-injected conditional branch/RET tests compare A/F/BC/DE/HL/SP/PC and hardware pushed word with two live external return words. Ordered inline physical reads retained. Finite continuation segments retain physical identities; same-interface mutation changes actual target and c200 value after public reapplication. |
| Canonical mutation/reapplication and reopen | Both entry paths reject changed consumed payload and then recover in the same DecompInterface without test cache flush. Installed separate-process reopen and annotated reapply check canonical and alias paths. |
| Current installed lifecycle and retired views | Six phases pass: prepared fresh application, independent reopen, annotated repair/reapply, edit/save, edited reopen/removal, final removed-state reopen. Six retired spaces remain mapped/non-executable with no instructions/functions; final user flow/comment edits survive. Ordinary analysis stays enabled. |
| Strict log accounting | Initial script compile failure, view-refinement failure, concurrency warning and native payload-decoding failure retained. Campaign 7 has zero unexpected ERROR/WARN; expected stale rejection is exact and phase-specific. No queue/analyzer disabled. |
| Initial conflicting CALL endpoints and legacy refs | Wrong CALL_OVERRIDE, wrong primary CALL and real legacy far-call supplemental endpoint reject before mutation; existing knowledge preserved. Automatic conversion of legacy annotations is not implemented. Public removal and fresh review remain explicit operations, not silently authorized normalization. |
| Later ROM-window crossing | Same-space continuation 3ffe followed by banked 4000 now gets a proven view and works through both native entry paths. Branch/conditional RET cases and split-block later-byte permissions tested. |
| Nested false noReturn/CALL_RETURN metadata | Matched ordinary RET witness authorizes only exact site/target repairs, exposed in public and saved inventory. Negative unrelated overrides remain rejected. Installed repair/inventory survives analysis and separate-process reopen. |
| Restoring/nonrestoring/constant/true-nonreturn/nonlocal combinations | Expanded installed matrix passes physical/native/frame/flag checks for these finite combinations, including nested configured helpers and nested ordinary returning callee. Known nonlocal CPU/physical/SP state is preserved; unknown/nonrepresentable exits remain required unresolved work. |
| Native compatibility, premises and dependency invalidation | Strict parsing/incoming premises, raw effect proof, native vetoes, paired live annotations, consumed memory/context/contracts/types, nested configuration isolation and return witnesses preserved. Concurrent mutation causes complete bounded revalidation, not weakened dependency checks. |
| Discovery assumptions | Tests and installed pre-prepare check explicitly reject missing helper/callee Instructions. Prepared instruction fixtures and missing-Function creation are distinguished from genuinely fresh instruction discovery. Fresh-import closure through missing instructions remains unimplemented. |
| Compatibility and saved old work | No decoder/register/compiler/mapping/native dependency change. Old executable registry versions reject; synthetic v3-record public remove/review/reapply passes. This does not establish actual archived-v3 Program migration. Older view stamps retain uncertain work conservatively; no new cleanup authority inferred. |
| Normal Decompiler-window verification | Six canonical/alias windows match retained installed C after normal Symbol Tree navigation; physical callees verified in Listing. Normal CodeBrowser close/reopen rechecked canonical4200 and alias4800. Exact stock launcher/install/native identity and jpackage runtime hashes recorded. See gui-verification.md for screenshots, review and scope limits. |
| Full provider/package/build-input qualification | Current full-4 567/567, focused-9 94/94, lint/build and build-input pass. Exact installed package member verification and all-six-phase campaign pass. Platform tuple is pinned Ghidra 12.1.3 / JDK 21.0.12.1/custom mac_arm_64 native companion; no stock native or other-platform claim. |
| Renewed independent review | Separate adversarial and correctness workers reviewed/verified bounded surfaces. Paired invalidation, missing nested inventory and wrong-operand ownership findings have source fixes and regressions. Review cannot certify remaining original requirements. |
| General same-CPU/different-bank execution | **Still required and unresolved.** Current view cannot assign two physical sources to overlapping CPU ranges; canonical lowering is still conditioned on that validated finite view. A state-sensitive native representation/proof is needed; safe rejection is not support. |
| Later continuation calls/mapper writes and wider effects | **Still required and unresolved.** Current continuation walker rejects later interprocedural/indirect flow and mapper writes rather than proving their subsequent physical states. Required broader mapper/ABI/RAM-image/asynchronous and all-input behavior remains outside the finite candidate's proof, not waived. |

The locked-desktop GUI blocker is resolved for the finite comparison cases. The concrete
implementation blockers are the current finite execution view's inability to
represent same-CPU competing physical paths, continuation traversal's missing
later-call/mapper effect propagation, and missing-instruction discovery. Resolving
these requires executable integration and their original acceptance tests; this
receipt does not narrow those obligations or declare the banking architecture done.

## Retained native C diagnostics

The successful installed process logs have no unexpected WARN/ERROR. The retained
C is not warning-free: Ghidra reports functions replaced by their installed
injections, inlined-function metadata on nested roots, and removal of unreachable
blocks at canonical/nonlocal call sites. These comments remain visible. The latter
are the obsolete original terminal/branch operations displaced by the complete
injected CFG; physical CALL, return/exit and side-effect checks are retained.
A scan of every retained final C file found no bad-instruction, truncation,
halt_baddata, unresolved or unimplemented diagnostic. The independent artifact
review separately reclassified all process logs and checked saved inventories.

The subsequent GUI-only turn changed evidence and source roadmap status, not
provider code or the qualified archive. The source roadmap's GUI status now
postdates the packaged roadmap; package SHA256 and all installed bytes remain
those recorded above. No unrelated build or native campaign was rerun for this
verification-only documentation update.
