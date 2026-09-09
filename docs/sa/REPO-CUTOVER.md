# Repository cutover and history policy

The normal GhidraBoy Git checkout on `integrate-ghigbc` is the sole maintained development source. The former SA workspace is evidence, disposable runtime/cache and local operational navigation. A preserved source directory pending retirement is inactive and read-only; it must not receive development or serve as a build dependency. There is no source compatibility symlink.

The [implementation plan](IMPLEMENTATION-PLAN.md), [decision gates](DECISION-GATES.md) and [implementation status](IMPLEMENTATION-STATUS.md) are tracked project authority. Workspace plan files are pointers. Current architecture, contracts, fixtures, checkers, native patch definitions, dependency pins and optional debugger remain maintained in Git. The external reconciliation/disposition inventory accounts for accepted inputs, checkout inputs and historical artifacts by exact content identity and retaining commit.

The [evidence index](evidence-index.json) identifies accepted evidence, source manifests, cutover commits/trees and recovery artifacts. Resolve external relative locations under the selected SA workspace. Detailed run output, inventories, source recovery archives and new execution receipts stay outside the source tree. A same-disk duplicate is not an independent backup. Permanent old-source retirement requires verified recovery, reconciliation, final validation, writer quiescence and independent backup; until then its preservation is explicit and retirement is blocked.

## Future main-history guardrail

This cutover repairs the maintained tree on `integrate-ghigbc`; it does not authorize importing the branch’s historical graph into `main`. Historical evidence blobs remain in earlier commits. Current-tree cleanup, future main ancestry and object-store size are separate concerns; this operation does not purge history or claim a clean object store.

Do not merge, fast-forward, reset or otherwise advance `main` as part of this cutover. An ordinary whole-branch merge or fast-forward that imports unwanted historical evidence ancestry is not the future integration plan. Eventual main integration requires a separately reviewed curated/squash/snapshot strategy that preserves validated maintained content, reconciles destination-side changes and retains provenance. The exact method is undecided and outside REPO-CUTOVER.

Preserve development history/refs in the identified recovery archives and all-refs bundle. Do not rewrite history, delete refs, prune objects/reflogs, squash the distinct cutover commits or invent historical W1/W2/W3 commits. The exact cutover checkpoint is recorded by a later documentation-only index update and external report, avoiding a self-referential commit hash.

This guardrail is a gate before main integration, not an added prerequisite for authorized W4/G3 development on `integrate-ghigbc`. After master acceptance of the cutover, later work may be authorized without first deciding main integration. Recording a checkpoint does not freeze the development branch indefinitely. This execution stops after delivering the cutover report.
