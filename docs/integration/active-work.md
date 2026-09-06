# Current execution / ownership checkpoint

See [handoff](agent-handoff.md) and [state snapshot](handoff-state.json) first.
The implementation is committed through `1518f02`. All implementation/platform
workers finished; final consumer refresh never ran because its agent hit a usage
limit. Do not depend on old agent contexts or assume that attempt is a test result.

## Existing work that must not be duplicated

Both final 30-minute measurement phases and their bounded budget assessments
completed during this handoff. Original tool IDs are no longer usable; SameBoy
subsequently completed idle/cleanup and all four recorded process IDs were absent.
Independent harness exit statuses remain unavailable; the mGBA marker does not
waive its uncaught AWT errors.
Exact paths/PIDs/timestamps and immutable copies are in the state JSON. Collect
rather than restart. mGBA already has uncaught closed-trace AWT errors; neither a
completed progress counter nor the observed terminal PASS marker settles that failure.

## Suggested next bounded team

| Lane | Ownership | First deliverable |
| --- | --- | --- |
| Coordinator | Shared ledger/status/handoff, source/artifact freeze, reviews and sole physical CUA control | Collect jobs; explicit remaining-gate plan and final evidence decisions |
| Lifecycle worker | Assigned trace/lifecycle production files and dedicated tests only | Reproducer/cause/fix for mGBA ClosedException plus trustworthy uncaught-error accounting |
| Consumer worker | GhiBW3 build/link/parity checks and its separate receipt | Final tuple consumer proof or precise blocker, without touching unrelated files |
| Evidence auditor | Read-only source/artifact/gate audit; separate proposed reconciliation | Which existing receipts satisfy each exit condition and which checks actually remain |

Use fresh workers with `fork_turns="none"` and self-contained bounded packets. At
most three workers plus coordinator; one owner per writable file set. Aim for a
small initial context (specific sections/files), not full plan/history dumps.
Each worker ends one concrete chunk with a concise result and durable notes. Send
follow-ups only while its context remains small and the work is closely related.
Never let separate agents control the same UI or shared packaging staging area.

Serialize packagers: `debugger/build/candidate-test-classes` is shared. Separate
runtime extractions, user homes and evidence directories for test lanes. Run long
jobs through wrappers that persist exit status and exact commands; yielded or
lost tool handles must not cause duplicate executions. Preserve original budgets.

Final Mac/Linux package suites and paired latency pass at their named scopes;
final lifecycle/resource acceptance, final physical GUI, consumer refresh and
release/cutover reconciliation remain. Physical Steam Deck checks are explicitly
deferred. No remote publication/archival or quota reset is authorized.
