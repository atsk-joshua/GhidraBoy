# Current execution directive: documentation-only pause

The user stopped CUA execution and requested an accurate plan/docs/handoff refresh.
Do not open more apps/browsers, launch GUI probes, or resume the old timed observer.
See [handoff](agent-handoff.md) and [state](handoff-state.json).

Done: runtime code `1fce58f`, reproducible six packages/source archive, scoped
Mac/Linux component checks, native/static/hardware/profile/research/consumer
evidence, both final 30-minute soaks and controlled/all-retained latency budgets.
GhiGBC duplicate implementation cutover and private GhiBW3 commits remain intact.

New unresolved issues: full-tool timeout/disposal errors, stale trace-manager
coordinates, logged service exceptions that the uncaught collector does not count,
and unreliable CUA app/window/keyboard targeting. Exact original teardown
exception not independently reproduced; no proposed cleanup fix has been applied.
Broader lifecycle gates are reopened; no physical GUI gate or release PASS.

Before the user killed the sessions, two normal Ghidra JVMs were found: intended patched
12.1.3 PID47285 and unintended old12.1.2 PID47493. All sessions are assistant-created
according to the user. Revalidate identity before cleanup/attachment; do not start
another. Use one persistent configured session/project on an execution resume.
VNC containers are stopped. Chrome connection concern remains unresolved; only
in-app noVNC navigation was intentionally performed. No Chrome/VNC use by default.

The prior license-only blocker is stale: the intended home has accepted agreement
and disabled-tips preferences. Last GUI view is not proven to belong to the
candidate. All investigation workers are complete; no background validation jobs
remain ; the user reports killing the normal GUI processes. Physical Deck stays deferred.
