# Working in GhidraBoy

GhidraBoy owns generic Game Boy/Game Boy Color static tooling and its optional
debugger. The root project is the sole SM83 provider. Private game studies own
their ROMs, annotations, exact-game conventions and research artifacts.

## Start with current state

- Read the current user task and inspect git status before editing. Current user
  instructions take precedence over repository guidance; keep work within the
  authorized task scope.
- Preserve unrelated staged, unstaged and untracked work. Do not reset or
  overwrite another worker's changes.
- Do not prefix branches with `codex/`.
- Use [docs/README.md](docs/README.md) to find the current documentation authority.
- For priorities and accepted checkpoints, read [SA status](docs/sa/IMPLEMENTATION-STATUS.md),
  [the retained plan](docs/sa/IMPLEMENTATION-PLAN.md), [decision gates](docs/sa/DECISION-GATES.md)
  and [docs/roadmap.md](docs/roadmap.md). Do not schedule work from historical handoffs.
- This Git checkout is the sole maintained development source. Workspace copies
  are evidence/runtime/cache or inactive recovery, never a second source authority.
  Keep detailed execution receipts outside the source tree; use the [evidence index](docs/sa/evidence-index.json).
- Follow the [cutover and future main-history guardrail](docs/sa/REPO-CUTOVER.md).
  Development-branch cleanup does not authorize importing historical evidence ancestry into main.
- For static implementation, read
  [the implementation handoff](docs/static-analysis-implementation.md) and the
  relevant requirements in [the specification](docs/static-analysis-spec.md).
- Before processor-specification work, read
  [data/languages/AGENTS.md](data/languages/AGENTS.md). Before debugger work, read
  [debugger/AGENTS.md](debugger/AGENTS.md), even when working from the root.
  For cross-area changes, read both scoped files.
- Source describes implemented behavior; specifications describe required
  behavior. Investigate discrepancies instead of silently choosing one.
- Historical receipts and handoffs describe their recorded artifacts.
  Revalidate them before using them as evidence for the current checkout.

## Execution and coordination

- Complete the requested work through appropriate verification. Resolve routine,
  reversible implementation choices without repeatedly asking permission.
- Keep research-only and planning-only tasks within that scope.
- For substantial work with independent subtasks, use subagents when available.
  Delegate concrete implementation, investigation or independent review work.
- Give each implementation worker nonoverlapping file ownership. Coordinate
  shared interfaces before edits and integrate dependent changes sequentially.
- Keep useful implementation or integration work with the primary agent.
  Use inherited model/settings unless the task specifies otherwise.
- Coordinate builds and tests that share output directories or installations;
  parallel agents must not race on the same generated artifacts or Program.
- The primary agent owns integration, verification and the final report.
  Subagent conclusions require supporting evidence.
- Do not create separate user-visible tasks for internal subtasks.

## Correctness requirements

- Preserve the distinction between CPU addresses, physical storage, execution
  views and file offsets. Respect mapper state, aliases and access kind.
- Keep original bytes, patches and initialized/replaced RAM images distinct.
- Preserve 16-bit CPU arithmetic and pointer semantics even when an analysis
  representation uses wider physical addresses.
- Keep instruction effects, validated overrides, call conventions and
  decompiler transformations explicit and consistent.
- Treat unknown state as unknown. Observed behavior is not proof of all paths;
  a completed bounded analysis is not proof of whole-ROM completeness.
- Do not suppress warnings, invent prototypes or bounds, make ROM writable,
  truncate bodies or remove failed entries merely to improve results.
- Fingerprint every consumed analysis dependency and reject stale results.
  Generated references must not become circular evidence.
- Correct invalid annotations through reviewable migrations with explicit
  provenance, rollback and saved-work verification.

## Implementation boundaries

- Keep static-only builds independent of Python, SDL, emulator libraries and
  neighboring private checkouts.
- Use supported Ghidra APIs where they express the required behavior.
  Prototype uncertain mechanisms before applying them broadly.
- Changes to language, constructors, context/register layout, compiler IDs,
  mapping schemas or persisted records require an explicit compatibility
  decision and the appropriate migration checks.
- Preserve dependency pins, notices and attribution. Record evidence for
  dependency changes.
- Keep private ROMs, Programs, traces, checkpoints and game-derived artifacts
  out of generic tests and distributions. Prefer self-authored fixtures.
- Use disposable copies for installed, migration and GUI experiments.
  Verify process and installation identity; do not disturb unrelated sessions.
- Publishing or modifying active installations must be authorized by the task.

## Validation

All commands and plain paths below are relative to the repository root.

- Follow [building](docs/building.md) and [validation](docs/validation.md). Use
  the checked-in Gradle wrapper, JDK 21 and the pinned Ghidra distribution.
- Run focused tests that reproduce the changed behavior, then the appropriate
  broader checks. Include new test classes in focused test selections.
- For provider implementation changes, the standard broader command is:
  `./gradlew test ktlintCheck buildExtension`
- Choose Python/tooling suites through `tools/check.py` for the affected area.
- Verify raw instruction semantics separately from injected/high p-code,
  native decompiler output and persisted Program state.
- Persisted behavior changes need actual save/reopen checks. Fresh import
  alone does not establish compatibility.
- Documentation-only changes need relevant link, payload and consistency
  checks; do not launch an unrelated native or GUI campaign.
- Record exact source/dependency/fixture identities, commands and outcomes.
  Report failures, skips and unrun requirements separately.

## Documentation and roadmap

- Update the relevant contract, user documentation and tests when behavior
  changes. Keep planned features distinct from implemented capabilities.
- Record architectural decisions in `docs/decisions/` with alternatives,
  evidence, migration implications and remaining obligations.
- Update roadmap status only for work actually completed and verified.
- Retain roadmap items. Priorities may change; replacements must identify the
  old item, replacement IDs and any remaining scope.
- Preserve historical receipts. New artifacts require new evidence.
- Keep transient status, test counts, local paths and active-session details
  out of AGENTS.md.

## Code Review Rules

Flag unsound certainty, inconsistent raw/overridden flow, missing invalidation,
incorrect physical identity, lost call/stack/flag effects, unsafe annotation
migration, and tests whose expectations merely repeat the implementation.

For semantic, persistence or runtime changes, obtain independent review where
practical. The final report must explain behavior changes, verification,
limitations and the next unresolved obligation.
