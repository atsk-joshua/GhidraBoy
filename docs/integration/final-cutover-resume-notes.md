# GhiGBC local compatibility cutover

Local changes only; no commits, branch changes, publication, archival, installation, or history removal. Canonical source repository was not edited. All 62 changed tracked code paths were checked against the audited source SHA-256 before mutation; hashes were written to the machine receipt before removal/replacement. The resolver is the sole new code file.

## Result

- `_ghidraboy_compat.py` resolves `GHIDRABOY_ROOT` or sibling `GhidraBoy`, validates integrated checkout/entry points, and routes commands with argument and exit status preservation.
- `python/ghigbc/__init__.py` initializes the canonical package and sets its canonical package search path, preserving `ghigbc` module/class names. Old seven implementation/resource files were removed after replacement.
- Public shell/Python commands, old generic Python tests, and four generic Java scripts retain original filenames as thin delegates. Imported Python delegates retain legacy module locations for unittest discovery while functions hold canonical globals/resource paths. Launcher metadata remains discoverable; execution reaches the canonical launcher. Existing game delegates and ProgramKnowledge export wrapper remain unchanged.
- The audit map mislabeled `scripts/install_legacy_v2.py` as an existing thin delegate. With coordinator approval it now delegates to the canonical schema-2 installer/rollback reader; `--help` confirms its API remains available.
- Old Gradle task aliases `buildExtension`, `build`, and `assemble` invoke canonical `integrationArtifacts`; `clean` invokes canonical `:GhiGBC:clean`. The old build has no extension packaging plugin and no static-provider implementation. Settings retain only the compatibility project name. Obsolete Module.manifest and extension.properties were removed after successful delegated build.
- Duplicate native C/header/patch, generic Java extension implementations, dependency lock, and generic test fixture/license copies were removed. Generic CI is disabled except for a manually triggered migration notice.

## Validation

22 focused checks pass, plus three Gradle checks. Old package imports resolve canonical backend/agent/native/profile/mapping/dispatch/display files; `python -m ghigbc.agent --help` succeeds. Dispatch/mapping/runtime test suites pass through old test paths; discovery loads all 46 legacy test cases without import failures. Runtime helper API import and legacy rollback help succeed. All shell delegates (including launcher) plus Python command delegates preserve spaced/metacharacter arguments and exit 23. Explicit and missing canonical-root overrides, missing target diagnostics, and both canonical and legacy checkout paths with spaces are covered. Four Java delegates compile against the selected Ghidra distribution.

`bash scripts/build_extension.sh --dry-run` reaches actual canonical tasks `:zip`, `:GhiGBC:buildExtension`, and `:integrationArtifacts`, all SKIPPED. Old direct Gradle `buildExtension --dry-run` succeeds (Gradle skips the Exec task by design). Actual old direct Gradle `buildExtension` succeeds and invokes canonical integrationArtifacts. Initial sandbox socket denial was resolved by approved local Gradle verification outside the sandbox. `git diff --check` passes.

## Preserved and limitations

The three historical game-specific Java harnesses remain byte-for-byte unchanged for coordinator reconciliation. No docs/README were edited by this worker. Existing untracked docs/STUDENT_GUIDE.md and output/, repository history/refs/tags, old build/dist/.deps artifacts, installed runtimes, checkpoints, rollback journals, and baseline bundles were preserved. Compatibility entry points are marked for retention for at least two releases.

Java delegates were compiled but no new Java UI/headless session was run; full native/UI suites were not rerun. This cutover establishes routing and does not assert new emulator or game outcomes.

Machine receipt: `/private/tmp/ghidraboy-ghigbc-cutover-receipt.json`. Focused logs: `/private/tmp/ghidraboy-ghigbc-checks/`. Gradle logs: `/private/tmp/ghidraboy-ghigbc-shell-build-dryrun.log`, `/private/tmp/ghidraboy-ghigbc-gradle-dryrun.log`, `/private/tmp/ghidraboy-ghigbc-gradle-build.log`.
