# Integrated debugger migration and rollback

Generic development now needs only GhidraBoy. GhiBW3 is an optional additional
checkout for exact-revision game research; the old GhiGBC checkout is historical.
Keep old tags, source bundles, checkpoint files and distributions intact.

## Build and select a runtime

Select Ghidra 12.1.3 and Java 21 with `GHIDRA_INSTALL_DIR` and `JAVA_HOME`.
The default `./gradlew check buildExtension` builds the static provider without
emulator/Python/SDL dependencies. Add `-PwithDebugger=true integrationArtifacts`
to generate both Java extensions and their verified artifact manifest.

Follow `debugger/README.md` for the selected native build. Package with
`debugger/scripts/package_candidate.py --backend sameboy`, `--backend mgba`, or
`--backend both`, plus the documented platform/Ghidra/JDK arguments. The default
remains SameBoy. An unselected backend's library and boot assets are not required.

## Upgrade an installation

1. Save Programs and traces, stop targets, and close the selected Ghidra instance.
2. Extract the exact platform candidate into a new directory. Preserve its archive
   and SHA256; never install over an old extracted directory.
3. Run `bash Setup.sh --ghidra /path/to/ghidra --java-home /path/to/jdk`.
   Use `--user-home /path/to/isolated/home` for validation. Existing Python 3.9+
   is checked and isolated; no system interpreter replacement is required.
4. Retain the returned rollback manifest and any interrupted-operation journal.
   Restart Ghidra. Installed launcher offers match the selected runtime backends.
5. Validate the extracted package with `bash Validate.sh`. A combined package can
   also run `bash scripts/test_observation_report.sh` and
   `bash scripts/test_research_experiment.sh` without source or compilation tools.

To change backend composition, install the corresponding selected-backend package
through the same transaction. Do not manually delete managed libraries or edit
the runtime manifest. Static Programs and saved generic trace history remain
independent of the selected emulator.

## Recover or roll back

Use the exact journal from a failed operation with
`python3 scripts/install.py --recover /path/to/journal.json`.
Use the saved rollback manifest with
`python3 scripts/install.py --rollback /path/to/manifest.json`.
Provide the same Ghidra/JDK/user-home arguments used for installation when needed.
These transactions restore recorded bytes and preserve user-modified files rather
than silently overwriting them. Native decompiler executable and identity marker
are a separate pinned dependency; use its documented copy-only updater/rollback.

Old compatible CGB SameBoy schema-2 checkpoints are tested through the new reader.
New pending-fetch checkpoints require that reader; an older runtime cannot be
assumed to resume them. mGBA observations can be reopened, but its experimental
tier does not advertise checkpoint resume or state conversion.

Public extension IDs, Java action/profile APIs, Python compatibility imports and
legacy delegates remain. Delegates stay for at least two supported release cycles
and until known consumers migrate; removal requires a documented incompatible
change and reader/migration tests. No remote publication or repository archival
is implied by this local cutover.

Physical Steam Deck verification is explicitly deferred until the rest of the
integration is solid. Linux virtual-display acceptance does not replace it.
