# Validation suites and authority

Product capabilities and supported workflows are defined by the root README,
[user workflows](user-workflows.md), and the [GhidraBoy debugger support contract](../debugger/docs/SUPPORT.md).
Engineering qualification applies to exact source, build and package identities;
[historical modernization evidence](modernization-evidence.md) and
[integration receipts](sa/evidence-index.json#docs/integration/final-qualification.md) are not fresh results
for this checkout. Game-specific corpus evidence does not substitute for
generic regressions or establish whole-ROM semantic correctness.

The current [roadmap](roadmap.md) makes static accuracy the first development
priority. The [static acceptance matrix](static-analysis-spec.md#acceptance-matrix)
adds required future semantic, discovery, dependency and migration gates. Existing
commands below do not yet implement that entire matrix; their passing results
must not be relabeled as SA-07 completion. Existing integration, GUI, platform and
release requirements remain retained, with historical receipts unchanged.

| Suite | Command | Requirements / scope |
| --- | --- | --- |
| Aggregate inexpensive checks | `python3 tools/check.py` | Python standard library, Git, shell syntax; no installation or ROM |
| Build-input contract | `python3 tools/check.py --suite build-inputs` | Also run by CI before the Ghidra build |
| Build/qualification tooling | `python3 tools/check.py --suite tools` | Synthetic updater and evidence-comparator regressions; actual Java companion test requires DEBUGGER_JAVA_PACKAGE and DEBUGGER_JAVA_PACKAGE_SHA256; otherwise skipped |
| Pure debugger contracts | `python3 tools/check.py --suite debugger-pure` | Dispatch, mapping, interpreter selection, package selection, collection |
| Static provider build/tests | `./gradlew test buildExtension` | Selected Ghidra 12.1.3 and JDK 21 |
| Integrated extensions | `./gradlew -PwithDebugger=true integrationArtifacts` | Same runtime; writes verified build/integration/artifacts.json |
| Native adapter execution | `cd debugger && bash scripts/test_native.sh` | Prepared native dependencies and synthetic ROMs; separate explicit campaign |
| Installed/migration | `python3 tools/run_validation.py --help` | Explicit copied installed/legacy distributions and fixtures; CI provisions these |
| Interactive acceptance | `debugger/scripts/test_ui_actions.sh` | Explicit GUI campaign; never implied by inexpensive checks |

The original command remains supported:
`PYTHONPATH=debugger:debugger/python python3 -m unittest discover -s debugger/tests/build_tools -v`.
The aggregate deliberately does not indiscriminately discover native debugger
modules or import Trace RMI modules requiring an installed Python environment.

`debugger/scripts/package_candidate.py` accepts `--stage-root` and `--output-dir`
to keep a new composition separate from prior artifacts. It refuses existing
stages and archives. Package manifests identify their exact sources, dependencies
and payloads. An integrity-only historical audit is not current-source qualification.

The historical cleanup retained SM83 language version 1.0, `SM83:LE:16:default`, the default
compiler identity and all added compiler profiles. Saved-Program migration and
saved-instruction decoding are separate from the runtime support policy:
**current builds require Ghidra 12.1.3 / JDK 21**. No broader runtime support is
claimed. No provider semantics changed in this cleanup, and installed migration,
GUI/device and full decompilation acceptance were not rerun.

The current experimental stock transport uses language 2.0. Its full stock test
checkpoint remains failed, and normal-window qualification is blocked. See the
[transport decision](decisions/stock-ghidra-transport.md) and [current status](sa/IMPLEMENTATION-STATUS.md).

Historical engineering reports are preserved externally through the [evidence index](sa/evidence-index.json); the static extension ships the explicit user documentation allowlist in `packaging/static-docs.txt`. Packaged documentation links must resolve within the extracted payload.

See the [retained debugger identity inventory](debugger-identities.md) before proposing an identity migration.

Retained new captures and execution receipts use an explicit external work/output directory. Debugger Java capture writers and result collectors honor `GBC_EVIDENCE_DIR` (use an absolute path); their default is ignored `debugger/.local/results` from a source checkout or `.local/results` in an extracted package. UI phase markers, partial logs and growth JSON use that same directory. Generated collection ZIPs stay in `.local/results`. Ordinary ignored Gradle output remains in `build/`. Never place new run output into tracked documentation; maintained fixtures and design inputs under `docs/evidence` remain visible to Git.
