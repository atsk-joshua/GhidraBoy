# GhidraBoy debugger

Optional Game Boy/Game Boy Color debugging through Trace RMI: physical bank mappings, breakpoints, CPU access watches, immutable captured history, checkpoints, recoverable edits and an SDL game window. The existing backend is SameBoy. Further backends are under development and are not yet supported.

The root GhidraBoy project is the sole static SM83 provider. This module owns execution, trace publication and generic debugging services. Optional GhiBW3 supplies game-specific decoders and research views through the profile/action APIs.

With `GHIDRA_INSTALL_DIR` pointing to Ghidra 12.1.3 and `JAVA_HOME` to JDK 21, build both Java extensions from the repository root:

```sh
./gradlew -PwithDebugger=true integrationArtifacts
```

`build/integration/artifacts.json` identifies the actual provider/debugger JARs and extension archives by relative path and SHA256. No neighboring GhiGBC checkout is required. Omit `-PwithDebugger` for the static-only build, which does not configure debugger dependencies. `debugger/scripts/build_extension.sh` delegates to the root wrapper.

The native runtime and packaged installation are separate from the Java extension build. From the repository root:

```sh
python3 debugger/scripts/bootstrap.py --ghidra "$GHIDRA_INSTALL_DIR"
bash debugger/scripts/build_native.sh
bash debugger/scripts/build_extension.sh
python3 debugger/scripts/package_candidate.py --ghidra "$GHIDRA_INSTALL_DIR" --jdk "$JAVA_HOME" --platform macos-arm64
```

Use `linux-x86_64` on the corresponding build/runtime lane. Bootstrap obtains the pinned SameBoy source and assembler tools from `tools/dependencies.json`, verifies the exact source patch, and prepares a pipless environment with the existing Python. `--download-cache` optionally supplies already downloaded archives; their hashes are still checked. Gradle uses the root wrapper. No sibling source checkout is used by the generic build.

The packager consumes `build/integration/artifacts.json` and refuses stale or missing outputs. Archives appear in the root `dist/` directory. The old `package.py` and `package_deck_handoff.py` commands delegate to this same packager. Runtime requirements remain existing Python 3.9+ on the declared macOS arm64/Linux x86-64 lanes. See [runtime limits](docs/SUPPORT.md), [mapping contract](docs/contracts/mapping.md), [profile API](docs/contracts/profiles.md), and [installation/rollback](docs/INSTALL.md). Qualification of each lane remains tracked in the [integration ledger](../docs/integration/progress.md).

Build-input checks are separate from runtime-host tests:

```sh
PYTHONPATH=debugger:debugger/python python3 -m unittest discover -s debugger/tests/build_tools -v
bash debugger/scripts/test_native.sh
```

Native/Python tests are under `debugger/tests`; real installed Trace RMI tests are under `debugger/tests/ghidra`. Release qualification additionally requires isolated installation/recovery, saved-work compatibility and actual claimed-platform GUI/device checks. The old repository and release archives remain available for rollback and source provenance.

Credit: SameBoy by LIJI32 and contributors; GhidraBoy by Joonas Javanainen/Gekkio and contributors; Ghidra by the NSA; RGBDS contributors. Preserve the component notices in `LICENSES`. Private ROMs, Programs and checkpoints are excluded from distributions.
