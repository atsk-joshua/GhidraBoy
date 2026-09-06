# GhidraBoy debugger

Optional Game Boy/Game Boy Color debugging through Trace RMI: physical bank mappings, breakpoints, CPU access watches, immutable captured history, checkpoints, recoverable edits and an SDL game window. The existing backend is SameBoy. Further backends are under development and are not yet supported.

The root GhidraBoy project is the sole static SM83 provider. This module owns execution, trace publication and generic debugging services. Optional GhiBW3 supplies game-specific decoders and research views through the profile/action APIs.

With `GHIDRA_INSTALL_DIR` pointing to Ghidra 12.1.3 and `JAVA_HOME` to JDK 21, build both Java extensions from the repository root:

```sh
./gradlew -PwithDebugger=true integrationArtifacts
```

`build/integration/artifacts.json` identifies the actual provider/debugger JARs and extension archives by relative path and SHA256. No neighboring GhiGBC checkout is required. Omit `-PwithDebugger` for the static-only build, which does not configure debugger dependencies. `debugger/scripts/build_extension.sh` delegates to the root wrapper.

The native runtime and packaged installation are separate from the Java extension build. Their consolidation and acceptance are tracked in the [integration ledger](../docs/integration/progress.md); existing imported scripts remain available during that work. Runtime requirements remain existing Python 3.9+ on the declared macOS arm64/Linux x86-64 lanes. See [runtime limits](docs/SUPPORT.md), [mapping contract](docs/contracts/mapping.md), [profile API](docs/contracts/profiles.md), and [installation/rollback](docs/INSTALL.md).

Native/Python tests are under `debugger/tests`; real installed Trace RMI tests are under `debugger/tests/ghidra`. Release qualification additionally requires isolated installation/recovery, saved-work compatibility and actual claimed-platform GUI/device checks. The old repository and release archives remain available for rollback and source provenance.

Credit: SameBoy by LIJI32 and contributors; GhidraBoy by Joonas Javanainen/Gekkio and contributors; Ghidra by the NSA; RGBDS contributors. Preserve the component notices in `LICENSES`. Private ROMs, Programs and checkpoints are excluded from distributions.
