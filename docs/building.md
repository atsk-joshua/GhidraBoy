# Building and packaging

Use Ghidra **12.1.3**, JDK **21** and the checked-in Gradle wrapper. Pinned inputs
are recorded in [tools/dependencies.json](../tools/dependencies.json). Set
`GHIDRA_INSTALL_DIR` to the selected binary distribution and `JAVA_HOME` to JDK 21.
The static provider requires no emulator, Python runtime or SDL.

From the repository root:

```sh
./gradlew buildExtension
./gradlew -PwithDebugger=true integrationArtifacts
```

The first command builds the static extension in `build/distributions/`.
The second also builds the debugger extension and writes verified JAR/archive
paths and SHA256 hashes to `build/integration/artifacts.json`. The property
`-Pghidra.dir=/path/to/ghidra` remains an alternative to GHIDRA_INSTALL_DIR.
Omitting `-PwithDebugger` keeps debugger dependencies out of the static build.

For the SameBoy native runtime and generic package:

```sh
python3 debugger/scripts/bootstrap.py --ghidra "$GHIDRA_INSTALL_DIR"
bash debugger/scripts/build_native.sh
python3 debugger/scripts/package_candidate.py \
  --ghidra "$GHIDRA_INSTALL_DIR" --jdk "$JAVA_HOME" --platform macos-arm64 \
  --stage-root build/new-package-stage --output-dir dist/new-package
```

Use `linux-x86_64` with matching Linux native outputs. Bootstrap verifies pinned
source/patch/tool identities; `--download-cache` can select previously downloaded
archives. It uses an existing Python interpreter and prepares an isolated
runtime environment. It does not replace the global Python installation.

The default backend is SameBoy. Select `--backend mgba` or `--backend both` after
following the [mGBA source/rebuild instructions](../debugger/docs/MGBA_SOURCE.md).
`--native-dir` selects verified outputs for the requested platform. The old
`package.py` and `package_deck_handoff.py` commands delegate to this packager.

The debugger requires both the native decompiler and Java register-lifetime
companions described in [installation](../debugger/docs/INSTALL.md). Supply
`--debugger-java-package /exact/debugger-java-dependency.zip` and
`--debugger-java-package-sha256 RECORDED_SHA256` to include the verified Java
companion. Without those options it must be supplied separately at installation.
Native decompiler companion archives remain separately selected platform artifacts.

Existing package stages and archives are refused. Choose new paths to preserve
previous observations. The manifest records source/dependency/payload identities;
rebuilding after source edits produces a new artifact requiring its own checks.
For selectable tests and qualification requirements, use [validation](validation.md).
