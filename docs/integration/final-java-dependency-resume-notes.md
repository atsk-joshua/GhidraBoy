# Debugger Java dependency delivery — PASS

Implemented in `/Users/joshuahansen/dev/GhidraBoy` without commits or runtime packaging runs:

- `tools/debugger_dependency_update.py`: standalone offline build, copy-only install/verify/rollback, exact reviewed baseline/source/patch/output hashes, exclusive output publication, symlink/overlap/existing-output refusal. Both mutation actions write only a new bundle containing `distribution/` and receipt; source is never modified.
- `tools/test_debugger_dependency_update.py`: eight tests, including actual pinned companion, corruption, mismatched inputs, copy/rollback source preservation, output races, links and runtime guards.
- `tools/dependencies.json`: separate `debuggerJavaPatch` entry, version `12.1.3+ghidraboy.register-lifetime.1`; native `switch-recovery.2` entry unchanged.
- `debugger/scripts/build_inputs.py`, `install.py`, `doctor.py`: runtime Java identity/JAR check; installer refuses before creating a home; doctor readiness requires the Java dependency; refusal gives copy-updater command.
- `debugger/scripts/package_candidate.py`: declares `debugger_java`, includes standalone updater, optionally embeds verified Java companion via paired flags below, includes `shared_profile_fixture.py` universally and `test_mapper_geometry.py` only for SameBoy compositions, as coordinator requested.
- `debugger/scripts/test_installer.py`: narrow real-package installer assertions for missing Java marker and corrupted JAR.

## Reproducibility and safety evidence

Two independent offline builds with `javac 21.0.12.1` produced byte-identical companion ZIPs:

`/private/tmp/ghidraboy-java-dependency/build-1/debugger-java-dependency.zip`

`/private/tmp/ghidraboy-java-dependency/build-2/debugger-java-dependency.zip`

SHA256: `9bf8b95ad0eca51c7ffc78f91943fdf58b3e92a6727dbe12ac6ff18343f970a2`

- Original Debugger.jar: `7f72777cda59badf9f0b8e878f7a9d52040c39593a1e05251285ccafae6baecc`
- Patched Debugger.jar: `3b75891c6734b23f03c0313cb5fc582a9410676b799c8c1af3e30e3696b10bbf`
- Patch: `84a7da39520e7e2eaf12ebc49aa2f7c78f9e7e5fd19be3bda4e1ac55eb227df7`
- Only changed JAR member: `ghidra/app/plugin/core/debug/gui/register/DebuggerRegistersProvider.class`.
- Companion includes pinned original/patched Java source, patch, exact original rollback JAR, reviewed patched JAR, dependency identity, build recipe and rollback recipe. Distribution source archive remains unchanged; companion supplies matching modified source.
- Full 879 MB distribution install, verify and rollback passed. Source file bytes/modes stayed identical; rollback distribution equals original tree. Existing output refusal exit 2.
- Actual installer CLI refused unpatched/corrupted Java before creating selected home. Doctor reports Java MATCHED for patched distribution and unusable for baseline. Overall doctor readiness was not asserted: isolated empty home lacks installed extensions/Python wheels, and sandbox denies loopback binding. Native identity remained MATCHED (`switch-recovery.2`, binary `5b736c3e9236667d35a732f226c99f0014736b9fe506147886a7f15ccb94939a`).
- Eight updater tests (including real companion), three package selection tests, Python syntax and narrow diff whitespace checks passed.

Commands, child PIDs, expected/actual exits and logs: `/private/tmp/ghidraboy-java-dependency/commands.jsonl`, `build-command.json`, both `build-*/commands.jsonl`, `*.log`. Hashes/receipts: `source-hashes.json`, `source-before.json`, `validation.json`, both `build-*/receipt.json`, `installed/receipt.json`, `rolled-back/receipt.json`. Validation drivers: `validate.py`, `runtime-guards.py`.

## Coordinator commands

Already built and installed; use this distribution for packaging and fresh runtime acceptance:

`/private/tmp/ghidraboy-java-dependency/installed/distribution`

Offline rebuild into a NEW output (third build name is intentionally unused):

```sh
cd /Users/joshuahansen/dev/GhidraBoy
python3 tools/debugger_dependency_update.py build --ghidra /private/tmp/ghidraboy-integration-20260906/rmi-install --jdk /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home --patch /Users/joshuahansen/dev/GhidraBoy/tools/patches/ghidra-12.1.3-debugger-register-lifetime.patch --output /private/tmp/ghidraboy-java-dependency/build-3
```

Install into another NEW copy if needed:

```sh
python3 tools/debugger_dependency_update.py install --ghidra /private/tmp/ghidraboy-integration-20260906/rmi-install --package /private/tmp/ghidraboy-java-dependency/build-1/debugger-java-dependency.zip --sha256 9bf8b95ad0eca51c7ffc78f91943fdf58b3e92a6727dbe12ac6ff18343f970a2 --output /private/tmp/ghidraboy-java-dependency/coordinator-copy
python3 tools/debugger_dependency_update.py verify --ghidra /private/tmp/ghidraboy-java-dependency/installed/distribution
```

Copy-only rollback (choose unused output; `rolled-back` already exists from proof):

```sh
python3 tools/debugger_dependency_update.py rollback --ghidra /private/tmp/ghidraboy-java-dependency/installed/distribution --package /private/tmp/ghidraboy-java-dependency/build-1/debugger-java-dependency.zip --sha256 9bf8b95ad0eca51c7ffc78f91943fdf58b3e92a6727dbe12ac6ff18343f970a2 --output /private/tmp/ghidraboy-java-dependency/coordinator-rollback
```

Runtime packaging, serialize under coordinator ownership. Use the coordinator’s verified native output directory with `--native-dir` (the default `debugger/build` currently lacks `mgba-source.tar`); existing final artifacts/native prerequisites still apply:

```sh
python3 debugger/scripts/package_candidate.py --backend both --native-dir "$GBC_VERIFIED_NATIVE_DIR" --platform macos-arm64 --ghidra /private/tmp/ghidraboy-java-dependency/installed/distribution --jdk /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home --debugger-java-package /private/tmp/ghidraboy-java-dependency/build-1/debugger-java-dependency.zip --debugger-java-package-sha256 9bf8b95ad0eca51c7ffc78f91943fdf58b3e92a6727dbe12ac6ff18343f970a2
```

Repeat with `--backend sameboy` / `mgba` for separate compositions. Companion validation is independent of emulator and host platform. Linux native dependencies remain a separate selection.

In extracted runtime package, standalone updater is `scripts/debugger_dependency_update.py` and embedded companion is `dependencies/debugger-java-dependency.zip`; trusted digest is in `suite.json` under `debugger_java_companion`. Setup continues to require an explicitly selected patched distribution and does not mutate it.

Runtime install/doctor resolves the selected Ghidra root (including ordinary macOS `/tmp` and `/var` aliases), then refuses symlinks inside the managed tree. A test covers selected-root aliases and internal symlink refusal. The copy-only updater deliberately requires canonical paths and reports this in its CLI help/refusal; all evidence commands use `/private/tmp`.
