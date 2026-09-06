# Building the patched native dependency

The current dependency is explicitly named `12.1.3+ghidraboy.switch-recovery.2`. It combines the earlier override-index correction with logical-right-shift bounds and zero-only range handling. Its base Java/application version remains Ghidra 12.1.3; the native executable is not an official Ghidra build. A separate `ghidraboy-native-dependency.json` marker records the patch and executable hashes. The earlier `.1` packages and matching updater remain unchanged under `dist/decomp3/`.

`tools/build_native_decompiler.py` validates the patch/source-lock hashes in `tools/dependencies.json`, checks all 238 pinned pristine native source files, and creates a new distribution copy. It never patches the input installation. Modified/already-patched source, an existing work directory, ambiguous SM83 providers, unsupported target architectures, and a JRE without `javac` are rejected.

The source lock is derived from the official archive with SHA256 `93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54`. The patch is applied once in the new copy; only `jumptable.cc` may change. Compiler/version/executable identity, source hashes, commands, native artifact format/architecture, and rollback bytes are recorded. Headless error markers and missing regression markers cannot pass silently.

## macOS arm64

Use a Ghidra 12.1.3 distribution containing its pristine shipped C++ sources and one installed GhidraBoy provider:

```sh
python3 tools/build_native_decompiler.py \
  --ghidra /tmp/ghidraboy-input \
  --jdk /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  --work /tmp/ghidraboy-native-new-build \
  --component-tests
```

The helper runs the self-authored six-case native regression and its generated C over all 256 byte inputs. It also requires the nibble-dispatch regression to recover exactly sixteen targets and pass 256 generated-C cases, with the assembled routine bytes matched to the independent oracle. The build runs the C-only oracle explicitly; separate SameBoy and native boundary-test receipts establish the additional mechanisms. The existing component `DecompilerTest` is optional through `--component-tests`. A successful native build and its new distribution are retained even if a later validation gate fails.

The historical `.1` macOS build passed all its native/C checks and all twelve DecompilerTest cases. Its native executable was byte-identical to an independently built earlier copy using the same pinned source, patch and toolchain. These are historical results, not substituted for `.2` checks. Archive hashes can differ because archives include run-specific paths and validation timings; the native binary is the reproducibility target.

The `.2` macOS build passes both native/C families and all twelve DecompilerTest
cases. A separate complete run passes all 456 provider tests on that exact
dependency. Two earlier component-test attempts failed before tests started:
the sandbox first refused the Gradle cache lock, then its local lock socket.
The successful run used a copied cache and authorized local IPC, reusing the
unchanged native binary under the pinned-build identity checks. Failed receipts
remain retained; no test failure or diagnostic was hidden.

## Linux x86-64

The same helper runs natively on Linux with a full JDK 21, GNU C++, make, patch, clang (for the generated-C test), and readelf. The recorded Ubuntu 22.04 validation container is reproduced by `tools/patches/Dockerfile.native-linux-jammy`; the image is a build/test environment, not part of the distributed native runtime.

When testing in a network-disabled container, provide a hostname that resolves locally:

```text
--network none --hostname ghidraboy-native-build --add-host ghidraboy-native-build:127.0.0.1
```

Use read-only mounts for the repository and input distribution, and a separate writable work mount. For example, inside that container:

```sh
python3 /repo/tools/build_native_decompiler.py \
  --ghidra /input-ghidra \
  --jdk /usr/lib/jvm/java-21-openjdk-amd64 \
  --work /out/new-build
```

The `.2` Ubuntu 22.04/GCC 11 build passes both native regressions and all 512 generated-C inputs, with exactly sixteen nibble-switch targets. Its required versions reach GLIBC 2.34 and GLIBCXX 3.4.29. The historical `.1` Debian 13/GCC 14 build required GLIBC 2.38 and GLIBCXX 3.4.32. These differ from the broader official native executable baseline; downstream runtime compatibility must be checked against the chosen artifact rather than inferred from the `linux_x86_64` name. The helper records complete version-symbol requirements in the identity/build manifests.

The first Linux attempt used a cached runtime with only a JRE; the next attempt reached a passing fixture but logged a hostname-resolution startup error. Both runs remained failed. Adding the full JDK and a local hostname fixed the environment without suppressing errors. Their evidence remains available.

## Validating an already-built executable

A successful native compile does not need repeating after fixing an unrelated validation environment. Supply the unchanged binary and its exact successful native-build receipt while still using a fresh work directory:

```sh
python3 tools/build_native_decompiler.py \
  --ghidra /tmp/ghidraboy-input --jdk /path/to/jdk21 \
  --work /tmp/ghidraboy-new-validation \
  --reuse-native /previous/distribution/Ghidra/Features/Decompiler/os/linux_x86_64/decompile \
  --reuse-build /previous/build.json
```

Reuse checks binary hash, target architecture, dependency version, patch/source-lock hashes, all patched source files, and a passing native-build receipt. It does not reuse a previous regression PASS: native and generated-C validation execute again in the new copy. A failed or altered artifact cannot be substituted silently.

## Package and rollback contract

Each successful run produces an explicitly versioned platform ZIP, `build.json`, `package.json`, and a new distribution. The ZIP contains the native executable, identity marker, patch, source lock, license, exact original native bytes when present, and `rollback.json`. No commercial ROM, GZF, checkpoint, private decompiled corpus or user annotations are included.

The helper does not apply the ZIP to an active installation. The standalone copy-only updater `tools/native_dependency_update.py` verifies both managed destination files before changing a private stage; [exact install/verify/rollback commands](install-and-rollback.md) are documented separately:

- `Ghidra/Features/Decompiler/os/PLATFORM/decompile`
- `Ghidra/Features/Decompiler/ghidraboy-native-dependency.json`

Rollback restores exact backups, or removes a file only when the manifest proves that file was added by this update. If either current file differs from the installed hash, preserve the edited/different file and require explicit reconciliation. The identity marker must be rolled back with the executable so the installation cannot falsely advertise the patched dependency afterward.

Existing whole-ROM, annotation-preservation, broader native-suite and downstream deployment gates remain separate from these bounded native dependency checks. The stock Java JumpTable/default DecompInterface path has been verified; these checks do not claim an interactive GUI session was exercised.
