# Linux validation environment

The generic Linux validation recipe belongs to GhidraBoy. `Runtime.Dockerfile` retains the prior suite's pinned Python base and JRE/Xvfb/SDL runtime setup. The native compiler image recipe remains `../patches/Dockerfile.native-linux-jammy`. Building either recipe again creates a new environment until its dependencies and tests are verified; local image IDs are evidence, not published pullable image names.

The immutable image IDs, native library inspection and tested archive identities are in `../../docs/integration/m3-linux-evidence.json`. SDL bytes and their notice are pinned in `../dependencies.json` under `debuggerRuntime.sdl2`; the packager rejects mismatched fallback files. Extract these from the identified runtime image into `debugger/build/sdl-linux`, without changing the host's SDL or library path.

For a normal Linux source build, use the root-documented bootstrap and `debugger/scripts/build_native.sh`. The isolated M3 compiler run instead copied the verified, patched SameBoy source and adapter into a dedicated `/work` directory and ran:

```sh
make -C SameBoy -j4 lib CONF=release CC=gcc SDL_CFLAGS= SDL_LDFLAGS= RGBASM_FLAGS= RGBGFX_FLAGS=
gcc -shared -fPIC -std=gnu11 -O2 -Wall -Wextra -ISameBoy -Inative native/ghigbc.c SameBoy/build/lib/libsameboy.a -o libghigbc.so -lm -lpthread
```

Those empty flags avoid probing unused frontend/assembler dependencies when building only the library. The architecture-independent boot and ROM fixtures were separately assembled with the pinned RGBDS toolchain. Inspect the resulting library with `debugger/scripts/inspect_linux_library.py --compiler DESCRIPTION --output RECEIPT`; inspection alone never marks Linux execution passed.

Runtime acceptance uses a separate unprivileged container with networking disabled. Mount only the extracted package, a verified copied Ghidra distribution, a test runner and result directories. Do not mount the source checkout or compiler build tree. Assert `cc`, `gcc`, `clang`, `make`, `javac`, `gradle` and `rgbasm` are absent. A no-system-SDL variant proves fallback loading from the package.

Use Docker `--init` before `xvfb-run`, and map the selected `--hostname` to `127.0.0.1` with `--add-host` when using `--network none`. These correct the observed PID-1 Xvfb readiness wait and offline hostname-resolution failures. They do not suppress test failures.

Within that runtime, select `GHIDRA_INSTALL_DIR`, `JAVA_HOME`, an isolated `GBC_TEST_HOME` and `GBC_EVIDENCE_DIR`, then execute:

```sh
bash Validate.sh
python3 scripts/test_installer.py --manifest suite.json --ghidra "$GHIDRA_INSTALL_DIR" --java-home "$JAVA_HOME" --work /out/new-installer-test
.venv12/bin/python scripts/test_display_runtime.py --require-local-sdl
```

Apply the native decompiler companion using its copy-only updater and expected archive SHA256 before selecting the resulting distribution. The runtime startup probe, actual Trace RMI checks, installer recovery/rollback and display smoke have separate receipts. A virtual display and emulated x86-64 execution on a Mac do not establish physical Steam Deck behavior, native-device performance or interactive GUI acceptance.
