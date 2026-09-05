# Steam Deck continuation

The target is Steam Deck desktop mode, Linux x86-64, Ghidra 12.1.2. This Mac cannot establish target readiness without access to that Deck. No SSH address was provided and the local Docker daemon is unavailable. Linux source/build support is provided; no Linux native binary is claimed tested.

Copy `GhiGBC-0.1.0-source.tar.gz` to a user-owned directory on the Deck and extract it. Build in that directory. Installation copies a versioned runtime into the user’s Ghidra settings and points the launcher at that runtime. Supply a JDK 21, C compiler/make, Python, and SDL2 in the user's development environment. Bootstrap downloads pinned RGBDS and Gradle and creates a local Python environment. A developer container or user-local toolchain avoids changing SteamOS's read-only base image.

```sh
cd /home/deck/path/to/GhiGBC
export GHIDRA_INSTALL_DIR=/home/deck/path/to/ghidra_12.1.2_PUBLIC
export JAVA_HOME=/home/deck/path/to/jdk-21
python3 scripts/bootstrap.py
scripts/build_native.sh
scripts/build_extension.sh
scripts/test_native.sh
.venv12/bin/python scripts/doctor.py --ghidra "$GHIDRA_INSTALL_DIR" --rom build/teaching.gbc
scripts/test_ghidra.sh
python3 scripts/install.py
```

For the registered bank breakpoint, native Resume, historical Go to writer, and bookmark buttons, run `bash scripts/test_ui_actions.sh` and follow `docs/UI_ACTION_VALIDATION.md`. Retain its pass log; this sequence passed on the development Mac, but still needs a Deck run.

The first GUI test in a fresh profile may display Ghidra's user agreement. Review it yourself; the tests do not silently accept it. The test creates disposable Ghidra projects under `build/projects/` and a user profile under `.local/ghidra-test-user/`. It uses actual Trace RMI and the installed plugin JAR, not a mock server.

Start normal Ghidra, open a copied program, enable GbcPlugin in the Debugger tool if absent, then choose GBC / SameBoy. Verify real window rendering and input, pause while holding a direction, switch focus, resume and check the direction released. Close the game/connection and verify the owned sidecar exits. Retain logs from `scripts/test_ghidra.sh` and screenshots of the native Ghidra Registers/Listing and game window.

For the annotated program: import a copy of the GZF, run `ExportGBW3ROM.java` to a new file, and doctor-check the exact hash before enabling the game profile. Follow QUICKSTART to identify a real unit, checkpoint, watch HP, attack, navigate the captured writer, restore, repeat and save/reopen the trace. A synthetic routine experiment does not meet this last gate.

Report OS version, `uname -m`, Ghidra version/revision from doctor, and step/pause results. If a build fails, preserve the compiler output; do not install a second SM83 language extension or upgrade the original annotated project to work around it.

## Prebuilt Linux candidate

`GhiGBC-0.1.0-linux-x86_64.tar.gz` now includes the cross-built Linux library, matched extension archives, boot asset, agent and teaching ROM. Its ELF x86-64 format and all exported ABI functions are verified, but it has **not been executed on the Deck**. It targets GNU libc 2.28 and uses SDL2 from the system.

For the first on-Deck test, extract that package and run:

```sh
cd /home/deck/path/to/GhiGBC-linux-x86_64
export GHIDRA_INSTALL_DIR=/home/deck/path/to/ghidra_12.1.2_PUBLIC
export JAVA_HOME=/home/deck/path/to/jdk-21
python3 scripts/prepare_runtime.py
scripts/test_native.sh
scripts/test_ghidra.sh
python3 scripts/install.py
```

This route needs Python, Java and SDL2, but no C compiler, RGBDS or Gradle for the initial install/test. For source rebuilds use the source archive and bootstrap/build commands above. The cross-build is reproducible with `scripts/build_linux_cross.sh` and the pinned Zig archive in `dependencies.lock.json`.

For a bounded integrated memory/trace-growth report, run `scripts/test_ghidra.sh --growth` and retain `docs/evidence/integrated-growth.json` with its stdout/stderr log. Doctor’s `ready_for_desktop_validation` checks SDL2 loading and desktop prerequisites; the actual window/input walkthrough is still required.
