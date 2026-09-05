# GhiGBC

A SameBoy-backed Game Boy Color debugger for Ghidra 12.1.2. Native C owns emulation and CPU watchpoint filtering; one Python sidecar publishes Trace RMI captures; a Java extension maps physical banks and provides study actions. GhidraBoy's `SM83:LE:16:default` language and student annotations are preserved.

**Working and validated on macOS arm64; Steam Deck deployment remains unverified.** Real Ghidra 12.1.2 tests pass for native stepping, register aliases, bank-qualified breakpoints, renamed static mappings and saved/reopened history. Native tests cover direct WRAM writers, blocked VRAM attempts, same-value writes, HALT/STOP/interrupt boundaries, ordinary step-over/out and checkpoint recovery. The automatic Ghidra launcher, versioned runtime installation/rollback and real CLASS 2 battle are verified on the development Mac. APC HP 10→3 resolves to `rom18::40b5` (`LD (HL),B`), and checkpoint replay reproduces it. Saved/reopened history retains the evidence.

See [implementation status](docs/IMPLEMENTATION_STATUS.md), [first-session guide](docs/QUICKSTART.md), and [native correctness contract](docs/NATIVE_CONTRACT.md). `docs/evidence/` contains actual build/test logs. Commercial inputs, checkpoints and project copies stay in ignored directories.

```sh
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra_12.1.2_PUBLIC
export JAVA_HOME=/absolute/path/to/jdk-21
python3 scripts/bootstrap.py
scripts/build_native.sh
scripts/build_extension.sh
scripts/test_native.sh
scripts/test_ghidra.sh
```

Dependencies and patches are pinned in `dependencies.lock.json`. Original Live Lab and Study Pack are preserved unchanged in `legacy/`; their historical records are distinct from new tests.

The Linux x86-64 candidate bundle includes a cross-built library and needs no C compiler for the first target test. Its ABI is inspected, but Linux/Steam Deck execution remains unverified. See [Steam Deck steps](docs/STEAM_DECK.md).

For the student-facing transfer, use `dist/GhiGBC-SteamDeck-Handoff-0.1.0.zip` and its START-HERE.md. It provides Setup, Validate and Collect-results scripts and keeps private game assets separate. Build it with `python3 scripts/package.py` followed by `python3 scripts/package_deck_handoff.py`.
