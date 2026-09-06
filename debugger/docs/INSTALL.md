# Install, upgrade and rollback

Extract the platform archive in your home folder. Keep Ghidra closed while changing its extensions. Use the existing system Python3.9+ (including the Python already on Steam Deck), Ghidra **12.1.3**, and Java21. No compiler, Gradle, RGBDS, root access, SteamOS read-only change, or global JVM library-path change is required.

The integrated candidate requires the matching GhidraBoy native decompiler update, `12.1.3+ghidraboy.switch-recovery.2`, for its static decompiler fixes. Setup verifies the selected distribution's identity marker and executable hash before changing any user directories. If the update is absent, use the separately supplied native archive and its trusted build/release SHA256 with the included copy-only updater:

```sh
python3 scripts/native_dependency_update.py install --source "/path/to/ghidra_12.1.3_PUBLIC" --package "/path/to/native-platform.zip" --package-sha256 "EXPECTED_SHA256" --output "/path/to/new-ghidra-bundle"
```

The debugger also requires **12.1.3+ghidraboy.register-lifetime.1**, a separate
Ghidra Java correction for register rendering after target/trace closure. Apply
the included platform-independent companion to a new copy of the distribution
that already has the native decompiler update:

```sh
python3 scripts/debugger_dependency_update.py install --ghidra "/canonical/path/to/native-bundle/distribution" --package dependencies/debugger-java-dependency.zip --sha256 9bf8b95ad0eca51c7ffc78f91943fdf58b3e92a6727dbe12ac6ff18343f970a2 --output "/canonical/path/to/new-debugger-bundle"
```

Select that new bundle's `distribution` directory for Setup. Both updaters
preserve their source installation; Setup verifies both dependency identities
and never patches the chosen distribution in place. The Java companion includes
the matching source, patch and exact original JAR for rollback. Its updater
requires canonical paths (on macOS use `/private/tmp`, not `/tmp`).

To undo the Java update, use the same command with `rollback`, the updated
distribution as `--ghidra`, and another unused output directory. This restores
the original JAR in a new copy; the current debugger installer will correctly
reject that unpatched copy. Keep the companion archives and updater receipts.
Native companion binaries remain separate platform artifacts with their own
acceptance evidence. Static-only GhidraBoy does not require the debugger Java fix.

```sh
bash Setup.sh --ghidra "/path with spaces/ghidra_12.1.3_PUBLIC" --java-home "/path/to/jdk-21"
```

Setup uses `python3` by default; GBC_PYTHON or --python may select another existing interpreter. No exact patch/minor allowlist, upper-version cap, interpreter download, or global Python change is imposed. It checks required standard-library capabilities, creates an isolated venv with that interpreter, and verifies the actual bundled wheels and native runtime. The bundled pure-Python wheels are installed offline into that venv; neither pip nor ensurepip is required. Recorded test versions are evidence, not installation requirements. The selected distribution supplies exact pinned Trace RMI/protobuf wheels offline. Linux uses normal host graphics integration; bundled SDL2 is a process-local fallback when system SDL2 cannot load. Its remaining dynamic libraries are host prerequisites, recorded in the acceptance report. An explicit process-local GBC_SDL2_LIBRARY can select an alternate tested SDL2 file.

For the optional study package, extract it separately and add `--study "/path/to/GhiBW3-study/study.json"`. The generic installer verifies the complete matched composition and all payload hashes before replacing an extension. Static-only users can install the GhidraBoy and GhiBW3Static ZIPs with Ghidra's normal extension installer and leave GhiGBC/GhiBW3Live absent.

Installation creates a new complete versioned runtime and a durable rollback journal. It stages and validates native loading, SDL2, Python wheels, and profile discovery before committing extension replacements. A lock prevents concurrent installs. Interrupted transactions recover to the coherent old installation on the next setup; an interrupted partial preparation can remain as an explicitly reported unactivated runtime directory to preserve uncertain files.

Use the exact journal path printed by Setup for rollback or explicit recovery:

```sh
python3 scripts/install.py --rollback "/absolute/path/GhiGBC-rollback/ID/manifest.json"
python3 scripts/install.py --recover "/absolute/path/GhiGBC-rollback/ID/manifest.json"
```

Rollback validates all targets/backups first and refuses to delete user-modified files. Resolve the named changed files by preserving copies before retrying. Rollback from the installed runtime's copy of install.py is supported. Never delete your older 12.1.2 bundle to install this candidate. This package does not silently upgrade a 12.1.2 Ghidra installation.

To remove the study composition while retaining the generic debugger, rerun generic Setup with `--remove-study`. This creates another reversible transaction. Saved traces, raw history, ROMs, Programs, comments and unrelated annotations are outside the installer’s managed paths.
