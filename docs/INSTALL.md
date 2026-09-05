# Install, upgrade and rollback

Extract the platform archive in your home folder. Keep Ghidra closed while changing its extensions. Use the tested Python (3.13.15 Linux x86-64; 3.14.7 macOS arm64), Ghidra **12.1.3**, and Java21. No compiler, Gradle, RGBDS, root access, SteamOS read-only change, or global JVM library-path change is required.

```sh
bash Setup.sh --ghidra "/path with spaces/ghidra_12.1.3_PUBLIC" --java-home "/path/to/jdk-21"
```

Set GBC_PYTHON to your tested Python executable if `python3` names a different version. The selected distribution supplies exact pinned Trace RMI/protobuf wheels offline. Linux uses normal host graphics integration; bundled SDL2 is a process-local fallback when system SDL2 cannot load. Its remaining dynamic libraries are host prerequisites, recorded in the acceptance report. An explicit process-local GBC_SDL2_LIBRARY can select an alternate tested SDL2 file.

For the optional study package, extract it separately and add `--study "/path/to/GhiBW3-study/study.json"`. The generic installer verifies the complete matched composition and all payload hashes before replacing an extension. Static-only users can install the GhidraBoy and GhiBW3Static ZIPs with Ghidra's normal extension installer and leave GhiGBC/GhiBW3Live absent.

Installation creates a new complete versioned runtime and a durable rollback journal. It stages and validates native loading, SDL2, Python wheels, and profile discovery before committing extension replacements. A lock prevents concurrent installs. Interrupted transactions recover to the coherent old installation on the next setup; an interrupted partial preparation can remain as an explicitly reported unactivated runtime directory to preserve uncertain files.

Use the exact journal path printed by Setup for rollback or explicit recovery:

```sh
python3 scripts/install.py --rollback "/absolute/path/GhiGBC-rollback/ID/manifest.json"
python3 scripts/install.py --recover "/absolute/path/GhiGBC-rollback/ID/manifest.json"
```

Rollback validates all targets/backups first and refuses to delete user-modified files. Resolve the named changed files by preserving copies before retrying. Rollback from the installed runtime's copy of install.py is supported. Never delete your older 12.1.2 bundle to install this candidate. This package does not silently upgrade a 12.1.2 Ghidra installation.

To remove the study composition while retaining the generic debugger, rerun generic Setup with `--remove-study`. This creates another reversible transaction. Saved traces, raw history, ROMs, Programs, comments and unrelated annotations are outside the installer’s managed paths.
