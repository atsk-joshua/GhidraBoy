# Start here — GhiGBC on your Steam Deck

This package adds a SameBoy Game Boy Color debugger to **Ghidra 12.1.2**. Start with the included teaching ROM, then use a copy of your annotated Game Boy Wars 3 program.

The debugger, actual battle workflow and UI actions were tested on an Apple silicon Mac. This Linux x86-64 package was cross-built; **your Steam Deck run is the remaining platform validation**. Keep the results ZIP so we can confirm it worked or diagnose a failure.

For the full engineering history, decisions and reasons, read **docs/HANDOFF_REPORT.md**.

## 1. Prepare

Use Desktop Mode. Extract the entire ZIP into a writable folder under your home directory, such as `~/GhiGBC-SteamDeck`. Close Ghidra before setup. In Dolphin, open a terminal in the extracted folder.

You need Ghidra **12.1.2**, a JDK **21 or newer**, Python **3.10–3.14**, and SDL2. If Ghidra is already running, Java may already be installed. Setup uses the prebuilt library and the Python wheels shipped with your Ghidra installation; it does not need a C compiler, Gradle or RGBDS.

If you need the matching Ghidra version, use the [official Ghidra 12.1.2 release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.2_build). Extract its public release archive to a separate folder and point setup there.

Run:

```sh
bash Setup.sh
```

Setup looks for Ghidra in your home, Downloads and Applications folders. If it cannot find the installation or JDK, use your actual paths:

```sh
bash Setup.sh --ghidra /home/deck/ghidra_12.1.2_PUBLIC --java-home /path/to/jdk-21
```

The paths are remembered in this folder. Installation creates a versioned per-user runtime and backs up prior managed extensions. Its result and rollback path are in `.local/deck-results/install.json`. If you already installed GhidraBoy inside Ghidra's own folder, setup will report the duplicate language; keep one compatible GhidraBoy installation before retrying.

If setup reports a missing dependency, keep its log. Do not disable SteamOS's read-only filesystem or change global packages just to get past the check.

## 2. Run the teaching check

```sh
bash Validate.sh
```

This runs native tests and real Ghidra tests, including a 250-stop memory/trace-growth measurement. It creates a separate test project/profile. Review Ghidra's user agreement if shown. A successful run prints that automated checks passed.

Then run the interactive button walkthrough:

```sh
bash Validate.sh --ui
```

Follow `docs/UI_ACTION_VALIDATION.md`: go to `StudentBankTwo`, create its physical-bank breakpoint, use Resume, select the captured write, go to its historical writer and save a bookmark. Current instructions are also written to `docs/evidence/ui-action-phase.txt`. Each action permits eight minutes.

## 3. Try the actual game window

Restart normal Ghidra. Import `build/teaching.gbc`, open the **Debugger** tool and enable **GbcPlugin** if it is absent. Choose **GBC / SameBoy** from the debugger launch menu and select the teaching ROM. The installed runtime path and connection are configured automatically.

Use arrows, **Z/X**, **Enter**, and **Backspace** in the game window. Check that the window remains responsive when paused. Hold a direction, pause, switch focus, release the key and resume: the direction must not remain stuck. Close the game window and confirm the agent disconnects.

Write what happened in the included **NOTES.txt**, including your SteamOS version, whether the game window opened, and any focus/input problem. The teaching fixture is for debugger checks; it is not a full game.

## 4. Use your annotated GBW3 program

Commercial ROMs, GZF files and checkpoints are separate from this software package. Work from a **copy** of your own annotated GZF. If you need the matching ROM, run `legacy/gbw3-live-lab/ExportGBW3ROM.java` in Ghidra against that copy and export a new file.

The verified profile requires SHA256:

```text
e779a6b56575a2afafb7e1e99411b23d7400a8fddbda8bd52c660b7903c3b451
```

A different ROM runs as a generic debugger. Follow `docs/QUICKSTART.md` to reach a battle, save a checkpoint, select a real unit by coordinates/type, watch its HP, attack, inspect the captured writer, restore and repeat. The previous Mac battle observed APC HP10→3 at `rom18::40b5`, `LD (HL),B`; callers remain unknown unless verified.

**Go to writer** selects read-only Trace mode for history. Choose **Control Target w/ Edits Disabled** to follow the live machine again. Selecting history does not restore execution; use the checkpoint action for that.

## 5. Send back the results

```sh
bash Collect-results.sh
```

This creates `GhiGBC-results-<time>.zip` in the extracted folder. It contains only the allowlisted setup/test logs and your notes, not ROMs, Ghidra projects, checkpoints or saves. Logs may contain your hostname and local file paths; review the ZIP before sharing it with your dad.

If anything fails, stop at that step, keep the error log and collect the results. There is no need to enable SSH.

## Rollback and limits

Use the exact rollback manifest printed by setup:

```sh
python3 scripts/install.py --rollback /absolute/path/to/manifest.json
```

Rollback preserves changes it cannot safely undo and reports them. Original ROM/project/save files are not installation targets.

CPU-origin watches are supported; DMA/HDMA watches are not. Ordinary CALL/RET/RST over/out is tested; GBW3 far-call over/out remains disabled. There is no inferred full stack, battery-save import, or audio output in this release. `docs/DEVELOPMENT_VALIDATION.md` summarizes the verified development results.
