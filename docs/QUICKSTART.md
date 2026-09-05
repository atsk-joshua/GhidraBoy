# GBC / SameBoy first session

Target: Steam Deck desktop mode (Linux x86-64), Ghidra **12.1.2**. macOS arm64 is the development host. A real CLASS 2 battle, checkpoint replay, and trace persistence are verified on the development Mac. Steam Deck installation and desktop behavior still need target validation.

Set `GHIDRA_INSTALL_DIR` to your Ghidra 12.1.2 directory. The build requires Java 21, Python 3.10–3.14, a C compiler, make, RGBDS 1.0.1, Gradle 8.14.3, and SDL2. Do not change SteamOS system packages or disable its read-only filesystem; use a development container or user-local tools if needed.

From the package directory:

```sh
python3 scripts/bootstrap.py
scripts/build_native.sh
scripts/build_extension.sh
scripts/test_native.sh
python3 scripts/doctor.py --ghidra "$GHIDRA_INSTALL_DIR" --rom build/teaching.gbc
python3 scripts/install.py
```

Installer copies a versioned runtime (native library, agent, Python environment, open-source boot asset), backs up prior managed extensions, and prints a rollback manifest. Older runtimes stay available for rollback. Roll back with `python3 scripts/install.py --rollback /absolute/path/to/manifest.json`. It refuses to discard post-install edits. The original Ghidra installation, ROM, and project are not modified by installation.

Restart Ghidra. Import `build/teaching.gbc` into a new project, open the **Debugger** tool, and enable the **GbcPlugin** if absent. Select **GBC / SameBoy** from the debugger launch menu. Choose the teaching ROM. The launcher creates the Trace RMI connection automatically. The runtime directory field is filled by the installer; no socket configuration is required.

The Registers window shows the actual CPU PC. A bank is a physical memory page selected into a CPU address window; the same PC can identify different code in different banks. Use the physical `romN` trace memory spaces or **GBC → Breakpoint in this physical bank** from a static listing to keep breakpoints tied to one bank. A breakpoint pauses before execution; a watchpoint pauses at the instruction boundary after an attempted access. A same-value write still counts as an access.

For the game, open a **copy** of the annotated GZF. The unchanged `legacy/gbw3-live-lab/ExportGBW3ROM.java` exports a new matching ROM from that copy. Confirm doctor reports SHA256 `e779a6b56575a2afafb7e1e99411b23d7400a8fddbda8bd52c660b7903c3b451` and `gbw3_profile: true`. Other hashes remain generic and receive no game interpretation.

Launch the exported ROM, use arrows, Z/X, Enter, and Backspace, and reach an actual map battle. Pause and save a checkpoint using the Machine object's remote action with a **new directory**. A checkpoint saves execution state; a trace snapshot only records an observation.

Identify a real unit by map coordinates and type in the GBC Study panel. Candidate rows alone do not prove an active battle. Select its HP and **Watch selected HP**, resume, and perform an attack. In Writes, inspect before/final-after, select **Go to writer**, and verify the static instruction. The caller remains unknown unless separately established. Restore the checkpoint and repeat, then save the trace. The damage routines return remaining HP.

Current limits and validation progress are recorded in `IMPLEMENTATION_STATUS.md`. Ordinary generic CALL/RET/RST step-over/out is tested; GBW3 far-call over/out remains disabled and caller attribution remains unknown. See `ACTUAL_BATTLE.md` for the verified map battle and `STEAM_DECK.md` for target validation.

To export authoritative program knowledge without changes, run `scripts/ExportGbcKnowledge.java` in Ghidra and choose a new `.knowledge.json` output. It includes labels, namespaces, functions, memory/file mappings, structures and comments; keep this personal export outside redistributable packages.

The installed runtime also retains `scripts/install.py`, so rollback remains available even if the development checkout is moved. Use the rollback manifest printed by installation; it restores the matching older runtime/extension pair and refuses to discard changed files.

For deliberate edits, enable **Experiment edits** in the launcher and pause first. The Machine actions **Experiment: edit register** and **Experiment: edit WRAM byte** require a new recovery-checkpoint directory. Inspect `Machine.Edits` for debugger origin, before/after values, physical WRAM identity and the recovery link. These are separate from CPU watch events. Restore that checkpoint to undo the edit; invalid or running-state requests are rejected before creating recovery files.

**Go to writer** switches to read-only **Trace** mode when selecting an older capture. To continue playing, choose **Control Target w/ Edits Disabled** from Ghidra’s control-mode toolbar; Target mode follows the current live stop. Viewing history does not restore emulator execution—use the checkpoint action for that.

Registers are the CPU’s small working values. PC is the CPU address of the next instruction at a breakpoint stop. To compare the old lab’s game-maintained bank shadow, inspect captured CPU memory at `ram:ff80`; it is a diagnostic, while Machine ROM0/ROMX report the actual mapper state.

Selecting a row in Writes shows its original epoch, physical target/HP field, attempted value, access origin and timing precision. The after byte is the final physical byte at the instruction boundary, not proof of a separate commit for every internal access. Restored captures also expose ParentCheckpoint and its state SHA256 in Machine attributes.
