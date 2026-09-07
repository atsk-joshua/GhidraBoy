# Deferred interactive acceptance

Run `bash Validate.sh --ui` from the extracted candidate with GHIDRA_INSTALL_DIR and JAVA_HOME set to the selected12.1.3/JDK21 paths. The precompiled observer needs no javac. It creates a separate project/home and uses Ghidra's standard Debugger tool; it never clicks the actions being tested.

Before interacting, positively identify the **GhiGBC UI Validation** window and its isolated user-home/process. Keep user projects and other running Ghidra windows untouched. The current candidate's interactive gate is pending because the Mac was locked during off-device integration. Historical12.1.2 UI pass logs are not evidence for this candidate.

1. In static Listing for teaching.gbc, navigate to StudentBankTwo. Use GBC → Breakpoint in this physical bank (or the registered action through Ghidra's action chooser). The observer checks ROM bank2+0x29 after the block was renamed.
2. At continue_bank, click native Resume. Expect bank2 / CPU4029. The same PC in bank1 must not satisfy this breakpoint.
3. At continue_writer, click Resume. The observer armed WRAM3+0x34; the captured bank3 writer must be selected despite writes to another bank.
4. At later_state, click Resume, then open **GBC History**, select the captured write and click Go to writer. The observer checks the original snapshot, exact static writer and read-only historical Trace mode.
5. At bookmark, click Bookmark observation. The existing note must remain alongside the new captured observation.

Each phase allows eight minutes. Read docs/evidence/ui-action-phase.txt for the next step. Only UI_ACTIONS_PASSED after cleanup is a pass; keep timeouts/partial logs as failures. Collect-results.sh includes these logs. Do not reinterpret this observer as a renderer, physical held-key/focus, or Deck performance test.

Game-specific UI acceptance instructions are maintained by the optional profile project.
