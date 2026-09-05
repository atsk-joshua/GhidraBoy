# Interactive Ghidra action acceptance

Run on a desktop with Ghidra 12.1.2 and the prepared runtime/build artifacts:

```sh
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra_12.1.2_PUBLIC
export JAVA_HOME=/absolute/path/to/jdk-21
bash scripts/test_ui_actions.sh
```

The test imports only the redistributable teaching ROM, creates a separate project and user profile, loads Ghidra's shipped Debugger tool with its front end, and connects the real SameBoy agent. It prepares fixtures and observes services; it does not invoke the UI actions under test. Each phase permits eight minutes. Follow `docs/evidence/ui-action-phase.txt` for the current action.

1. Focus the **static Listing: teaching.gbc**, choose **Navigation → Go To**, enter `StudentBankTwo`, and press OK. Right-click that address and choose **GBC → Breakpoint in this physical bank**. Alternatively open Ghidra’s action chooser with Cmd+3 on macOS or Ctrl+3 on Linux, filter `GBC`, select that same registered action and press OK. This block was renamed; the observed breakpoint must still identify physical ROM bank 2, offset `0x29`.
2. When the phase says `continue_bank`, click native **Resume (F5)**. The trace must stop at bank 2, CPU `4029`; the same PC in bank 1 must not match the new breakpoint.
3. At `continue_writer`, click Resume. The harness has armed WRAM bank 3, offset `0x34`; the fixture also writes bank 4. A bank-3 event must be captured.
4. At `later_state`, click Resume to reach the later bank-2 fixture at `4567`. Open **Window → GBC Study**, select the event in **Writes**, then click **Go to writer**. The observer requires the event's older snapshot and the exact static `StudentHPWriter` address.
5. At `bookmark`, select the event again and click **Bookmark observation**. The observer checks that the captured-snapshot note was added and the existing student bookmark was preserved.

Only `UI_ACTIONS_PASSED` in `docs/evidence/ui-actions.log` is a pass. The test saves the trace and terminates its owned agent when successful. A timeout or partial phase is not evidence that an action works. If the shipped saved layout is off-screen, use the operating system's window zoom/move controls.

## Current evidence

The corrected development-Mac run ends `UI_ACTIONS_PASSED` and exits 0. Actual CUA actions navigated by label, invoked the registered bank action through Ghidra’s standard action chooser, clicked native Resume at each phase, selected Writes, clicked Go to writer and Bookmark observation. The observer verified bank 2 / CPU 4029, the WRAM event, later bank-2 PC4567, return from snapshot 8 to event snapshot 5 at static `StudentHPWriter` / 016d, read-only Trace mode, and preservation of the existing bookmark. The agent saved its trace and terminated.

The first run exposed a product bug: Target mode refused the older snapshot. Go to writer now changes a present-following mode to read-only Trace mode when navigating history and explicitly activates the event’s trace. The before-fix log is retained as `ui-actions-before-navigation-fix.log`.

The passing run still logs a Ghidra Model-tree `Duplicate node name: MappingReady` assertion and macOS accessibility child-index exceptions. The observed actions completed, but the log is not error-free; the Model-tree diagnostic needs separate follow-up. No Steam Deck execution or game-profile HP-button click is claimed by this teaching-fixture test.

## Actual game HP button

With the private inputs at the documented development paths, run:

```sh
bash scripts/test_ui_actions.sh --hp
```

This requires `.local/student-copy.gzf`, `build/experiments/student12.gbc`, and the verified `.local/game-evidence/class2-fire-ready` checkpoint. It imports a fresh project copy and restores that checkpoint through the real agent. Select APC slot50, HP10, in GBC Study > Units and click Watch selected HP. The observer checks physical WRAM bank3, offset0x324, WRITE.

The final development-Mac run passed the actual action and complete session cleanup: `hp-ui.log` ends `HP_UI_PASSED`, process exit0. The final run recorded no Swing timeout, trace-activation exception or duplicate mapping-node assertion. See `hp-ui-result.json` for the observed bank, offset and selected unit.

Earlier runs stalled in the native Mac decompiler or teardown; those logs remain as prior diagnostics. After the user clarified desktop approval timing, the stall did not recur. The observer now handles an initially empty trace, allows front-end cleanup to return rather than exiting the JVM prematurely, and clears the active trace before tool disposal. Only the post-cleanup HP_UI_PASSED marker is a full pass; HP_BUTTON_ACTION_PASSED alone verifies the button.

The separate mapping-marker regression also passed real trace/history/launcher checks. MappingSnapshot identifies exactly which snapshot has complete mappings and avoids alternating readiness booleans. Steam Deck execution remains unverified.
