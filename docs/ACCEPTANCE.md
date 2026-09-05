# Acceptance evidence

Current selected release target: Ghidra 12.1.2 / Linux x86-64 (Steam Deck desktop mode). Development evidence below was collected on MacBookPro.localdomain, macOS 26.5.2 arm64, Java 21.0.12.1, Python 3.14.7, SameBoy v1.0.3 with the pinned CPU provenance patch.

| Requirement | Evidence and limit |
|---|---|
| Same PC in two ROM banks | Real Ghidra tests: CPU $4029 bank 1/2, physical ROM bytes, bank-specific breakpoint and historical bytes |
| Explicit static mappings | Real 12.1.2 plugin test: file-offset-derived mappings, renamed bank block, reverse translation and preserved student label |
| Direct UI actions | `ui-actions.log`: UI_ACTIONS_PASSED / exit 0. CUA selected the registered bank action through Ghidra’s action chooser, clicked native Resume, historical Go to writer and Bookmark observation. Exact historical snap/static address, read-only Trace mode and preservation of the old bookmark verified by services. Game-profile HP button separately verified below; Deck run not covered |
| HP panel command | Actual CUA selection of APC slot50 and Watch selected HP created WRAM3 offset0x324 WRITE. `hp-ui-result.json`: HP_UI_PASSED, full cleanup completed, exit0. Final log has no Swing timeout, trace-activation exception or duplicate mapping-node assertion |
| Mapping completion | Exact snapshot marker, uncaptured-future rejection, independent reopen: `mapping-marker-ghidra.log` / REAL_TRACE_TEST_PASSED. Older boolean metadata remains readable |
| Save/reopen history | Independent reopened Ghidra trace retains old CPU bytes and static mapping |
| Input identity | Real native tests replace ROM/boot files at load time and verify the emulator uses the fingerprinted copies; checkpoint boot identity remains stable after replacement/deletion |
| Register values / aliases | Real Ghidra: AF=12B0, BC=3456, DE=789A, HL=BCDE, PC=4567, SP=CFFE, A/F/B/C aliases |
| WRAM watchpoint provenance | Native: bank 3/4 D034 filtering, arbitrary direct store, exact writer origin, same-value/access versus change |
| Blocked writes / peeks | Native: VRAM attempted write with unchanged physical byte; repeated inspector reads preserve entire savestate |
| CPU execution boundaries | Native: ordinary/CB, interrupt without stale CPU writer, HALT/STOP wait; conditional CALL/RST step-over/out |
| Mapper edges | Native: MBC5 9-bit bank 256, MBC1 ROM0 bank 32, SVBK zero and echo alias; MBC3 RTC selectors explicitly unknown |
| Restore / edits | Real Ghidra methods verify register/physical WRAM edits, default/running-state rejection, recovery, historical values, no false guest event, and debugger-origin edit/recovery metadata after reopen |
| Profile fidelity | Exact exported ROM hash, 53 unit / 33 weapon tables and byte-writer opcode verified; wrong ROM stays generic |
| Legacy baseline | Original 11 tests pass, 256 initiative / 150 damage / 8 modifiers / 3 synthetic order cases rerun |
| Launcher | Ghidra discovers packaged launch offer and starts real agent automatically. Complete initial capture/save and structured termination passed in the approved clean profile |
| Installer / rollback | New isolated user profile installed a versioned runtime and both extensions; complete rollback verified. Actual Steam Deck install pending |
| SDL desktop | Real Mac window: Start opens menu; paused keyboard tap registered, minimizing released a seeded guest-held key, and desktop close saved TERMINATED state through Ghidra. 120.000 s wall /119.999 s emulated. Steam Deck UX remains open |
| Latency / growth | Integrated250-stop run: step p95 37.625ms, pause269.863ms including settling; agent RSS +16KiB, Ghidra RSS +178320KiB, trace +1196032 bytes, dropped0. Bounded observation, not long-term leak proof; not Deck measurements |
| Actual battle | Real Ghidra-connected CLASS 2 attack: APC 10→3, writer rom18::40b5, restore/repeat and independent reopen pass; see ACTUAL_BATTLE.md |

Primary logs: `native-tests.log`, `mapper-tests.log`, `real-ghidra12-test.log`, `clean-ghidra12-test.log`, `legacy-tests.log`, `legacy-routines.json`, `desktop-probe.log`, `ghidraboy12-build.log`, `extension12-build.log`, `install-test.json`, under `docs/evidence/`. Some failed intermediate runs are described in IMPLEMENTATION_STATUS; only explicit final pass markers support a passed check.

Unclaimed coverage: DMA/HDMA access watches, verified GBW3 far-call callers or step-over, arbitrary mapper families, all IO per-access commit timing, full reconstructed stack, battery-save import, remote target desktop access. GBW3 far-call over/out is rejected with an explanation; the UI reports unknown caller.

The requirement-by-requirement audit and explicit target gap are in COMPLETION_AUDIT.md. Latest capture parent and restoration evidence: checkpoint-parent-native.log (25 tests) and checkpoint-parent-ghidra.log (REAL_TRACE_TEST_PASSED).
