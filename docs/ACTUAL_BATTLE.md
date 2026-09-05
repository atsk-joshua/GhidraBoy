# Real GBW3 map-battle evidence

Validated in a real **Ghidra 12.1.2** session on the development Mac, using the copied annotated GZF and matching exported ROM. This is a normal **CLASS 2 tutorial mission**, not an isolated routine call, manufactured RAM state, or Steam Deck validation.

The player selected HUMVEE in slot 1, moved toward APC in slot 50, chose Fire and confirmed the APC target through the real SDL game window. Before the exchange both had 10 HP. The stopped capture showed HUMVEE at 5 HP and APC at 3 HP.

The bank-qualified HP watchpoint targeted **WRAM bank 3, CPU `$D324`, physical offset `$324`**, which is slot 50's HP field. It stopped after the CPU attempted the store:

- Writer: **`rom18::40b5`**, physical ROM bank 18, offset `$B5`, file offset `$480B5`.
- Instruction: **`LD (HL),B`**, opcode `$70`.
- Existing containing function: **`FUN_rom18__40a1`**.
- Captured before/final-after: **10 → 3**; attempted value 3, CPU origin.
- Caller: **unknown**, not inferred from the post-write PC or stack.

Saved the full-emulator `class2-fire-ready` checkpoint before confirming Fire. Restore reset the units to 10 HP and started a new epoch. Repeating Fire produced the same APC 10→3 write. The prior event, memory and mappings survived later restores, another attack, trace save, project close and independent trace reopen.

`actual-battle-verification.log` and `actual-battle.json` hold the independently reopened Ghidra checks, physical mapping, opcode, captured combat scratch fields and relevant units. The newer replay verifies all 100 unit records survive persistence via binary attributes. `actual-battle-original.json` records the first session; its unit summary was reconstructed from preserved physical WRAM because Ghidra 12.1.2 truncated its older long-string metadata. The underlying memory and writer events were intact.

Private local continuation assets, excluded from distributions:

- `build/projects/Battle-1788579290888.gpr` — latest saved trace and copied annotated program.
- `.local/game-evidence/class2-fire-ready/` — full SameBoy state plus matching metadata; restore with the Machine action in a matching session.
- `.local/game-evidence/class2-after-attack/` — the original attack's stopped state.

In the student UI, open the copied program, launch its matching ROM, restore the Fire-ready checkpoint, watch slot 50 HP, resume, select Fire and confirm the APC target. In GBC Study → Writes, select the captured event and Go to writer. Save/reopen the trace to inspect history. Do not copy the commercial ROM, GZF or checkpoints into public packages.
