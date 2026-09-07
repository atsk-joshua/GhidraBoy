# Saved instruction compatibility

Fresh decoding does not verify saved Ghidra instruction parse trees. The withdrawn
`20260905-decomp1` candidate added a separate POP AF constructor; it passed CPU
and decompiler tests but misinterpreted existing saved POPs. Never install that
candidate or use it to save annotated Programs. Keep original backups and use
the distinct `20260905-decomp2` correction only after its compatibility gates.

The correction restores the original single POP constructor, its ordering,
pattern and token bindings. Its branchless mask is FFh for BC/DE/HL and F0h for
AF, preserving architectural effects without the synthetic unreachable branch.
Constructor identity must be treated as part of persisted language compatibility,
not inferred solely from unchanged byte lengths and mnemonics on fresh imports.

`src/test/scripts/GhidraBoyInstructionCompatibility.java` maintains a self-authored
501-instruction regression: one encoding for each of 245 legal base opcodes and
all 256 CB opcodes. Its seed mode requires a fresh zero-filled 32 KiB Program and
restricts each disassembly to that instruction's exact range. It contains no
commercial ROM bytes. For every instruction, check mode freezes the saved text,
length and raw p-code before performing a fresh PseudoDisassembler decode, then
compares them exactly. P-code comparison catches invisible errors such as a
missing POP AF flag mask even when the displayed mnemonic still matches.

Use two disposable installations containing exactly one provider each. Create
an empty work directory with a projects directory and zero-filled 32768-byte
`fixture.bin`. Seed with the old provider and allow the project to save:

```sh
"$OLD_GHIDRA/support/analyzeHeadless" "$WORK/projects" Instructions \
  -import "$WORK/fixture.bin" -loader BinaryLoader \
  -processor SM83:LE:16:default -cspec default -noanalysis \
  -scriptPath "$GHIDRABOY/src/test/scripts" \
  -postScript GhidraBoyInstructionCompatibility.java seed "$WORK/seed.txt"
```

Preserve that old project and work on a copy when opening it under the candidate.
Run check mode on the saved Program, allow a save, then run the same check once
more with `-readOnly` to validate a subsequent reopen:

```sh
"$NEW_GHIDRA/support/analyzeHeadless" "$WORK/projects" InstructionsCopy \
  -process fixture.bin -noanalysis \
  -scriptPath "$GHIDRABOY/src/test/scripts" \
  -postScript GhidraBoyInstructionCompatibility.java check "$WORK/check.txt"
```

Require `INSTRUCTION_COMPATIBILITY_PASS instructions=501`, zero reported
mismatches, and no script errors. A negative control using the withdrawn
specialized-POP provider fails this test on persisted POP AF p-code; it must
remain a failing diagnostic, never an accepted compatibility result.

This compact corpus does not replace validation of a user's annotated Program.
For a migration, freeze the original instruction roster and compare saved
instructions against fresh decoding under the candidate, then validate save/reopen
on a copy. Unexpected old/new p-code differences need explanation; intended
semantic improvements are distinct from saved/fresh decode mismatches, which
must be zero. Do not delete or redisassemble existing instructions merely to
make a preservation comparison pass. Retain the complete original Program/GZF;
an instruction inventory is not a Program backup.
