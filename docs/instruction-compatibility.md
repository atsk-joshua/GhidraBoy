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

## Installed language-1 to language-2 upgrade

The extension now packages the actual final-language-1 storage descriptor and an
explicit simple translator. See the [compatibility decision](decisions/sm83-v1-v2-compatibility.md).
Keep the complete original project closed and backed up. Open only a disposable
copy with the candidate installation. Inspect the initial translated state before
running enhancement or analysis; save and close, then verify the saved current
Program immutably in another process. Canonical code must keep analysis-entry mode
zero. Existing incompatible executable records remain historical data and refuse
unsupported use/removal; language translation is not proof migration.

The reusable final-version-1 qualification command is:

```sh
python3 tools/sm83_compatibility.py --old-ghidra "$OLD_COPY" \
  --ghidra "$NEW_COPY" --zip "$CANDIDATE_ZIP" --jdk "$JAVA_HOME" \
  --work "$NEW_EVIDENCE_DIRECTORY"
```

Both installations must be task-owned temporary copies. The runner verifies the
ten old language inputs against the recorded source, retains the old project and
complete 501-instruction inventory, uses installed core translation, then a first
immutable reopen and cancellation/recovery checks. The existing installed runner
still exercises `42032f9`; the migration runner still creates a real 11.3.1 database
and preserves its intentional ADC correction. Enhancement/reanalysis has its own
later disposable copy, distinct from the first immutable observation.
