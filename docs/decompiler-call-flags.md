# Assembly call flag effects

A native Ghidra 12.1.3 regression established that the old assembly-default
`__asm` compiler model incorrectly retained incoming F across a call. F was
neither a candidate return register nor listed as killed by calls.

The self-authored fixture sets carry with SCF, calls a two-instruction
`CCF; RET` callee, then writes 1 or 2 to work RAM depending on carry. Compiled
SLEIGH execution writes 2, because the callee clears carry. Before the fix,
native C tests the pre-call value `0x10` after the call, selecting 1. A second
fixture without SCF uses `in_F` after the call. Neither output produces a warning;
the defect is semantic, not diagnostic noise.

The default compiler model now lists F in `killedbycall`. Both callers use the
call-produced `extraout_F` instead of the old flag value. The decompiler
regression checks that recovered F has an INDIRECT definition and independently
executes the fixture's compiled p-code, covering initial carry set and clear.
Unknown calls remain calls: the default does not inline or infer the callee's
flag-returning convention.

This correction is intentionally conservative. `extraout_F` is still an
unexplained return value in C-like output, and a `CCF; RET` callee with a default
void signature does not explain its flag result. Use independently proven
per-function storage/signatures or preservation conventions for accurate
interprocedural interpretation. Do not annotate all commercial-ROM functions
with a guessed C ABI, or treat the absence of a warning as complete recovery.

The before/after native outputs and emulator result are retained locally in
`/tmp/gbw3-semantics-review/flags-call-before-results.txt` and
`flags-call-killed-results.txt`. The experiment used a private Ghidra copy and
self-authored bytes; the user's installation and ROM were not modified.

Only assembly `__asm` call effects changed. Explicit SDCC profiles already
listed AF among their killed registers. Instruction decoding, raw CPU p-code,
register layout, and memory mappings are unchanged. Existing explicit storage
and annotations are not replaced.
