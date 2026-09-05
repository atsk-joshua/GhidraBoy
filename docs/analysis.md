# Bounded static analysis

`BankAnalysis.analyze(program, start, explicitState, monitor, apply)` is opt-in
and operates on existing defined instructions. The worklist is bounded to 4096
address/state/register-constant combinations. Null state is unknown. Simple
COPY, zero extension, add/subtract, bitwise and shifts propagate constants;
unmodeled outputs become unknown. Register overlap is tracked bytewise. Unique
p-code temporaries are reset per instruction. Unknown stores invalidate mapper
state; unknown calls clear state and register knowledge on return. Internal
p-code branches are conservatively not interpreted as arithmetic paths.

Both STORE and direct-memory output varnodes are inspected: real Ghidra SLEIGH
may encode `LD (2000),A` as a direct memory assignment. A known mapper write
re-resolves its next CPU address into the new execution view. It does not
continue stale-bank fallthrough. Calls/jumps use explicit mapper state, and
merged candidates are retained; any unresolved alternative prevents a confident
supplemental reference. Data is never swept as code. Findings are printed,
persisted in options and bookmarked. Existing operand references are preserved;
owned supplemental references are removed on a subsequent applied run only if
the recorded source/type/target still match.

References are descriptive and do not promise rewritten decompiler indirect
flow. No live bank is selected and ROM remains read-only. The analysis currently
has no general interprocedural summaries or arbitrary far-call recovery. Indirect
sites and undefined fallthrough are reported for review.

`FarCallConvention` is an explicit per-program opt-in for one exact MBC3
trampoline: pop the RST return, read inline bank:u8 and target:u16, push the
return advanced by three payload bytes, then transfer via pushed target/RET.
The exact body bytes and each RST site are validated before any mutation. It
adds a fallthrough override past the inline payload and a provenance bookmark;
the trampoline remains visible in p-code. A compiled-p-code fixture executes the
trampoline and verifies target entry, adjusted return and restored SP. It is not
a generic RST 28 interpretation. MBC1 versions would require additional high-
register assumptions and are deliberately unsupported.

`FunctionDiscovery` accepts existing entry points, explicit declared-code seeds,
and proven direct-call conclusions. It creates functions only at defined code,
leaving existing function bodies and all marked data intact; it does not sweep
banks or treat every symbol/vector as a function.

Known ROM overlay identity can resolve same-window control flow when no mapper
write intervenes; it does not establish unrelated RAM/VRAM/data selections.
Unknown call returns re-resolve fallthrough: ordinary fixed low windows remain
known, while banked/MBC1-remappable windows stop without an explicit state.
