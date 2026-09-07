# Processor and compiler specifications

These instructions supplement the [root instructions](../../AGENTS.md).
Read [instruction compatibility](../../docs/instruction-compatibility.md),
[CPU validation](../../docs/cpu-validation.md),
[compiler support](../../docs/compiler-support.md) and the relevant
[static-accuracy requirements](../../docs/static-analysis-spec.md).
Run commands from the repository root.

- SLEIGH defines architectural instruction behavior. Keep game-specific
  conventions out of unconditional instruction constructors.
- Preserve byte widths, wrapping, overlapping registers, flags and ordered
  memory effects.
- CALL/CALLIND p-code does not implicitly push a return address. Account for
  real stack effects when modeling software calls.
- Distinguish processor semantics from ABI rules and per-function knowledge.
  Assembly remains the default without evidence for a compiler convention.
- Constructor identity and pattern matching affect saved instructions.
  Unchanged display or length does not establish saved-Program compatibility.
- Follow Ghidra language-versioning rules; do not arbitrarily freeze or bump
  versions. Record the decision and test the corresponding migration.
- Do not replace architectural operations with opaque userops solely to make
  C output cleaner. Verify data flow and execution behavior.
- Test compiled SLEIGH, native decompilation and relevant saved/fresh decoding.
  Add boundary and negative cases, not only the motivating example.
- Edit source specifications, not generated .sla files.
