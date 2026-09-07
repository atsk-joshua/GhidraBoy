# Debugger implementation

These instructions supplement the [root instructions](../AGENTS.md).
Read [the debugger overview](README.md), [the support matrix](docs/SUPPORT.md)
and the relevant [backend](docs/contracts/backend.md),
[mapping](docs/contracts/mapping.md) and [profile](docs/contracts/profiles.md)
contracts. Check current code when historical contract wording conflicts with
the support matrix. Paths in commands are relative to the repository root unless
the referenced workflow explicitly says otherwise.

- Keep emulator internals and native ABI layouts inside backend adapters.
  Generic session, profile and trace code consumes normalized contracts.
- Preserve the static extension as the sole SM83 provider.
- Captures must preserve their original session, epoch, snapshot, physical
  identity and observation precision.
- Historical selections are observations, not authorization to mutate the
  current target. Validate action context before execution.
- Distinguish physical bytes, CPU-visible bytes, attempted accesses and
  committed effects. Keep unavailable observations explicitly unknown.
- Backend capabilities must reflect implemented and verified operations.
  Do not infer parity from a shared interface or successful startup.
- Preserve installed identifiers and saved-work readers. Consult
  [the identity inventory](../docs/debugger-identities.md) before changing
  compatibility surfaces.
- Verify pause, shutdown, connection and trace lifetimes. Logged service
  failures count even when the process exits successfully.
- Run the relevant pure, native, installed and lifecycle checks for the
  changed boundary. Use [validation](../docs/validation.md) to select them.
- Preserve checkpoint/trace provenance and private-asset exclusions.
  Package changes need manifest, installation and rollback verification.
