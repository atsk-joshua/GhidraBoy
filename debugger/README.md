# GhidraBoy debugger

Optional live Game Boy/Game Boy Color debugging through Ghidra Trace RMI.
SameBoy is the reference backend; mGBA supplies an experimental CGB/MBC5 tier.
The root extension remains the sole SM83 provider.

Use the [support matrix](docs/SUPPORT.md) for exact execution, watch, checkpoint,
edit and saved-work capabilities. Unsupported actions are withheld or rejected.
Captured history and portable observation reports retain their original identities
and can be reviewed independently of live execution.

- For a prebuilt package, follow [installation, upgrade and rollback](docs/INSTALL.md). Its commands run from the extracted package root.
- For source builds, follow [building and packaging](../docs/building.md).
- For tests and exact-artifact qualification, follow [validation](../docs/validation.md).
- For extension authors, use the [mapping](docs/contracts/mapping.md), [profile](docs/contracts/profiles.md) and [backend](docs/contracts/backend.md) contracts.

The installed extension ID remains `GhiGBC`; this is the GhidraBoy debugger's
compatible module identity. See the [identity inventory](../docs/debugger-identities.md)
before changing names used by launchers, saved tools, runtime imports or journals.

Credit and component notices remain with SameBoy, mGBA, Ghidra, RGBDS and
GhidraBoy under LICENSES. Private ROMs, Programs, traces and checkpoints are
excluded from distributable packages.
