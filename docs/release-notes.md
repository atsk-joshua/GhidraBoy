# 20260905-dev2 — hardening preview

All six independently reproduced audit defects have maintained regressions and
fixes: incomplete analysis no longer publishes a singleton as proof; wide accesses
apply every byte; reachable bank-zero execution views exist; fallthrough crosses
CPU windows correctly; shared symbol sources retain independent claims; BOOT
symbols cannot leak through RAM aliases.

Analysis now has typed completion and confidence, partial mapper knowledge,
canonical dependency fingerprints and persisted ownership for safe removal and
reapplication. Far-call support is restricted to verified fixed-ROM callers,
because the supported trampoline does not restore the bank.

Manual salvage retains original tails and incomplete input without inventing
mapper certainty. Mapping schema v2 describes provenance, support and unmapped
ranges. Symbols gain source lifecycle, deliberate companion lookup, filtering,
Unicode escapes and end-marker placement. Per-function compiler storage is backed
by current and actual historical SDCC fixtures. Sourced hardware masks and a native
manual index are included.

Actual Ghidra 11.3.1 database upgrade and reanalysis are tested separately from the
old-language-on-12.1.3 fixture. Build evidence records actual reports, vector counts,
dependency pins and reproducible ZIP hashes. The target remains Ghidra 12.1.3/JDK21;
language and default compiler identifiers, register layout and 16-bit pointers stay
unchanged. Keep project backups and follow user-workflows.md for rollback.

This remains a development preview pending installed GUI acceptance. General
runtime banking, arbitrary far calls, exotic mapper wiring, universal SDCC support
and cycle/interrupt timing are outside the supported static model. No GhiGBC
integration, push or release publication is part of this continuation.
