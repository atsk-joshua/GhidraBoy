# Static contract v2

This is GhidraBoy's Java/JSON contract, consumed by the GhiGBC adapter v1 in the
local 12.1.3 integration candidate. GhidraBoy provides no debugger, execution engine,
telemetry or live bank selection. GhiGBC owns runtime translation, ambiguity policy,
trace lifespans and versioned static snapshot transport.

`ProgramMapping.inspect(Program)` returns a deterministic, sorted snapshot.
`mapping-schema.json` describes the exported envelope. The schema is validated against actual exported snapshots using jsonschema 4.25.1.
Language/compiler IDs,
original FileBytes SHA256/length, raw header, calculated checksums, selected
hardware, mapper, warnings, source ranges, permissions and aliases are included.
Program options persist the parsed cartridge and override provenance; Ghidra
address property maps anchor RAM identities. Input bytes are never repaired on
import. The original SHA256 is distinct from `Sha256.of(exportBytes(..., true,
false, monitor))`, which describes current patches.

Physical identity is `(region, bank, offset)`: ROM banks are 16 KiB, WRAM banks
4 KiB, VRAM/SRAM banks 8 KiB; MBC2_RAM is 512 byte-addressed low-nibble entries.
Ranges may be portions of a bank. Names like `rom18` are decimal presentation
only. FileBytes sources establish ROM identity after rename, split or join.
Alias targets use the Program address factory, including real overlay spaces.
The API never uses a language-only factory for program overlays. RAM without
loader anchors remains unresolved in legacy programs. An explicit anchor can
be added with `ProgramMapping.identifyRam` with checked interval bounds after a human
identifies its region and bank; topology is never silently recreated.

`physicalToStatic`, `fileToStatic` return lists (empty = unmapped, multiple =
several views). `staticToPhysical` follows byte aliases and returns identities.
`MapperState.translate(cartridge, state, cpu, write)` reports mapped, unknown,
unmapped or device results. Null mapper state never assumes bank 1. Explicit
state JSON example:

```json
{"romLow":1,"romHigh":0,"mode":0,"ramSelect":0,"ramEnabled":false,"vbk":0,"svbk":1,"latch":0}
```

Write ROM addresses are mapper control operations, not ROM patches. I/O and RTC
selections are device results. A byte-mapped ROM view does not make writes
redirect automatically in Ghidra p-code: CPU p-code still addresses the static
`ram` space. Analysis records those controls in bookmarks and only adds
supplemental references when justified. References do not rewrite indirect
p-code or implement dynamic memory banking.

The present schema is a snapshot, not a live protocol. Space names can change;
regenerate snapshots after renaming or editing topology. Stable physical ROM
identity is reconstructed from actual sources, not exported display strings.
Multilevel/custom byte mapping and manually detached ROM blocks require review;
not every arbitrary third-party topology is reconstructible.


Schema v2 includes typed cartridge/header/geometry/support states, structured
request provenance (requested/selected mode, mapper override/selection, hardware
and its source), physical/source ranges with permissions and alias relationships,
and explicit known-unmapped original file intervals. Unknown, RAW-only and device
states are not converted to mapped certainty. Deterministic sorting is separate
from display names, which are not stable identities.

MapperTopology derives execution aliases from the mapper's reachable windows.
Every supported reachable ROM/window pair has a shared-byte view. Unsupported
wiring stays explicit; the loader does not duplicate storage to invent views.
Existing annotated legacy Programs are enhanced with metadata, never automatically
rebuilt to match new-import topology. Exact static endpoints use the Program's
actual overlay space, including end markers beyond its initialized extent.

Original export reads immutable FileBytes; current export starts with those bytes
and overlays established patches. Known-unmapped tails remain intact. Lost,
conflicting or detached sources produce explicit rejection rather than being
mistaken for a known-unmapped interval. Mapping schema versioning is independent
of SLEIGH language versioning; language 1.0 remains appropriate for p-code-only
changes with unchanged decode/register/context definitions.
