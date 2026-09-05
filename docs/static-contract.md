# Static contract v1

This is GhidraBoy's local Java/JSON contract. It is not agreed with, consumed by,
or integrated into GhiGBC. No debugger, execution engine, telemetry or live bank
selection is provided.

`ProgramMapping.inspect(Program)` returns a deterministic, sorted snapshot.
`mapping-schema.json` describes the exported envelope. Language/compiler IDs,
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
be added with `ProgramMapping.anchor` inside a transaction after a human
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
