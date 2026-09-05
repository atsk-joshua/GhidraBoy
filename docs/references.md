# Sources and provenance

- Upstream baseline: https://github.com/Gekkio/GhidraBoy/tree/42032f9d97e9e502dc10a14743bdb3d1b9388588
- Compatibility port: https://github.com/ptthess/GhidraBoy-12.1.2-port/tree/91169cd0bcf3039689d6a9ca4e915fbf14d2cbf4
  The three requested commits were cherry-picked with -x and original authors.
  No overlapping DohmBoy/pbiswal port or dual-version source-set refactor used.
- Exact API implementation inspected in the installed Ghidra 12.1.3 source ZIPs:
  AbstractProgramLoader, Memory, MemoryBlockSourceInfo, FileBytes,
  EndianSettingsDefinition, PrototypeModel and parameter allocation definitions.
- Official release/digest: https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.3_build
- Language versioning: https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/GhidraDocs/languages/versioning.html
- Cartridge/mapper references: https://gbdev.io/pandocs/The_Cartridge_Header.html
  and https://gbdev.io/pandocs/MBC1.html (also MBC2, MBC3, MBC5).
- Symbol grammar: https://github.com/gbdev/rgbds-www/blob/master/src/pages/sym.mdx
- DAA cross-check: https://github.com/LIJI32/SameBoy/blob/v1.0.3/Core/sm83_cpu.c
- CPU vectors: https://github.com/SingleStepTests/sm83/tree/f9c30210245dd691661db39f5ace022c465ecc2f
- Hardware reference bundled under CC0: https://github.com/gbdev/hardware.inc/tree/189324b77f99cf287f4153e0001830e8738a4068
  Includes original attribution/license; version 5.3.0. Register descriptions and
  interrupt masks are available on new imports without replacing user comments.
- Compiler archive: https://github.com/gbdk-2020/gbdk-2020/releases/tag/4.5.0
  Exact digest and emitted-code command appear in compiler-support.md.

Useful online processor/manual references (no proprietary PDFs bundled):
https://gbdev.io/pandocs/ and https://rgbds.gbdev.io/docs/gbz80.7 .
