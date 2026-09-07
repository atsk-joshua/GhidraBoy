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

## Static analysis reference catalog

Reviewed 2026-09-07 for the [research record](static-analysis-research.md) and
[planned specification](static-analysis-spec.md). Version-pinned source is the
authority for the targeted Ghidra behavior. Floating documentation and game
repositories below are research references, not new build dependency pins;
capture exact revisions/hashes when creating implementation fixtures. Keep
hardware observations, code-derived facts, compiler contracts and emulator
heuristics distinct. Newer documentation alone does not change current support.

### Ghidra semantics and integration

| Source | Use and limitation |
| --- | --- |
| [SLEIGH manual](https://ghidra.re/ghidra_docs/languages/html/sleigh.html) and [p-code operation reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html) | Instruction effects, widths, address spaces, userops, and call/branch/return semantics |
| [12.1.3 compiler specification](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Features/Decompiler/src/main/doc/cspec.xml) | Register strategy, stack, call effects and fixups; descriptions require matching implementation tests |
| [Parameter model rules](https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/protorules/package-summary.html) | Candidate replacement for some manual ABI allocation; full SDCC expressibility unproven |
| [InstructionDB](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/code/InstructionDB.java) and [InstructionPcodeOverride](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/InstructionPcodeOverride.java) | Stored flow references versus raw/overridden p-code; [reference override constraints](https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/RefType.html) |
| [Nonreturn analyzer](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/FindNoReturnFunctionsAnalyzer.java) | Analysis ordering, fallthrough callfixups and automatic CALL_RETURN decisions |
| [SymbolicPropogator](https://ghidra.re/ghidra_docs/api/ghidra/program/util/SymbolicPropogator.html), [AbstractAnalyzer](https://ghidra.re/ghidra_docs/api/ghidra/app/services/AbstractAnalyzer.html) and [shift behavior](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Framework/Emulation/src/main/java/ghidra/pcode/opbehavior/OpBehaviorIntRight.java) | Reuse candidates for analysis scheduling and width-correct evaluation |
| [FunctionManagerDB](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/function/FunctionManagerDB.java), [native flow](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Features/Decompiler/src/decompile/cpp/flow.cc) and [DecompInterface](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html) | Body address-space restrictions, overlay transport, cache invalidation and debug dumps |
| [HCS12 semantics](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Processors/HCS12/data/languages/HCS_HC12.sinc) and [segment specification](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Processors/HCS12/data/languages/HCS12.pspec) | Paging precedent, not a complete or automatically suitable GB model |
| [JVM jumpassist](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Processors/JVM/data/languages/JVM.pspec), [native jump tables](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Features/Decompiler/src/decompile/cpp/jumptable.cc) and [value-set solver](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Features/Decompiler/src/decompile/cpp/rangeutil.cc) | Recovery mechanisms with constant-metadata, address-space and memory/call-analysis limits |
| [Improving Disassembly and Decompilation](https://ghidra.re/ghidra_docs/GhidraClass/Advanced/improvingDisassemblyAndDecompilation.pdf) | Official workflow for calls, control flow, types, mutability and troubleshooting; not permission to hide warnings |
| [SourceFileManager](https://ghidra.re/ghidra_docs/api/ghidra/program/model/sourcemap/SourceFileManager.html) and [pointer typedef inspection](https://ghidra.re/ghidra_docs/api/ghidra/program/database/data/PointerTypedefInspector.html) | Native metadata integration; pointer modifiers do not by themselves implement mapper state |
| [12.1.3 language versioning](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/GhidraDocs/languages/versioning.html) | Separate p-code changes from constructor/context/register changes and migrations |

### Upstream issues and proposals

These describe relevant failure classes; their status does not qualify this
project's exact case. Recheck before selecting an upstream dependency change.

- [#9349: context-aware bank resolution](https://github.com/NationalSecurityAgency/ghidra/discussions/9349): Ideas proposal, not an implemented API in the inspected 12.1.3.
- [#6651: handling banked ROM](https://github.com/NationalSecurityAgency/ghidra/discussions/6651) and [#7052: 8051 code-bank switching](https://github.com/NationalSecurityAgency/ghidra/issues/7052): related representation problems.
- [#5747: pushed return plus JMP](https://github.com/NationalSecurityAgency/ghidra/issues/5747): software-call continuation problem; open when reviewed.
- [#889: nonreturn decisions reasserted by analysis](https://github.com/NationalSecurityAgency/ghidra/issues/889): historical closed question, not evidence of a universal fix.

### Hardware and cartridge research

- [Pan Docs source and chapter index](https://github.com/gbdev/pandocs/blob/master/src/SUMMARY.md): CPU, boot, CGB mode, interrupts, DMA, memory, devices and cartridge chapters. Its [references](https://github.com/gbdev/pandocs/blob/master/src/References.md) lead to underlying research.
- [Gekkio, GB: Complete Technical Reference](https://gekkio.fi/files/gb-docs/gbctr.pdf), directly retrieved revision **192, 2026-08-16**, and [source](https://github.com/Gekkio/gb-ctr). Preface limits generalization to CGB; MMM01/TAMA5 chapters remain TODO. Older indexed revision 184 is not the reviewed edition.
- [RGBDS SM83 instruction manual](https://github.com/gbdev/rgbds/blob/master/man/gbz80.7): instruction/flag/encoding reference; use SM83, not a generic Z80 manual.
- Pan Docs [MBC1/MBC1M](https://github.com/gbdev/pandocs/blob/master/src/MBC1.md), [MBC2](https://github.com/gbdev/pandocs/blob/master/src/MBC2.md), [MBC3/MBC30](https://github.com/gbdev/pandocs/blob/master/src/MBC3.md), [MBC5](https://github.com/gbdev/pandocs/blob/master/src/MBC5.md): ordinary and variant wiring, aliases and device selection.
- Pan Docs [MBC6](https://github.com/gbdev/pandocs/blob/master/src/MBC6.md), [MBC7](https://github.com/gbdev/pandocs/blob/master/src/MBC7.md), [MMM01](https://github.com/gbdev/pandocs/blob/master/src/MMM01.md), [M161](https://github.com/gbdev/pandocs/blob/master/src/M161.md), [Camera](https://github.com/gbdev/pandocs/blob/master/src/Gameboy_Camera.md), [other mappers](https://github.com/gbdev/pandocs/blob/master/src/othermbc.md): smaller windows, flash/EEPROM, alternate startup and board-specific state.
- [HuC1 original research](https://jrra.zone/blog/huc1.html), [HuC3 research discussion](https://gbdev.gg8.se/forums/viewtopic.php?id=744) and [Pan Docs HuC3](https://github.com/gbdev/pandocs/blob/master/src/HuC3.md): inspect unknowns and conflicting geometry rather than treating all descriptions as equally complete.
- [Game Boy hardware database](https://gbhwdb.gekkio.fi/): board/chip evidence for controller and wiring identity; a header alone need not distinguish variants.
- [mGBA TAMA5](https://github.com/mgba-emu/mgba/blob/master/src/gb/mbc/tama5.c), [HuC3](https://github.com/mgba-emu/mgba/blob/master/src/gb/mbc/huc-3.c), and [unlicensed mappers](https://github.com/mgba-emu/mgba/blob/master/src/gb/mbc/unlicensed.c): implementation comparisons; not independent proof of every hardware behavior.
- [Mooneye tests](https://github.com/Gekkio/mooneye-test-suite) and [SameSuite](https://github.com/LIJI32/SameSuite): preserve hardware-model and acceptance/emulator-only distinctions. SingleStepTests above assumes flat RAM and cannot validate mapper/bus behavior.

### Game construction and metadata

- GBDK 4.5.0 [current banked call](https://github.com/gbdk-2020/gbdk-2020/blob/4.5.0/gbdk-lib/libc/targets/sm83/___sdcc_bcall_ehl.s), [legacy banked call](https://github.com/gbdk-2020/gbdk-2020/blob/4.5.0/gbdk-lib/libc/targets/sm83/___sdcc_bcall.s), [far-pointer type](https://github.com/gbdk-2020/gbdk-2020/blob/4.5.0/gbdk-lib/include/gbdk/far_ptr.h) and [helper](https://github.com/gbdk-2020/gbdk-2020/blob/4.5.0/gbdk-lib/libc/targets/sm83/far_ptr.s), plus [calling guidelines](https://gbdk.org/docs/api/docs_coding_guidelines.html) and [SDCC manual](https://sdcc.sourceforge.net/doc/sdccman.pdf). Exact emitted-code fixtures decide version-specific allocation; contemporary GBDK is not a universal commercial-game ABI.
- RGBDS [assembly/LOAD/UNION/charmaps](https://github.com/gbdev/rgbds/blob/master/man/rgbasm.5), [object/source/relocation format](https://github.com/gbdev/rgbds/blob/master/man/rgbds.5), [linker scripts](https://github.com/gbdev/rgbds/blob/master/man/rgblink.5) and [linker options](https://github.com/gbdev/rgbds/blob/master/man/rgblink.1). Pin format revisions when importing metadata.
- [WLA-DX bank/slot directives](https://wla-dx.readthedocs.io/en/latest/asmdiv.html): separate slot addresses from ROM banks; its metadata is not RGBDS .sym syntax.
- Reconstructed Crystal [far calls](https://github.com/pret/pokecrystal/blob/master/home/farcall.asm), [RST helpers](https://github.com/pret/pokecrystal/blob/master/home/header.asm), [HRAM unions](https://github.com/pret/pokecrystal/blob/master/ram/hram.asm), [VBlank](https://github.com/pret/pokecrystal/blob/master/home/vblank.asm), [event interpreter](https://github.com/pret/pokecrystal/blob/master/engine/overworld/scripting.asm), and [audio engine](https://github.com/pret/pokecrystal/blob/master/audio/engine.asm): concrete software patterns, not original compiler provenance.
- Reconstructed Red [bank switching](https://github.com/pret/pokered/blob/master/home/bankswitch.asm) and LADX [copy helpers](https://github.com/zladx/LADX-Disassembly/blob/main/src/code/home/copy_data.asm), [interrupts](https://github.com/zladx/LADX-Disassembly/blob/main/src/code/home/interrupts.asm), [engine documentation](https://github.com/zladx/LADX-Disassembly/wiki/Game-engine-documentation): compare multiple conventions before generalizing. Do not redistribute game-derived artifacts as generic fixtures.
