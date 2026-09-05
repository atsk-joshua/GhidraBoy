# Third-party provenance

- SameBoy core and open-source CGB boot ROM: LIJI32 and contributors, Expat/MIT. Pinned v1.0.3 commit in dependencies.lock.json. The shim links only core code, not Cocoa/SDL frontend source. Boot ROMs assembled locally from SameBoy/BootROMs using RGBDS; no Nintendo boot ROM downloaded.
- GhidraBoy: Joonas Javanainen and contributors, Apache 2.0. Release commit and compatibility patch recorded. Preserves original SM83 language ID and names. Its rebuilt extension includes its LICENSE.
- RGBDS: RGBDS contributors, MIT. Build tool for our self-authored teaching fixture and SameBoy boot assets.
- Ghidra/ghidratrace: National Security Agency, Apache 2.0; use the user's Ghidra 12.1.2 distribution and its matched wheels. Ghidra itself is not redistributed in the source package.
- SDL2: SDL contributors, zlib license; system/user installation dynamically loaded, not redistributed in the source package.
- `legacy/` contains the user's supplied Live Lab and Study Pack, preserved verbatim. Prior validation files are historical except where rerun evidence explicitly says otherwise.
- `tests/fixtures/banks.asm` is newly authored under MIT and can be redistributed. Commercial ROMs, GZF files, battery saves and checkpoints are excluded from packages.
- Linux cross-build uses Zig 0.14.1 (MIT; license included), targeting x86_64-linux-gnu.2.28. The Linux library's ELF header, exported ABI symbols and shared-library requirements are inspected; Linux execution is not claimed until the target tests pass.
