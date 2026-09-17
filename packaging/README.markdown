# GhidraBoy

Game Boy/Game Boy Color static analysis for Ghidra 12.1.3 and Java 21. This development extension provides SM83 instruction semantics, cartridge/boot import, bank-aware mapping, symbols, conservative analysis and per-function compiler conventions.

Install this ZIP through Ghidra's extension manager and restart Ghidra. Static analysis does not require an emulator, Python runtime or SDL. The optional GhidraBoy debugger runtime is distributed separately.

Open a prepared Program, inspect Tools → GhidraBoy → Program Status..., then use Analysis → Auto Analyze... and run **GhidraBoy Bank and Mapper Analysis**. Basic analysis does not require Script Manager, MapperState JSON or a proof file. Existing language-v1 Programs require the separately packaged outer migration workflow before opening the migrated copy normally.

- [Import, navigation, symbols and export](docs/user-workflows.md)
- [Supported inputs and mappers](docs/input-policy.md)
- [Analysis and annotation preservation](docs/analysis.md)
- [Compiler conventions](docs/compiler-support.md)
- [Instruction semantics and validation limits](docs/cpu-validation.md)
- [Static mapping contract](docs/static-contract.md)
- [Development roadmap and planned static accuracy](docs/roadmap.md)
- [Native decompiler dependency and reversible installation](docs/native-decompiler/install-and-rollback.md)

The current decompiler fixes use the separately versioned native dependency `12.1.3+ghidraboy.switch-recovery.2`. Its platform archive and copy-only updater preserve the original Ghidra installation. The extension ZIP alone does not install that native update. Observe the documented hardware, mapper and analysis limits; this candidate does not claim every feature or platform is qualified.

GhidraBoy retains Joonas Javanainen/Gekkio and contributor attribution. See LICENSE and LICENSES for the component notices.
