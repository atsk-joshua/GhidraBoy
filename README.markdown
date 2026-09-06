# GhidraBoy modernization (development preview)

Current target: **Ghidra 12.1.3, JDK 21**. The default build provides static CPU,
cartridge, mapping and script tooling. The optional [debugger module](debugger/README.md)
adds SameBoy execution and Trace RMI; qualification of the integrated release is
tracked in the [integration ledger](docs/integration/progress.md).

- [Install, import, navigation, symbols, export and rollback](docs/user-workflows.md)
- [Input and mapper policy](docs/input-policy.md)
- [Versioned Java/JSON static contract](docs/static-contract.md)
- [CPU validation](docs/cpu-validation.md)
- [Compiler support](docs/compiler-support.md)
- [Conservative analysis](docs/analysis.md)
- [Development release notes](docs/release-notes.md)
- [Interactive acceptance checklist](docs/gui-validation.md)
- [Acceptance evidence and remaining work](docs/modernization-evidence.md)
- [Primary sources and attribution](docs/references.md)

Build with `JAVA_HOME` pointing to JDK 21 and `GHIDRA_INSTALL_DIR` to 12.1.3:
`./gradlew clean build`. ZIPs appear in `build/distributions`. The documentation
records executed checks separately from incomplete requirements; this preview
must not be treated as completion of the full modernization acceptance matrix.

---

# GhidraBoy: Sharp SM83 / Game Boy extension for Ghidra

**Very experimental! No compatibility guarantees!**

Historical upstream releases (not production targets of this modernization branch):

- 11.4.2
- 11.4.1
- 11.3.2
- 11.3.1
- 11.3
- 11.2
- 11.1.2
- 11.1.1
- 11.1

![Tetris disassembly](screenshot.png)

## Features

* Sharp SM83 (CPU core used in Game Boy) support for Sleigh
* Game Boy ROM loader:
  - Can load unbanked ROMs (&lt;= 32kB, e.g. Tetris)
  - Can load banked ROMs (&gt; 32kB, e.g. Pokemon)
  - Can load greyscale boot ROMs (DMG/DMG0/MGB/SGB/SGB2)
  - Can load color boot ROMs (CGB/CGB0)
* Memory blocks based on the hardware memory map
  - Banked regions use overlays (TODO: figure out if there's a better way to
    support them)
  - GB vs GBC differences are handled (e.g. banked WRAM)
- Symbols for hardware registers (0xFFxx range)
  - GB vs GBC differences are handled (e.g. existence of KEY1 register)
* Game Boy cartridge header data types
  - Enumerated types for some things

## How to install

1. Download a [prebuilt GhidraBoy release](https://github.com/Gekkio/GhidraBoy/releases), or build it yourself.
2. Start Ghidra
3. File -> Install Extensions
4. Press the plus icon ("Add extension")
5. Choose the built or downloaded GhidraBoy zip file
6. Restart Ghidra when prompted to load the extension properly

## How to build

As a prerequisite, you need to have a Ghidra installation somewhere (an actual
installation, not a copy of Ghidra source code!).

```
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./gradlew
```

or

```
./gradlew -Pghidra.dir=/path/to/ghidra
```

You can then find a built extension .zip in the `build/distributions` directory.

## Open questions / problems

- Decompiler output is difficult to read if certain instructions are used (e.g.
  rotates, JP HL for jumptables)
- Default "ASM calling convention" assumes all registers can be inputs and/or
  outputs. Inputs/outputs are often guessed incorrectly, so manual tuning is
  required for almost every function
- Are overlays the only / the best solution for handling banked memory areas?
  Right now in banked ROMs every function call to 0x4000-0x7fff needs to be
  manually resolved to the correct bank(s)

## License

Licensed under the Apache License, Version 2.0.
