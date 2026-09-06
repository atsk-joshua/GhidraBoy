# GhidraBoy Debugger

Integration candidate for Game Boy/Game Boy Color debugging with Ghidra 12.1.3, Java 21 and an existing Python 3.9+ interpreter. This package contains the static GhidraBoy extension, the compatible debugger extension, a prebuilt SameBoy runtime, and synthetic validation fixtures. Further backends are not yet supported by this package.

Use [installation and rollback](docs/INSTALL.md) to select the correct Ghidra distribution and native decompiler companion. With Ghidra closed:

```sh
bash Setup.sh --ghidra "/path/to/selected/distribution" --java-home "/path/to/java-21"
```

Restart Ghidra, import a supported ROM, open its Debugger tool, and select the GBC / SameBoy launch offer. Execution controls, registers, physical-bank breakpoints and captured history use the normal debugger services. Historical selection is observational; edits require paused experiment mode and a recovery checkpoint.

`Validate.sh` runs native and real installed Trace RMI checks; `Validate.sh --ui` selects interactive debugger acceptance. Set `GHIDRA_INSTALL_DIR`, `JAVA_HOME`, and an isolated `GBC_TEST_HOME` when validating a candidate. `Collect-results.sh` collects diagnostic results. Successful automated checks do not establish physical Steam Deck or interactive GUI acceptance.

- [Current support and limitations](docs/SUPPORT.md)
- [Native observation semantics](docs/NATIVE_CONTRACT.md)
- [Static/live mapping](docs/contracts/mapping.md)
- [Optional research profiles](docs/contracts/profiles.md)

The archive's `suite.json` records exact file identities, dependencies and required native decompiler metadata. Python dependencies are installed offline in an isolated environment. No compiler, Gradle, RGBDS or source checkout is required on the runtime host. Game-specific GhiBW3 profiles remain optional and require a matched composition.

Component attribution and licenses are retained under LICENSES. Private ROMs, Programs, saves and checkpoints are not distributed.
