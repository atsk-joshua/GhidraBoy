# GhidraBoy Debugger

Integration candidate for Game Boy/Game Boy Color debugging with Ghidra 12.1.3, Java 21 and an existing Python 3.9+ interpreter. This package contains the static GhidraBoy extension, the compatible debugger extension, the selected prebuilt emulator runtime(s), and synthetic validation fixtures. `suite.json` records `sameboy`, experimental `mgba`, or both; the default build selects SameBoy.

Use [installation and rollback](docs/INSTALL.md) to select the correct Ghidra distribution and native decompiler companion. With Ghidra closed:

```sh
bash Setup.sh --ghidra "/path/to/selected/distribution" --java-home "/path/to/java-21"
```

Restart Ghidra, import a supported ROM, open its Debugger tool, and select the launch offer for an installed backend: GBC / SameBoy or GBC / mGBA (experimental). Execution controls, registers, physical-bank breakpoints and captured history use the normal debugger services. Historical selection is observational; SameBoy edits require paused experiment mode and a recovery checkpoint. The experimental mGBA adapter supports native CGB/MBC5 without rumble and execution breakpoints; watches, checkpoint restore, and experiment edits are unavailable. It uses engine post-boot state without a boot ROM.

`Validate.sh` runs native and real installed Trace RMI checks; `Validate.sh --ui` selects interactive debugger acceptance for the SameBoy candidate. mGBA packages run the common capability-negotiated real RMI harness. Set `GHIDRA_INSTALL_DIR`, `JAVA_HOME`, and an isolated `GBC_TEST_HOME` when validating a candidate. `Collect-results.sh` collects diagnostic results. Successful automated checks do not establish physical Steam Deck or interactive GUI acceptance.

- [Current support and limitations](docs/SUPPORT.md)
- [Native observation semantics](docs/NATIVE_CONTRACT.md)
- [Static/live mapping](docs/contracts/mapping.md)
- [Optional research profiles](docs/contracts/profiles.md)

The archive's `suite.json` records exact file identities, dependencies and required native decompiler metadata. Python dependencies are installed offline in an isolated environment. No compiler, Gradle, RGBDS or source checkout is required on the runtime host. Game-specific GhiBW3 profiles remain optional and require a matched composition.

Component attribution and licenses are retained under LICENSES. Packages including mGBA also carry complete pinned corresponding source and rebuild instructions in docs/MGBA_SOURCE.md. Private ROMs, Programs, saves and checkpoints are not distributed.
