# M7 static/live mapping conformance

Implemented 2026-09-06 in `debugger/ghidra-extension/src/main/java/ghigbc/BankMappings.java`.

The adapter maps the provider's explicit `MBC2_RAM` identity to the existing live `cart` vocabulary. The live numeric cart region remains 4; static mapping schema 2 and adapter envelope version 1 remain unchanged. Reverse lookups retain physical bank/offset identity. Candidate lookup includes both static SRAM and MBC2_RAM identities and retains ambiguity instead of choosing a mapper by block name.

For MBC2, `Machine.Mapper == "MBC2"` selects sixteen 512-byte CPU windows across `a000–bfff`. All windows resolve to the same 512 physical cells. Captures without Mapper recover MBC2 identity from actual static MBC2_RAM ranges. Disabled cartridge RAM and RTC selection do not claim CPU SRAM mappings. Physical `cart0` still maps the canonical low-nibble storage. A static mapping expresses storage coordinates, not equality of captured bytes: a stored physical nibble `0b` appears as CPU read value `fb`. Existing provider-created CPU aliases remain selectable; their reverse identities identify the same cell.

While `Machine.Boot` is true, the adapter subtracts `Machine.BootRanges` from the low ROM window. BootRanges is JSON containing sorted, nonoverlapping half-open integer intervals: DMG `[[0,256]]`, CGB `[[0,256],[512,2304]]`. Current Python publishes a string; the reader also accepts UTF-8 bytes. Missing legacy metadata conservatively reserves both CGB boot windows. Malformed metadata withholds low ROM CPU mappings and records a MappingIssues diagnostic. Boot unmap restores the complete low ROM window. Physical ROM capture mappings remain available while CPU boot windows are hidden.

## Reproducible check

From the GhidraBoy root, select Java 21 and a Ghidra 12.1.3 distribution with the static SM83 provider installed, then run:

```sh
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
export GHIDRA_INSTALL_DIR=/tmp/ghidraboy-switch-recovery2-mac-final/distribution
export GRADLE_USER_HOME=/tmp/ghidraboy-switch2-gradle-cache
./gradlew -PwithDebugger=true :GhiGBC:check
bash debugger/scripts/test_m7_mappings.sh
```

The source runner selects the static provider JAR from `build/integration/artifacts.json`, compiles the mapping adapter and isolated Java harness, and creates a fresh home/project under `debugger/build`. It requires the existing self-authored `debugger/build/teaching.gbc` fixture. Frozen acceptance/performance harnesses and packages are not changed.

`M7MappingContractTest.java` imports a real 32 KiB DMG MBC2 cartridge through the installed Game Boy loader and uses a real DBTrace and static mapping manager. It verifies MBC2 bank recognition, all sixteen static and CPU mirror identities, physical and CPU nibble-coordinate distinctions, DMG/CGB/legacy boot windows, boot unmap, disabled cart/RTC exclusions, invalid metadata diagnostics, legacy Mapper fallback, and preserved historic mappings. Native core execution and Trace RMI transport are outside this isolated test; the nibble values are explicit trace fixtures, so native/Python conformance remains necessary to prove the emulator supplies them.

The native macOS Java compile and isolated mapping test passed. Retained local test output: `debugger/build/m7-evidence/mapping-contract.log`. Ghidra emits pre-existing AutoImporter deprecation warnings; these do not fail compilation or conformance. No user Program, staged files, or frozen performance artifacts were modified by the test.
