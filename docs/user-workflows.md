# Install and first use

Target **Ghidra 12.1.3, JDK 21**, using the checked-in Gradle 9.0.0 wrapper and
Kotlin 2.2.10. Development version: **20260905-dev3**. Set `JAVA_HOME` and
`GHIDRA_INSTALL_DIR`, then run `./gradlew clean build`. `SOURCE_DATE_EPOCH` is a
tracked metadata input, defaulting to 1788566400; use identical inputs when
comparing clean ZIPs. Do not compare hashes from different platforms as an
unqualified reproducibility result.

In the project window choose File → Install Extensions, add the ZIP from
`build/distributions`, and restart. Remove the previous GhidraBoy extension
before installing its replacement: two versions can leave conflicting JARs.
Keep a backup of the original extension and projects. Language ID
`SM83:LE:16:default`, compiler `default`, registers and 16-bit pointers are stable.

Standard cartridges use File → Import File and the Game Boy loader. Inspect its
options and warnings. For deliberate manual import, run `GhidraBoyImport.java`
from Script Manager's Game Boy category. Choose CARTRIDGE, SALVAGE, DMG_BOOT or
CGB_BOOT, then the hardware choice. This creates a new Program. SALVAGE retains
incomplete/trailing bytes; read [input policy](input-policy.md) before using it.

```sh
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /tmp/gb-project demo \
  -preScript GhidraBoyImport.java /path/synthetic.gb SALVAGE AUTO CGB -noanalysis
```

If macOS reports it cannot verify `decompile`, dismiss the dialog with Done and
verify the installation's provenance before using the system's per-item approval
workflow. Do not delete the helper or disable Gatekeeper globally. This warning
alone is not a malware verdict. The native helper is a Ghidra dependency, not a
GhidraBoy binary. GUI acceptance requires actually operating dialogs; successful
headless scripts alone do not establish it.

# Tools, navigation and symbols

Run `GhidraBoyTools.java`. Its action chooser exposes inspection, mapping export,
file/physical/CPU navigation, symbol sources, analysis and ROM exports. Navigation
shows a choice when several static views share the same physical bytes. CPU
navigation requires explicit mapper state; it does not select a live bank.
Headless syntax is `-postScript GhidraBoyTools.java ACTION ARGUMENTS -noanalysis`.

| Action | Arguments / behavior |
| --- | --- |
| inspect / mapping-json | Print snapshot / write new JSON destination |
| navigate-file | Hex file offset |
| navigate-physical | `ROM:2:10` (region, hex bank, bank-relative offset) |
| navigate-cpu | Hex CPU address, MapperState JSON |
| preview-sym / import-sym | Absolute RGBDS `.sym` path, optional boundary-choice JSON file |
| companion-sym | Deliberately look for one same-directory, same-stem `.sym`; preview before GUI application |
| symbol-sources | List active source identifiers and label claims |
| reload-sym / remove-sym | Select an active source in GUI; supply its absolute identifier headlessly |
| export-retained-sym | Source identifier, new output file |
| export-sym | New output file for current labels/functions |
| identify-ram | Static start, region, hex bank, hex offset, hex length |
| enhance-legacy | Optional mapper (`AUTO`), optional known hardware (`GB`/`CGB`) |

Symbol preview can filter all/resolved/unresolved/local entries; console output
shows local parents, placements and diagnostics. Boundary/end markers offer an
explicit placement choice or remain unresolved. For headless choices, map the
printed entry key to an exact static address in a JSON object. Source entries
and choices are retained for reload/export. WLA-DX and map files are unsupported.
RGBDS UTF-8, escapes, wide banks, BOOT/ANY and private `@` metadata are supported.

Each source claims a label independently. Removing one source keeps labels
claimed by another. Removal deletes only unchanged labels created by GhidraBoy;
user labels, renamed/moved symbols and promoted functions are protected. Reload
reconciles the selected source, preserving the other claims. File changes require
an explicit reload; there is no background directory scan.

# Analysis and per-function ABI

`analysis-preview` takes MapperState JSON (or `null`), a static start, optional
new output JSON path and optional configuration JSON. Example state:

```json
{"romLow":1,"romHigh":0,"mode":0,"ramSelect":0,"ramEnabled":false,"vbk":0,"svbk":1,"latch":0}
```

`analysis-apply` takes a saved preview JSON. `analyze` previews and applies in one
run. `analysis-remove` removes unchanged owned references, bookmarks, functions
and far-call overrides. Applying again refreshes owned additions; later user
edits remain protected. `discover-functions` uses current saved results and
existing entry points. Stale results are rejected: rerun preview after patches,
remapping or changing assumptions. Incomplete runs keep candidates but add no
confident references. See [analysis](analysis.md).

`far-call-preview` and `far-call-convention` take explicit convention JSON with
`trampoline`, `expectedBodyHex`, `callSites`, and `stackPointer`. Only the exact
supported ordinary-MBC3 trampoline with proven fixed-ROM callers is accepted.
`far-call-remove` removes its unchanged additions. No universal RST convention
is inferred.

Run `GhidraBoyAbi.java` at an existing function, select request JSON, inspect the
printed storage and confirm application to that function. Headless arguments:
`request.json staticAddress [apply]`; omission of `apply` is a preview. For example:

```json
{"profile":"sdcc451-call1","returnType":"u16","parameters":[{"name":"count","type":"u8"},{"name":"buffer","type":"ptr"},{"name":"flags","type":"u8"}]}
```

This selects packed custom storage per function without changing the Program's
compiler spec. See [compiler support](compiler-support.md) for tested profiles,
explicit aggregate storage and limitations. Hardware descriptions and mask enums
are supplied on new import; existing user types/comments are preserved. Ghidra's
processor manual action opens the bundled self-authored SM83 reference index.

# Export, migration and rollback

`export-original`, `export-current` and `export-repair` require a **new** output
path. Original export reads immutable FileBytes. Current export overlays proven
patches and preserves known-unmapped original tails/boot holes. Conflicting alias
patches, missing sources and detached ambiguous mappings are rejected. Repair is
explicit and reports changed checksum offsets and the output SHA256.

Close and copy the complete original project directory and `.gpr` before opening
under newer Ghidra. Enhance only the copy. `enhance-legacy` preserves known
historical hardware choices; unknown hardware remains unknown unless explicitly
identified. Use `identify-ram` for reviewed RAM intervals; conflicts are rejected.
Topology and annotations are never silently recreated. Reanalyze reviewed code.

Actual 11.3.1 creation/save/close and 12.1.3 upgrade/reanalysis/reopen were tested
with a legal self-authored fixture, separately from old-language-on-12.1.3 tests.
For rollback, close the upgraded copy, reinstall the original extension in its
original Ghidra version, and open the untouched backup. An upgraded database is
not guaranteed to reopen in the old version.

See [GUI checklist](gui-validation.md) for the interactive acceptance still to run
and [evidence](modernization-evidence.md) for exact gates and limitations.
