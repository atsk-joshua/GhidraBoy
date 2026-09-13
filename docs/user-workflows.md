# Install and first use

Use **Ghidra 12.1.3 / JDK 21** and select an exact static extension ZIP from
its build or release receipt. A filename or old validation count alone does not
qualify an artifact. The static extension works without an emulator or Python.

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

New hardware mask enums use one stable name for each numeric value. Every alias
and description from the pinned hardware.inc definitions remains in that member's
comment and the packaged source JSON. This avoids ambiguous enum-value warnings
in the decompiler without changing register values. Existing enum definitions are
retained exactly by the conflict handler, including aliases and student edits;
updating those saved types requires a separate previewed migration and is not
performed automatically by reapplying hardware reference information.

# Export, migration and rollback

`export-original`, `export-current` and `export-repair` require a **new** output
path. Original export reads immutable FileBytes. Current export overlays proven
patches and preserves known-unmapped original tails/boot holes. Conflicting alias
patches, missing sources and detached ambiguous mappings are rejected. Repair is
explicit and reports changed checksum offsets and the output SHA256.

Close and copy the complete original project directory and `.gpr` before opening
under newer Ghidra. For SM83 1-to-2, first inspect the core-translated copy, save
and close it, and verify immutable first use in another process before enhancement
or reanalysis. The [language compatibility workflow](instruction-compatibility.md#installed-language-1-to-language-2-upgrade)
describes the supported route and preservation limits. Enhance only a further copy. `enhance-legacy` preserves known
historical hardware choices; unknown hardware remains unknown unless explicitly
identified. Use `identify-ram` for reviewed RAM intervals; conflicts are rejected.
Topology and annotations are never silently recreated. Reanalyze reviewed code.

Actual 11.3.1 creation/save/close and 12.1.3 upgrade/reanalysis/reopen were tested
with a legal self-authored fixture, separately from old-language-on-12.1.3 tests.
For rollback, close the upgraded copy, reinstall the original extension in its
original Ghidra version, and open the untouched backup. An upgraded database is
not guaranteed to reopen in the old version.

See [GUI checklist](gui-validation.md) for the interactive acceptance still to run
for supported behavior. Exact historical qualification receipts remain in the
source checkout under `docs/modernization-evidence.md`; they are not current
acceptance of a newly built package.

### Reviewed execution contexts (candidate)

The experimental stock path has separate production APIs (`installStock`,
`emitStock`, and `SoftwareCallApplication.previewStock`). In GhidraBoy Tools,
`stock-predicate-install` installs a reviewed bounded predicate root;
`stock-contexts` navigates existing owned entries, `stock-source` reaches their
original source, and `stock-current` checks authority explicitly. Native recovery
still uses the ordinary Decompiler. This is a partial qualification, not a release
recommendation for old annotated Programs. The bounded language-1-to-2 upgrade
and unsupported-record refusal policy are described in the
[compatibility decision](decisions/sm83-v1-v2-compatibility.md). Historical
normal-window lifecycle and retained switch limits are described in the
[transport decision](decisions/stock-ghidra-transport.md).

The following companion-based instructions describe the retained earlier route;
they do not establish stock transport or current normal-window qualification.

State-sensitive software calls can produce several execution contexts at the
same CPU address. `software-call-preview` includes their physical instruction
ranges, state and discovery inventories. `software-call-apply` commits the
reviewed changes transactionally. Canonical storage and existing user work are
preserved; discovered canonical instructions remain after removal.

When a callee requires the optional state-entry native companion, proved callers
use their matching execution aliases. In GhidraBoy Tools, `software-call-contexts`
lists the contexts for a canonical physical function; `software-call-select-context`
selects the context shown by its normal Decompiler window. The Function comment
records the selected register, mapper, stack and memory premises. A conditional
model header remains visible in the Decompiler. Selecting a display context
does not change another caller's context and does not prove unspecified inputs.
Modified dependencies or owned context metadata require a new review.

The optional companion is installed into a new distribution copy with
`tools/state_entry_native.py` from the source checkout. It is separate from the
static extension and from the preceding switch-only native companion. Consult
the current source qualification receipt before using an artifact; implementation
and build success alone are not installed or GUI qualification.

This state-sensitive candidate is not yet qualified for fresh ordinary analysis.
The current source handoff records an automatic thunk/fixup drift failure and
pending installed/GUI verification. Use disposable Programs for this candidate;
the preceding finite workflow qualification does not establish this wider path.

## Conditional stock entries

New reviewed software-call preview/apply requests, including `GhidraBoyTools`,
use the stock transport. Ordinary, predicate and configured-domain public install
methods do the same. Existing authority retains its recorded transport; earlier
stock-carrier and companion records are preserved and are not automatically
converted. Open a reviewed conditional entry to inspect its result; selecting a
stock context navigates to that entry without specializing the canonical Function.

Carrier bytes are presentation storage, not the source routine. Use the Tools
source-navigation action for original physical instructions. Explicit refresh is
required after a consumed dependency changes. See the
[route and compatibility decision](decisions/stock-route-completion.md).

These development routes do not qualify existing annotated language-1 Programs.
Keep those Programs on their original provider until separate migration approval.

## Explicit finite-dispatch views

For a bounded synchronous MBC5 root, use `GhidraBoyTools.java` with
`stock-predicate-preview` and an explicit premise JSON file, for example
`{"root":"0100","inputs":[65408],"entryHL":null}`. An optional fixed entry HL must
name one declared input cell; its byte remains unknown. The source Function may
explicitly expose byte A or word HL as its custom result, with no custom parameters.
The qualified entry checks that result storage against the source.

In headless/script use, the preview arguments are the premise file and a new proof
output path. `stock-predicate-apply <proof.json>` installs a reviewed complete
preview. `stock-contexts`, `stock-current` and `stock-source` provide existing
navigation and currentness inspection. After a consumed byte edit, preview again
from the original premises and use `stock-predicate-refresh <proof.json> <carrier>`;
then refresh the Decompiler window. There is no automatic proof replacement.
`stock-predicate-remove <carrier>` removes unchanged owned artifacts and preserves
later edits and canonical source listing.

This qualified stock view supports proved finite indirect jumps, ordered immutable
ROM reads and the declared input/frame domain. Unknown mutable target tables,
incomplete paths, unsupported effects and exhausted budgets refuse installation.
It does not fix canonical automatic switch recovery or validate a public override.
See [the dispatch contract](decisions/static-dispatch-model.md) for limits and
experimental record compatibility.
