# Install and first use

Use Ghidra **12.1.3** and JDK **21**. Set `JAVA_HOME` and `GHIDRA_INSTALL_DIR`,
then run `./gradlew clean build`. The fixed development version is 20260905-dev1.
Gradle 9.0.0 has an official wrapper SHA256 pin. Java/Kotlin both target 21;
Ghidra 11 and 12.1.2 are not advertised targets. `SOURCE_DATE_EPOCH` optionally
overrides a fixed UTC metadata epoch. ZIP entries have fixed timestamps/order.
Compiled language, source, scripts, schema, docs and licenses are packaged;
tests and external test vectors are excluded.

Choose File → Install Extensions in Ghidra's project window, add the ZIP from
`build/distributions`, and restart. Avoid installing a second SM83 extension.
Import a standard cartridge; select Game Boy and inspect warnings. For deliberate
nonstandard images, run `GhidraBoyImport.java` in Script Manager and choose
CARTRIDGE, DMG_BOOT or CGB_BOOT. It creates a new program, never overwriting an
open one. Headless equivalent:

```sh
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /tmp/gb-project demo \
  -preScript GhidraBoyImport.java /path/synthetic.gb CARTRIDGE AUTO CGB -noanalysis
```

Run `GhidraBoyTools.java` in Script Manager's Game Boy category. Actions include
inspect, mapping-json, file/physical/CPU navigation, symbol preview/import,
retained symbol export, original/current ROM export, explicit checksum repair,
legacy enhancement, bounded analysis, and an exact validated far-call convention.
Navigation prints representations for copying; multiple static views require a
choice. These use standard Ghidra script dialogs and task cancellation.

Headless example: `-process program -postScript GhidraBoyTools.java inspect
-noanalysis`. Other actions take their action name then output/path/address
argument; CPU navigation also takes MapperState JSON. Analysis takes explicit
state JSON (or `null`) and optional static start address. Far-call configuration
is JSON containing `trampoline`, `expectedBodyHex`, and `callSites`. Only the exact
reviewed inline-three-byte MBC3 trampoline in `FarCallConvention.SUPPORTED_BODY`
is supported. Default RST behavior never changes automatically.

# Symbols and export

Supply UTF-8 RGBDS `.sym`. GUI previews placement before import; headless import
explicitly applies it. Private metadata is ignored; ordinary unknown metadata
warns without losing the symbol. BOOT and any-bank forms remain distinct;
any-bank labels expand to actual mapped views. Banks may exceed 255. Local
labels retain qualified names and the parser exposes parent attachment.
Ambiguous boundary/end markers are retained with diagnostics. WLA-DX and `.map`
are unsupported. No automatic function creation or directory scan occurs.
Reimport is idempotent; source-owned unchanged labels may be removed through
`removeOwned` or replaced on reload; user-created/edited symbols are preserved.
The retained export preserves original source locations/names. `export-sym`
exports current labels/functions through physical mappings, reporting any
unrepresentable names or unresolved locations.

ROM export requires a new destination. Original reads immutable FileBytes;
current reconstructs physical sources and checks duplicate edit conflicts.
Patches do not require globally writable cartridge blocks. Checksum repair is a
separate explicit action reporting changed offsets and SHA256. Boot holes retain
original bytes. Missing/ambiguous sources fail rather than guessing block names.
Partial/trailing cartridge bytes are rejected at import under current policy.

# Upgrade and rollback

Close and copy the complete original project directory and .gpr before opening
under newer Ghidra; keep the original ZIP. Work on the copy. Inspect first;
`enhance-legacy` explicitly adds reconstructed ROM metadata and reports unknown
RAM identity without changing topology or labels. Selectively reanalyze only
reviewed regions. Language ID, compiler default, register offsets and language
version 1.0 remain unchanged. P-code changes alone need no major bump.

Rollback: close the upgraded copy, reinstall the original extension in its
original Ghidra installation, and open the untouched project backup. An upgraded
database is not guaranteed to reopen in an older Ghidra. The executed fixture
uses old language on 12.1.3; actual 11.3.1 database migration is a separate
unexecuted gate. CI definitions are not evidence of remote CI execution.
