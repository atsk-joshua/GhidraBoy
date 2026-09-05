# Modernization evidence — hardening preview

The six independent reproductions remain fixed and regression-tested. The final
function ownership preservation defect is addressed by version 2 conservative
receipts and FunctionOwnershipTest, with installed persistence coverage. Full
acceptance remains incomplete while installed GUI workflows are unverified; the
final generated ledger also requires the ownership and all existing gates to pass. The requirement ledger below distinguishes implementation and
executed tests from that external environment gate. Generated reports are the
authority for the final commit, dirty state, exact counts and ZIP hashes.

## Baseline, provenance and environment

Work continues from reviewed `7dd6ed18652dd3eaea0161506ebf9b711b0ad55f` on
`modernization`. Existing `-x` cherry-picks are preserved: ac77201 → 937253d,
a3ade39 → 94ececd, 91169cd → e8ad870. No wholesale import, production 11/12 source
split, history rewrite or GhiGBC change was performed. Baseline
[Actions run 33956121926](https://github.com/atsk-joshua/GhidraBoy/actions/runs/33956121926)
passed on 7dd6ed1: 399 tests, 21,000 selected external vectors, installed lifecycle,
actual 11.3.1 migration and package/schema checks. Its successful status and exact
head were read from GitHub during this continuation; draft release was skipped. The branch had
already been pushed; this continuation is local and does not push or publish.
The tag-triggered draft-release job is preserved.

Pinned dependencies and official archive digests are in
[tools/dependencies.json](../tools/dependencies.json). Primary target: Ghidra
12.1.3 PUBLIC, JDK21, Gradle9.0.0, Kotlin2.2.10. Local native tests use Homebrew
Ghidra12.1.3/mac_arm_64 and OpenJDK21.0.12.1. Installed tests use a separately
extracted official12.1.3 distribution. Actual migration uses official11.3.1 with
the matching 20250830 extension in a disposable installation. Current/historical
compiler fixtures use GBDK4.5.0/4.0.6, SDCC4.5.1/4.1.6. See compiler-support.md.
Only macOS arm64 is a local native platform claim. The successful Linux CI run above applies to the reviewed baseline;
the dev3 continuation has local validation only. Windows is untested.

## Requirement ledger

PASS below means implemented and exercised by the named maintained tests; the
final generated gate ledger can still report command failures. Test paths are
under [src/test/kotlin/fi/gekkio/ghidraboy](../src/test/kotlin/fi/gekkio/ghidraboy).
The exact six before-fix failures are retained in
[audit-before.log.txt](evidence/audit-before.log.txt). AuditRegressionTest exercises
actual production code and compiled p-code, with real Ghidra Programs.

| Requirement | Status | Implementation and maintained evidence | Limitation / next action |
| --- | --- | --- | --- |
| R1 incomplete worklist confidence | PASS | BankAnalysis, AnalysisResult; AuditRegressionTest, AnalysisHardeningTest | Global confidence suppression on incomplete runs; candidate reporting retained |
| R2 all access bytes/order/wrap | PASS | PcodeConstants, BankAnalysis, SLEIGH byte stores; AuditRegressionTest, AnalysisBoundaryTest | No second instruction interpreter |
| R3 reachable execution windows | PASS | MapperTopology, CartridgeLayout, ProgramMapping; AuditRegressionTest, MapperTopologyTest | Unsupported wiring remains explicit RAW |
| R4 window fallthrough/fetch/PC wrap | PASS | BankAnalysis; AuditRegressionTest, AnalysisBoundaryTest | Stop when bytes or execution identity cannot be established |
| R5 shared source membership | PASS | SymbolService; AuditRegressionTest, SymbolOwnershipTest, installed lifecycle | User edits/functions protected; source workflow GUI unverified |
| R6 BOOT direct/alias isolation | PASS | SymbolService; AuditRegressionTest, SymbolTest | Unresolved entries retained |
| Evaluation/aggregation/application separation | PASS | PcodeConstants, MapperKnowledge, AnalysisCandidates, AnalysisApplication, AnalysisOwnership | Java formatting committed separately from fixes |
| Versioned results/stale invalidation | PASS | AnalysisResult, ProgramFingerprint; AnalysisLifecycleTest, installed lifecycle | Canonical iteration survives rename/reopen; changed dependencies require new preview |
| Owned preview/apply/remove/reapply | PASS | AnalysisOwnership; AnalysisLifecycleTest, FunctionOwnershipTest, installed lifecycle | Bare functions only; variables/types and legacy receipts retained conservatively; dialogs unverified |
| Function user edits and legacy ownership migration | Executed by final runner | FunctionOwnershipTest, GhidraBoyInstalledFunctionOwnership; function-ownership-before.log.txt | 20 edit categories across three removal routes, variable details, legacy edits, type mutations, cancellation and separate-process reopen |
| Partial mapper knowledge | PASS | MapperKnowledge; AnalysisHardeningTest, AnalysisBoundaryTest | No generic interprocedural summaries |
| Seed-based functions | PASS | FunctionDiscovery; AnalysisLifecycleTest, AnalysisHardeningTest | No symbol/vector sweep |
| Far-call target and return/SP/identity | PASS | FarCallConvention; AnalysisLifecycleTest, BankAnalysisTest | Exact MBC3 body and fixed-ROM callers only; switchable callers rejected |
| Stable language/compiler/register/pointer contract | PASS | Language files, CompilerSpecTest, migration fixtures | P-code-only version1.0 retained; STOP historical behavior retained |
| Strict/manual/salvage input and immutable bytes | PASS | Cartridge, CartridgeLayout; CartridgeTest, SalvageTest | Unknown geometry does not establish mapper certainty; salvage cap16MiB |
| Capability/RAM/rumble validation | PASS | Cartridge, MapperState; CartridgeTest, MapperTopologyTest | MBC1M/MBC30/exotic wiring unsupported |
| Boot/checksum/transaction behavior | PASS | CartridgeLayout; CartridgeTest, installed checksum test | No fabricated boot header or silent checksum repair |
| Deterministic mapping schema/source identities | PASS | ProgramMapping, mapping-schema.json; CartridgeTest, SalvageTest, validate_schema.py | Actual exported JSON validated; arbitrary detached mappings rejected |
| Current/original/repair export | PASS | ProgramMapping; CartridgeTest, SalvageTest, SymbolBoundaryTest | Known tails retained; ambiguity/conflict/detachment rejected |
| Legacy hardware and explicit RAM anchors | PASS | LegacyEnhancement, ProgramMapping.identifyRam; CartridgeTest, actual migration | Unknown historical selection remains UNKNOWN; no topology rebuild |
| RGBDS grammar/private metadata/escapes | PASS | SymbolFile, SymbolService; SymbolTest, SymbolBoundaryTest | WLA-DX/map unsupported |
| Companion/preview/boundaries/source lifecycle/export | PASS (headless/API) | GhidraBoyTools, SymbolService; SymbolBoundaryTest, SymbolOwnershipTest, installed lifecycle | Interactive chooser/filter/reload/remove acceptance pending |
| Hardware descriptions/mask enums/manual | PASS | HardwareReference, generated definitions, manual index; CartridgeTest | Preserves existing comments/types; GUI manual action pending |
| Per-function scalar/pointer/cleanup ABI | PASS | CompilerAbi, prototype models; CompilerAbiTest, CompilerSpecTest | Explicit profile selection; no whole-Program switching required |
| Historical/variadic/aggregate/banked/preservation evidence | PASS (bounded profiles) | Pinned compiler sources/assembly; CompilerAbiTest | Explicit aggregate storage; banked callee only, no universal helpers/attributes |
| Semantic decompiler behavior | PASS | CompilerAbiTest, decompiler/DecompilerTest, BankAnalysisTest | References remain descriptive; no dynamic banking claim |
| Genuine11.3.1 database migration | PASS | migration_smoke.py; Create1131Fixture/Verify1131Upgrade | Copied legal fixture; original tree hash unchanged; old/new ADC p-code checked |
| Separate old-language-on12.1.3 preservation | PASS | installed_smoke.py; GhidraBoyPreservation | Does not substitute for historical database gate |
| Clean installed ZIP/public script discovery | PASS (headless) | installed_smoke.py; InstalledCheck/InstalledLifecycle | All public scripts compiled/executed; dialogs not inferred |
| Installed GUI workflows | Requires observed final receipt | gui-validation.md; artifact-bound GUI receipt in generated evidence | User authorized single-instance desktop testing after other agent stopped; verify process and ZIP before interaction |
| CPU exhaustive/external/boundary tests | PASS | emu suites, AnalysisBoundaryTest; cpu-validation.md | Static semantics only, no cycle/HALT/STOP/IME timing claim |
| Actual vector/sample hashes/counts | PASS | ExternalVectorTest, fetch_vectors.py | 21 selected files ×1000=21000; ordinary samples168; not full upstream corpus |
| Clean reproducibility/metadata/package doctor | Executed by final runner | run_validation.py; build metadata tracked inputs; doctor.py | Compare same platform/JDK/Ghidra/epoch; generated receipts hold both hashes |
| Machine evidence/CI report retention | Implemented | release_evidence.py, run_validation.py, CI validate.sh | Baseline run33956121926 passed; dev3 remains local, with retained logs/reports |
| Documentation/rollback/static independence | Updated | user-workflows, input-policy, static-contract, compiler-support, release-notes | Full acceptance not claimed while GUI is blocked |

## Reproduce the gates

Use fresh disposable directories. Migration fixtures must never target a real user
project. Fetch historical dependencies with `tools/fetch_dependency.py` (official
URL plus SHA256 verification), extract11.3.1 and its matching extension there.
Prepare another official12.1.3 installation for installed tests. Fetch vectors:

```sh
python3 tools/fetch_vectors.py --count 1000 --output /tmp/ghidraboy-vectors
python3 tools/run_validation.py --native \
  --ghidra /path/to/native/ghidra_12.1.3_PUBLIC \
  --jdk /path/to/jdk21 \
  --installed-ghidra /tmp/ghidraboy-installed/ghidra_12.1.3_PUBLIC \
  --legacy-ghidra /tmp/ghidraboy-migration/ghidra_11.3.1_PUBLIC \
  --vectors /tmp/ghidraboy-vectors \
  --work /tmp/ghidraboy-validation-fresh
```

Supply `--gui-evidence receipt.json` only with actual observations; the default
records GUI as BLOCKED. Python jsonschema4.25.1 is required. The runner executes
actual comprehensive vectors, clean build, a second clean package build, final
tests, real exported-schema validation, package doctor, epoch input invalidation,
installed lifecycle and actual historical migration. Command return codes and
required markers are recorded. No requested vector count is treated as execution.

Outputs: `build/reports/evidence/release-evidence.json`, `requirements.md`, command
logs, copied comprehensive-vector XML, installed/migration receipts, ordinary
JUnit XML in `build/test-results/test`, and `build/distributions/SHA256SUMS` beside
the installable dev3 ZIP. Generated evidence records commit/dirty state, dependency
pins, tested platform, actual suite/file/vector counts and skipped/blocked gates.
The reviewed baseline suite had399 tests with zero failures/errors/skips; final
reports, not this historical count, establish the delivered checkout's result.
