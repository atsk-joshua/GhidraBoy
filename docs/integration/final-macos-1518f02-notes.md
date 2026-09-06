# Corrected final macOS installed acceptance

All **16 of 16 component commands pass** for corrected source `1518f02f88921def373bf09aa67d4c499517b377`. Every command was rerun against a fresh independent extraction; no result depends solely on reuse of earlier acceptance. The prior `93b7130` missing-fixture failure and its receipts remain preserved in [the original evidence](final-macos-evidence.json).

| Package | Native/Python tests | Installer checks | Observation assertions | SDL backends | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| SameBoy | 91 | 11 | 34 | 1 | PASS |
| mGBA | 17 | 12 | 34 | 1 | PASS |
| Combined | 105 | 11 | 34 | 2 | PASS |

Each package passed extracted `Validate.sh`, install/crash-recovery/rollback/user-edit/hash/native-dependency refusal checks, SDL smoke, doctor core and desktop readiness, and observation creation plus independent Java reopening. Combined packaged research adds **85 PASS assertions**, completing the controlled SameBoy one-instruction checkpoint/restore/repeat experiment, independently reopening the observations, and rejecting unsupported mGBA checkpoint creation before mutation. Both research sidecars exit and the harness reports no uncaught asynchronous errors. Counts include repeated acceptance assertions across package compositions.

The correction adds only `tests/fixtures/banks.asm` and `tests/ghidra/ResearchExperimentTest.java` to each payload. Independent archive inspection verified all 81/72/93 pre-existing payloads respectively remain byte-identical to the original SameBoy/mGBA/combined packages. The new assembly SHA-256 is `3485ec6b78f9232aba899527aad387da9aaef50fd0c24ec40f18720ddc0cce18`; the research runner SHA-256 is `e309117de1b24be7588da98b1977fb81c764daf1c9a24630b835f9b8bd84e172`. These hashes match the repository files, packaged files, and generated experiment recipe. The recipe ROM hash also matches actual packaged bytes. Every manifest-listed archive member was hash-verified. Native adapters, extension JARs, and precompiled acceptance bytecode retain their prior hashes.

Runs used `/private/tmp/ghidraboy-final-mac-acceptance-1518f02`, fresh extractions and separate homes/evidence, leaving the parent’s soak/UI runtimes untouched. The controlled `PATH` excludes `cc`, `gcc`, `clang`, `make`, `cmake`, `javac`, `gradle`, and `rgbasm`; configured `JAVA_HOME` exposes only Java 21. All installed checks used existing Python 3.9.6 and precompiled acceptance bytecode. Host build tools remain elsewhere, so this proves the tested commands need no exposed compiler/build tooling.

SDL came from existing Homebrew `/opt/homebrew/opt/sdl2/lib/libSDL2.dylib`; no fresh-Mac bundled-SDL claim is made. Final executable-aware process inspection found no acceptance-owned Java, emulator-sidecar, or SDL test processes. A first text-only inspection matched its own shell command and was corrected to filter executable identity; it was not a test-process leak. Physical input/focus acceptance, paired metrics, long soaks, Linux fallback qualification, and physical Steam Deck verification remain separate scopes.

[Corrected machine-readable evidence](final-macos-1518f02-evidence.json) records exact commands, archive/native/Java/source/log hashes, continuity proof, research recipe and actual-file hash checks, doctor reports, and cleanup. Durable copies are under `dist/integration-final-1518f02/macos/acceptance`. No production, package, or test files were edited during this requalification.
