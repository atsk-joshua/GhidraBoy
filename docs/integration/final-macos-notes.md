# Final macOS installed acceptance

The frozen `93b713091382f8de5419fa3c9b4bed75c77b1e92` macOS packages pass 15 of 16 requested component commands. Combined-package research acceptance fails because the archive omits `tests/fixtures/banks.asm`, which the precompiled `ResearchExperimentTest` hashes when writing its experiment recipe. This archive set is **not fully accepted**. No production code, package manifest, or test was changed during this run.

| Package | Native/Python tests | Installer checks | Observation assertions | SDL backends | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| SameBoy | 91 | 11 | 34 | 1 | PASS |
| mGBA | 17 | 12 | 34 | 1 | PASS |
| Combined | 105 | 11 | 34 | 2 | Research blocked by omitted fixture |

Every package passed its extracted `Validate.sh`, the isolated install/crash-recovery/rollback/user-edit/hash/native-dependency refusal matrix, SDL window/event-pump/cleanup smoke, doctor core and desktop readiness, and Java observation creation plus independent reopening. SameBoy additionally publishes 250 stopped captures in its real Trace RMI growth check. Combined validation exercises both selected backends; mGBA-only installation proves its runtime does not depend on a SameBoy adapter or boot-ROM tree. These counts are repeated acceptance assertions across compositions, not counts of distinct product features.

Runs used separate fresh extractions beneath `/private/tmp/ghidraboy-final-mac-acceptance`, unique test homes, and separate evidence paths. A controlled `PATH` exposes runtime utilities and the existing Python 3.9.6, with no `cc`, `gcc`, `clang`, `make`, `cmake`, `javac`, `gradle`, or `rgbasm`. The configured Java home exposes only a link to Java 21; installed tests use `GhiGBC-acceptance.jar`. Host build tools remain installed elsewhere, so this demonstrates no build-tool dependency in these exercised commands rather than their absence from the machine.

macOS SDL smoke loaded `/opt/homebrew/opt/sdl2/lib/libSDL2.dylib`, an existing Homebrew prerequisite. This does not establish that a fresh Mac receives SDL from these packages. Linux bundled-SDL evidence and physical Steam Deck verification are separate. Physical desktop input/focus testing, paired performance measurements, and long soaks are outside this component run.

The SameBoy validation log retains a Ghidra `ThreadedTerminal` bad-file-descriptor message during terminal shutdown, followed by explicit owned-sidecar exit, truthful terminated state, and no uncaught asynchronous JVM errors. The failed research run retains its socket-close diagnostic during exception cleanup. A final process inspection found no Java test, emulator sidecar, or SDL smoke process belonging to this acceptance workspace. No other Ghidra session was modified.

The minimal packaging correction is to include the self-authored `tests/fixtures/banks.asm` and regenerate/requalify the affected archive set. The original failed run remains preserved. [Machine-readable evidence](final-macos-evidence.json) contains exact commands, environment, counts, all archive-member manifest verification results, source identity and file-map digest, native and Java hashes, and copied log hashes. Logs and manifests are retained under `dist/integration-final-93b7130/macos/acceptance`.
