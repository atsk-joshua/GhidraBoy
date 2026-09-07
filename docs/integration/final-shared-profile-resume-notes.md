# Shared real-backend profile/history contract — PASS

Authoritative execution: `/private/tmp/ghidraboy-shared-profile/run-final.sh`, invoked with desktop access. Final harness exit **0**; separate provider-free JVM exit **0**. Both shared asynchronous JVM error collectors passed after cleanup. The 12 inventoried JVM/agent PIDs are absent after completion.

Released source files (no further edits pending):

- `debugger/tests/ghidra/BackendTraceTest.java`, SHA-256 `dd9ac04a388ad3408134a3afd4819a93d8505911fa8d433dd50d1058ab01c93b`.
- New packaged fixture **`debugger/tests/shared_profile_fixture.py`**, SHA-256 `ee66ca5737d1ff838eb30b327d90a8e5cad823f202298d3db4fd1da5ac46fd47`.

No edits to RealTraceTest, build/install/package scripts, shared docs, or production code. No commits. The existing backend script already compiles the modified Java class; the new Python test fixture must be present in extracted packages.

Run the contract with `bash scripts/test_backend_trace.sh sameboy mgba --profile-contract` from the runtime root with the normal configured Ghidra, Java, Python, isolated installed test home, and evidence directory. The direct authoritative runner installs only manifest-verified GhidraBoy/GhiGBC archives into its isolated home, then compiles RealTraceTest, MappingContractTest, and BackendTraceTest. This avoids the concurrently modified installation scripts.

Coverage is the same production Agent and shared assertions for both actual engines, without skips: **SameBoy × five provider modes and mGBA × five provider modes**. Each target gets a copied Python runtime, isolated HOME, explicitly installed profiles.json, and copied native library files. Modes are exact-match synthetic; absent manifest; missing import; provider-construction failure; wrong ROM revision fingerprint. The fixture declares only one WRAM byte and requires only common physical capture.

Each mode proves raw bank-1 capture, real bank-qualified breakpoint/resume to bank 2, five additional real steps, complete exact-snapshot static mappings, and persisted history. Synthetic mode checks one typed field, integer/observed validity, profile/version, session/epoch/capture, exact physical source coordinates and length, field-batch snapshot, and equality with the captured raw WRAM byte. Other modes check generic selection, zero fields, and the expected error or clean wrong-revision rejection while the same raw controls/history contract continues.

Historical selection uses the real DebuggerTraceManagerService in read-only Trace mode. Before and after the additional steps, the selected bank-1 snapshot retains its CPU byte/mapping while the current target retains bank-2 bytes/mapping and its current capture ID. Real selected-capture actions with the historical context are rejected without changing the live capture. SameBoy explicitly rejects stale selected profile watches. mGBA explicitly reports the unsupported physical-watch capability while common selected-capture validation still runs.

All ten traces are saved and reopened in the producing JVM. After tool/project cleanup, every installed fixture manifest and provider module is removed. BackendTraceTest starts a separate JVM, which checks removal and reopens both first and last snapshots of all ten persisted traces, reusing the raw/decoded/provenance/mapping assertions without launching Python or an emulator. The final producer log contains 846 PASS assertions; the child log contains 175.

Frozen authoritative artifacts:

- SameBoy native: `ba30da5996633003cbcf26ab528aa2f6bee1c774c97f5db194c1ddefd2714f49` (coordinator's final mapper-identity fix).
- mGBA native: `9c0b84e7bd678e695950bbf5451aa916d6b2d6e7c55f08327d6659ff8ac675cf`.
- Patched Ghidra Debugger.jar: `3b75891c6734b23f03c0313cb5fc582a9410676b799c8c1af3e30e3696b10bbf` from `/private/tmp/ghidraboy-lifecycle-validation/patched-install`.
- Java 21: `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`.
- Python: `/Users/joshuahansen/dev/GhidraBoy/debugger/.venv12/bin/python`.
- Java component jars/archives: verified through `build/integration/artifacts.json`; exact classpath preserved in evidence.

Evidence under `/private/tmp/ghidraboy-shared-profile`:

- `run-final.sh`: exact repeatable authoritative setup/compile/run command.
- `run-5-final.log`, `run-5-final.exit`: authoritative producer log and exit 0.
- `evidence-final/backend-provider-free-reopen.log`: child PASS and clean async collector.
- `evidence-final/backend-profile-history.json`: project/trace paths and first/last snapshots for all modes.
- `evidence-final/{sameboy,mgba}-{synthetic,absent,missing,failing,wrong-revision}-backend-agent.log`: ten owned target logs.
- `sha256.txt`, `frozen-runtime-hashes.json`: test/native/Ghidra hashes, per-runtime copied native hashes, and provider-removal checks.
- `classes.txt`, `classpath.txt`: compiled class directory and exact selected Java classpath.
- `owned-pids.json`, `owned-process-final.json`: producer JVM 52108; agents 52111, 52125, 52133, 52136, 52137, 52142, 52145, 52150, 52156, 52171; child JVM 52174; all absent. Every agent also passed its bounded process-exit assertion in the harness. Numeric per-agent return codes were not separately emitted by the preexisting agent-exit helper.
- `run-exits.json`: exits for all attempted runs.

Earlier runs are preserved, not used as final acceptance: run 1 aborted at macOS GUI startup inside sandbox (134); run 2 lacked SM83 language registration in the first isolated home (1); run 3 selected historical coordinates while still in target-follow mode (1). Run 4 passed (0), but preceded the final frozen-native and explicit-watch enhancements. Run 5 is the authoritative result. `git diff --check` passed; compilation produced only six existing AutoImporter deprecation/removal warnings.
