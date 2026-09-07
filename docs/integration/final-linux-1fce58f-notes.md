# Final exact-artifact Linux acceptance: 1fce58f

Status: PASS. Fresh final archives for all three compositions ran in the original image `sha256:1955ff1e743d7b182f5b991d3d192e05604fb7497fcdc8a2772d56dd072418ca`, with `--network none`, uid 501, no system SDL, JRE 21, and verified absence of cc/gcc/clang/make/cmake/javac/gradle/rgbasm. Only isolated extracted package, copied Ghidra, output, and runner mounts were supplied.

| Package | Native tests | Basic RMI/reopen | Install/recovery/guards | Failure lifecycle | Profiles/provider-free reopen | 250 stops | Reports/reopen | Research/reopen/refusal |
|---|---:|---|---|---|---|---|---|---|
| both | 110 | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| sameboy | 96 | PASS | PASS | PASS | PASS | PASS | PASS | N/A |
| mgba | 17 | PASS | PASS | PASS | PASS | N/A | PASS | N/A |

All three also passed preparation, real Setup installation, bundled SDL/display, and doctor readiness. Installer suites verified 13 checks for combined/SameBoy and 14 for mGBA (including its independent runtime check), including two injected-crash recovery paths, self rollback, user edit refusal, payload refusal, missing native dependency, missing Java dependency, and corrupted Debugger.jar refusal. Final package acceptance jars were used with no runtime compilation.

Lifecycle assertions check real register-table readiness/rendering for active and automatically closed disconnect/crash/replacement targets: 12 phases for combined, 6 for each single backend. They additionally verify saved raw bytes/source identity after loss, stale session rejection, owned agent exits, and no uncaught asynchronous errors. No marker alone establishes a pass; recorded command exits, detailed assertions, JSON evidence, archive hashes, and container states are required.

Provider-free reopen ran a separate JVM for 10 combined and 5 each single-backend histories after deleting provider manifests/code. Observation reports were independently reopened in Java. Combined research independently reopened repeat/checkpoint evidence and refused unsupported mGBA checkpoint creation before mutation. Growth sampled 0/125/250 real stops for combined and SameBoy; this is bounded measurement, not a long-duration leak proof.

Full commands, input hashes, output hashes, process IDs, container IDs, logs, exits, environment, and cleanup: `/Users/joshuahansen/dev/GhidraBoy/dist/integration-final-1fce58f/linux/acceptance/qualification.json`; file hash inventory `/Users/joshuahansen/dev/GhidraBoy/dist/integration-final-1fce58f/linux/acceptance/evidence-sha256.json`. Full installations and DBTrace projects remain in `/private/tmp/ghidraboy-linux-1fce58f/run-*`; the durable evidence directory retains results, reports, installer logs, and profile/research artifacts without redundant installed homes/caches.

Cleanup: all three owned acceptance containers exited, were inspected, and were removed. Their stopped state/PID 0 and post-removal absence are recorded. The existing desktop container retained the same ID, running PID and start time; no desktop interaction, restart, stop, or relay change was performed. Original Ghidra and all three runtime copies retained the hashes of all 5222 original files.

Failures: []. Scope is Linux x86-64 Docker/Xvfb on macOS; physical Steam Deck remains deferred.
