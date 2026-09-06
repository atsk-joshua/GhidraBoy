# M8 independent backend packaging

Evidence date: 2026-09-06. This bounded chunk implements package selection and verifies macOS arm64 composition. It does not qualify experimental mGBA as Basic Debugging, establish Linux mGBA acceptance, or complete deferred physical Steam Deck verification.

## Implementation

`debugger/scripts/package_candidate.py` accepts `--backend sameboy|mgba|both`; omission preserves the existing SameBoy archive name and default. `--native-dir` selects platform build outputs without overwriting the source tree's native libraries. Each selected native binary is checked for the claimed architecture. The mGBA adapter additionally requires a schema-1 receipt matching the locked core revision, patch, binary, source archive, current adapter sources and builder. A generated `runtime-backends.json` records selected IDs and default. Unselected Python adapters, native libraries, boot ROMs, tests and dependency-lock entries are omitted.

The existing installer, journal and rollback implementation are shared. It verifies backend composition against runtime metadata, copies only hash-verified runtime files, configures selected launchers and removes unselected launch offers from the same verified GhiGBC extension archive. One `runtime_probe.py` handles installer, preparation and doctor native readiness, and optional display loading. Core installation no longer depends on SDL being available; doctor reports desktop readiness separately. The backend factory rejects uninstalled IDs before importing an adapter. No separate installer or Java backend plugin is introduced.

mGBA-only installs have no SameBoy native library or `.deps/SameBoy` directory. The mGBA launcher selects native `CGB` explicitly and does not offer unsupported experiment edits or hardware revisions. The shared Java extension and acceptance JAR handle both backends. Package validation uses the existing SameBoy suite for SameBoy-only and the common capability-negotiated Trace RMI harness when mGBA is selected.

## Source and compatibility identity

The mGBA dependency is pinned at revision `685023e05d90d87050fb357f46f7bd2d907083f5`. Packages containing it carry the complete pristine git source archive, MPL 2.0 license, exact modified-file patch, adapter sources and builder. See `debugger/docs/MGBA_SOURCE.md` for included-source rebuilding and attribution. The pristine archive hash is `a59017f0dee15f8f9067c5f0638707f81487de595274f6b9e5a3e88f2bb517e9`.

An isolated clean-checkout build and a second build from that exact source tar, in different directories, both produced binary SHA-256 `9c0b84e7bd678e695950bbf5451aa916d6b2d6e7c55f08327d6659ff8ac675cf`. Both produced canonical compatibility identity `4caedd6229328555235c04783a46c10a1482621e52117965a40938b7fd91cb02`. This identity includes binary, source revision/archive, patch, adapter source and builder hashes with an explicit format version. Host labels and diagnostic absolute command paths are excluded. Receipts retain those diagnostics separately. Byte-identical rebuilding still requires the same compiler/SDK/platform.

Native outputs for this chunk are `/private/tmp/ghidraboy-m8-native`; reproducibility comparison outputs are `/private/tmp/ghidraboy-m8-rebuilt`. The native main build directory and the previously frozen SameBoy candidate were not modified.

## Executed checks

- Source mGBA adapter suite: 14 tests pass.
- Package selection/identity tests: 3 pass, including immutable identity changes, diagnostic relocation invariance, unknown schema rejection, invalid/duplicated backend selections, manifest disagreement, unverified runtime members, and legacy SameBoy fallback.
- Extracted mGBA-only archive: 17 native/package tests pass, plus real `BACKEND_TRACE_CONTRACT_PASSED`. This exercises capability-negotiated controls, execution breakpoints at the same PC in distinct banks, shared static mappings, bounded process shutdown and backend-neutral saved trace reopening.
- Extracted combined archive: 99 native/package tests pass, plus the common real Trace RMI contract passes for both SameBoy and mGBA using the same Java extension classes.
- Default SameBoy-only archive: 85 native/package tests and `REAL_TRACE_TEST_PASSED` with the growth option; automatic existing SameBoy launch offer, checkpoint/history behavior and installed real RMI remain passing. Snapshot archive SHA-256 `3a2e098dba84b5f3ff155e6ff1c9bf1024bb5bb4c2bac0c7c5a31aafcf08ef35`, extracted at `/private/tmp/ghidraboy-m8-sameboy-extracted`; log `/private/tmp/ghidraboy-m8-sameboy-validate.log`.
- mGBA-only installer matrix: 12 checks pass, including independent runtime readiness without SameBoy files, installed launch-offer selection, two interrupted-transaction recoveries, upgrade/rollback, preservation of user edits/unrelated extensions, payload hash refusal and missing native-decompiler refusal.
- Python syntax compilation passes. Whole-repository `git diff --check` reports only context whitespace within the literal pre-existing mGBA patch, whose exact pinned digest is intentionally retained.

Detailed logs are `/private/tmp/ghidraboy-m8-source-tests.log`, `/private/tmp/ghidraboy-m8-validate-v2.log`, `/private/tmp/ghidraboy-m8-both-validate.log`, `/private/tmp/ghidraboy-m8-install-checks/results.json`, `/private/tmp/ghidraboy-m8-package-build.log`, and `/private/tmp/ghidraboy-m8-source-rebuild.log`.

These are intermediate package snapshots because M9 and generic integration sources were being finalized in parallel. The tested mGBA-only archive SHA-256 is `ae7d2ca4106917cc46bc14027e41ae1b7e08649884e9d51452d6b43f299618a4` (extracted at `/private/tmp/ghidraboy-m8-extracted-v2`); combined archive SHA-256 is `305dda40bf630a3ec6f4234c52edafd6c3b475986ddbc1429cc0d558c4c5ec04` (extracted at `/private/tmp/ghidraboy-m8-both-extracted`). Final release evidence must refresh the complete extension/artifact/package tuple after integration sources are frozen. The three package selections retain the same verified Java extension ZIPs; selection is applied during installation.

## Remaining platform/release scope

Build and execute a native Linux x86_64 mGBA adapter in the Linux validation lane, verify its dynamic dependencies and included source reproduction, then run extracted mGBA-only and combined installer/native/real-RMI acceptance there. `build_mgba.py` and `--platform linux-x86_64 --native-dir ...` support that flow, but no Linux mGBA success is claimed here. The current macOS mGBA binary links only Apple system frameworks/libraries; this does not imply Linux or SteamOS compatibility.

After final M9 changes, rebuild `integrationArtifacts`, package the final tuple and rerun extracted acceptance. Existing native build receipts remain valid only while native sources and builder hashes remain unchanged. Archive reproducibility should be compared only after source inventory and extension outputs are frozen. Physical Steam Deck and remaining interactive acceptance stay deferred until all other evidence is solid, as directed by the user.
