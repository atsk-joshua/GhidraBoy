# Validation layers

The read-only component workflow runs the pinned native build and Python/bridge tests without launching Ghidra or installing a study extension. Third-party actions use verified full SHAs; checkout credentials are not persisted. No publication action is attached to PRs or component completion.

Changed-boundary integration is `scripts/test_ghidra.sh` with a matched manifest, an isolated GBC_TEST_HOME and explicit selected Ghidra/JDK. It includes mapping conformance, plugin/service initialization, stale remote requests, edits/restore and independent reopen. Optional study integration is GhiBW3/scripts/test_battle.sh with copied authorized private inputs, or GhiBW3/scripts/test_static.py for the independent static artifact.

The final candidate gate runs the extracted archive's Validate.sh in a fresh home, with the source checkout absent. Linux runs on an unprivileged x86-64 Debian13 container without make/gcc/javac/Gradle/RGBDS. A250-stop bounded soak records same-host latency, dropped events, process RSS and intentionally retained trace growth. Performance observations are not improvements or a leak diagnosis; actual Deck thresholds and physical responsiveness are assessed in M5.

Run scripts/test_installer.py for matched package hashes, interruption recovery, profile removal, self rollback and preservation of changed user files. Inspect every required marker and nonzero exit; a printed pass marker cannot override plugin initialization failure. GUI action/rendering/focus checks use a positively identified isolated application and remain a separate gate from headless/Xvfb checks.

Publication requires explicit authorization after reviewing the final source/file manifests, hashes, licenses and acceptance report. No remote workflow was dispatched during local integration.
