# GhiGBC

A generic SameBoy-backed Game Boy debugger for Ghidra: real Trace RMI, physical bank mappings, breakpoints and CPU access watches, immutable captured history, checkpoints, explicit recoverable edits, and an SDL game window.

GhidraBoy is the sole SM83/static-analysis provider. GhiGBC owns live hardware observations, trace publication, execution ordering and installation. Optional GhiBW3 supplies exact-revision game decoding and study UI; generic debugging does not require it.

The local candidate targets Ghidra12.1.3 with Java21, Python3.14.7 on macOS arm64 and Python3.13.15 on Linux x86-64. Use the prebuilt platform archive and [installation/rollback guide](docs/INSTALL.md), then the [generic teaching walkthrough](docs/TEACHING.md). See [support and limits](docs/SUPPORT.md), [mapping boundary](docs/contracts/mapping.md) and [profile API](docs/contracts/profiles.md).

Contributor dependency order is maintained GhidraBoy → GhiGBC → optional GhiBW3. Set GHIDRA_INSTALL_DIR/JAVA_HOME, then run scripts/build_native.sh and scripts/build_extension.sh. Run scripts/test_native.sh for standalone native/Python gates; scripts/test_ghidra.sh uses an isolated installed profile and a real Trace RMI process. scripts/package_candidate.py creates reproducible prebuilt archives; use --help for explicit inputs. scripts/test_installer.py exercises actual recovery/rollback behavior against matched manifests.

The source/validation ledger is in the existing GhiBW3 repository at docs/integration/LEDGER.md. Old 12.1.2 student archives remain intact as rollback. Interactive GUI/Deck acceptance and publication are separate; local package results do not imply a completed Steam Deck installation.

Credit: SameBoy by LIJI32 and contributors; GhidraBoy by Joonas Javanainen/Gekkio and contributors; Ghidra by the NSA; RGBDS contributors. Exact file notices are in LICENSES and the component archives. Private commercial ROMs, Programs and checkpoints are excluded from packages.
