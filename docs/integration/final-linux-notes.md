# Final Linux qualification

Evidence date: 2026-09-06. Frozen revision: `93b713091382f8de5419fa3c9b4bed75c77b1e92`. All three Linux packages passed the extracted-package base runtime suite and portable observation capture/reopen. Final acceptance is blocked by a combined-package research provenance omission: `ResearchExperimentTest` reads `tests/fixtures/banks.asm` and `tests/ghidra/ResearchExperimentTest.java` to hash its recipe inputs, but neither file is packaged. The first missing file caused `NoSuchFileException`; the standalone research reopen and direct mGBA checkpoint rejection were not reached. Production sources were not changed by this qualification lane.

| Package | Archive SHA-256 | Native/package tests | Installer checks | Runtime and observation |
| --- | --- | ---: | ---: | --- |
| SameBoy | `5bb4167fe721b6eeeb19f4ed08932c4ef64b48ddbc76c9952b16ba0e9825a635` | 91 | 11 | PASS |
| mGBA | `16c232dcff07c4b4a6d4d36585ab353b83b6ebe12274cd363677804f4cc4f6b1` | 17 | 12 | PASS |
| Combined | `794ed62e97cc3ca9f568f5fea8dccc047c10a6282461f5030e890a3d781a3f48` | 105 | 11 | PASS; additional research failed |

Each archive was built twice serially with byte-identical output and manifest. All three manifests identify the same 342 tracked build/runtime source files; canonical file-hash-map SHA-256 is `1432601746b8ee2a94aeb195258c2f258b0466245424e0198c378fd43beb05d2`. Java artifact manifest SHA-256 is `fa84c769065339233f441888b3201b2d7e8c72d808e85097baff0260cac72c05`. Exact manifest, extension, native, runner, build-log and runtime-log hashes are in [final-linux-evidence.json](final-linux-evidence.json). Archives, manifests, logs and portable reports are retained under `dist/integration-final-93b7130/linux/`.

Runtime used image `sha256:1955ff1e743d7b182f5b991d3d192e05604fb7497fcdc8a2772d56dd072418ca`, Docker x86-64 emulation on macOS arm64, Linux `6.12.76-linuxkit`, glibc 2.41, Python 3.13.15 and Java 21.0.12.1. Each fresh container ran as UID 501 with `--init --network none`, the explicit loopback hostname, a read-only Ghidra distribution and Xvfb. No compiler/build tools or system SDL were available. Bundled SDL 2.32.4 passed window creation, paused event pumping and cleanup. Doctor reported native, generic-test and desktop readiness for every selected backend. The retained decompiler remained `12.1.3+ghidraboy.switch-recovery.2`, binary SHA-256 `f21150bc269246b67d652a1aeb83eff94c98a886e1a60b5b774ec2c444e8c783`.

SameBoy's real Trace RMI suite passed watch/edit/checkpoint/history and automatic-launcher assertions. Its 250-capture growth probe completed in 154.48 seconds with zero dropped events; this bounded run is not a long-duration leak proof. mGBA and combined passed the shared backend RMI contract, including static-upload retry, physical-bank mapping, bounded shutdown and saved observation reopening. Installer checks covered crash recovery at both mutation boundaries, upgrades, self-rollback, preservation of user edits, hash rejection and native-dependency rejection. Portable report tests exercised invalid-data rejection and a separate Java process reopening captured evidence without an emulator.

SameBoy native SHA-256: `5ba65dd4539c6c4b9367b932e8a27cf67c4894cd45b11cd7c65f515106fb3126`; mGBA native SHA-256: `7635d8f329a9755120be89a2b81d1641dbf7e4dd06dabde7c425a3e133840b44`. Mac dylibs retained their original hashes.

Two temporary helper issues are separate from the package failure: the host's older Python lacked the tar extraction `filter` keyword, so extraction used host `tar`; the original combined-only selector printed an expected `AssertionError` for single-backend variants before their successful exit. That exact executed wrapper is retained as `executed-runner.sh`; the reusable wrapper now uses a clean conditional with `NOT_APPLICABLE` for single-backend research. No passing suite was repeated solely for that logging change.

Physical Steam Deck verification is deferred by the user. Container/Xvfb success does not establish physical controller/focus/compositor behavior or the ABI of every downstream Linux system.
