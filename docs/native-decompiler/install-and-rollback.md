# Copy-only native install, verification and rollback

`tools/native_dependency_update.py` is a standalone Python 3.9+ tool. It never updates a source distribution in place. Install and rollback each publish a new bundle containing `distribution/` and `receipt.json`; the entire bundle appears through one exclusive atomic directory rename. Existing output paths are never replaced.

Use the package SHA256 recorded by the trusted build/validation receipt. The tool hashes and parses the same bounded ZIP bytes, rejects unsafe/duplicate paths and links, checks the pinned patch/source/dependency identities and platform, and validates both native executable and marker hashes/modes before changing a staged copy. Unrelated files and edits are preserved. Edited native executables or identity markers are refused.

The current source updater and examples target `12.1.3+ghidraboy.switch-recovery.2`. The original native files must match the package's recorded base. A source already carrying `.1` must first be rolled back into a new copy using its matching retained updater/package under `dist/decomp3/`; the `.2` updater deliberately refuses mismatched managed files.

## macOS arm64 example

Install into a new copy:

```sh
python3 tools/native_dependency_update.py install \
  --source /tmp/ghidraboy-switch-recovery2-input \
  --package 'dist/switch-recovery2/ghidra-native-12.1.3+ghidraboy.switch-recovery.2-mac_arm_64.zip' \
  --package-sha256 4882d0623e4eddcbd9e8a31b4aa6db4ada947a5062ad2a84f2e62850f339157a \
  --output /tmp/ghidraboy-my-native-update
```

The resulting Ghidra copy is `/tmp/ghidraboy-my-native-update/distribution`. Verify it:

```sh
python3 tools/native_dependency_update.py verify \
  --source /tmp/ghidraboy-my-native-update/distribution \
  --package 'dist/switch-recovery2/ghidra-native-12.1.3+ghidraboy.switch-recovery.2-mac_arm_64.zip' \
  --package-sha256 4882d0623e4eddcbd9e8a31b4aa6db4ada947a5062ad2a84f2e62850f339157a
```

Rollback also creates a new copy; the patched source remains available:

```sh
python3 tools/native_dependency_update.py rollback \
  --source /tmp/ghidraboy-my-native-update/distribution \
  --package 'dist/switch-recovery2/ghidra-native-12.1.3+ghidraboy.switch-recovery.2-mac_arm_64.zip' \
  --package-sha256 4882d0623e4eddcbd9e8a31b4aa6db4ada947a5062ad2a84f2e62850f339157a \
  --output /tmp/ghidraboy-my-native-rollback
```

Rollback restores the exact original binary and marker contents/modes, or removes the owned added marker/file when the package records original absence. It does not claim to restore timestamps or filesystem ownership. Other edits in the patched source are copied into the rollback result rather than discarded.

## Linux x86-64

Run the same commands on a Linux x86-64 host, using the preferred Ubuntu 22.04 package:

```text
dist/switch-recovery2/ghidra-native-12.1.3+ghidraboy.switch-recovery.2-linux_x86_64.zip
SHA256: 873e4b45ed2e1fe6e364e5c74497af572a8c3b5e2af3b0511ee905d359d5aa2c
```

Source/output paths must be appropriate to that host. Cross-platform installation is refused because the runtime check must execute the target native binary. The preferred Linux artifact requires GLIBC 2.34 and GLIBCXX 3.4.29; recorded package requirements remain authoritative.

The startup check requires the exact native protocol response to a harmless unknown command. Ghidra's native executable exits 1 on end-of-input even when healthy, so an empty-input exit code alone is insufficient. The structured response proves OS loading, initialization and protocol dispatch; loader stderr, a missing response or a timeout fails before publication. Actual decompilation/corpus tests remain separate.

## Cancellation and concurrent-edit behavior

Before publication, all work occurs in a private staging bundle. An exception or cancellation removes that unpublished stage; no partly updated destination appears. `--cancel after-first-file` and `--cancel before-publish` are explicit regression options for install/rollback. Exit 3 reports cancellation, exit 2 refusal/failure, and exit 0 successful copy publication or verification.

If interruption arrives immediately after atomic publication, the complete bundle is retained and reported using its unique transaction receipt. A destination created concurrently is never overwritten, including an empty directory. Source contents and ordinary file modes are checked again before publication.

The tool supports ordinary-file distribution trees on macOS arm64 and Linux x86-64, using their exclusive atomic rename APIs. Symlink/special-file trees are refused rather than reinterpreted. Use a normal extracted distribution copy as input.

## Executed checks

Seven mechanical regression tests cover full install/verify/rollback, cancellation after either staged file boundary, preservation/refusal of edited managed files, unsafe ZIP paths/links/duplicates and wrong digests, runtime-probe failure without publication, exclusive publication races, and interruption after a completed rename. Real platform packages are also exercised separately; receipts are retained with the new copies. The platform ZIPs themselves remain unchanged.
