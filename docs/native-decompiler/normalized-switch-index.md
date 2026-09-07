# Ghidra 12.1.3 normalized switch override index defect

Status: reproduced and corrected in isolated native builds; not installed into the user's active Ghidra or included in normal GhidraBoy binaries. This is a dependency patch and regression, not a second processor implementation.

## Causal defect

`JumpBasicOverride::trialNorm` returns an index into `PathMeld::opMeld`, identifying the operation at which emulation should start. `recoverModel` assigned that operation index to `varnodeIndex`. Later `JumpBasic::findUnnormalized` uses `varnodeIndex` to index the separate `commonVn` array. The two indexes are not interchangeable.

Native diagnostic output confirms a normalized varnode resolved by a real Java DynamicHash and successfully emulated to all requested destinations. Its operation index was 6 while `commonVn` had only four elements, and the actual normalized varnode was at index 3. The subsequent unchecked access was out of bounds. This can silently replace the intended switch expression or terminate the decompiler.

[The patch](../../tools/patches/ghidra-12.1.3-jumpbasic-override-index.patch) searches `commonVn` for the actual accepted trial varnode and stores that index. If it is absent, the existing trivial-model fallback remains in force. It does not change case labels, emulate a guessed switch variable, suppress warnings, or alter instruction semantics.

## Redistributable regression

`src/test/scripts/NormalizedSwitchRegression.java` assembles a self-authored guarded six-case switch. An unsigned input >=6 returns zero. Inputs 0..2 select phase zero; inputs 3..5 select phase three. A three-byte lookup produces 1/2/3, and the actual switch index is `lookup-1+phase`. A six-word target table leads to distinct return values 10/20/30/40/50/60.

The helper `NormalizedSwitchDecompiler.java` uses existing protected DecompInterface/public DecompileCallback/Encoder extension points to transmit a native normalized override. It computes the hash from the returned HighFunction; no hash, logical label or p-code instruction is fabricated. The helper does not write Program annotations and refuses to replace an existing jump override.

The test checks the native returned case labels/destinations and that the final BRANCHIND consumes the combined index. `tools/verify_normalized_switch_fixture.py` executes the generated C for all 256 byte inputs. Its sole translation adapts the 16-bit memory lookup into the self-authored fixture byte array; switch expressions, labels and return values remain unchanged.

Observed results:

- Stock native: wrong generated C on inputs 3, 4 and 5 (three failures among 256), returning the first phase's values.
- Patched native: 256/256 generated-C results match the guarded fixture.
- Bounds-checked stock native (`commonVn.at(i)`): the regression terminates with `std::out_of_range: vector`.
- The same bounds-checked build with the index correction: native regression and all 256 generated-C cases pass.

The manual-switch warning is retained in every generated C result. Ordinary stock Java JumpTable overrides also produce the correct combined index after the native patch; explicit norm transport is not required for the known real-ROM example.

## Reproduce in an isolated dependency copy

Run the script using a Ghidra Program with the SM83 language selected; the script allocates its own new Program for the fixture and releases it afterward:

```text
-postScript NormalizedSwitchRegression.java NEW_PRIVATE_OUTPUT_DIRECTORY
```

Include `GhidraBoy/src/test/scripts` in the script path. Then:

```sh
python3 tools/verify_normalized_switch_fixture.py PRIVATE_FIXTURE_DIRECTORY NEW_PRIVATE_VERIFICATION_DIRECTORY
```

To build the isolated macOS arm64 native executable from the pinned Ghidra sources after applying the patch:

```sh
make -j8 ghidra_opt ARCH_TYPE='-arch arm64' ADDITIONAL_FLAGS='-mmacosx-version-min=11.0 -w'
```

The research used a fresh `/tmp` copy of the complete distribution and replaced only that copy's `Ghidra/Features/Decompiler/os/mac_arm_64/decompile`. The active/default installation and original distributions remain unchanged. Linux/native suite validation, dependency update packaging and a supported deployment/rollback workflow remain necessary before shipping this patch.

Private build logs, stock/diagnostic/patched/bounds-checked executables, fixture results, generated C and SHA256 identities are retained under `/tmp/gbw3-normalized-native/`. Game-specific observations are outside the generic regression scope.
