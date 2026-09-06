# M8 Linux backend qualification

Evidence date: 2026-09-06. This lane uses emulated Linux x86-64 Docker containers on macOS and Xvfb. Physical Steam Deck verification remains deferred by the user. The retained native-decompiler dependency remains `12.1.3+ghidraboy.switch-recovery.2`, as required by `tools/dependencies.json`.

## Isolated native builds

The prior builder image is `sha256:7b73cdbae90f39b5d39295fb977d8e45d0d69eaecf2f787ea9eefe1fee1a5233`. `tools/linux/NativeAdapters.Dockerfile` adds CMake 3.22.1 in a separate image, `sha256:a6c3a75c83e92805cc3fa99372e6e6ac9602be30b77310610491da4091acfac0`. Both adapters were compiled with GCC 11.4.0 in offline, unprivileged Linux containers. Main macOS native outputs and the prior Linux evidence were preserved.

SameBoy source was copied from the pinned `208ba4afabffab9edde416f2dbb8ae459e34adb8` checkout with the locked observer patch. Reverse-application verification passed. Its isolated build used the documented `make lib` flags and the current native adapter, including observer and DMG/MBC2 corrections. The resulting ELF x86-64 binary SHA-256 is `cac728d1d4a67c303f62e76eede4a0f4abc9d44e26621e584a883bc518481ac8`. ELF/ABI inspection passed; required libraries are `libm.so.6`, `libmvec.so.1`, `libc.so.6` and the ELF loader.

mGBA was built twice in different directories from the exact included pristine archive `a59017f0dee15f8f9067c5f0638707f81487de595274f6b9e5a3e88f2bb517e9`. Both builds produced binary SHA-256 `7635d8f329a9755120be89a2b81d1641dbf7e4dd06dabde7c425a3e133840b44` and canonical compatibility identity `24049d7602ee3b40e45220fccb9c130fd04872fd1a703e664c6cea000d8bb398`. Its only required libraries are `libm.so.6`, `libc.so.6` and the ELF loader. Both adapters load in the retained runtime image without compiler dependencies.

Builds, source receipts, ELF output and reproducibility comparison are retained under `/private/tmp/ghidraboy-m8-linux-final`. Native outputs are in its `native/` directory; reproduction outputs are in `rebuilt/`. Runtime image: `sha256:1955ff1e743d7b182f5b991d3d192e05604fb7497fcdc8a2772d56dd072418ca`.

## Runtime qualification

`tools/linux/runtime-check.sh` verifies no compiler/build tools or system SDL, then runs package/native/Trace RMI, installer recovery/rollback, backend-aware packaged SDL and doctor checks in an extracted runtime. Containers use `--init --network none`, unprivileged UID 501, an offline loopback hostname entry and Xvfb. Only the extracted package, copied Ghidra distribution, test runner and results directory are mounted.

An interim mGBA-only package (`144f98bd7b038708d7a26ff115a353e1afee05eecfcb94657cb45a437a706d00`, manifest `a5fb2d4da2a9f6e0007d68b3fc5ffd9f4351344df3980055bd2febd71e5b3141`) passed 17 native/package tests, the real shared `BACKEND_TRACE_CONTRACT_PASSED`, 12 installer checks, packaged SDL creation/event-pump/cleanup and doctor core/desktop readiness. The RMI contract exercises automatic static-upload retry, bank mappings, bounded process shutdown and saved backend-neutral observation reopening. Results are in `mgba-interim-results/`; archive and runtime output are retained separately. Runtime Python is 3.13.15 and glibc is 2.41.

This is an interim Java/source snapshot while final native-CGB device tests are in progress. After the STOP/wake boundary correction, the canonical SameBoy patch changed to `afb55300828df629058e9fde30024801705cb4ffc3c935e58c5720da5d217b67`. A fresh isolated rebuild from the corrected source produced `5ba65dd4539c6c4b9367b932e8a27cf67c4894cd45b11cd7c65f515106fb3126`, replacing the earlier binary only in the isolated `native/` output directory. The new patch reverse-check and ELF/ABI inspection passed. `sameboy-final-native-receipt.json` records exact adapter/header/patch hashes; the final native binary is ready for package execution.

Final package identities and results remain pending the frozen Java/source tuple. No final SameBoy runtime success is claimed by the rebuild alone.
