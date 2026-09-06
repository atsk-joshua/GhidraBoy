# SameBoy breakpoint at wakeup: implementation and qualification

2026-09-06, macOS arm64. This focused follow-up fixes the failing CGB speed-switch breakpoint in `debugger/tests/test_cgb_devices.py`. It preserves the private inspection engine introduced by the accuracy work. The source changes are local and uncommitted; no staging or remote writes occurred.

## Defect and design

SameBoy can enter `GB_cpu_run` halted, advance the speed-switch countdown, wake and fetch the next opcode within that same call. The adapter's outer `!halted` breakpoint check therefore missed the first runnable instruction after the switch. Reporting a breakpoint while the CPU remained indefinitely halted would be incorrect.

The canonical patch adds a callback immediately before an opcode fetch, after the core has selected its actual run path. The native adapter retains its ordinary outer breakpoint check and uses the same matcher through this callback for boundaries not already checked. Indefinite HALT/STOP waits and interrupt entry do not invoke an opcode-fetch breakpoint. The callback also sets the actual instruction writer address before bus events occur.

A stopped fetch needs a continuation, rather than a new call through wake timing and EI/interrupt arbitration. The patch appends an aligned `uint64_t ghigbc_opcode_pending` to the end of the saved `core_state` section: bit 0 records the pending fetch; bit 1 retains deferred vblank bookkeeping. `GB_run` finishes its post-CPU bookkeeping after the pending instruction resumes. With no stopped fetch, the original execution path remains unchanged.

The section grows from **152 to 160 bytes** with all prior field offsets preserved. SameBoy retains unread values when loading a short section, so its loader explicitly defaults the new marker to zero before reading legacy sections. The private inspection engine loads the same saved continuation and remains isolated from the execution engine. No fields were added to the public `gc_state` ABI and no physical region IDs changed.

Canonical patch SHA256: `afb55300828df629058e9fde30024801705cb4ffc3c935e58c5720da5d217b67`. The dependency lock is updated to this value.

## Checkpoint compatibility

New checkpoints identify the new canonical patch. The adapter additionally accepts exactly the prior patch `a352600754f52b4b4d9118b1e17c00396374f0581e6f225508d8056691f27f6d` for **schema 2, CGB-E** only. Every other identity constraint remains checked: core, configuration, model, clock, ROM and boot fingerprints, backend, payload filename and timebase. The existing verified payload copy and SHA256 check remain unchanged. Unknown patch hashes and changed identity fields fail before native restore.

The real retained M5 checkpoint was copied without modifying its metadata or payload from:

`/private/tmp/ghidraboy-integration-20260906/m5-synthetic-package/GhidraBoy-Debugger-20260905-integration1-macos-arm64/build/trace-checkpoint-1788689341040`

Its metadata SHA256 is `2dc13b227210d3b03963e8bba5c0a3dbecbf8d04740468b8a972d6a29409eb35`; its payload SHA256 is `ac7e24840483e3e9bc0eead31d1fae9512f596dd5853fb98a5b6258b5ebd4089`. Verification first restores that genuine old state, then stops the same machine at a pending speed-switch fetch, and restores the old state again. The new marker clears to zero, registers return to PC `0x4567` / ROM bank 2 / BC `0x3456`, and the complete reserialized engine state matches the first restore byte for byte.

Old readers are **not qualified to resume new pending-fetch checkpoints**. Their expected patch fingerprint differs and must continue rejecting the new envelope. This is one-way, explicitly bounded compatibility, not a general permission to ignore patch mismatches.

## Verification

All following commands ran from `/Users/joshuahansen/dev/GhidraBoy` and completed with independently collected **exit 0**. Logs and reports are under `dist/integration-baseline-20260906/`.

| Command | Result | Log/report |
| --- | --- | --- |
| `bash debugger/scripts/build_native.sh` | PASS | `sameboy-wake-build.log` |
| `PYTHONPATH=debugger/python debugger/.venv12/bin/python -m unittest discover -s debugger/tests -p test_sameboy_wake.py -v` | **3 tests PASS** | `sameboy-wake-tests.log` |
| `PYTHONPATH=debugger/python debugger/.venv12/bin/python -m unittest discover -s debugger/tests -p test_cgb_devices.py -v` | **2 tests PASS**, unchanged parent tests | `sameboy-wake-cgb-devices.log` |
| `bash debugger/scripts/test_native.sh` | **104 tests PASS** | `sameboy-wake-native-tests.log` |
| `PYTHONPATH=debugger/python debugger/.venv12/bin/python dist/integration-baseline-20260906/sameboy-wake-legacy/verify.py` | Genuine M5 checkpoint restore while pending; full state equality PASS | `sameboy-wake-legacy/report.json` |
| `python3 tools/accuracy_sameboy.py --mooneye-source /private/tmp/ghidraboy-m7-mooneye --assembler-source /private/tmp/ghidraboy-m7-wla --output dist/integration-baseline-20260906/sameboy-wake-accuracy` | **55 rows / 165 variant runs PASS** | `sameboy-wake-accuracy/report.json` |
| `python3 dist/integration-baseline-20260906/sameboy-wake-speed-pristine/verify.py` | Direct authored speed-switch fixture: all **3 variants PASS** | `sameboy-wake-speed-pristine/report.json` |
| `git -C debugger/.deps/SameBoy diff --check` | Actual patched core source whitespace PASS | Tool output, no diagnostics |

The three new regression tests cover no false breakpoint during indefinite HALT, stopping before the wake opcode, one-instruction/four-tick resume in double speed, checkpointed continuation, equal full guest state and total ticks versus uninterrupted execution, loading a short legacy core section while pending, and rejecting unrelated identity mismatches. The deliberately shortened test payload only exercises section compatibility; the separate M5 verification proves compatibility with a genuine old writer.

The fresh 55-row accuracy report rebuilds pristine and instrumented cores from the pinned SameBoy Git object using the updated canonical patch. All normalized streams match; **3,986 inspected boundaries** report **zero serialized-state changes**. Fixture classification and limits remain those in `m7-accuracy-notes.md`; this receipt supersedes its source attribution for the repeated named rows, not its scope limitations.

The additional speed-switch fixture executes the redistributable CGB boot, prepares KEY1, executes STOP, and checks `(KEY1 & 0x81) == 0x80` using a standard register pass/fail signature. Pristine, instrumented and inspected variants each take **1,170,457 core calls / 26,302,792 8 MHz ticks**, produce identical normalized streams, and pass. Its inspected variant adds **73 unchanged serialized-state boundaries**. It is self-authored regression evidence, not an independently published test ROM or locally collected physical-hardware result.

Linux/package qualification is coordinated separately. This work does not waive physical-device acceptance, whole-project performance qualification or remaining migration gates. Canonical patch files contain required whitespace in unified-diff context; source whitespace is checked on the actual patched core rather than changing patch context or hashes to satisfy an outer patch-file whitespace check.

## Source and evidence identities

These hashes identify this completed worker snapshot. Other coordinated changes in the shared checkout are excluded; later changes need fresh attribution.

| Path | SHA256 |
| --- | --- |
| `debugger/backends/sameboy/native/ghigbc.c` | `1154614462bed583e560ba99ad9b0b3632c95f405e752a1c2a8230735f770e16` |
| `debugger/backends/sameboy/native/patches/0001-cpu-bus-provenance.patch` | `afb55300828df629058e9fde30024801705cb4ffc3c935e58c5720da5d217b67` |
| `debugger/python/ghigbc/backends/sameboy.py` | `a0d66569306ac5aa33a35aa93b8b34614332646745f32195b8734b68db086681` |
| `debugger/python/ghigbc/session.py` | `011597c78f1c12ad43df07183b66bbfeaa825e240425c93273257c549c3f15ae` |
| `debugger/tests/test_sameboy_wake.py` | `7abbc33b9ba097644e069332404d8efa2fc6065d2378c3857899f79e0ac1e5db` |
| `debugger/tests/test_cgb_devices.py` | `4105ec627bacc21eee2a9afa69f30f913a7a230f7371fd105432d96fb3440b46` |
| `debugger/build/libghigbc.dylib` | `67e39fead16cdddb492cef8b5d978072d32cd4d2d2109aa7efd076bd46ca7cb1` |
| `tools/dependencies.json` | `f08e956902e0e5814b07b36b90f51d07b01d1a8fbaf35993f867b58661aa6e61` |
| `dist/integration-baseline-20260906/sameboy-wake-build.log` | `434200e72c63285a7119d336d2026aa32a8824f48bd6b1f6deeac985b2827793` |
| `dist/integration-baseline-20260906/sameboy-wake-tests.log` | `748002f8a29fedf06d89d2f2e6be6452a0dc4b4e4dda922a172bbec0442101dd` |
| `dist/integration-baseline-20260906/sameboy-wake-cgb-devices.log` | `bf4247d84085fe4fa8146b2bce017bac7b91ca27cf90dd4b0db73ae9fd37e8a9` |
| `dist/integration-baseline-20260906/sameboy-wake-native-tests.log` | `23bd3fef092ab2b8e9063af55a5c8f5011faca4a8ac612414f8e00aa1f369b6f` |
| `dist/integration-baseline-20260906/sameboy-wake-legacy/verify.py` | `c5efcbe6363ae9cf1be15ad448c89859f85b3d83a4f9a0e652407cd8e8173e56` |
| `dist/integration-baseline-20260906/sameboy-wake-legacy/report.json` | `d23d20e24f5660ed46c8a379eb26115d3ff7f46a86c5eed8f5e9c716db95de75` |
| `dist/integration-baseline-20260906/sameboy-wake-accuracy/report.json` | `ff31b80adbb626e43bcf137d9fe23167927ab643ab79bde16ca31f33a38eea89` |
| `dist/integration-baseline-20260906/sameboy-wake-speed-pristine/verify.py` | `b41651ccb34e756e8c8bc611fec88e5341443fd4f89bc9abe78a6f89d9abc523` |
| `dist/integration-baseline-20260906/sameboy-wake-speed-pristine/report.json` | `f55906e12b3571c6e17be929f6412d7a8856807349feb377ae729c951416f6fe` |
