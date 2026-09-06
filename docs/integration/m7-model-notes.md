# M7 SameBoy hardware and MBC2 implementation notes

2026-09-06, local macOS arm64 source qualification. This bounded implementation extends the uncommitted model work described in `agent-handoff.md`. It is not M7 completion or a release acceptance receipt. No commits, staging, remote writes, shared plan/status edits, or unrelated file changes were made by this worker.

## Implemented boundary

- Explicit `CGB-E` and `DMG-B` construction requires the corresponding 2304-byte or 256-byte boot input. Native construction validates the model and boot size; Python validates observed model, mode and physical allocation sizes. Unsupported/old native libraries fail with rebuild guidance instead of synthesizing mode from the cartridge header.
- Additive `gc_snapshot_hardware` copies CPU/register/memory/event state and the six-field hardware descriptor under one native lock. `gc_state`, region numbers, original C creation entry points and original `gc_snapshot` remain ABI compatible. The new Python adapter requires the additive coherent snapshot API; this does not require old native libraries to implement hardware observations.
- Immutable snapshots expose actual model/mode and physical WRAM/VRAM bounds. DMG-B exposes two 4 KiB WRAM banks, one 8 KiB VRAM bank and only boot `[0,256)`. CGB hardware retains eight WRAM/two VRAM banks even in DMG compatibility mode. CGB boot coverage is `[0,256)` and `[512,2304)`; after boot both models expose no active boot range.
- CGB schema-2 checkpoint identity remains unchanged. DMG uses schema 3. Generic schema-3 identity excludes mutable observed mode, so a boot transition cannot make the same configured machine reject its checkpoint.
- Native range validation checks real bank availability, offsets/lengths, cartridge partial banks, boot holes, OAM/HRAM/IO boundaries and integer overflow. Python rejects invalid ranges and IDs before ctypes conversion; the native API independently enforces physical bounds.
- MBC2 types `05` and `06` are enabled. Cartridge region ID **4** remains unchanged. Physical bank 0 exposes **512 low-nibble cells**. CPU `A000–BFFF` mirrors canonical offsets `0–511`; CPU reads retain the driven high `F` nibble. Watches retain the attempted CPU byte and address while before/after values describe the canonical physical nibble. A change predicate ignores changes confined to irrelevant upper bits. No core-state bytes are changed by normalizing observations.
- Cartridge allocations smaller than 8 KiB expose only their physical bytes and bank 0. This corrects SameBoy direct-access bank masking for partial cartridge banks. The 2 KiB MBC1 regression covers high-bank selection and CPU mirrors.
- Agent publishes additive `Machine.Mapper` (`ROM-only`, `MBC1`, `MBC2`, `MBC3`, `MBC5`), `Machine.BootRanges` (JSON string of half-open integer pairs), and integer `WRAMSize`, `VRAMSize`, `CartSize`. CPU-to-physical breakpoint translation uses the captured boot ranges and canonical cartridge mirror offset. Static `MBC2_RAM` reconciliation and Java bank mapping are a separate coordinated worker's scope.

## Verification

All commands ran from `/Users/joshuahansen/dev/GhidraBoy`; each listed process completed with independently collected **exit 0**.

| Command | Result | Retained log under `dist/integration-baseline-20260906/` |
| --- | --- | --- |
| `bash debugger/scripts/build_native.sh` | Native library/boot/fixture build; no compiler diagnostic | `m7-model-mbc2-build.log` |
| `PYTHONPATH=debugger/python debugger/.venv12/bin/python -m unittest discover -s debugger/tests -p test_models_mbc2.py -v` | **11 tests PASS**, 2.978 s | `m7-dedicated-model-mbc2-tests.log` |
| `bash debugger/scripts/test_native.sh` | **80 tests PASS**, 4.295 s | `m7-model-mbc2-tests.log` |
| `git diff --check` | PASS | Tool output, no diagnostics |

The dedicated suite executes actual DMG-B boot and banked ROM code, CGB native and DMG-on-CGB boot transitions, restores on both sides of boot, schema compatibility, mismatched boot/old-library rejection, original snapshot ABI, native/Python bank bounds, concurrent native restores versus coherent snapshots, partial MBC1 RAM, both MBC2 cartridge types on both models, A8 mapper selection, zero-bank remapping, RAM enable/disable, mirrored nibble reads/writes/watches, change predicates, checkpoint restore and noninvasive memory capture. All ROM inputs are derived from the repository's self-authored synthetic fixtures.

The partial MBC1 test deliberately requests 2 KiB RAM and retains SameBoy's expected diagnostic: “This ROM requests a RAM size smaller than a bank, it may misbehave if this was not done intentionally.” Existing fixture mirror-write diagnostics are also retained. Neither diagnostic was hidden or counted as an independent accuracy result.

## Remaining qualification

These checks cover the adapter contract and named synthetic hardware/mapper behaviors. They do not establish the plan's independent accuracy matrix, pristine/instrumented differential results, physical-device acceptance, production ROM compatibility, or refreshed extracted macOS/Linux acceptance. Launcher/package DMG boot wiring and Java static/runtime mapping integration are coordinated separately and are not qualified by this receipt. The earlier frozen M6 candidate and soak predate these source changes and must remain separately identified.

## Exact artifact and source identities

The table below records the final native/model worker snapshot. Concurrent unrelated work in this shared checkout is excluded. Later changes to a listed file require fresh evidence attribution.

| Path | SHA256 |
| --- | --- |
| `debugger/backends/sameboy/native/ghigbc.c` | `6ef9a3d751e8eee0f6540119ba8d49370dba2cf50eaab5e0522aa8abeef93f3d` |
| `debugger/backends/sameboy/native/ghigbc.h` | `0f52aa0792eba6065d0fa9db68febc85435fd9f273fad3fa3d43542177e3219d` |
| `debugger/python/ghigbc/backends/sameboy.py` | `1d2e5ebe89185f661c16e6ea9c1b80a48575a9a97f0754863f712462905929c9` |
| `debugger/python/ghigbc/backend.py` | `0cdfdad00d5f2bd43e401c66f71468123e724f6d42549078c336c9c983564362` |
| `debugger/python/ghigbc/session.py` | `5afd2c318e07a7619a6fe1d2fbf64bc4734803be7aad559ef33d70238169fd48` |
| `debugger/python/ghigbc/agent.py` | `5b764f09e742965d0e472e02fd460a10817d6699b7f48f9196e029fbc3254a79` |
| `debugger/tests/test_backend.py` | `e6dc32263ac7b8f0cbff7f577a3d2191cca1f9ffb1ee38582f3d9785418e5e44` |
| `debugger/tests/test_models_mbc2.py` | `ea8d88b87440092600cb66cc072da951c2c374bcf0ab42ca4a6298a7dbf505f4` |
| `debugger/build/libghigbc.dylib` | `804791840e4883ac62bf141f6db1a265232b116c3d8cf143669bac207dd8e8c2` |
| `debugger/.deps/SameBoy/build/bin/BootROMs/cgb_boot.bin` | `f767b8e7e510a255f81328c89dba6e0c996b370e1bc86aebb8584a7da47a5bba` |
| `debugger/.deps/SameBoy/build/bin/BootROMs/dmg_boot.bin` | `6f64da4cecd7e54e2f928eb3e3ba7810a7a567d0d247cc71737d1771e073a916` |
| `dist/integration-baseline-20260906/m7-model-mbc2-build.log` | `b5eb736b9bbd655c0fa9996490b89fed7657c33295e46a8c3ace1ee78e937153` |
| `dist/integration-baseline-20260906/m7-dedicated-model-mbc2-tests.log` | `4156bd595adca02f6ac9ac652b4af9e8c9d57f5e987c98af2826a76cedd232e9` |
| `dist/integration-baseline-20260906/m7-model-mbc2-tests.log` | `2145f837a1a77bbfefbacb79dd70c48dbd049e70d4f9a6de076813c68638758e` |
