# M7 bounded independent accuracy and pristine comparison

2026-09-06, macOS 26.5.2 arm64, native execution. This receipt qualifies the named
source snapshot and selected tests only. It does not complete M7 or Release B.

## Result and scope

**55 fixture/model rows passed in all three execution variants (165 runs).**
The variants are a pristine SameBoy core; the patched core running the real
GhidraBoy native adapter with CPU writes watched across the entire address
space; and that adapter with periodic `gc_snapshot_hardware` inspection.
All normalized streams match the pristine stream byte for byte. The inspected
variant also preserves the complete serialized engine state at **3,986** sampled
boundaries and observes **2,893,833** CPU write events. Events are exercised, not
used as the source of correctness expectations. There are no expected-failure
suppressions or skipped rows in this selected matrix.

| Input classification | DMG-B | CGB-E | Evidence boundary |
| --- | --- | --- | --- |
| Mooneye acceptance | 19 PASS | 17 PASS | EI/interrupt timing, HALT, timer reload/write behavior and OAM DMA; CGB uses DMG compatibility mode |
| Mooneye misc | — | 2 PASS | CGB-family VBlank/STAT and unused IO-bit expectations, DMG compatibility mode |
| Mooneye emulator-only MBC2 | 7 PASS | 7 PASS | All seven pinned MBC2 fixtures: RAM, register bits, unused bits, 512 Kbit/1 Mbit/2 Mbit ROM banking |
| Self-authored banked fixture | 1 PASS | 2 PASS | Native DMG, DMG-on-CGB and native CGB; synthetic regression expectations |

Mooneye's classifications are retained. In particular, the MBC2 files remain
`emulator-only`, even though their source comments describe upstream verification
using a flash cartridge with a genuine MBC2A chip. This is published external
provenance, not physical testing performed here. **Locally collected hardware
evidence remains unverified.**

`HW-03` has partial named-subsystem coverage. `ACCURACY-01` passes for these
fixtures and sampled boundaries. `ACCURACY-02` is not run by this same-core
harness. `CPU-01` exhaustive SLEIGH/vector gates are separate and unchanged.
The matrix does not cover STOP, CGB speed switching, HDMA, every PPU/APU/bus
behavior, or an independent native-CGB ROM suite. Original boot register/divider
expectations are excluded because the boot inputs are SameBoy's redistributable
boot implementations. These runs execute boot; they do not qualify a post-boot
initialization policy. Synthetic model/boot-unmapping coverage remains separate
from independent hardware expectations.

## Method and discovered defect

Both cores are exported from the same pinned Git object. The instrumented copy
receives only the canonical locked patch; it compiles the current native adapter
from frozen copies of `ghigbc.c` and `ghigbc.h`. Pristine execution calls `GB_run`
directly and has no GhidraBoy callbacks. The adapter variant calls the production
allocator/configurator, installs a full CPU-space write watch and advances one
`GB_run` call per iteration through `gc_run`.

Model, boot bytes, ROM bytes, initial random seed, no-button input and accurate
emulated RTC mode are matched. No fixture uses an RTC mapper. Every 16,384 run
calls, and at the final signature, the probe compares registers/flags, 8 MHz
ticks, mode/boot state, selected banks, physical WRAM/VRAM/cart/OAM/HRAM/IO bytes
and pixel output. Seeded undefined startup memory is useful for detecting
same-core differences; it is not a hardware expectation. No cross-core private
state format equality is required.

The independent probe found a real observer defect during CGB boot: before the
fix, inspection changed serialized engine state in 70 of 71 sampled boundaries
of the synthetic CGB run. `GB_safe_read_memory` can advance APU state while
reading registers. The coordinator fixed production capture to read CPU memory
using a separate inspection engine. The passing matrix above includes that fix.
The retained pre-fix logs are `m7-accuracy/observer-failure.stdout.log` and
`m7-accuracy/observer-failure.stderr.log` under the baseline artifact directory;
the guest signature passed, but the observer check correctly failed the run.
Those diagnostic logs predate frozen adapter copies and are not a complete
source-attributed acceptance receipt.

Two negative comparator tests pass: a changed byte beyond the first comparison
chunk reports its exact offset/value, and truncated/missing streams fail.
Identical streams pass. Unexpected run differences remain unclassified and
retain first-byte diagnostics instead of being suppressed.

## Reproduction and retained artifacts

The manifest is [`tools/accuracy-fixtures.json`](../../tools/accuracy-fixtures.json).
It pins [Mooneye source revision 31510e12](https://github.com/Gekkio/mooneye-test-suite/tree/31510e12eea6286d36eea060a6adde755e1067aa)
and the [WLA-DX revision selected by that revision's CI](https://github.com/vhelin/wla-dx/tree/89a90a56be5c2b8cf19a9afa3e1b32384ddb1a97).
Both are public source inputs; no private ROM or original boot firmware is used.
The canonical SameBoy revision remains `208ba4afabffab9edde416f2dbb8ae459e34adb8`.

From the repository root, provide local Git repositories containing these exact
revisions, and choose a new output directory:

```sh
python3 tools/accuracy_sameboy.py \
  --mooneye-source /private/tmp/ghidraboy-m7-mooneye \
  --assembler-source /private/tmp/ghidraboy-m7-wla \
  --output dist/integration-baseline-20260906/m7-accuracy-final
debugger/.venv12/bin/python -m unittest discover \
  -s tools -p test_accuracy_harness.py -v
```

The runner performs no network access and never writes the normal runtime
library. It exports pinned Git objects rather than trusting dirty checkouts,
builds isolated libraries/assembler/fixtures, freezes adapter inputs, and
records binary, ROM, boot and source hashes. Apple clang 21.0.0 and CMake 4.4.3
were used; the historical pinned assembler needs CMake's
`CMAKE_POLICY_VERSION_MINIMUM=3.5` option. This does not change assembler source.
`--reuse-build` reuses this tool's prepared dependency outputs and recompiles
the probes against fresh frozen adapter inputs. Use a fresh directory for
independent rebuild provenance.

Final commands exited **0**. The full generated report is
`dist/integration-baseline-20260906/m7-accuracy-final/report.json` and its run log
is `dist/integration-baseline-20260906/m7-accuracy-final.log`. Individual command
lines, exit codes, durations, model/mode, source/binary identities and fixture
hashes are in the report. Source exports, licenses, compile logs and per-run logs
are retained alongside it. Normalized streams are retained as `.bin.gz` with
both compressed and uncompressed SHA256 values; 520,171,374 bytes were compared
per variant comparison across the matrix. Comparator log:
`dist/integration-baseline-20260906/m7-accuracy-comparator-tests.log`.

| Receipt input/output | SHA256 |
| --- | --- |
| `report.json` | `0d0a01968f40e0fb035ee75ec2941d0434d7ef64a04ddc424a511e475a10509d` |
| Final run log | `d19f010e9d458fc79ef7994d4c4564c6a93e81f3db68204494de1ef1c7657962` |
| Frozen `ghigbc.c` | `0d1989f1bb2c4ab3405af4c9b3257a154d02500d05b6f10a3a515d6594a5c56c` |
| Frozen `ghigbc.h` | `0f52aa0792eba6065d0fa9db68febc85435fd9f273fad3fa3d43542177e3219d` |
| Probe source | `ecf1fceb2a91985a673b63c859302e43c35d85e4b8ea681759963ce3a0d97488` |
| Runner source | `cdda7119b109f70ebb51fa86155cc2eec8760afd9de7ea2111c07f3dd478b9a3` |
| Fixture manifest | `d09938f6b814cf7a94da0703730e7d86812948e2deaf6b46aa237c93c9c4c842` |

Changes to these inputs require fresh attribution. This worker changed only the
accuracy tools, their comparator tests and this note; the production observer
fix and its dedicated regression are owned by the coordinator. No commits,
staging, shared plan/status edits or release-support claims were made here.
