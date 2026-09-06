#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0; see NATIVE_ORACLE_LICENSE.
"""Execute the self-authored nibble-switch fixture in SameBoy for all 256 inputs.

Owned by GhiGBC: hardware execution, native captures and stack/register checks.
The independent static C/range verifier remains in GhidraBoy.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROUTINE_HEX = "7ee6f0cb37875f16002ae5e60f210002195e2356626be9"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def address(value):
    return value.to_bytes(2, "little")

def native_oracle(ghigbc, work):
    boot = bytearray(0x900)
    boot[:3] = bytes.fromhex("c3fc00")
    boot[0xfc:0x100] = bytes.fromhex("3e01e050")
    boot_path = work / "boot.bin"
    boot_path.write_bytes(boot)
    rom = bytearray(0x8000)
    rom[0x100:0x103] = bytes.fromhex("c30020")
    rom[0x134:0x144] = b"NIBBLE ORACLE\0\0\x80"
    rom[0x147:0x14a] = bytes((0x19, 0, 0))
    # Identical operations to the assembler fixture; relocated from100 to300.
    # Only the absolute table address0200 is embedded in this straight-line code.
    routine = bytes.fromhex(ROUTINE_HEX)
    rom[0x300:0x300 + len(routine)] = routine
    for case in range(128):
        target = 0x1000 + case * 8
        rom[0x200 + 2 * case:0x202 + 2 * case] = address(target)
        rom[target:target + 7] = bytes((0xe1, 0x3e, case, 0xea, 0, 0xc0, 0xc9))
    code = bytearray.fromhex("f3afe04031f0df")  # DI; LCD off; SP=dff0.
    for value in range(256):
        code += bytes((0x3e, value)) + bytes.fromhex("ea00c12100c1cd0003fa00c0")
        code += b"\xea" + address(0xc200 + value)
        code += bytes((0x7d, 0xea)) + address(0xc400 + value)
        code += bytes((0x7c, 0xea)) + address(0xc500 + value)
        code += b"\x08" + address(0xc600 + 2 * value)
    stop = 0x2000 + len(code)
    if stop + 2 > 0x4000:
        raise ValueError("Native driver escaped fixed ROM")
    rom[0x2000:stop] = code
    rom[stop:stop + 2] = bytes.fromhex("18fe")
    rom[0x14d] = (-sum(rom[0x134:0x14d]) - 25) & 255
    rom[0x14e:0x150] = (sum(rom) & 65535).to_bytes(2, "big")
    rom_path = work / "nibble-oracle.gbc"
    rom_path.write_bytes(rom)
    sys.path.insert(0, str(ghigbc / "python"))
    from ghigbc.native import Machine, CORE, CONFIG

    with Machine(rom_path, boot=boot_path) as machine:
        machine.breakpoint("rom", 0, stop)
        machine.prepare()
        for _ in range(2000):
            if machine.run_slice():
                break
        else:
            raise RuntimeError("Native execution exceeded finite slice bound")
        capture = machine.capture()
        memory = capture.memory
        checks = {
            "reachedStop": capture.state["pc"] == stop,
            "bootDisabled": capture.state["boot"] == 0,
            "romUnchanged": memory[:0x8000] == rom,
            "allResultBytes": list(memory[0xc200:0xc300]) == [n >> 4 for n in range(256)],
            "allReturnedHl": memory[0xc400:0xc500] == b"\x01" * 256 and memory[0xc500:0xc600] == b"\xc1" * 256,
            "allReturnedSp": memory[0xc600:0xc800] == bytes.fromhex("f0df") * 256,
            "lastInputPreserved": memory[0xc100] == 255,
        }
        return {"status": "PASS" if all(checks.values()) else "FAIL", "checks": checks,
                "cases": 256, "resultBytes": list(memory[0xc200:0xc300]), "romSha256": sha(rom_path),
                "bootSha256": sha(boot_path), "routineHex": routine.hex(),
                "nativeLibrarySha256": sha(Path(machine.lib._name)), "core": CORE, "config": CONFIG}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=False)
    result = native_oracle(Path(__file__).resolve().parents[1], args.work)
    result["schema"] = "ghigbc-nibble-switch-native-v1"
    result["scriptSha256"] = sha(Path(__file__))
    (args.work / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "cases": result["cases"]}))
    return 0 if result["status"] == "PASS" else 1

if __name__ == "__main__":
    sys.exit(main())
