#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0; see NATIVE_ORACLE_LICENSE.
"""Independent SameBoy oracle for self-authored direct cartridge-write fixtures.

Uses a documented minimal boot bypass and generated MBC5 ROMs, not commercial
code. No emulator register/memory edits occur. GhiGBC is a validation dependency,
not a runtime dependency of the static provider.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghigbc", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=False)
    boot = bytearray(0x900)
    boot[0:3] = bytes.fromhex("c3fc00")
    boot[0xfc:0x100] = bytes.fromhex("3e01e050")
    boot_path = args.work / "self-authored-boot.bin"
    boot_path.write_bytes(boot)
    # Disable LCD, establish Z+C, then perform each tested instruction sequence.
    prefix = bytes.fromhex("afe04037")
    fixtures = [
        ("byte-control", "3e02ea0020fa0020ea00c0", {"romx": 2, "ramC000": 0x5a, "flags": 0x90}),
        ("word-selector-boundary", "31020108ff2ffa0020ea00c0", {"romx": 258, "ramC000": 0x5a, "sp": 0x0102, "flags": 0x90}),
        ("word-rom-vram-boundary", "31341208ff7f", {"romx": 1, "vram0": 0x12, "sp": 0x1234, "flags": 0x90}),
        ("word-address-wrap", "3e0aea000031341208ffff", {"cart_enabled": 0, "ie": 0x34, "sp": 0x1234, "flags": 0x90}),
    ]
    sys.path.insert(0, str(args.ghigbc / "python"))
    from ghigbc.native import Machine, CORE, CONFIG

    results = []
    for name, code_hex, expected in fixtures:
        rom = bytearray(0x800000)
        rom[0] = 0x42
        rom[0x100:0x103] = bytes.fromhex("c30003")
        rom[0x134:0x140] = b"BUS FIXTURE\0"
        rom[0x143] = 0x80
        rom[0x147:0x14a] = bytes((0x1b, 8, 2))
        rom[0x2000], rom[0x2fff], rom[0x3000] = 0x5a, 0x6b, 0x7c
        rom[0x4000], rom[0x7fff], rom[0x8000], rom[258 * 0x4000] = 0x11, 0x6d, 0xb2, 0xa7
        code = prefix + bytes.fromhex(code_hex)
        end = 0x300 + len(code)
        rom[0x300:end] = code
        rom[end:end + 2] = bytes.fromhex("18fe")
        rom[0x14d] = (-sum(rom[0x134:0x14d]) - 25) & 255
        checksum = sum(rom) & 65535
        rom[0x14e:0x150] = checksum.to_bytes(2, "big")
        rom_path = args.work / (name + ".gbc")
        rom_path.write_bytes(rom)
        before_hash = sha(rom_path)
        with Machine(rom_path, boot=boot_path) as machine:
            machine.breakpoint("rom", 0, end)
            machine.prepare()
            for _ in range(1000):
                if machine.run_slice():
                    break
            else:
                raise RuntimeError("Native bound exhausted: " + name)
            capture = machine.capture()
            actual = {"romx": capture.state["romx"], "ramC000": capture.memory[0xc000],
                      "flags": capture.state["af"] & 255, "sp": capture.state["sp"],
                      "cart_enabled": capture.state["cart_enabled"], "ie": capture.memory[0xffff],
                      "vram0": capture.bank_bytes("vram", 0)[0]}
            checks = {key: actual[key] == value for key, value in expected.items()}
            checks.update(bootDisabled=capture.state["boot"] == 0,
                          reachedStop=capture.state["pc"] == end,
                          fixedRom0Unchanged=capture.memory[0] == 0x42,
                          fixedRom2000Unchanged=capture.memory[0x2000] == 0x5a,
                          fixedRom2fffUnchanged=capture.memory[0x2fff] == 0x6b,
                          fixedRom3000Unchanged=capture.memory[0x3000] == 0x7c,
                          selectedRomWindowMatches=capture.memory[0x4000] == rom[capture.state["romx"] * 0x4000],
                          fixedRomWindowUnchanged=capture.memory[:0x4000] == rom[:0x4000],
                          selectedRomWindowUnchanged=capture.memory[0x4000:0x8000] == rom[capture.state["romx"] * 0x4000:(capture.state["romx"] + 1) * 0x4000],
                          inputFileUnchanged=sha(rom_path) == before_hash)
            results.append({"name": name, "status": "PASS" if all(checks.values()) else "FAIL",
                            "romSha256": before_hash, "stop": end, "expected": expected,
                            "actual": actual, "checks": checks,
                            "nativeLibrarySha256": sha(Path(machine.lib._name))})
    result = {"schema": "ghidraboy-direct-bus-native-v1", "status": "PASS" if all(r["status"] == "PASS" for r in results) else "FAIL",
              "core": CORE, "config": CONFIG, "bootSha256": sha(boot_path),
              "scriptSha256": sha(Path(__file__)), "fixtures": results,
              "scope": "Self-authored instructions under real MBC5 execution; minimal boot bypass, no state edits",
              "limits": ["Direct byte/word stores only", "No whole-game/indirect-store coverage", "Flat CPU Programs are a separate non-cartridge model"]}
    (args.work / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "fixtures": [(r["name"], r["status"]) for r in results]}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
