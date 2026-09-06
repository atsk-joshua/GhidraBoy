#!/usr/bin/env python3
"""Check returned nibble-switch C and independent SameBoy execution for all bytes.

Input is the JSON from the self-authored NibbleSwitchRangeProbe. Returned C is
compiled verbatim, with only its byte typedef and external byte declaration.
GhiGBC owns the optional independent SameBoy driver. This tool invokes it as a
separate process and compares its receipt; C-only validation has no runtime dependency.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROUTINE_HEX = "7ee6f0cb37875f16002ae5e60f210002195e2356626be9"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native_oracle(ghigbc, work):
    driver = ghigbc / "tests/nibble_switch_oracle.py"
    native_work = work / "native"
    completed = subprocess.run([sys.executable, str(driver), "--work", str(native_work)],
                               capture_output=True, text=True, timeout=180)
    (work / "native-driver.log").write_text(completed.stdout + completed.stderr)
    if completed.returncode:
        raise RuntimeError("GhiGBC native oracle failed; see native-driver.log")
    result = json.loads((native_work / "result.json").read_text())
    if result.get("schema") != "ghigbc-nibble-switch-native-v1" or result.get("cases") != 256:
        raise ValueError("Unexpected GhiGBC native oracle receipt")
    result["driverPath"] = str(driver)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    oracle = parser.add_mutually_exclusive_group(required=True)
    oracle.add_argument("--ghigbc", type=Path, help="Also run the independent SameBoy oracle")
    oracle.add_argument("--c-only", action="store_true", help="Explicitly limit this run to returned C and recovered targets")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=False)
    raw = args.report.read_bytes()
    report = json.loads(raw)
    if not report.get("completed") or report.get("error") or not isinstance(report.get("c"), str):
        raise ValueError("Decompiler did not return completed C")
    if "WARNING:" in report["c"]:
        raise ValueError("Unexpected decompiler warning retained in fixture")
    routine_matches = report.get("routineHex") == ROUTINE_HEX if "routineHex" in report else None
    if routine_matches is False:
        raise ValueError("Native oracle instructions differ from the decompiled fixture")
    c_path = args.work / "returned.c"
    c_path.write_text(report["c"])
    expected_targets = [format(0x1000 + n * 8, "04x") for n in range(16)]
    tables = report.get("tables", [])
    range_ok = (len(tables) == 1 and tables[0].get("labels") == list(range(16))
                and tables[0].get("cases") == expected_targets)
    harness = r'''#include <stdint.h>
#include <stdio.h>
typedef uint8_t byte;
byte DAT_c000;
#include "returned.c"
int main(void) {
    for (unsigned value = 0; value < 256; ++value) {
        byte input[3] = { (byte)value, 0x5a, 0xa5 };
        DAT_c000 = 0xff;
        byte *result = nibble_switch(input);
        if (result != input + 1 || DAT_c000 != value / 16 ||
            input[0] != value || input[1] != 0x5a || input[2] != 0xa5) {
            fprintf(stderr, "Mismatch at input %u\n", value);
            return 1;
        }
        printf("%u\n", (unsigned)DAT_c000);
    }
    return 0;
}
'''
    harness_path = args.work / "harness.c"
    harness_path.write_text(harness)
    compiler = shutil.which(args.cc)
    if not compiler:
        raise ValueError("C compiler unavailable")
    executable = args.work / "nibble-test"
    command = [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-fsanitize=address,undefined",
               str(harness_path), "-o", str(executable)]
    built = subprocess.run(command, capture_output=True, text=True, timeout=90)
    (args.work / "compile.log").write_text(built.stdout + built.stderr)
    if built.returncode:
        raise RuntimeError("Returned C did not compile; see compile.log")
    ran = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30,
                         env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0"))
    (args.work / "run.log").write_text(ran.stdout + ran.stderr)
    values = [int(line) for line in ran.stdout.splitlines() if line.isdigit()]
    c_ok = ran.returncode == 0 and values == [n >> 4 for n in range(256)]
    native = native_oracle(args.ghigbc.resolve(), args.work) if args.ghigbc else {"status": "NOT_REQUESTED"}
    matched = c_ok and values == native["resultBytes"] if args.ghigbc else None
    passed = range_ok and c_ok and (args.c_only or (matched and native["status"] == "PASS"))
    result = {"schema": "ghidraboy-nibble-switch-oracle-v1", "status": "PASS" if passed else "FAIL",
              "verificationScope": "C_RANGE_AND_SAMEBOY" if args.ghigbc else "C_AND_RANGE_ONLY",
              "reportSha256": hashlib.sha256(raw).hexdigest(), "scriptSha256": sha(Path(__file__)),
              "returnedCSha256": sha(c_path), "returnedCCompiledVerbatim": True,
              "routineHexMatches": routine_matches,
              "cCases": 256, "cStatus": "PASS" if c_ok else "FAIL", "exactRecoveredRange": range_ok,
              "nativeMatchesC": matched, "native": native, "compilerCommand": command,
              "limits": ["Self-authored fixture; no commercial ROM or whole-corpus acceptance.",
                         "C contract covers the result byte, unchanged input bytes and returned pointer; it does not express every CPU register or flag.",
                         "Native execution additionally verifies HL and SP after every call; boot bypass and driver are self-authored, with no state edits.",
                         "The stock negative control can return correct values despite containing unreachable extraneous cases; the exact-range gate detects that defect."]}
    (args.work / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("status", "cStatus", "exactRecoveredRange", "nativeMatchesC")}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
