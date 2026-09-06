#!/usr/bin/env python3
"""Build/run the pinned M1 probe; no dependency downloads or installation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time

REVISION = "685023e05d90d87050fb357f46f7bd2d907083f5"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--rom", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    args = parser.parse_args()
    source, rom, work = args.source.resolve(), args.rom.resolve(), args.work.resolve()
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        parser.error("Probe requires mGBA revision " + REVISION)
    if subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"]):
        parser.error("Probe requires an unmodified source checkout")
    work.mkdir(parents=True, exist_ok=False)
    probe_dir = Path(__file__).resolve().parent
    receipt = {
        "schema": 1, "status": "RUNNING", "sourceRevision": revision,
        "sourceRepository": "https://github.com/mgba-emu/mgba",
        "host": platform.platform(), "romSha256": sha(rom),
        "probeSources": {p.name: sha(p) for p in [Path(__file__), probe_dir / "mgba_probe.c", probe_dir / "CMakeLists.txt"]},
        "commands": [], "scope": "M1 feasibility; not a supported backend or complete hardware validation",
    }

    def record():
        (work / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")

    def run(name, command, timeout):
        started = time.monotonic()
        entry = {"name": name, "command": [str(arg) for arg in command]}
        receipt["commands"].append(entry)
        record()
        with (work / (name + ".log")).open("w") as output:
            try:
                result = subprocess.run(entry["command"], stdout=output, stderr=subprocess.STDOUT,
                                        timeout=timeout, check=False)
                entry["exitCode"] = result.returncode
            except subprocess.TimeoutExpired:
                entry["timeoutSeconds"] = timeout
                entry["exitCode"] = None
        entry["durationSeconds"] = time.monotonic() - started
        record()
        if entry["exitCode"] != 0:
            raise RuntimeError(name + " failed; inspect " + str(work / (name + ".log")))

    try:
        run("configure", ["cmake", "-S", probe_dir, "-B", work / "build",
                          "-DMGBA_SOURCE=" + str(source), "-DCMAKE_BUILD_TYPE=Release"], 120)
        run("build", ["cmake", "--build", work / "build", "--parallel", str(min(4, os.cpu_count() or 1))], 300)
        executable = work / "build/mgba-probe"
        run("probe", [executable, rom], 30)
        lines = (work / "probe.log").read_text().splitlines()
        results = [json.loads(line) for line in lines if line.startswith('{"schema":')]
        if len(results) != 1 or results[0].get("status") != "PASS":
            raise RuntimeError("Missing or ambiguous probe result")
        receipt.update(status="PASS", result=results[0], executableSha256=sha(executable))
    except Exception as error:
        receipt.update(status="FAIL", error=str(error))
        raise
    finally:
        record()
    print(json.dumps(receipt["result"], indent=2))


if __name__ == "__main__":
    main()
