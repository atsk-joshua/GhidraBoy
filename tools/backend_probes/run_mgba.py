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

    def run(name, command, timeout, allow_timeout=False):
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
        entry["logSha256"] = sha(work / (name + ".log"))
        record()
        if entry["exitCode"] != 0 and not (allow_timeout and "timeoutSeconds" in entry):
            raise RuntimeError(name + " failed; inspect " + str(work / (name + ".log")))
        return entry

    try:
        run("configure", ["cmake", "-S", probe_dir, "-B", work / "build",
                          "-DMGBA_SOURCE=" + str(source), "-DCMAKE_BUILD_TYPE=Release"], 120)
        run("build", ["cmake", "--build", work / "build", "--parallel", str(min(4, os.cpu_count() or 1))], 300)
        executable = work / "build/mgba-probe"
        receipt["executableSha256"] = sha(executable)
        receipt["abiBuildFiles"] = {}
        for name in ("flags.make", "link.txt"):
            path = work / "build/CMakeFiles/mgba-probe.dir" / name
            if path.exists():
                receipt["abiBuildFiles"][name] = dict(sha256=sha(path), content=path.read_text())
        run("probe", [executable, rom], 30)
        lines = (work / "probe.log").read_text().splitlines()
        results = [json.loads(line) for line in lines if line.startswith('{"schema":')]
        if len(results) != 1 or results[0].get("status") != "PASS":
            raise RuntimeError("Missing or ambiguous probe result")
        receipt["haltCases"] = {}
        for case in ("halt-step", "halt-run-loop"):
            entry = run(case, [executable, rom, "--" + case], 2, allow_timeout=True)
            receipt["haltCases"][case] = "TIMED_OUT" if entry["exitCode"] is None else "RETURNED"
        receipt.update(status="PASS", result=results[0])
        if "TIMED_OUT" in receipt["haltCases"].values():
            receipt["limitations"] = ["Public core calls stalled at HALT; watchdog cleanup passed. "
                                      "Instruction-level atomic pause alone is insufficient. "
                                      "A bounded native implementation is required before Basic Debugging qualification."]
    except Exception as error:
        receipt.update(status="FAIL", error=str(error))
        raise
    finally:
        record()
    print(json.dumps({key: receipt[key] for key in ("status", "result", "haltCases", "limitations")
                      if key in receipt}, indent=2))


if __name__ == "__main__":
    main()
