#!/usr/bin/env python3
"""Apply the pinned additive tick patch to a private copy, build and verify."""
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
        parser.error("Requires mGBA revision " + REVISION)
    if subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"]):
        parser.error("Requires unmodified source checkout; the runner patches only a private archive")
    work.mkdir(parents=True, exist_ok=False)
    probe = Path(__file__).resolve().parent
    native = probe.parents[2] / 'debugger/backends/mgba/native'
    patch = native / 'patches/0001-sm83-no-idle.patch'
    receipt = {
        "schema": 1, "status": "RUNNING", "sourceRevision": revision,
        "sourceRepository": "https://github.com/mgba-emu/mgba", "host": platform.platform(),
        "romSha256": sha(rom), "patchSha256": sha(patch),
        "executionSources": {name: sha(native / name) for name in ('execution.c', 'execution.h')},
        "probeSources": {p.name: sha(p) for p in sorted(probe.iterdir()) if p.is_file()},
        "commands": [], "scope": "Pinned native execution feasibility; not production adapter qualification",
        "limitations": [
            "HALT_BUG is a valid execution boundary but upstream checkpoint loading rejects it; reject checkpoint there.",
            "Plain STOP signals the native callback; a production owner must stop execution on that signal.",
            "GB-only CGB/post-boot fixture; no DMA, debugger hook or hardware-conformance qualification.",
            "Pause measured between native calls; no hard realtime or native crash containment guarantee.",
        ],
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
                entry.update(exitCode=None, timeoutSeconds=timeout)
        entry.update(durationSeconds=time.monotonic() - started, logSha256=sha(work / (name + ".log")))
        record()
        if entry["exitCode"] != 0:
            raise RuntimeError(name + " failed; inspect " + str(work / (name + ".log")))

    try:
        archive = work / "source.tar"
        patched = work / "source"
        patched.mkdir()
        run("archive", ["git", "-C", source, "archive", "--format=tar", "--output=" + str(archive), revision], 30)
        receipt["sourceArchiveSha256"] = sha(archive)
        run("extract", ["tar", "-xf", archive, "-C", patched], 30)
        run("patch-check", ["git", "-C", patched, "apply", "--check", patch], 10)
        run("patch", ["git", "-C", patched, "apply", patch], 10)
        receipt["patchedSources"] = {name: sha(patched / name) for name in
                                     ("include/mgba/internal/sm83/sm83.h", "src/sm83/sm83.c")}
        run("configure", ["cmake", "-S", probe, "-B", work / "build", "-DMGBA_SOURCE=" + str(patched),
                          "-DCMAKE_BUILD_TYPE=Release"], 120)
        run("build", ["cmake", "--build", work / "build", "--parallel", str(min(4, os.cpu_count() or 1))], 300)
        executable = work / "build/mgba-execution-probe"
        receipt["executableSha256"] = sha(executable)
        receipt["abiBuildFiles"] = {}
        for name in ("flags.make", "link.txt"):
            path = work / "build/CMakeFiles/mgba-execution-probe.dir" / name
            if path.exists():
                receipt["abiBuildFiles"][name] = dict(sha256=sha(path), content=path.read_text())
        run("probe", [executable, rom], 30)
        results = [json.loads(line) for line in (work / "probe.log").read_text().splitlines()
                   if line.startswith('{"schema":')]
        if len(results) != 1 or results[0].get("status") != "PASS":
            raise RuntimeError("Missing or ambiguous probe result")
        receipt.update(status="PASS", result=results[0])
    except Exception as error:
        receipt.update(status="FAIL", error=str(error))
        raise
    finally:
        record()
    print(json.dumps({key: receipt[key] for key in ("status", "result", "limitations")}, indent=2))


if __name__ == "__main__":
    main()
