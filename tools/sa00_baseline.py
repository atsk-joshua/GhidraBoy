#!/usr/bin/env python3
"""Reproduce the generic SA-00 baseline and three-process saved-result checks.

Requires a disposable Ghidra 12.1.3 distribution with a platform decompiler.
Never accepts an active installation; keeps every process log and result.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("ghidra", "jdk", "zip", "work"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    ghidra, work = args.ghidra.resolve(), args.work.resolve()
    roots = (Path("/tmp").resolve(), Path(tempfile.gettempdir()).resolve())
    if not any(ghidra.is_relative_to(root) for root in roots) or "ghidraboy" not in str(ghidra):
        parser.error("--ghidra must be a disposable temporary ghidraboy distribution")
    if work.exists():
        parser.error("--work must be a new path; historical receipts are never overwritten")
    extension = ghidra / "Ghidra/Extensions/GhidraBoy"
    if extension.exists():
        parser.error("disposable distribution already has GhidraBoy; use a fresh distribution")
    work.mkdir(parents=True)
    with zipfile.ZipFile(args.zip) as archive:
        archive.extractall(extension.parent)
    rom = bytearray(0x10000)
    rom[0x104:0x134] = bytes.fromhex(
        "ce ed 66 66 cc 0d 00 0b 03 73 00 83 00 0c 00 0d 00 08 11 1f 88 89 00 0e "
        "dc cc 6e e6 dd dd d9 99 bb bb 67 63 6e 0e ec cc dd dc 99 9f bb b9 33 3e")
    rom[0x143], rom[0x147], rom[0x148], rom[0x149] = 0x80, 0x13, 1, 3
    rom[0x150:0x15c] = bytes.fromhex("31 00 c1 3e 02 ea 00 20 cd 00 40 c9")
    rom[0x180], rom[0x8000] = 0xe9, 0xc9
    # Valid checksums; fixture is self-authored generic code, no commercial game.
    checksum = 0
    for byte in rom[0x134:0x14d]:
        checksum = (checksum - byte - 1) & 255
    rom[0x14d] = checksum
    rom[0x14e:0x150] = (sum(rom) & 65535).to_bytes(2, "big")
    fixture = work / "sa00-generic-mbc3-v1.gb"
    fixture.write_bytes(rom)
    digest = hashlib.sha256(rom).hexdigest()
    repo = Path(__file__).resolve().parents[1]
    profile, projects = work / "profile", work / "projects"
    profile.mkdir(); projects.mkdir()
    cache = work / "cache"
    cache.mkdir()
    env = dict(os.environ, JAVA_HOME=str(args.jdk.resolve()),
               JAVA_TOOL_OPTIONS=f"-Duser.home={profile}", XDG_CACHE_HOME=str(cache))
    records = []
    for mode in ("prepare", "reopen", "stale"):
        command = [str(ghidra / "support/analyzeHeadless"), str(projects), "sa00"]
        command += ["-import", str(fixture)] if mode == "prepare" else ["-process", fixture.name]
        command += ["-noanalysis", "-scriptPath", str(repo / "src/test/scripts"),
                    "-postScript", "GhidraBoySa00.java", mode, str(work), digest]
        with (work / f"{mode}.log").open("w") as output:
            completed = subprocess.run(command, env=env, cwd=work, stdout=output, stderr=subprocess.STDOUT)
        log = (work / f"{mode}.log").read_text()
        marker = {"prepare": "SA00_PREPARE_PASS", "reopen": "SA00_REOPEN_REAPPLY_MUTATE_PASS",
                  "stale": "SA00_STALE_REOPEN_PASS"}[mode]
        passed = completed.returncode == 0 and marker in log and "ERROR" not in log
        records.append(dict(mode=mode, command=command, exitCode=completed.returncode,
                            status="PASS" if passed else "FAIL", marker=marker))
        (work / "run.json").write_text(json.dumps(dict(fixtureSha256=digest,
            extensionSha256=hashlib.sha256(args.zip.read_bytes()).hexdigest(),
            processes=records), indent=2) + "\n")
        print(f"{mode}: {'PASS' if passed else 'FAIL'} ({work / (mode + '.log')})", flush=True)
        if not passed:
            raise SystemExit(1)
    print("SA00_BASELINE_PERSISTENCE_PASS")


if __name__ == "__main__":
    main()
