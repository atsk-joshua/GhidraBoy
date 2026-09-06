#!/usr/bin/env python3
"""Build isolated pinned accuracy inputs and compare pristine/real-adapter runs.

Supply local Git repositories containing the revisions in accuracy-fixtures.json.
No downloads, runtime-library writes, boot-ROM substitution, or hidden skips.
Use --reuse-build only for an existing output prepared by this tool; probes are
always recompiled so production observer fixes receive new source attribution.
"""
import argparse
import concurrent.futures
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path(__file__).with_name("accuracy-fixtures.json")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def compare_outputs(expected, actual):
    """Retain a bounded, actionable mismatch; never accept a missing stream."""
    expected, actual = Path(expected), Path(actual)
    if not expected.is_file() or not actual.is_file():
        return {"matches": False, "reason": "missing output"}
    with expected.open("rb") as left, actual.open("rb") as right:
        offset = 0
        while True:
            a, b = left.read(65536), right.read(65536)
            if a != b:
                index = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
                return {"matches": False, "reason": "unclassified state/output divergence",
                        "firstDifferenceOffset": offset + index,
                        "expectedByte": a[index] if index < len(a) else None,
                        "actualByte": b[index] if index < len(b) else None}
            if not a:
                return {"matches": True, "bytesCompared": offset}
            offset += len(a)


def command(args, cwd, log):
    with Path(log).open("w") as output:
        result = subprocess.run([str(a) for a in args], cwd=cwd, stdout=output,
                                stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {args}; see {log}")


def archive(repository, revision, destination):
    # Export the Git object, never uncommitted work or case-folded checkout files.
    data = subprocess.check_output(["git", "-C", str(repository), "archive", revision])
    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as source:
        for entry in source.getmembers():
            path = Path(entry.name)
            if path.is_absolute() or ".." in path.parts or not (entry.isfile() or entry.isdir()):
                raise ValueError(f"Unsupported archive entry: {entry.name}")
        source.extractall(destination)
    return hashlib.sha256(data).hexdigest()


def prepare(args, fixtures, runtime):
    out = args.output
    patch = ROOT / "debugger" / runtime["patch"]
    if sha(patch) != runtime["patch_sha256"]:
        raise ValueError("SameBoy patch differs from canonical dependency lock")
    identity = {"sameboyRevision": runtime["commit"], "patchSha256": sha(patch),
                "fixtureManifestSha256": sha(MANIFEST)}
    marker = out / "build-inputs.json"
    if args.reuse_build:
        saved = json.loads(marker.read_text())
        if any(saved.get(key) != value for key, value in identity.items()):
            raise ValueError("Build inputs changed; choose a fresh --output")
        identity = saved
    else:
        out.mkdir(parents=True, exist_ok=False)
        for variant in ("pristine", "instrumented"):
            identity[variant + "SourceArchiveSha256"] = archive(
                ROOT / "debugger/.deps/SameBoy", runtime["commit"], out / variant)
        command(["patch", "-p1", "-i", patch], out / "instrumented", out / "patch.log")
        for variant in ("pristine", "instrumented"):
            command(["make", "lib", "CONF=release", "-j", args.jobs], out / variant,
                    out / (variant + "-build.log"))
        identity["mooneyeSourceArchiveSha256"] = archive(
            args.mooneye_source, fixtures["mooneye"]["revision"], out / "mooneye")
        identity["assemblerSourceArchiveSha256"] = archive(
            args.assembler_source, fixtures["assembler"]["revision"], out / "wla")
        command(["cmake", "-S", "wla", "-B", "wla/build", "-DCMAKE_BUILD_TYPE=Release",
                 "-DCMAKE_POLICY_VERSION_MINIMUM=3.5"], out, out / "wla-configure.log")
        command(["cmake", "--build", "wla/build", "--target", "wla-gb", "wlalink", "-j", args.jobs],
                out, out / "wla-build.log")
        targets = sorted(set(fixtures["bothModels"] + fixtures["DMG-B"] + fixtures["CGB-E"]))
        command(["make", *["build/" + name + ".gb" for name in targets],
                 "WLA=" + str(out / "wla/build/binaries/wla-gb"),
                 "WLALINK=" + str(out / "wla/build/binaries/wlalink")],
                out / "mooneye", out / "fixtures-build.log")
        marker.write_text(json.dumps(identity, indent=2) + "\n")
    # Freeze current adapter inputs before compiling either executable.
    native = ROOT / "debugger/backends/sameboy/native"
    copied = out / "adapter"
    copied.mkdir(exist_ok=True)
    for name in ("ghigbc.c", "ghigbc.h"):
        (copied / name).write_bytes((native / name).read_bytes())
        identity[name] = sha(copied / name)
    probe = out / "accuracy_sameboy_probe.c"
    probe.write_bytes(Path(__file__).with_name("accuracy_sameboy_probe.c").read_bytes())
    identity["probeSha256"] = sha(probe)
    identity["runnerSha256"] = sha(__file__)
    libs = ["-framework", "Cocoa", "-lm", "-lpthread"] if platform.system() == "Darwin" else ["-lm", "-lpthread"]
    for variant in ("pristine", "instrumented"):
        options = ["-DACCURACY_INSTRUMENTED", "-I" + str(copied)] if variant == "instrumented" else []
        command([os.environ.get("CC", "cc"), "-std=gnu11", "-O2", "-Wall", "-Wextra", *options,
                 "-I" + str(out / variant), probe, out / variant / "build/lib/libsameboy.a",
                 *libs, "-o", out / (variant + "-probe")], out, out / (variant + "-probe-build.log"))
        identity[variant + "ProbeSha256"] = sha(out / (variant + "-probe"))
        identity[variant + "LibrarySha256"] = sha(out / variant / "build/lib/libsameboy.a")
    return identity


def run_case(args, name, model, rom, protocol):
    case = args.output / "runs" / model / name
    case.mkdir(parents=True, exist_ok=True)
    boot = ROOT / "debugger/.deps/SameBoy/build/bin/BootROMs" / (
        "dmg_boot.bin" if model == "DMG-B" else "cgb_boot.bin")
    entry = {"fixture": name, "model": model, "romSha256": sha(rom),
             "bootSha256": sha(boot), "romCgbFlag": rom.read_bytes()[0x143],
             "protocol": protocol, "variants": {}}
    for variant in ("pristine", "instrumented", "inspected"):
        executable = "pristine" if variant == "pristine" else "instrumented"
        path = case / (variant + ".bin")
        cmd = [str(args.output / (executable + "-probe")), str(rom), str(boot), model,
               str(path), str(args.max_runs), protocol, "1" if variant == "inspected" else "0"]
        started = time.monotonic()
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=120)
        (case / (variant + ".stdout.log")).write_text(result.stdout)
        (case / (variant + ".stderr.log")).write_text(result.stderr)
        lines = [line for line in result.stdout.splitlines() if line.startswith('{"result":')]
        summary = json.loads(lines[-1]) if lines else {"result": "ERROR"}
        summary.update(exitCode=result.returncode, elapsedSeconds=round(time.monotonic() - started, 3),
                       outputSha256=sha(path) if path.exists() else None, command=cmd)
        entry["variants"][variant] = summary
    pristine = entry["variants"]["pristine"]["outputSha256"]
    entry["instrumentationComparison"] = compare_outputs(case / "pristine.bin", case / "instrumented.bin")
    entry["inspectionComparison"] = compare_outputs(case / "pristine.bin", case / "inspected.bin")
    entry["instrumentationMatches"] = pristine is not None and entry["instrumentationComparison"]["matches"]
    entry["inspectionMatches"] = pristine is not None and entry["inspectionComparison"]["matches"]
    entry["passed"] = entry["instrumentationMatches"] and entry["inspectionMatches"] and all(
        value["exitCode"] == 0 for value in entry["variants"].values())
    for variant, summary in entry["variants"].items():
        path = case / (variant + ".bin")
        if path.exists():
            compressed = path.with_suffix(".bin.gz")
            with path.open("rb") as source, compressed.open("wb") as destination:
                with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=0) as zipped:
                    shutil.copyfileobj(source, zipped)
            summary["compressedOutput"] = str(compressed.relative_to(args.output))
            summary["compressedOutputSha256"] = sha(compressed)
            path.unlink()
    return entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mooneye-source", type=Path, required=True)
    parser.add_argument("--assembler-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reuse-build", action="store_true")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--max-runs", type=int, default=6000000)
    args = parser.parse_args()
    if args.jobs < 1 or args.max_runs < 1:
        parser.error("jobs and max-runs must be positive")
    args.output = args.output.resolve()
    fixtures = json.loads(MANIFEST.read_text())
    runtime = json.loads((ROOT / "tools/dependencies.json").read_text())["debuggerRuntime"]["sameboy"]
    identity = prepare(args, fixtures, runtime)
    cases = []
    for model in ("DMG-B", "CGB-E"):
        for name in fixtures["bothModels"] + fixtures[model]:
            cases.append((name, model, args.output / "mooneye/build" / (name + ".gb"), "mooneye"))
    for model, name in (("DMG-B", "teaching-dmg.gb"), ("CGB-E", "teaching-dmg.gb"), ("CGB-E", "teaching.gbc")):
        cases.append(("synthetic/" + name, model, ROOT / "debugger/build" / name, "synthetic"))
    report = {"schema": 1, "host": platform.platform(), "identity": identity,
              "fixtures": fixtures, "policy": {"seed": "0x676869647261626f", "boot": "execute SameBoy redistributable boot",
              "rtc": "GB_RTC_MODE_ACCURATE; no RTC cartridge fixtures", "input": "no buttons",
              "sampleEveryRunCalls": 16384, "maxRunCalls": args.max_runs,
              "undefinedStartup": "Deterministically seeded for same-core comparison only; no hardware expectation",
              "watch": "CPU writes across full address space; armed only on instrumented variants",
              "comparison": "Equal run-call boundaries and final test signature: registers, flags, 8MHz ticks, selected banks, raw physical RAM/VRAM/cart/OAM/HRAM/IO and pixels",
              "physicalHardware": "UNVERIFIED", "crossBackend": "NOT_RUN"}, "results": []}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = [executor.submit(run_case, args, *case) for case in cases]
        for future in concurrent.futures.as_completed(futures):
            entry = future.result()
            report["results"].append(entry)
            print(f"{'PASS' if entry['passed'] else 'FAIL'} {entry['model']} {entry['fixture']}", flush=True)
    report["results"].sort(key=lambda entry: (entry["model"], entry["fixture"]))
    report["passed"] = all(entry["passed"] for entry in report["results"])
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
