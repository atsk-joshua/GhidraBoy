#!/usr/bin/env python3
"""Build, package and verify the optional macOS arm64 state-entry native protocol.

Installation publishes a NEW disposable distribution bundle. The source and any
active installation remain unchanged. A build/startup receipt is not semantic,
GUI, migration or release qualification.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

import native_dependency_update as base

ROOT = Path(__file__).resolve().parents[1]
BASE_VERSION = "12.1.3"
VERSION = "12.1.3+ghidraboy.switch-recovery.2.state-entry.1"
PROTOCOL = "__ghidraboy_state_entry_v1"
CONVENTION = "__ghidraboy_state_entry_v1"
SCHEMA = "ghidraboy-state-entry-native-v1"
TARGET = "mac_arm_64"
PATCH = ROOT / "tools/patches/ghidra-12.1.3-state-entry-1.patch"
PATCH_SHA256 = "91d8d2bfe6b2478cfb98f2c609d975036eb523a3c481c6f05d7516c87d503388"
MARKER = "Ghidra/Features/Decompiler/state-entry-native.json"
BINARY = "Ghidra/Features/Decompiler/os/mac_arm_64/decompile"
SOURCE = "Ghidra/Features/Decompiler/src/decompile/cpp"
BUILD_STATUS = "BUILT_UNQUALIFIED_STATE_ENTRY_PROTOCOL"


def document(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def require_host():
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        raise ValueError("Only macOS arm64 is implemented for the optional state-entry protocol")


def inputs():
    pin = json.loads((ROOT / "tools/dependencies.json").read_text())["nativeDecompilerPatch"]
    switch = ROOT / pin["patch"]
    lock = ROOT / pin["pristineSourceLock"]
    if (pin["dependencyVersion"] != base.DEPENDENCY or base.digest(switch) != base.PATCH_SHA256
            or base.digest(lock) != base.SOURCE_LOCK_SHA256 or base.digest(PATCH) != PATCH_SHA256):
        raise ValueError("State-entry build inputs differ from the reviewed patch/source identities")
    return switch, lock


def validate_identity(identity):
    expected = {"schema": SCHEMA, "protocol": PROTOCOL, "callingConvention": CONVENTION,
                "baseGhidraVersion": BASE_VERSION, "nativeDependencyVersion": VERSION,
                "baseDependencyVersion": base.DEPENDENCY, "platform": TARGET,
                "statePatchSha256": PATCH_SHA256, "switchPatchSha256": base.PATCH_SHA256,
                "sourceLockSha256": base.SOURCE_LOCK_SHA256, "officialNative": False}
    if not isinstance(identity, dict) or any(identity.get(k) != v for k, v in expected.items()):
        raise ValueError("Unrecognized state-entry native identity")
    for key in ("binarySha256", "patchedSourcesSha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", identity.get(key, "")):
            raise ValueError("Invalid state-entry digest: " + key)


def validate_binary(data):
    if len(data) < 8 or data[:4] != bytes.fromhex("cffaedfe") or int.from_bytes(data[4:8], "little") != 0x100000c:
        raise ValueError("State-entry binary must be Mach-O arm64")


def verify(distribution, probe=False):
    distribution = Path(distribution)
    base.require_base(distribution)
    for relative in (BINARY, MARKER):
        path = distribution / relative
        for ancestor in (path, *path.parents):
            if ancestor == distribution:
                break
            if ancestor.is_symlink():
                raise ValueError("State-entry managed path contains a symlink")
        base.file_record(path)
    identity = json.loads((distribution / MARKER).read_text())
    validate_identity(identity)
    if (distribution / base.MARKER).exists():
        raise ValueError("Contradictory switch-only marker is present beside composite state-entry marker")
    binary = distribution / BINARY
    validate_binary(binary.read_bytes())
    if base.digest(binary) != identity["binarySha256"] or not binary.stat().st_mode & stat.S_IXUSR:
        raise ValueError("State-entry executable differs from its capability marker")
    result = {"identity": identity, "status": "VERIFIED_BYTES_ONLY", "semanticQualification": "UNRUN"}
    if probe:
        require_host()
        result["startup"] = base.native_probe(binary)
    return result


def execute(args, cwd, log):
    with log.open("w") as output:
        completed = subprocess.run([str(x) for x in args], cwd=cwd, stdout=output, stderr=subprocess.STDOUT)
    if completed.returncode:
        raise ValueError("Command failed; retained log: " + str(log))


def build(ghidra, jdk, work, jobs=4):
    require_host()
    switch, lock = inputs()
    ghidra, jdk, work = Path(ghidra).resolve(), Path(jdk).resolve(), Path(work).absolute()
    work = work.parent.resolve() / work.name
    base.require_base(ghidra)
    if work.exists() or work.is_symlink() or work.is_relative_to(ghidra) or ghidra.is_relative_to(work):
        raise ValueError("Build work must be a new independent directory")
    if not re.search(r'^JAVA_VERSION="21[.\"]', (jdk / "release").read_text(), re.M):
        raise ValueError("JDK 21 is required")
    if not (jdk / "bin/javac").is_file() or not 1 <= jobs <= 32:
        raise ValueError("Full JDK and a job count from 1 to 32 are required")
    pristine = base.tree_snapshot(ghidra / SOURCE)
    expected = json.loads(lock.read_text())["files"]
    if {k: v["sha256"] for k, v in pristine.items()} != expected:
        raise ValueError("Native source differs from the pinned pristine source lock")
    work.mkdir()
    receipt = {"status": "BUILD_IN_PROGRESS", "baseGhidraVersion": BASE_VERSION,
               "nativeDependencyVersion": VERSION, "semanticQualification": "UNRUN",
               "sourceDistribution": str(ghidra), "jdk": str(jdk),
               "jdkReleaseSha256": base.digest(jdk / "release"), "pristineSources": pristine,
               "statePatchSha256": PATCH_SHA256, "switchPatchSha256": base.PATCH_SHA256,
               "sourceLockSha256": base.SOURCE_LOCK_SHA256}
    document(work / "build.json", receipt)
    try:
        source_root = work / "source"
        source = source_root / SOURCE
        shutil.copytree(ghidra / SOURCE, source)
        if base.tree_snapshot(source) != pristine:
            raise ValueError("Native sources changed while copying")
        execute(["patch", "--batch", "--forward", "-p1", "-i", switch], source_root, work / "switch-patch.log")
        execute(["patch", "--batch", "--forward", "-p1", "-i", PATCH], source_root, work / "state-patch.log")
        patched = base.tree_snapshot(source)
        changed = sorted(k for k in pristine if pristine[k]["sha256"] != patched[k]["sha256"])
        if changed != ["coreaction.cc", "flow.cc", "jumptable.cc"] or set(patched) != set(pristine):
            raise ValueError("Patches changed unexpected native sources")
        receipt["patchedSources"] = patched
        execute(["clang++", "--version"], work, work / "compiler-version.log")
        execute([jdk / "bin/javac", "-version"], work, work / "jdk-version.log")
        command = ["make", "-j" + str(jobs), "ghidra_opt", "CXX=clang++ -std=c++11",
                   "ARCH_TYPE=-arch arm64", "ADDITIONAL_FLAGS=-mmacosx-version-min=11.0 -w"]
        receipt["buildCommand"] = command
        execute(command, source, work / "native-build.log")
        binary = source / "ghidra_opt"
        validate_binary(binary.read_bytes())
        receipt["startup"] = base.native_probe(binary)
        identity = {"schema": SCHEMA, "protocol": PROTOCOL, "callingConvention": CONVENTION,
                    "baseGhidraVersion": BASE_VERSION, "nativeDependencyVersion": VERSION,
                    "baseDependencyVersion": base.DEPENDENCY, "platform": TARGET,
                    "statePatchSha256": PATCH_SHA256, "switchPatchSha256": base.PATCH_SHA256,
                    "sourceLockSha256": base.SOURCE_LOCK_SHA256,
                    "patchedSourcesSha256": hashlib.sha256(json.dumps(patched, sort_keys=True).encode()).hexdigest(),
                    "binarySha256": base.digest(binary), "officialNative": False}
        validate_identity(identity)
        receipt.update(status=BUILD_STATUS, identity=identity)
        document(work / "build.json", receipt)
        package = work / "state-entry-native-mac_arm_64.zip"
        files = {BINARY: binary.read_bytes(), MARKER: (json.dumps(identity, indent=2, sort_keys=True) + "\n").encode(),
                 "build.json": (work / "build.json").read_bytes(), "state-entry.patch": PATCH.read_bytes(),
                 "switch-recovery.patch": switch.read_bytes(), "pristine-source-lock.json": lock.read_bytes(),
                 "LICENSE": (ghidra / "LICENSE").read_bytes(),
                 "Decompiler-LICENSE.txt": (ghidra / "Ghidra/Features/Decompiler/LICENSE.txt").read_bytes()}
        with zipfile.ZipFile(package, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFREG | (0o755 if name == BINARY else 0o644)) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
        result = {"package": str(package), "packageSha256": base.digest(package), "identity": identity,
                  "status": BUILD_STATUS, "semanticQualification": "UNRUN"}
        document(work / "package.json", result)
        return result
    except Exception as failure:
        receipt.update(status="BUILD_FAILED", failure=str(failure))
        document(work / "build.json", receipt)
        raise


def read_package(path, expected_sha256):
    path = Path(path)
    if path.stat().st_size > 128 * 1024 * 1024 or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("Invalid package size or expected digest")
    with path.open("rb") as stream:
        raw = stream.read(128 * 1024 * 1024 + 1)
    if len(raw) > 128 * 1024 * 1024:
        raise ValueError("Package exceeds size bound")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("Package differs from trusted expected SHA256")
    files = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if len(archive.infolist()) != 8 or sum(i.file_size for i in archive.infolist()) > 128 * 1024 * 1024:
            raise ValueError("Unexpected state-entry package inventory or size")
        for info in archive.infolist():
            name = info.orig_filename
            if (name != str(PurePosixPath(name)) or name.startswith("/") or ".." in PurePosixPath(name).parts
                    or "\\" in name or ":" in name or "\x00" in name or name in files or info.is_dir() or info.flag_bits & 1):
                raise ValueError("Unsafe or duplicate state-entry package path")
            mode = base.regular_mode(info)
            if stat.S_IFMT((info.external_attr >> 16) & 0xffff) not in (0, stat.S_IFREG):
                raise ValueError("Package member is not an ordinary file")
            if name == BINARY and not mode & stat.S_IXUSR:
                raise ValueError("Packaged native binary is not executable")
            files[name] = archive.read(info)
    if set(files) != {BINARY, MARKER, "build.json", "state-entry.patch", "switch-recovery.patch",
                      "pristine-source-lock.json", "LICENSE", "Decompiler-LICENSE.txt"}:
        raise ValueError("Unexpected state-entry package members")
    identity = json.loads(files[MARKER])
    validate_identity(identity)
    validate_binary(files[BINARY])
    expected_files = {BINARY: identity["binarySha256"], "state-entry.patch": PATCH_SHA256,
                      "switch-recovery.patch": base.PATCH_SHA256, "pristine-source-lock.json": base.SOURCE_LOCK_SHA256}
    if any(hashlib.sha256(files[name]).hexdigest() != digest for name, digest in expected_files.items()):
        raise ValueError("State-entry package payload hashes disagree")
    receipt = json.loads(files["build.json"])
    if receipt.get("status") != BUILD_STATUS or receipt.get("identity") != identity or receipt.get("semanticQualification") != "UNRUN":
        raise ValueError("Package lacks consistent unqualified build receipt")
    source_hash = hashlib.sha256(json.dumps(receipt.get("patchedSources"), sort_keys=True).encode()).hexdigest()
    if source_hash != identity["patchedSourcesSha256"]:
        raise ValueError("Patched-source receipt differs from capability identity")
    return {"identity": identity, "files": files, "packageSha256": expected_sha256}


def install(source, destination, package):
    require_host()
    source, destination = Path(source).resolve(), Path(destination).absolute()
    destination = destination.parent.resolve() / destination.name
    base.require_base(source)
    if (destination.exists() or destination.is_symlink() or destination.is_relative_to(source)
            or source.is_relative_to(destination) or not destination.parent.is_dir()):
        raise ValueError("Destination must be a new independent bundle in an existing parent")
    if (source / MARKER).exists() or (source / MARKER).is_symlink():
        raise ValueError("Source already has a state-entry marker; use its preserved original distribution")
    before = base.tree_snapshot(source)
    stage = Path(tempfile.mkdtemp(prefix=".state-entry-native-", dir=destination.parent))
    committed = False
    try:
        copied = stage / "distribution"
        shutil.copytree(source, copied)
        if base.tree_snapshot(copied) != before or base.tree_snapshot(source) != before:
            raise ValueError("Source changed during copy; no distribution published")
        backups = {}
        for relative in (BINARY, base.MARKER):
            original = source / relative
            backups[relative] = before.get(relative)
            if original.exists():
                backup = stage / "original" / relative
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(original, backup)
        old_marker = copied / base.MARKER
        if old_marker.exists():
            old_marker.unlink()
        for relative in (BINARY, MARKER):
            path = copied / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(package["files"][relative])
            path.chmod(0o755 if relative == BINARY else 0o644)
        verified = verify(copied, probe=True)
        expected = dict(before)
        expected.pop(base.MARKER, None)
        for relative in (BINARY, MARKER):
            expected[relative] = base.file_record(copied / relative)
        if base.tree_snapshot(copied) != expected or base.tree_snapshot(source) != before:
            raise ValueError("Unexpected copied/source distribution drift")
        receipt = {"schema": "ghidraboy-state-entry-install-v1", "source": str(source),
                   "packageSha256": package["packageSha256"], "before": backups,
                   "verification": verified, "semanticQualification": "UNRUN",
                   "rollback": "Use unchanged source distribution; exact managed-file backups retained under original/"}
        document(stage / "receipt.json", receipt)
        base.publish_exclusive(stage, destination)
        committed = True
        return {"bundle": str(destination), "distribution": str(destination / "distribution"), "receipt": receipt}
    finally:
        if not committed:
            shutil.rmtree(stage)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build_parser = sub.add_parser("build")
    for name in ("ghidra", "jdk", "work"):
        build_parser.add_argument("--" + name, type=Path, required=True)
    build_parser.add_argument("--jobs", type=int, default=4)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--distribution", type=Path, required=True)
    verify_parser.add_argument("--probe", action="store_true")
    install_parser = sub.add_parser("install")
    for name in ("source", "destination", "package"):
        install_parser.add_argument("--" + name, type=Path, required=True)
    install_parser.add_argument("--package-sha256", required=True)
    args = parser.parse_args(argv)
    if args.command == "build":
        result = build(args.ghidra, args.jdk, args.work, args.jobs)
    elif args.command == "verify":
        result = verify(args.distribution, args.probe)
    else:
        result = install(args.source, args.destination, read_package(args.package, args.package_sha256))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, zipfile.BadZipFile) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        sys.exit(1)
