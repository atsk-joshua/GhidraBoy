#!/usr/bin/env python3
"""Install/verify/rollback the native patch using NEW distribution copies only.

A complete bundle (distribution + receipt) is published with exclusive atomic
rename. Neither install nor rollback changes its source distribution in place.
The expected package SHA256 must come from the trusted build/validation receipt.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import io
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
import uuid

BASE = "12.1.3"
DEPENDENCY = "12.1.3+ghidraboy.switch-recovery.2"
PATCH_SHA256 = "1974f640681d2299ddc6825571a1c3ae35b24d0625dc7d996301ab8a5c1f0baf"
SOURCE_LOCK_SHA256 = "e10ae49046cbec450ca62834c4ac5075fe6d9f6a12dc4513d6f73258f490caf9"
MARKER = "Ghidra/Features/Decompiler/ghidraboy-native-dependency.json"
PROBE_COMMAND = b"ghidraboy_native_probe"
PROBE_INPUT = b"\0\0\1\2\0\0\1\x0e" + PROBE_COMMAND + b"\0\0\1\x0f\0\0\1\3"
PROBE_OUTPUT = b"\0\0\1\6\0\0\1\x10Bad command: " + PROBE_COMMAND + b"\0\0\1\x11\0\0\1\7"


class Cancelled(Exception):
    pass


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(data)
    return result.hexdigest()


def host_target():
    pair = (platform.system(), platform.machine())
    if pair == ("Darwin", "arm64"):
        return "mac_arm_64"
    if pair[0] == "Linux" and pair[1] in ("x86_64", "amd64"):
        return "linux_x86_64"
    raise ValueError("Unsupported native update host: " + repr(pair))


def regular_mode(info):
    mode = (info.external_attr >> 16) & 0xffff
    if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR) or mode & 0o7000:
        raise ValueError("ZIP contains links, special files or privileged mode bits")
    return stat.S_IMODE(mode) or (0o755 if info.is_dir() else 0o644)


def read_package(path, expected_sha256):
    with path.open("rb") as stream:
        raw = stream.read(256 * 1024 * 1024 + 1)
    if len(raw) > 256 * 1024 * 1024:
        raise ValueError("Compressed package exceeds size bound")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256) or digest_bytes(raw) != expected_sha256:
        raise ValueError("Package digest differs from trusted expected SHA256")
    files, modes, names = {}, {}, set()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if len(archive.infolist()) > 100 or sum(info.file_size for info in archive.infolist()) > 256 * 1024 * 1024:
            raise ValueError("Native package exceeds bounded file count/size")
        for info in archive.infolist():
            name = info.orig_filename
            canonical = str(PurePosixPath(name))
            if ("\x00" in name or "\\" in name or ":" in name or name.startswith("/")
                    or ".." in PurePosixPath(name).parts or canonical != name.rstrip("/")
                    or canonical in ("", ".") or canonical in names or info.flag_bits & 1):
                raise ValueError("Unsafe, duplicate, noncanonical or encrypted ZIP member")
            names.add(canonical)
            mode = regular_mode(info)
            if not info.is_dir():
                files[canonical] = archive.read(info)
                modes[canonical] = mode
    def document(name):
        value = json.loads(files[name])
        if not isinstance(value, dict):
            raise ValueError("Package manifest must be a JSON object")
        return value
    identity, rollback, build = document("native-dependency.json"), document("rollback.json"), document("build.json")
    if (identity.get("schema") != "ghidraboy-native-dependency-identity-v1" or identity.get("officialNative") is not False
            or identity.get("baseGhidraVersion") != BASE or identity.get("nativeDependencyVersion") != DEPENDENCY
            or identity.get("patchSha256") != PATCH_SHA256 or identity.get("sourceLockSha256") != SOURCE_LOCK_SHA256):
        raise ValueError("Unreviewed native dependency identity")
    target = identity.get("platform")
    if target != host_target():
        raise ValueError("Package target does not match this runtime host")
    binary = "Ghidra/Features/Decompiler/os/" + target + "/decompile"
    if (rollback.get("schema") != "ghidraboy-native-rollback-v1" or rollback.get("path") != binary
            or rollback.get("baseGhidraVersion") != BASE or rollback.get("nativeDependencyVersion") != DEPENDENCY):
        raise ValueError("Unexpected rollback identity or managed path")
    marker_rollback = rollback["identityMarker"]
    if marker_rollback.get("path") != MARKER or files[MARKER] != files["native-dependency.json"]:
        raise ValueError("Installed marker is absent, mismatched or has an unexpected path")
    if digest_bytes(files[binary]) != identity.get("binarySha256") or identity["binarySha256"] != rollback.get("expectedInstalledSha256"):
        raise ValueError("Native executable digest is inconsistent")
    if digest_bytes(files[MARKER]) != marker_rollback.get("expectedInstalledSha256"):
        raise ValueError("Identity marker digest is inconsistent")
    if (digest_bytes(files["ghidra-12.1.3-switch-recovery-2.patch"]) != PATCH_SHA256
            or digest_bytes(files["ghidra-12.1.3-decompiler-source.json"]) != SOURCE_LOCK_SHA256):
        raise ValueError("Package patch/source lock differs from pinned review")
    if (build.get("status") != "PASS_LOCAL_NATIVE_GATES" or build.get("nativeBinarySha256") != identity["binarySha256"]
            or build.get("nativeDependencyVersion") != DEPENDENCY or build.get("platform") != target):
        raise ValueError("Package lacks a consistent passing build receipt")
    before, after = {}, {}
    for relative, receipt in ((binary, rollback), (MARKER, marker_rollback)):
        if type(receipt.get("originalExisted")) is not bool:
            raise ValueError("Rollback requires an explicit original-existence receipt")
        after[relative] = {"bytes": files[relative], "mode": modes[relative]}
        if receipt["originalExisted"]:
            backup = receipt.get("backup")
            if backup not in files or not backup.startswith("rollback/") or digest_bytes(files[backup]) != receipt.get("originalSha256"):
                raise ValueError("Missing or mismatched original backup")
            before[relative] = {"bytes": files[backup], "mode": modes[backup]}
        else:
            if receipt.get("originalSha256") is not None:
                raise ValueError("Absent original file cannot have a hash")
            before[relative] = None
    data = after[binary]["bytes"]
    if target == "mac_arm_64":
        correct_kind = data[:4] == bytes.fromhex("cffaedfe") and int.from_bytes(data[4:8], "little") == 0x100000c
    else:
        correct_kind = data[:6] == b"\x7fELF\x02\x01" and int.from_bytes(data[18:20], "little") == 62
    if not correct_kind or not after[binary]["mode"] & stat.S_IXUSR:
        raise ValueError("Native format, architecture or executable mode differs")
    return {"identity": identity, "rollback": rollback, "before": before, "after": after,
            "binary": binary, "sha256": expected_sha256}


def file_record(path):
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode):
        raise ValueError("Managed/source object is not an ordinary file: " + str(path))
    return {"sha256": digest(path), "mode": stat.S_IMODE(mode)}


def tree_snapshot(root):
    result = {}
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError("Use a regular-file distribution copy; links/special files are not accepted: " + str(path))
        if stat.S_ISREG(mode):
            result[str(path.relative_to(root))] = file_record(path)
    return result


def require_base(root):
    if not root.is_dir() or root.is_symlink():
        raise ValueError("Distribution must be an ordinary directory")
    properties = root / "Ghidra/application.properties"
    if not re.search(r"^application.version=" + re.escape(BASE) + r"$", properties.read_text(), re.M):
        raise ValueError("Wrong base Ghidra version")


def require_state(root, expected):
    for relative, desired in expected.items():
        path = root / relative
        for parent in (path, *path.parents):
            if parent == root:
                break
            if parent.is_symlink():
                raise ValueError("Managed path contains a symlink")
        if desired is None:
            if path.exists() or path.is_symlink():
                raise ValueError("Unexpected file where the package records absence: " + relative)
        elif not path.is_file() or file_record(path) != {"sha256": digest_bytes(desired["bytes"]), "mode": desired["mode"]}:
            raise ValueError("Edited, missing or incompatible managed file preserved: " + relative)


def native_probe(binary):
    if not binary.exists():
        return {"status": "ORIGINAL_NATIVE_ABSENT", "runnableNative": False}
    result = subprocess.run([str(binary)], input=PROBE_INPUT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            cwd=binary.parent, timeout=10)
    # Pinned ghidra_process.cc returns the command-error response then exits 1 on EOF.
    # The exact structured response proves initialization/protocol dispatch occurred;
    # empty-input exit 1 alone cannot distinguish startup from a missing shared library.
    if result.returncode != 1 or result.stdout != PROBE_OUTPUT or result.stderr:
        raise ValueError("Native startup/protocol probe failed (possible runtime ABI issue): "
                         + str(result.returncode) + ": " + result.stderr.decode(errors="replace")[:2000])
    return {"status": "PASS_NATIVE_PROTOCOL_STARTUP", "runnableNative": True, "exitCode": result.returncode,
            "responseSha256": digest_bytes(result.stdout),
            "scope": "OS loader, native initialization and protocol dispatch only; not a decompilation/semantic test"}


def publish_exclusive(source, destination):
    libc = ctypes.CDLL(None, use_errno=True)
    if platform.system() == "Darwin":
        function = libc.renamex_np
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        result = function(os.fsencode(source), os.fsencode(destination), 0x4)  # RENAME_EXCL
    elif platform.system() == "Linux":
        function = libc.renameat2
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        result = function(-100, os.fsencode(source), -100, os.fsencode(destination), 1)  # RENAME_NOREPLACE
    else:
        raise ValueError("No supported exclusive atomic directory publication primitive")
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))


def update(mode, source, destination, package, cancel=None):
    source, destination = source.resolve(), destination.absolute()
    destination = destination.parent.resolve() / destination.name
    require_base(source)
    if destination.exists() or destination.is_symlink() or destination.is_relative_to(source) or source.is_relative_to(destination):
        raise ValueError("Output must be a new sibling-independent bundle; existing paths are never overwritten")
    if not destination.parent.is_dir():
        raise ValueError("Create the output parent directory first")
    expected, desired = (package["before"], package["after"]) if mode == "install" else (package["after"], package["before"])
    require_state(source, expected)
    original = tree_snapshot(source)
    stage = Path(tempfile.mkdtemp(prefix=".ghidraboy-native-stage-", dir=destination.parent))
    committed = False
    transaction = uuid.uuid4().hex
    receipt = None
    try:
        copied = stage / "distribution"
        shutil.copytree(source, copied, symlinks=False)
        if tree_snapshot(copied) != original:
            raise ValueError("Source changed while copying; nothing published")
        require_state(copied, expected)
        for index, (relative, value) in enumerate(desired.items()):
            path = copied / relative
            if value is None:
                if path.exists():
                    path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("wb") as stream:
                    stream.write(value["bytes"])
                    stream.flush()
                    os.fsync(stream.fileno())
                path.chmod(value["mode"])
            if cancel == "after-first-file" and index == 0:
                raise Cancelled("Requested cancellation after first staged managed-file change")
        require_state(copied, desired)
        runtime = native_probe(copied / package["binary"])
        wanted = dict(original)
        for relative, value in desired.items():
            if value is None:
                wanted.pop(relative, None)
            else:
                wanted[relative] = {"sha256": digest_bytes(value["bytes"]), "mode": value["mode"]}
        if tree_snapshot(copied) != wanted or tree_snapshot(source) != original:
            raise ValueError("Source or staged distribution changed; nothing published")
        require_state(source, expected)
        receipt = {"schema": "ghidraboy-native-copy-update-v1", "transactionId": transaction, "operation": mode, "status": "COMMITTED_NEW_COPY",
                   "source": str(source), "distribution": str(destination / "distribution"), "packageSha256": package["sha256"],
                   "packageNativeDependencyVersion": DEPENDENCY, "packageOfficialNative": False, "sourceUnchanged": True,
                   "resultIdentityState": "PATCHED_DEPENDENCY" if mode == "install" else "RESTORED_ORIGINAL_IDENTITY",
                   "updaterSha256": digest(Path(__file__)),
                   "runtime": runtime, "managedFiles": list(desired), "sourceFileCount": len(original),
                   "publication": "Exclusive atomic rename of distribution and receipt as one bundle",
                   "limits": ["No source files were modified", "Contents and ordinary file modes are verified; timestamps/ownership are not rollback identity", "Runtime startup is checked; corpus and semantic acceptance remain separate"]}
        (stage / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        if cancel == "before-publish":
            raise Cancelled("Requested cancellation before atomic publication")
        publish_exclusive(stage, destination)
        committed = True
        return receipt
    except KeyboardInterrupt:
        # A signal can arrive immediately after the exclusive rename returns. Never
        # delete an already-published bundle; report its complete, identifiable commit.
        published_receipt = destination / "receipt.json"
        if not stage.exists() and receipt is not None and published_receipt.is_file():
            published = json.loads(published_receipt.read_text())
            if published.get("transactionId") == transaction:
                committed = True
                published["interruptedAfterPublication"] = True
                return published
        raise Cancelled("Interrupted before publication; unpublished stage discarded")
    finally:
        if not committed and stage.exists():
            shutil.rmtree(stage)


def verify(source, package):
    source = source.resolve()
    require_base(source)
    require_state(source, package["after"])
    before = tree_snapshot(source)
    runtime = native_probe(source / package["binary"])
    if tree_snapshot(source) != before:
        raise ValueError("Distribution changed during verification")
    return {"status": "VERIFIED_PATCHED_COPY", "distribution": str(source), "packageSha256": package["sha256"], "runtime": runtime}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("install", "verify", "rollback"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cancel", choices=("after-first-file", "before-publish"), help="Explicit cancellation regression; publishes nothing")
    args = parser.parse_args()
    if args.operation == "verify" and (args.output or args.cancel):
        parser.error("verify does not accept output/cancellation options")
    if args.operation != "verify" and args.output is None:
        parser.error("install/rollback require a new --output bundle")
    try:
        package = read_package(args.package, args.package_sha256)
        result = verify(args.source, package) if args.operation == "verify" else update(args.operation, args.source, args.output, package, args.cancel)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Cancelled, KeyboardInterrupt) as error:
        print(json.dumps({"status": "CANCELLED_WITHOUT_PUBLICATION", "reason": str(error)}))
        return 3
    except (OSError, ValueError, KeyError, RuntimeError, zipfile.BadZipFile, subprocess.TimeoutExpired, AttributeError) as error:
        print(json.dumps({"status": "REFUSED_OR_FAILED", "reason": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
