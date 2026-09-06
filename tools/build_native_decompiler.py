#!/usr/bin/env python3
"""Build a pinned, explicitly unofficial native dependency in a fresh copy only.

Requires a pristine Ghidra12.1.3 source tree with one installed SM83 provider.
Never patches the input distribution. Produces a new distribution plus a small
native update/rollback package; does not install it into an active application.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import zipfile

REPO = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def tree_hashes(root):
    return {str(path.relative_to(root)): digest(path) for path in sorted(root.rglob("*")) if path.is_file()}


def platform_settings(system=None, machine=None):
    system, machine = system or platform.system(), machine or platform.machine()
    if system == "Darwin" and machine == "arm64":
        return "mac_arm_64", "clang++", ["ARCH_TYPE=-arch arm64", "ADDITIONAL_FLAGS=-mmacosx-version-min=11.0 -w"]
    if system == "Linux" and machine in ("x86_64", "amd64"):
        return "linux_x86_64", "g++", ["ARCH=x86_64"]
    raise ValueError("Validated build target unavailable for " + system + "/" + machine)


def require_pristine(source, lock):
    actual = tree_hashes(source)
    if actual != lock["files"]:
        differences = sorted(key for key in actual.keys() | lock["files"].keys() if actual.get(key) != lock["files"].get(key))
        raise ValueError("Native source is not pinned pristine input (already patched/changed?): " + ", ".join(differences[:12]))
    return actual


def native_binary_kind(path, target):
    data = path.read_bytes()[:64]
    if target == "mac_arm_64":
        return len(data) >= 8 and data[:4] == bytes.fromhex("cffaedfe") and int.from_bytes(data[4:8], "little") == 0x100000c
    return len(data) >= 20 and data[:5] == b"\x7fELF\x02" and data[5] == 1 and int.from_bytes(data[18:20], "little") == 62


def run(args):
    work, original, jdk = args.work.resolve(), args.ghidra.resolve(), args.jdk.resolve()
    if work.exists() or work.is_relative_to(REPO) or work.is_relative_to(original) or original.is_relative_to(work):
        raise ValueError("Use a fresh work directory outside the input distribution")
    if any(part.startswith(".") for part in work.parts):
        raise ValueError("Headless project paths must not contain dot-prefixed components")
    dependencies = json.loads((REPO / "tools/dependencies.json").read_text())
    pin = dependencies["nativeDecompilerPatch"]
    patch, lock_path = REPO / pin["patch"], REPO / pin["pristineSourceLock"]
    if digest(patch) != pin["patchSha256"] or digest(lock_path) != pin["pristineSourceLockSha256"]:
        raise ValueError("Patch/source-lock digest differs from dependency pin")
    lock = json.loads(lock_path.read_text())
    if lock["archiveSha256"] != dependencies["primaryGhidra"]["sha256"] or lock["baseGhidra"] != pin["baseGhidraVersion"]:
        raise ValueError("Native and official distribution identities disagree")
    properties = original / "Ghidra/application.properties"
    if not re.search(r"^application.version=" + re.escape(pin["baseGhidraVersion"]) + r"$", properties.read_text(), re.M):
        raise ValueError("Wrong base Ghidra version")
    pristine = require_pristine(original / lock["sourceDirectory"], lock)
    providers = list(original.glob("Ghidra/**/data/languages/sm83.ldefs"))
    if len(providers) != 1:
        raise ValueError("Require exactly one installed SM83 provider for native validation")
    provider = providers[0].parents[2]
    provider_hashes = tree_hashes(provider)
    target, default_compiler, make_flags = platform_settings()
    compiler = shutil.which(args.cxx or default_compiler)
    if not compiler or not shutil.which("make") or not shutil.which("patch") or not (jdk / "bin/java").is_file() or not (jdk / "bin/javac").is_file():
        raise ValueError("Missing native compiler/make/patch or full JDK (java and javac required)")
    relative_binary = Path("Ghidra/Features/Decompiler/os") / target / "decompile"
    original_binary = original / relative_binary
    original_hash = digest(original_binary) if original_binary.is_file() else None
    relative_identity = Path("Ghidra/Features/Decompiler/ghidraboy-native-dependency.json")
    original_identity = original / relative_identity
    original_identity_hash = digest(original_identity) if original_identity.is_file() else None
    work.mkdir(parents=True, mode=0o700)
    result = {"schema": "ghidraboy-native-dependency-build-v1", "status": "IN_PROGRESS", "officialNative": False,
              "baseGhidraVersion": pin["baseGhidraVersion"], "nativeDependencyVersion": pin["dependencyVersion"],
              "buildHelperSha256": digest(Path(__file__)), "platform": target, "inputDistribution": str(original), "pristineSourceLockSha256": digest(lock_path),
              "pristineSources": pristine, "patchSha256": digest(patch), "providerFiles": provider_hashes,
              "originalBinarySha256": original_hash, "commands": []}
    write_json(work / "build.json", result)
    env = os.environ.copy()
    env.update(JAVA_HOME=str(jdk), JAVA_TOOL_OPTIONS='-Duser.home="' + str(work / "home") + '"', SOURCE_DATE_EPOCH="1788566400")
    for name in ("home", "projects", "scripts", "package"):
        (work / name).mkdir()

    def execute(name, command, cwd, marker=None, timeout=1800):
        receipt = {"name": name, "command": list(map(str, command)), "cwd": str(cwd), "status": "BLOCKED"}
        result["commands"].append(receipt)
        write_json(work / "build.json", result)
        started = time.monotonic()
        with (work / (name + ".log")).open("w") as stream:
            process = subprocess.Popen(receipt["command"], cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                receipt["exitCode"] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                raise RuntimeError(name + " exceeded finite deadline")
        text = (work / (name + ".log")).read_text(errors="replace")
        receipt["seconds"] = round(time.monotonic() - started, 3)
        receipt["requiredMarker"] = marker
        passed = receipt["exitCode"] == 0 and (marker is None or marker in text) and not (name in ("native-regression", "nibble-native-regression") and re.search(r"\bERROR\b", text))
        receipt["status"] = "PASS" if passed else "FAIL"
        write_json(work / "build.json", result)
        if not passed:
            raise RuntimeError(name + " failed; see preserved log")
        return text

    result["compiler"] = {"path": compiler, "resolvedBinarySha256": digest(Path(compiler).resolve()), "version": execute("compiler", [compiler, "--version"], work).strip()}
    result["javaVersion"] = execute("java", [jdk / "bin/java", "-version"], work).strip()
    result["makeVersion"] = execute("make-version", ["make", "--version"], work).strip()
    distribution = work / "distribution"
    shutil.copytree(original, distribution, symlinks=False)
    source = distribution / lock["sourceDirectory"]
    require_pristine(source, lock)
    execute("apply-patch", ["patch", "--batch", "--forward", "-p1", "-i", patch], distribution)
    patched_sources = tree_hashes(source)
    changed = [key for key in pristine.keys() | patched_sources.keys() if pristine.get(key) != patched_sources.get(key)]
    if changed != ["jumptable.cc"]:
        raise ValueError("Patch changed unexpected source files: " + str(changed))
    result["patchedSourceFiles"] = patched_sources
    if args.reuse_native is not None:
        previous = json.loads(args.reuse_build.read_text())
        if (previous.get("nativeBinarySha256") != digest(args.reuse_native) or previous.get("platform") != target
                or previous.get("patchSha256") != digest(patch) or previous.get("pristineSourceLockSha256") != digest(lock_path)
                or previous.get("patchedSourceFiles") != patched_sources
                or previous.get("nativeDependencyVersion") != pin["dependencyVersion"]
                or not any(receipt.get("name") == "native-build" and receipt.get("status") == "PASS" for receipt in previous.get("commands", []))):
            raise ValueError("Reused native artifact does not match a successful pinned-source build receipt")
        result["reusedBuild"] = {"receiptSha256": digest(args.reuse_build), "nativeSha256": digest(args.reuse_native), "compiler": previous["compiler"], "commands": previous["commands"]}
        built = args.reuse_native
    else:
        execute("native-build", ["make", "-j" + str(args.jobs), "ghidra_opt", "CXX=" + compiler + " -std=c++11", *make_flags], source)
        built = source / "ghidra_opt"
    if not native_binary_kind(built, target):
        raise ValueError("Compiled executable has the wrong target format/architecture")
    target_binary = distribution / relative_binary
    target_binary.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built, target_binary)
    result["nativeBinarySha256"] = digest(target_binary)
    if target == "linux_x86_64":
        required = execute("linux-version-requirements", ["readelf", "--version-info", target_binary], work)
        old_required = execute("linux-original-version-requirements", ["readelf", "--version-info", original_binary], work) if original_hash else ""
        version_pattern = r"\b(?:GLIBCXX|GLIBC|CXXABI)_[0-9.]+"
        result["linuxRuntimeRequirements"] = {"requiredVersionSymbols": sorted(set(re.findall(version_pattern, required))),
                                             "originalVersionSymbols": sorted(set(re.findall(version_pattern, old_required))),
                                             "targetDeploymentValidation": "UNVERIFIED: local container execution does not establish every downstream system's ABI support"}
    marker = {"schema": "ghidraboy-native-dependency-identity-v1", "baseGhidraVersion": pin["baseGhidraVersion"],
              "nativeDependencyVersion": pin["dependencyVersion"], "officialNative": False, "platform": target,
              "patchSha256": digest(patch), "sourceLockSha256": digest(lock_path), "binarySha256": digest(target_binary)}
    if "linuxRuntimeRequirements" in result:
        marker["runtimeRequirements"] = result["linuxRuntimeRequirements"]
    write_json(distribution / "Ghidra/Features/Decompiler/ghidraboy-native-dependency.json", marker)
    for name in ("NormalizedSwitchDecompiler.java", "NormalizedSwitchRegression.java", "NibbleSwitchRangeProbe.java"):
        shutil.copy2(REPO / "src/test/scripts" / name, work / "scripts" / name)
    shutil.copy2(REPO / "tools/verify_normalized_switch_fixture.py", work / "scripts/verify_normalized_switch_fixture.py")
    shutil.copy2(REPO / "tools/verify_nibble_switch_fixture.py", work / "scripts/verify_nibble_switch_fixture.py")
    result["validationScripts"] = tree_hashes(work / "scripts")
    execute("native-regression", [distribution / "support/analyzeHeadless", work / "projects", "fixture", "-scriptPath", work / "scripts",
                                "-preScript", "NormalizedSwitchRegression.java", work / "fixture-output", "-noanalysis"], work,
            marker="NORMALIZED_SWITCH_REGRESSION_FINISHED PASS")
    fixture = json.loads((work / "fixture-output/result.json").read_text())
    if fixture["status"] != "PASS":
        raise ValueError("Native normalized-switch fixture did not pass")
    execute("generated-c-regression", [sys.executable, work / "scripts/verify_normalized_switch_fixture.py", work / "fixture-output", work / "c-output", "--cc", args.cc], work)
    c_result = json.loads((work / "c-output/result.json").read_text())
    if c_result["status"] != "PASS" or c_result["cases"] != 256 or c_result["failures"]:
        raise ValueError("Generated-C semantic regression failed")
    (work / "nibble-input.bin").write_bytes(bytes(0x8000))
    execute("nibble-native-regression", [distribution / "support/analyzeHeadless", work / "projects", "nibble-fixture",
            "-import", work / "nibble-input.bin", "-loader", "BinaryLoader", "-processor", "SM83:LE:16:default",
            "-cspec", "default", "-noanalysis", "-scriptPath", work / "scripts",
            "-postScript", "NibbleSwitchRangeProbe.java", work / "nibble-result.json"], work,
            marker="NIBBLE_SWITCH_RANGE_PROBE_COMPLETE")
    execute("nibble-generated-c-regression", [sys.executable, work / "scripts/verify_nibble_switch_fixture.py",
            work / "nibble-result.json", "--c-only", "--work", work / "nibble-c-output", "--cc", args.cc], work)
    nibble_result = json.loads((work / "nibble-c-output/result.json").read_text())
    if (nibble_result["status"] != "PASS" or nibble_result["cCases"] != 256
            or not nibble_result["exactRecoveredRange"] or nibble_result["routineHexMatches"] is not True
            or nibble_result["verificationScope"] != "C_AND_RANGE_ONLY"):
        raise ValueError("Nibble-switch range/generated-C regression failed")
    result["nibbleSwitchTests"] = {"status": "PASS", "cases": 256, "recoveredTargets": 16,
                                  "scope": "Exact native recovery and generated C; independent SameBoy receipt is separate"}
    result["componentDecompilerTests"] = "NOT_RUN"
    if args.component_tests:
        env["GHIDRA_INSTALL_DIR"] = str(distribution)
        env["GRADLE_USER_HOME"] = os.environ.get("GRADLE_USER_HOME", str(Path.home() / ".gradle"))
        result["componentSourceFiles"] = {str(path.relative_to(REPO)): digest(path) for path in sorted((REPO / "data/languages").glob("*")) if path.is_file()}
        result["componentSourceFiles"]["src/test/kotlin/fi/gekkio/ghidraboy/decompiler/DecompilerTest.kt"] = digest(REPO / "src/test/kotlin/fi/gekkio/ghidraboy/decompiler/DecompilerTest.kt")
        execute("component-decompiler", [REPO / "gradlew", "--no-daemon", "test", "--tests", "*DecompilerTest", "--console=plain"], REPO)
        reports = list((REPO / "build/test-results/test").glob("TEST-*DecompilerTest.xml"))
        if len(reports) != 1:
            raise ValueError("Expected actual DecompilerTest XML")
        import xml.etree.ElementTree as ET
        suite = ET.parse(reports[0]).getroot()
        if int(suite.attrib["tests"]) < 1 or int(suite.attrib["failures"]) or int(suite.attrib["errors"]):
            raise ValueError("DecompilerTest report is not passing")
        shutil.copy2(reports[0], work / reports[0].name)
        result["componentDecompilerTests"] = {"status": "PASS", "tests": int(suite.attrib["tests"]), "xmlSha256": digest(reports[0])}
    result["originalDistributionUnchanged"] = require_pristine(original / lock["sourceDirectory"], lock) == pristine and (digest(original_binary) if original_binary.is_file() else None) == original_hash and tree_hashes(provider) == provider_hashes and (digest(original_identity) if original_identity.is_file() else None) == original_identity_hash
    if not result["originalDistributionUnchanged"]:
        raise ValueError("Original distribution changed during build")
    package = work / "package"
    (package / relative_binary).parent.mkdir(parents=True)
    shutil.copy2(target_binary, package / relative_binary)
    shutil.copy2(patch, package / patch.name)
    shutil.copy2(lock_path, package / lock_path.name)
    write_json(package / "native-dependency.json", marker)
    write_json(package / "Ghidra/Features/Decompiler/ghidraboy-native-dependency.json", marker)
    rollback = {"schema": "ghidraboy-native-rollback-v1", "path": str(relative_binary), "originalExisted": original_hash is not None,
                "originalSha256": original_hash, "expectedInstalledSha256": digest(target_binary),
                "rule": "Restore the backup (or remove added executable) only if the current executable still matches expectedInstalledSha256; preserve edited/different files",
                "baseGhidraVersion": pin["baseGhidraVersion"], "nativeDependencyVersion": pin["dependencyVersion"]}
    if original_hash:
        (package / "rollback").mkdir()
        shutil.copy2(original_binary, package / "rollback/decompile.original")
        rollback["backup"] = "rollback/decompile.original"
    rollback["identityMarker"] = {"path": str(relative_identity), "originalExisted": original_identity_hash is not None,
                                  "originalSha256": original_identity_hash, "expectedInstalledSha256": digest(distribution / relative_identity)}
    if original_identity_hash:
        (package / "rollback").mkdir(exist_ok=True)
        shutil.copy2(original_identity, package / "rollback/native-dependency.original.json")
        rollback["identityMarker"]["backup"] = "rollback/native-dependency.original.json"
    rollback["transactionRule"] = "Check BOTH current binary and identity marker against their expected hashes before changing either; restore original marker or remove the owned added marker together with binary rollback"
    write_json(package / "rollback.json", rollback)
    if (original / "LICENSE").is_file():
        shutil.copy2(original / "LICENSE", package / "GHIDRA-LICENSE")
    result["status"] = "PASS_LOCAL_NATIVE_GATES"
    result["limits"] = ["Explicitly patched native dependency, not an official Ghidra release", "No active installation was modified", "Provider corpus/annotation, all-platform and complete upstream-native suite gates remain separate"]
    write_json(work / "build.json", result)
    shutil.copy2(work / "build.json", package / "build.json")
    archive = work / ("ghidra-native-" + pin["dependencyVersion"] + "-" + target + ".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
        for path in sorted(package.rglob("*")):
            if path.is_file():
                info = zipfile.ZipInfo(str(path.relative_to(package)), date_time=(2026, 9, 5, 0, 0, 0))
                info.external_attr = (path.stat().st_mode & 0xffff) << 16
                output.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
    write_json(work / "package.json", {"path": str(archive), "sha256": digest(archive), "nativeBinarySha256": digest(target_binary), "nativeDependencyVersion": pin["dependencyVersion"]})
    print(json.dumps({"status": result["status"], "distribution": str(distribution), "package": str(archive), "nativeSha256": digest(target_binary)}))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("ghidra", "jdk", "work"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--cxx")
    parser.add_argument("--cc", default="clang")
    parser.add_argument("--component-tests", action="store_true")
    parser.add_argument("--reuse-native", type=Path, help="Reuse an unchanged binary from a successful pinned native build; still validate in a fresh copy")
    parser.add_argument("--reuse-build", type=Path, help="Matching previous build.json receipt; required with --reuse-native")
    args = parser.parse_args()
    if (args.reuse_native is None) != (args.reuse_build is None):
        parser.error("--reuse-native and --reuse-build must be supplied together")
    if not 1 <= args.jobs <= 32:
        parser.error("jobs must be 1..32")
    existed = args.work.exists()
    try:
        return run(args)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        if not existed and (args.work / "build.json").exists():
            result = json.loads((args.work / "build.json").read_text())
            result.update(status="BLOCKED_OR_FAILED", error=str(error))
            write_json(args.work / "build.json", result)
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
