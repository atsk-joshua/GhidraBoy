"""Read canonical source dependencies and verified Gradle outputs without guessing paths."""
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def runtime_dependencies(root):
    root = Path(root)
    canonical = root.parent / "tools/dependencies.json"
    if canonical.is_file():
        data = json.loads(canonical.read_text())
        runtime = data["debuggerRuntime"]
        runtime["ghidra"] = {
            "version": data["primaryGhidra"]["version"],
            "archive_sha256": data["primaryGhidra"]["sha256"],
        }
        native = data["nativeDecompilerPatch"]
        runtime["native_decompiler"] = {
            "version": native["dependencyVersion"],
            "patchSha256": native["patchSha256"],
            "sourceLockSha256": native["pristineSourceLockSha256"],
            "baseGhidraVersion": data["primaryGhidra"]["version"],
        }
        java = data["debuggerJavaPatch"]
        runtime["debugger_java"] = {key: value for key, value in java.items()
                                    if key not in ("patch", "baselineSourceArchiveSha256")}
        return runtime
    # Extracted runtime packages carry a generated view, never a second source lock.
    return json.loads((root / "dependencies.lock.json").read_text())


def artifact_inputs(repository, manifest):
    repository = Path(repository).resolve()
    data = json.loads(Path(manifest).read_text())
    if data.get("schema") != 1 or set(data.get("components", {})) != {"GhidraBoy", "GhiGBC"}:
        raise ValueError("Build both extensions with the root integrationArtifacts task")
    resolved = {}
    for component, entries in data["components"].items():
        if set(entries) != {"jar", "archive"}:
            raise ValueError("Incomplete build outputs for " + component)
        resolved[component] = {}
        for kind, entry in entries.items():
            relative = Path(entry["path"])
            path = repository / relative
            if relative.is_absolute() or ".." in relative.parts or not path.resolve().is_relative_to(repository):
                raise ValueError("Build artifact path escapes repository")
            if path.is_symlink() or not path.is_file() or sha(path) != entry["sha256"]:
                raise ValueError("Stale or missing build artifact: " + str(relative))
            resolved[component][kind] = path
    return data, resolved


def verify_native_decompiler(ghidra, requirement, platform):
    """Verify the selected native dependency marker and executable without installing it."""
    if not requirement:
        return {"status": "UNSPECIFIED"}  # Older package formats did not carry this requirement.
    native_platform = {"macos-arm64": "mac_arm_64", "linux-x86_64": "linux_x86_64"}[platform]
    directory = Path(ghidra) / "Ghidra/Features/Decompiler"
    marker = directory / "ghidraboy-native-dependency.json"
    if not marker.is_file():
        raise ValueError("Missing GhidraBoy native decompiler dependency " + requirement["version"] +
                         "; use the documented copy-only native dependency updater")
    identity = json.loads(marker.read_text())
    expected = dict(requirement)
    expected["nativeDependencyVersion"] = expected.pop("version")
    expected.update(schema="ghidraboy-native-dependency-identity-v1", platform=native_platform, officialNative=False)
    if any(identity.get(key) != value for key, value in expected.items()):
        raise ValueError("Selected native decompiler identity does not match the package requirement")
    binary = directory / "os" / native_platform / "decompile"
    if not binary.is_file() or sha(binary) != identity.get("binarySha256"):
        raise ValueError("Selected native decompiler executable does not match its identity marker")
    return dict(status="MATCHED", identity=identity)


def verify_debugger_java(ghidra, requirement):
    """Require the reviewed register-lifetime JAR and its declared identity."""
    instruction = ("; use the copy-only updater: python3 scripts/debugger_dependency_update.py "
                   "install --ghidra <source> --package <debugger-java-dependency.zip> "
                   "--sha256 <trusted-package-sha256> --output <new-bundle>; then select "
                   "<new-bundle>/distribution")
    if not requirement:
        raise ValueError("Missing debugger Java package requirement; rebuild the runtime package" + instruction)
    if ghidra is None:
        raise ValueError("Select the patched Ghidra distribution" + instruction)
    selected = Path(ghidra).resolve()
    directory = selected / "Ghidra/Debug/Debugger"
    marker = directory / "ghidraboy-java-dependency.json"
    jar = directory / "lib/Debugger.jar"
    for path in (marker, jar):
        for parent in (path, *path.parents):
            if parent == selected:
                break
            if parent.is_symlink():
                raise ValueError("Debugger Java dependency contains a symlink" + instruction)
    if not marker.is_file():
        raise ValueError("Missing GhidraBoy debugger Java dependency " + requirement["dependencyVersion"] + instruction)
    try:
        identity = json.loads(marker.read_text())
    except (ValueError, OSError) as error:
        raise ValueError("Unreadable debugger Java identity marker" + instruction) from error
    expected = dict(requirement, schema="ghidraboy-debugger-java-dependency-v1")
    if identity != expected:
        raise ValueError("Selected debugger Java identity does not match the package requirement" + instruction)
    if not jar.is_file() or sha(jar) != requirement["jarSha256"]:
        raise ValueError("Selected Debugger.jar does not match the pinned Java dependency" + instruction)
    return dict(status="MATCHED", identity=identity)
