#!/usr/bin/env python3
"""One-command outer SM83 migration preserving pre-upgrade reference primacy."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ghidra_version(root: Path) -> str:
    properties = root / "Ghidra" / "application.properties"
    values = {}
    for line in properties.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values.get("application.version", "")


def run(command, log: Path, env):
    with log.open("xb") as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, env=env)
    if result.returncode:
        raise SystemExit(f"migration command failed ({result.returncode}); inspect {log}")


def project_paths(parent: Path, name: str):
    return parent / f"{name}.gpr", parent / f"{name}.rep"


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Migrate a copied SM83 language-v1 GZF with a pre-upgrade snapshot, exact primacy "
            "restoration, structural legacy preparation, and separate-process verification."
        )
    )
    parser.add_argument("--source", required=True, type=Path, help="immutable source GZF")
    parser.add_argument("--output", required=True, type=Path, help="new migrated GZF")
    parser.add_argument(
        "--legacy-ghidra",
        required=True,
        type=Path,
        help="Ghidra 12.1.3 copy with a source-compatible SM83 language-v1 provider",
    )
    parser.add_argument(
        "--ghidra",
        required=True,
        type=Path,
        help="Ghidra 12.1.3 copy containing the new GhidraBoy candidate",
    )
    parser.add_argument(
        "--scripts",
        required=True,
        type=Path,
        help="directory containing the three GhidraBoyMigration*.java scripts",
    )
    parser.add_argument("--work", required=True, type=Path, help="new retained work directory")
    args = parser.parse_args()

    source = args.source.resolve()
    output = args.output.resolve()
    work = args.work.resolve()
    if not source.is_file():
        parser.error("--source must be an existing regular file")
    if output == source or output.exists():
        parser.error("--output must be a new path distinct from --source")
    if work.exists():
        parser.error("--work must not already exist")
    if ghidra_version(args.legacy_ghidra) != "12.1.3" or ghidra_version(args.ghidra) != "12.1.3":
        parser.error("both Ghidra roots must be version 12.1.3")
    if not args.scripts.is_dir():
        parser.error("--scripts must be a directory")

    work.mkdir(parents=True)
    (work / "logs").mkdir()
    (work / "profiles" / "legacy").mkdir(parents=True)
    (work / "profiles" / "current").mkdir(parents=True)
    snapshot_scripts = work / "snapshot-script"
    snapshot_scripts.mkdir()
    shutil.copyfile(
        args.scripts / "GhidraBoyMigrationSnapshot.java",
        snapshot_scripts / "GhidraBoyMigrationSnapshot.java",
    )
    input_copy = work / "source-copy.gzf"
    shutil.copyfile(source, input_copy)
    source_before = sha256(source)
    if sha256(input_copy) != source_before:
        raise SystemExit("task-owned source copy is not byte-identical")

    legacy_name = "legacy-source"
    current_name = "migrated-copy"
    snapshot = work / "reference-primacy.json"
    apply_receipt = work / "apply-receipt.json"
    receipt = work / "separate-process-reopen.json"
    env = os.environ.copy()

    legacy_import_command = [
        str(args.legacy_ghidra / "support" / "analyzeHeadless"),
        str(work),
        legacy_name,
        "-import",
        str(input_copy),
        "-noanalysis",
    ]
    legacy_env = dict(env, HOME=str(work / "profiles" / "legacy"))
    run(legacy_import_command, work / "logs" / "legacy-import.log", legacy_env)

    legacy_snapshot_command = [
        str(args.legacy_ghidra / "support" / "analyzeHeadless"),
        str(work),
        legacy_name,
        "-process",
        input_copy.stem,
        "-scriptPath",
        str(snapshot_scripts),
        "-postScript",
        "GhidraBoyMigrationSnapshot.java",
        str(snapshot),
        "2",
        "-noanalysis",
        "-readOnly",
    ]
    run(legacy_snapshot_command, work / "logs" / "snapshot.log", legacy_env)
    snapshot_json = json.loads(snapshot.read_text())
    program_name = snapshot_json["binding"]["programName"]
    process_name = snapshot_json["binding"]["domainPath"].lstrip("/")

    legacy_gpr, legacy_rep = project_paths(work, legacy_name)
    current_gpr, current_rep = project_paths(work, current_name)
    shutil.copyfile(legacy_gpr, current_gpr)
    shutil.copytree(legacy_rep, current_rep)

    apply_command = [
        str(args.ghidra / "support" / "analyzeHeadless"),
        str(work),
        current_name,
        "-process",
        process_name,
        "-scriptPath",
        str(args.scripts.resolve()),
        "-postScript",
        "GhidraBoyMigrationApply.java",
        str(snapshot),
        str(apply_receipt),
        "-noanalysis",
    ]
    current_env = dict(env, HOME=str(work / "profiles" / "current"))
    run(apply_command, work / "logs" / "apply.log", current_env)
    if json.loads(apply_receipt.read_text()).get("status") != "PASS":
        raise SystemExit("migration apply receipt did not pass")

    verify_command = [
        str(args.ghidra / "support" / "analyzeHeadless"),
        str(work),
        current_name,
        "-process",
        process_name,
        "-scriptPath",
        str(args.scripts.resolve()),
        "-postScript",
        "GhidraBoyMigrationVerify.java",
        str(snapshot),
        str(receipt),
        "-noanalysis",
        "-readOnly",
    ]
    run(verify_command, work / "logs" / "reopen.log", current_env)
    if json.loads(receipt.read_text()).get("status") != "PASS":
        raise SystemExit("separate-process verification did not pass")

    export_command = [
        str(args.ghidra / "support" / "analyzeHeadless"),
        str(work),
        current_name,
        "-scriptPath",
        str(args.scripts.resolve()),
        "-postScript",
        "GhidraBoyMigrationExport.java",
        process_name,
        str(output),
        "-noanalysis",
        "-readOnly",
    ]
    run(export_command, work / "logs" / "export.log", current_env)
    if not output.is_file():
        raise SystemExit("migration export did not produce the requested GZF")
    if sha256(source) != source_before:
        raise SystemExit("immutable source GZF changed")

    manifest = {
        "schema": "ghidraboy.preview-m2-migration",
        "schemaVersion": 1,
        "status": "PASS",
        "source": str(source),
        "sourceSha256Before": source_before,
        "sourceSha256After": sha256(source),
        "taskOwnedInputCopySha256": sha256(input_copy),
        "output": str(output),
        "outputSha256": sha256(output),
        "snapshotSha256": sha256(snapshot),
        "applyReceiptSha256": sha256(apply_receipt),
        "reopenReceiptSha256": sha256(receipt),
        "programName": program_name,
        "legacyGhidra": str(args.legacy_ghidra.resolve()),
        "targetGhidra": str(args.ghidra.resolve()),
    }
    with (work / "migration-result.json").open("x") as result:
        json.dump(manifest, result, indent=2, sort_keys=True)
        result.write("\n")
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
