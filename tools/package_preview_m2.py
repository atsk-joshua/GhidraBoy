#!/usr/bin/env python3
"""Build a deterministic redistributable PREVIEW-M2 wrapper around an extension ZIP."""

import argparse
import hashlib
import json
import subprocess
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ["START-HERE.md", "INSTALL.md", "MIGRATION.md", "SUPPORTED-SCOPE.md", "LIMITATIONS.md", "ROLLBACK.md"]
MIGRATION_SCRIPTS = [
    "GhidraBoyMigrationSnapshot.java",
    "GhidraBoyMigrationApply.java",
    "GhidraBoyMigrationVerify.java",
    "GhidraBoyMigrationExport.java",
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--extension", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    extension = args.extension.resolve()
    output = args.output.resolve()
    if not extension.is_file():
        parser.error("--extension must be an existing file")
    if output.exists():
        parser.error("--output must not exist")
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="ghidraboy-preview-m2-") as temporary:
        stage = Path(temporary)
        (stage / "migration" / "scripts").mkdir(parents=True)
        (stage / "GhidraBoy-extension.zip").write_bytes(extension.read_bytes())
        for name in DOCS:
            (stage / name).write_bytes((ROOT / "packaging" / "preview-m2" / name).read_bytes())
        (stage / "migration" / "migrate_legacy_program.py").write_bytes(
            (ROOT / "tools" / "migrate_legacy_program.py").read_bytes()
        )
        for name in MIGRATION_SCRIPTS:
            (stage / "migration" / "scripts" / name).write_bytes(
                (ROOT / "ghidra_scripts" / name).read_bytes()
            )

        payload = sorted(
            path for path in stage.rglob("*") if path.is_file() and path.name not in {"MANIFEST.json", "SHA256SUMS"}
        )
        manifest = {
            "schema": "ghidraboy.engineering-preview-m2",
            "schemaVersion": 1,
            "sourceCommit": git("rev-parse", "HEAD"),
            "sourceTree": git("write-tree"),
            "branch": git("branch", "--show-current"),
            "extensionSha256": sha256(stage / "GhidraBoy-extension.zip"),
            "files": {
                path.relative_to(stage).as_posix(): {
                    "sha256": sha256(path),
                    "size": path.stat().st_size,
                }
                for path in payload
            },
        }
        (stage / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        checksum_files = sorted(path for path in stage.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
        (stage / "SHA256SUMS").write_text(
            "".join(f"{sha256(path)}  {path.relative_to(stage).as_posix()}\n" for path in checksum_files)
        )

        with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in sorted(path for path in stage.rglob("*") if path.is_file()):
                info = zipfile.ZipInfo(path.relative_to(stage).as_posix(), (2026, 9, 16, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o755 if path.suffix == ".py" else 0o644) << 16
                archive.writestr(info, path.read_bytes())
    print(json.dumps({"path": str(output), "sha256": sha256(output)}, indent=2))


if __name__ == "__main__":
    main()
