#!/bin/bash
set -euo pipefail

validation_root=$(mktemp -d /tmp/ghidraboy-ci-XXXXXX)
python3 -m pip install 'jsonschema==4.25.1'
python3 tools/fetch_dependency.py migrationGhidra "$validation_root/legacy.zip"
python3 tools/fetch_dependency.py migrationExtension "$validation_root/legacy-extension.zip"
unzip -q "$validation_root/legacy.zip" -d "$validation_root"
unzip -q "$validation_root/legacy-extension.zip" -d "$validation_root/ghidra_11.3.1_PUBLIC/Ghidra/Extensions"
cp -a "$GHIDRA_INSTALL_DIR" "$validation_root/ghidra"
python3 tools/fetch_vectors.py --count 1000 --output "$validation_root/vectors"
# Keep failure logs even if the runner cannot reach evidence generation.
trap 'mkdir -p build/reports/command-logs; cp "$validation_root/work/"*.log "$validation_root/work/commands.json" build/reports/command-logs/ 2>/dev/null || true' EXIT
python3 tools/run_validation.py --native --ghidra "$GHIDRA_INSTALL_DIR" \
  --jdk "$JAVA_HOME" --installed-ghidra "$validation_root/ghidra" \
  --legacy-ghidra "$validation_root/ghidra_11.3.1_PUBLIC" \
  --vectors "$validation_root/vectors" --work "$validation_root/work" \
  --dependency-file "migrationGhidra=$validation_root/legacy.zip" \
  --dependency-file "migrationExtension=$validation_root/legacy-extension.zip"
