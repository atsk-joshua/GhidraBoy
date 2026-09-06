#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR to Ghidra 12.1.3}"
repo_root="$(cd .. && pwd)"
exec "$repo_root/gradlew" -p "$repo_root" --no-daemon -PwithDebugger=true integrationArtifacts "$@"
