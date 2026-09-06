#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR to Ghidra 12.1.3}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$PWD/.deps/gradle-user}"
gradle_cmd="${GRADLE:-$PWD/.deps/gradle-8.14.3/bin/gradle}"
provider_root="${GHIDRABOY_ROOT:-$PWD/../GhidraBoy}"
(cd "$provider_root" && ./gradlew --no-daemon assemble)
"$gradle_cmd" -p ghidra-extension --no-daemon buildExtension
