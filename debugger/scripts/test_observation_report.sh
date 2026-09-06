#!/usr/bin/env bash
# Real DBTrace capture followed by a separate Java-only portable report reader.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/test_java_common.sh
ghigbc_test_init observation-java
ghigbc_test_compile ghidra-extension/src/main/java/ghigbc/*.java tests/ghidra/ObservationReportTest.java
ghigbc_test_java ObservationReportTest "$PWD" "$ghigbc_test_work"
ghigbc_test_java ObservationReportTest reopen "$ghigbc_test_work/observation.json"
