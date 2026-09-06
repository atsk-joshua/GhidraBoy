#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/test_java_common.sh
ghigbc_test_init backend-trace
ghigbc_test_compile tests/ghidra/RealTraceTest.java tests/ghidra/MappingContractTest.java tests/ghidra/BackendTraceTest.java
if [[ $# == 0 ]]; then
    # Built-in IDs contain no shell metacharacters; the factory validates installed selection.
    IFS=' ' read -r -a backend_names <<< "$(PYTHONPATH="$PWD/python" "$GBC_PYTHON" -c 'from ghigbc.backend import available_backends; print(" ".join(available_backends()))')"
    set -- "${backend_names[@]}"
fi
ghigbc_test_java BackendTraceTest "$PWD" "$@"
