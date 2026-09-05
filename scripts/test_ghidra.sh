#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GHIDRA_INSTALL_DIR:?Set Ghidra 12.1.3 path}"
: "${JAVA_HOME:?Set Java 21 home}"
export GBC_PYTHON="${GBC_PYTHON:-$PWD/.venv12/bin/python}"
user_home="${GBC_TEST_HOME:-$PWD/.local/ghidra-test-user}"
"$GBC_PYTHON" scripts/install.py --user-home "$user_home"
mkdir -p build/projects
test_classes="$(mktemp -d "$PWD/build/ghidra-test-classes.XXXXXX")"
python3 - "$GHIDRA_INSTALL_DIR" "$user_home" <<'PY'
from pathlib import Path
import sys,os,platform
home=Path(sys.argv[2])
settings=home/('Library/ghidra' if platform.system()=='Darwin' else '.config/ghidra')/'ghidra_12.1.3_PUBLIC/Extensions'
roots=[Path(sys.argv[1]),settings]
Path('build/ghidra-test-classpath.txt').write_text(os.pathsep.join(str(p.resolve()) for root in roots for p in root.rglob('*.jar') if 'yajsw' not in str(p)))
PY
cp_path="$(cat build/ghidra-test-classpath.txt)"
if [[ -f build/GhiGBC-acceptance.jar ]]; then
  test_classes="$PWD/build/GhiGBC-acceptance.jar"
else
  "$JAVA_HOME/bin/javac" -proc:none -cp "$cp_path" -d "$test_classes" tests/ghidra/RealTraceTest.java tests/ghidra/MappingContractTest.java
fi
"$JAVA_HOME/bin/java" -Duser.home="$user_home" -cp "$test_classes:$cp_path" RealTraceTest "$PWD" "$@"
