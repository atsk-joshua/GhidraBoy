#!/usr/bin/env bash
# Interactive acceptance: prepares real fixtures and observes manual/CUA clicks.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GHIDRA_INSTALL_DIR:?Set Ghidra 12.1.3 path}"
: "${JAVA_HOME:?Set Java 21 home}"
export GBC_PYTHON="${GBC_PYTHON:-$PWD/.venv12/bin/python}"
ui_home="${GBC_TEST_HOME:-$PWD/.local/ghidra-ui-test-user}"
"$GBC_PYTHON" scripts/install.py --user-home "$ui_home"
mkdir -p build/projects docs/evidence
ui_classes="$(mktemp -d "$PWD/build/ui-test-classes.XXXXXX")"
ui_classpath="$(python3 - "$GHIDRA_INSTALL_DIR" "$ui_home" <<'PY'
from pathlib import Path
import sys, os, platform
settings = Path(sys.argv[2]) / ('Library/ghidra' if platform.system() == 'Darwin' else '.config/ghidra') / 'ghidra_12.1.3_PUBLIC/Extensions'
print(os.pathsep.join(str(p.resolve()) for base in (Path(sys.argv[1]), settings) for p in base.rglob('*.jar') if 'yajsw' not in str(p)))
PY
)"
ui_test=UiActionTest
if [[ "${1:-}" == "--hp" ]]; then echo "Use the optional GhiBW3 study guide for the current HP UI check." >&2; exit 2; fi
if [[ -f build/GhiGBC-acceptance.jar ]]; then
  ui_classes="$PWD/build/GhiGBC-acceptance.jar"
else
  "$JAVA_HOME/bin/javac" -proc:none -cp "$ui_classpath" -d "$ui_classes" tests/ghidra/UiActionTest.java
fi
printf '%s\n' 'Follow docs/UI_ACTION_VALIDATION.md; phases are written to docs/evidence/ui-action-phase.txt.'
"$JAVA_HOME/bin/java" -Duser.home="$ui_home" -cp "$ui_classes:$ui_classpath" "$ui_test" "$PWD" "$GHIDRA_INSTALL_DIR"
