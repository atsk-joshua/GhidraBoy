#!/usr/bin/env bash
# Interactive acceptance: prepares real fixtures and observes manual/CUA clicks.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GHIDRA_INSTALL_DIR:?Set Ghidra 12.1.3 path}"
: "${JAVA_HOME:?Set Java 21 home}"
export GBC_PYTHON="${GBC_PYTHON:-$PWD/.venv12/bin/python}"
ui_home="${GBC_TEST_HOME:-$PWD/.local/ghidra-ui-test-user}"
"$GBC_PYTHON" scripts/install.py --user-home "$ui_home"
export GBC_EVIDENCE_DIR="${GBC_EVIDENCE_DIR:-$PWD/.local/results}"
mkdir -p build/projects "$GBC_EVIDENCE_DIR"
ui_classes="$(mktemp -d "$PWD/build/ui-test-classes.XXXXXX")"
ui_classpath="$(python3 - "$GHIDRA_INSTALL_DIR" "$ui_home" <<'PY'
from pathlib import Path
import sys, os, platform
settings = Path(sys.argv[2]) / ('Library/ghidra' if platform.system() == 'Darwin' else '.config/ghidra') / 'ghidra_12.1.3_PUBLIC/Extensions'
print(os.pathsep.join(str(p.resolve()) for base in (Path(sys.argv[1]), settings) for p in base.rglob('*.jar') if 'yajsw' not in str(p)))
PY
)"
ui_test=UiActionTest
if [[ $# -gt 0 ]]; then echo "This observer accepts no game-specific options." >&2; exit 2; fi
if [[ -f build/GhiGBC-acceptance.jar ]]; then
  ui_classes="$PWD/build/GhiGBC-acceptance.jar"
else
  "$JAVA_HOME/bin/javac" -proc:none -cp "$ui_classpath" -d "$ui_classes" tests/ghidra/UiActionTest.java
fi
printf 'Follow docs/UI_ACTION_VALIDATION.md; phases are written to %s/ui-action-phase.txt.\n' "$GBC_EVIDENCE_DIR"
"$JAVA_HOME/bin/java" -Duser.home="$ui_home" -cp "$ui_classes:$ui_classpath" "$ui_test" "$PWD" "$GHIDRA_INSTALL_DIR" "$@"
