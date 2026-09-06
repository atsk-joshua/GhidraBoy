#!/usr/bin/env bash
# Run inside the retained no-system-SDL runtime image with --init and xvfb-run.
set -euo pipefail
for tool in cc gcc clang make cmake javac gradle rgbasm; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "Unexpected build tool: $tool" >&2
        exit 1
    fi
done
test "$(id -u)" -ne 0
export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/ghidra}"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
export GBC_TEST_HOME=/out/test-home
export GBC_EVIDENCE_DIR=/out/rmi
export XDG_CACHE_HOME=/out/cache
mkdir -p "$XDG_CACHE_HOME"
cd /candidate
python3 - <<'PY' > /out/environment.json
import ctypes, json, os, platform
try:
    ctypes.CDLL('libSDL2-2.0.so.0')
except OSError:
    pass
else:
    raise SystemExit('Unexpected system SDL')
print(json.dumps(dict(platform=platform.platform(), machine=platform.machine(),
                     uid=os.getuid(), python=platform.python_version(), systemSDL=False,
                     scope='Virtual-display Linux x86-64 container; physical Steam Deck deferred'), indent=2))
PY
bash Validate.sh > /out/validate.log 2>&1
python3 scripts/test_installer.py --manifest suite.json --ghidra "$GHIDRA_INSTALL_DIR" \
    --java-home "$JAVA_HOME" --work /out/installer > /out/installer.log 2>&1
.venv12/bin/python scripts/test_display_runtime.py --require-local-sdl > /out/display.log 2>&1
GBC_PYTHON="$PWD/.venv12/bin/python" .venv12/bin/python scripts/doctor.py \
    --ghidra "$GHIDRA_INSTALL_DIR" --java-home "$JAVA_HOME" --user-home "$GBC_TEST_HOME" \
    --require-ready > /out/doctor.json
echo LINUX_EXTRACTED_PACKAGE_PASS
