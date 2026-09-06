#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .local
export PYTHONPATH="$PWD/python"
"${GBC_PYTHON:-.venv12/bin/python}" -m unittest discover -s tests -v
