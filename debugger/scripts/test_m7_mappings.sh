#!/usr/bin/env bash
# Isolated source conformance; does not alter frozen acceptance/performance packages.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GHIDRA_INSTALL_DIR:?Select Ghidra 12.1.3 with the static SM83 provider installed}"
: "${JAVA_HOME:?Select Java 21}"
mkdir -p build
mapping_work="$(mktemp -d "$PWD/build/m7-java.XXXXXX")"
mapping_classpath="$(python3 - "$GHIDRA_INSTALL_DIR" <<'PY'
import json, os, sys
from pathlib import Path
root=Path.cwd().parent
artifacts=json.loads((root/'build/integration/artifacts.json').read_text())
provider=root/artifacts['components']['GhidraBoy']['jar']['path']
if not provider.is_file(): raise SystemExit('Build the static provider with integrationArtifacts first')
print(os.pathsep.join([str(provider)]+[str(p) for p in Path(sys.argv[1]).rglob('*.jar') if 'yajsw' not in str(p)]))
PY
)"
"$JAVA_HOME/bin/javac" -proc:none -cp "$mapping_classpath" -d "$mapping_work" ghidra-extension/src/main/java/ghigbc/BankMappings.java tests/ghidra/M7MappingContractTest.java
"$JAVA_HOME/bin/java" -Duser.home="$mapping_work/home" -cp "$mapping_work:$mapping_classpath" M7MappingContractTest "$PWD"
