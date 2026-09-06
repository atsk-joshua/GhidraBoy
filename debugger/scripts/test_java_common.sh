# Shared source/extracted-package Java acceptance setup. Call after cd to runtime root.
ghigbc_test_init() {
    : "${GHIDRA_INSTALL_DIR:?Select Ghidra 12.1.3}"
    : "${JAVA_HOME:?Select Java 21}"
    export GBC_PYTHON="${GBC_PYTHON:-$PWD/.venv12/bin/python}"
    mkdir -p build
    ghigbc_test_work="$(mktemp -d "$PWD/build/$1.XXXXXX")"
    ghigbc_test_home="${GBC_TEST_HOME:-$ghigbc_test_work/home}"
    if [[ -f suite.json ]]; then
        "$GBC_PYTHON" scripts/install.py --user-home "$ghigbc_test_home"
        ghigbc_test_classes="$PWD/build/GhiGBC-acceptance.jar"
    else
        ghigbc_test_classes="$ghigbc_test_work/classes"
        mkdir -p "$ghigbc_test_classes"
    fi
    ghigbc_test_classpath="$(python3 - "$GHIDRA_INSTALL_DIR" "$ghigbc_test_home" <<'PY'
from pathlib import Path
import os,sys
sys.path.insert(0,str(Path.cwd()/'scripts'))
from build_inputs import artifact_inputs
if Path('suite.json').is_file():
    products=[str(p) for p in Path(sys.argv[2]).rglob('*.jar')]
else:
    root=Path.cwd().parent
    _, artifacts=artifact_inputs(root,root/'build/integration/artifacts.json')
    products=[str(artifacts[name]['jar']) for name in ('GhidraBoy','GhiGBC')]
print(os.pathsep.join(products+[str(p) for p in Path(sys.argv[1]).rglob('*.jar') if 'yajsw' not in str(p)]))
PY
)"
}

ghigbc_test_compile() {
    if [[ ! -f suite.json ]]; then
        "$JAVA_HOME/bin/javac" -proc:none -cp "$ghigbc_test_classpath" -d "$ghigbc_test_classes" "$@"
    fi
}

ghigbc_test_java() {
    "$JAVA_HOME/bin/java" -Duser.home="$ghigbc_test_home" -cp "$ghigbc_test_classes:$ghigbc_test_classpath" "$@"
}
