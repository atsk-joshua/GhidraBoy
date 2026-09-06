"""Check real runtime prerequisites without pinning the user's Python release."""
import json
import subprocess

# Path.is_relative_to and the bundled ghidratrace/protobuf wheels require Python >=3.9.
MINIMUM = (3, 9)
PROBE = '''import sys, json
if sys.version_info[:2] < (3, 9):
    raise SystemExit("Python 3.9 or newer is required by the bundled Ghidra wheels")
try:
    import ctypes, dataclasses, sysconfig, venv, zipfile
except ImportError as error:
    raise SystemExit("Existing Python is missing a required capability: " + str(error))
print(json.dumps({"executable": sys.executable, "version": sys.version.split()[0]}))
'''


def check_runtime(python):
    result = subprocess.run([str(python), '-c', PROBE], text=True, capture_output=True)
    if result.returncode:
        raise ValueError('Cannot use selected Python: ' + (result.stderr or result.stdout).strip())
    return json.loads(result.stdout)

# These exact dependencies are pure-Python wheels shipped by Ghidra. Installing them
# directly in the isolated venv avoids requiring pip/ensurepip on the host Python.
WHEEL_INSTALL = '''import pathlib, sys, sysconfig, zipfile
if sys.prefix == sys.base_prefix:
    raise SystemExit("Refusing to install wheels outside an isolated environment")
target = pathlib.Path(sysconfig.get_path("purelib"))
for name in ("ghidratrace-12.1-py3-none-any.whl", "protobuf-6.31.0-py3-none-any.whl"):
    with zipfile.ZipFile(pathlib.Path(sys.argv[1]) / name) as archive:
        for member in archive.infolist():
            path = pathlib.PurePosixPath(member.filename)
            if path.is_absolute() or ".." in path.parts or any(p.endswith(".data") for p in path.parts) or (member.external_attr >> 16) & 0o170000 == 0o120000:
                raise SystemExit("Unsupported or unsafe wheel layout: " + member.filename)
        archive.extractall(target)
'''


def prepare_environment(python, destination, wheels):
    from pathlib import Path
    check_runtime(python)
    subprocess.run([str(python), '-m', 'venv', '--without-pip', str(destination)], check=True, stdout=subprocess.DEVNULL)
    executable = Path(destination) / 'bin/python'
    subprocess.run([str(executable), '-c', WHEEL_INSTALL, str(wheels)], check=True)
    subprocess.run([str(executable), '-c', 'import ghidratrace.client, google.protobuf; from importlib.metadata import version; assert version("ghidratrace")=="12.1"; assert version("protobuf")=="6.31.0"'], check=True)
    return executable
