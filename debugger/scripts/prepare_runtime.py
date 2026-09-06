#!/usr/bin/env python3
"""Prepare matched Python dependencies for a prebuilt platform bundle, offline from Ghidra."""
import os,subprocess,sys
from pathlib import Path
from runtime_python import prepare_environment
root=Path(__file__).resolve().parents[1]
ghidra=Path(os.environ['GHIDRA_INSTALL_DIR'])
properties=dict(line.split('=',1) for line in (ghidra/'Ghidra/application.properties').read_text().splitlines() if '=' in line and not line.startswith('#'))
if properties.get('application.version')!='12.1.3':raise SystemExit('Ghidra 12.1.3 required')
python=prepare_environment(sys.executable,root/'.venv12',ghidra/'Ghidra/Debug/Debugger-rmi-trace/pypkg/dist')
env=dict(os.environ,PYTHONPATH=str(root/'python'))
subprocess.run([str(python),str(root/'scripts/runtime_probe.py')],env=env,check=True)
print('Selected native adapters and Python environment ready.')
