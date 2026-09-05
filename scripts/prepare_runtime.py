#!/usr/bin/env python3
"""Prepare matched Python dependencies for a prebuilt platform bundle, offline from Ghidra."""
import os,subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
ghidra=Path(os.environ['GHIDRA_INSTALL_DIR'])
properties=dict(line.split('=',1) for line in (ghidra/'Ghidra/application.properties').read_text().splitlines() if '=' in line and not line.startswith('#'))
if properties.get('application.version')!='12.1.2':raise SystemExit('Ghidra 12.1.2 required')
if sys.version_info<(3,10):raise SystemExit('Use Python 3.10–3.14')
subprocess.run([sys.executable,'-m','venv',str(root/'.venv12')],check=True)
python=root/'.venv12/bin/python'
subprocess.run([str(python),'-m','pip','install','--no-index','--find-links',str(ghidra/'Ghidra/Debug/Debugger-rmi-trace/pypkg/dist'),'ghidratrace==12.1','protobuf==6.31.0'],check=True)
env=dict(os.environ,PYTHONPATH=str(root/'python'))
subprocess.run([str(python),'-c','from ghigbc.native import Machine,ROOT; m=Machine(ROOT/"build/teaching.gbc"); print(dict(m.capture().state)); m.close()'],env=env,check=True)
print('Native loading and Python environment ready. Run scripts/test_native.sh, scripts/test_ghidra.sh and scripts/install.py.')
