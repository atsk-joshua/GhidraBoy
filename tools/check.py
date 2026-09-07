#!/usr/bin/env python3
"""Explicit inexpensive Python suites; native and installed checks stay opt-in."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--suite', choices=['all', 'tools', 'build-inputs', 'debugger-pure'], default='all')
args = parser.parse_args()
env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
           PYTHONPATH=os.pathsep.join(str(root / p) for p in ('debugger', 'debugger/python', 'debugger/tests')))
suites = {
    'tools': [['discover', '-s', 'tools', '-p', 'test_*.py', '-v']],
    'build-inputs': [['discover', '-s', 'debugger/tests/build_tools', '-v']],
    'debugger-pure': [['-v', 'test_dispatch', 'test_mapping', 'test_deck_handoff',
                      'test_runtime_python', 'test_package_selection']],
}
for name, commands in suites.items():
    if args.suite in ('all', name):
        for command in commands:
            subprocess.run([sys.executable, '-m', 'unittest', *command], cwd=root, env=env, check=True)
if args.suite == 'all':
    for directory in ('debugger/scripts', '.github/scripts'):
        for path in sorted((root / directory).glob('*.sh')):
            subprocess.run(['bash', '-n', str(path)], check=True)
