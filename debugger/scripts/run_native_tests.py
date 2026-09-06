#!/usr/bin/env python3
"""Run selected backend lanes without importing unselected adapter tests."""
import os
from pathlib import Path
import sys
import unittest

root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
sys.path.insert(0,str(root/'python'))
sys.path.insert(0,str(root/'tests'))
from ghigbc.backend import available_backends

installed=available_backends()
choice=os.environ.get('GBC_TEST_BACKENDS')
selected=tuple(choice.split(',')) if choice else installed if (root/'runtime-backends.json').exists() else ('sameboy',)
if not selected or len(set(selected))!=len(selected) or any(name not in installed for name in selected):
    raise SystemExit('Select installed test lanes with GBC_TEST_BACKENDS=sameboy,mgba')
names=[]
for path in sorted((root/'tests').glob('test_*.py')):
    if path.name=='test_mgba.py' and 'mgba' not in selected:continue
    if 'sameboy' not in selected and path.name not in ('test_mgba.py','test_package_selection.py'):continue
    names.append(path.stem)
print('Selected native test backends: '+', '.join(selected),flush=True)
suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in names)
raise SystemExit(0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1)
