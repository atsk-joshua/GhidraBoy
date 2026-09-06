import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('runtime_python', Path(__file__).resolve().parents[1]/'scripts/runtime_python.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)

class RuntimePythonTests(unittest.TestCase):
    def test_existing_interpreter_passes_capability_probe(self):
        self.assertEqual(runtime.check_runtime(sys.executable)['version'], sys.version.split()[0])

    def test_old_and_new_patch_versions_are_not_allowlisted(self):
        for version in ('3.9.6', '3.11.2', '3.13.0', '3.13.7', '3.15.0'):
            result = subprocess.CompletedProcess([], 0, json.dumps({'version': version, 'executable': '/usr/bin/python3'}), '')
            with patch.object(runtime.subprocess, 'run', return_value=result):
                self.assertEqual(runtime.check_runtime('/usr/bin/python3')['version'], version)

    def test_missing_capability_is_reported_without_replacing_python(self):
        failure = subprocess.CompletedProcess([], 1, '', 'Existing Python is missing a required capability: ctypes')
        with patch.object(runtime.subprocess, 'run', return_value=failure):
            with self.assertRaisesRegex(ValueError, 'ctypes'):
                runtime.check_runtime('/usr/bin/python3')

    def test_dependency_minimum_is_the_only_version_floor(self):
        result = subprocess.run([sys.executable, '-c', 'import sys; sys.version_info=(3,8,20);\n'+runtime.PROBE], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('bundled Ghidra wheels', result.stderr)

    def test_wheel_install_refuses_the_system_environment(self):
        result = subprocess.run([sys.executable, '-c', 'import sys; sys.prefix=sys.base_prefix;\n'+runtime.WHEEL_INSTALL, '/nonexistent-wheels'], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('outside an isolated environment', result.stderr)
