"""Architecture checks for the production boundary, separate from runtime fixtures."""
import ast
from pathlib import Path
import unittest


class BackendBoundaryTests(unittest.TestCase):
    def test_generic_modules_do_not_access_emulator_bindings(self):
        root=Path(__file__).resolve().parents[2]/'python/ghigbc'
        for name in ('agent.py','display.py','session.py','profile.py','mapping.py'):
            with self.subTest(module=name):
                tree=ast.parse((root/name).read_text())
                for node in ast.walk(tree):
                    if isinstance(node,ast.ImportFrom):
                        self.assertNotIn(node.module,('native','backends.sameboy'))
                    if isinstance(node,ast.Attribute):
                        self.assertNotIn(node.attr,('handle','lib'))

    def test_native_adapter_sources_have_one_backend_home(self):
        root=Path(__file__).resolve().parents[2]
        self.assertFalse((root/'native').exists())
        adapter=root/'backends/sameboy/native'
        self.assertTrue((adapter/'ghigbc.c').is_file())
        self.assertTrue((adapter/'ghigbc.h').is_file())
        self.assertTrue((adapter/'patches/0001-cpu-bus-provenance.patch').is_file())
