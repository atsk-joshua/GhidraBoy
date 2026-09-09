"""Capture collection honors the configured output location without importing old reports."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


class OutputDestinationTests(unittest.TestCase):
    def test_collector_uses_configured_capture_directory_and_keeps_archive_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / 'package'
            scripts = root / 'scripts'
            scripts.mkdir(parents=True)
            shutil.copy2(Path(__file__).resolve().parents[1] / 'debugger/scripts/collect_results.py', scripts)
            capture = Path(directory) / 'captures'
            capture.mkdir()
            (capture / 'ui-actions.log').write_text('current capture')
            (capture / 'private.gb').write_bytes(b'private fixture')
            legacy = root / 'docs/evidence'
            legacy.mkdir(parents=True)
            (legacy / 'old.log').write_text('historical result')
            env = dict(os.environ, GBC_EVIDENCE_DIR=str(capture))
            result = subprocess.run([sys.executable, str(scripts / 'collect_results.py')],
                                    env=env, capture_output=True, text=True, check=True)
            archive = Path(result.stdout.strip())
            self.assertEqual(archive.parent, root / '.local/results')
            with zipfile.ZipFile(archive) as package:
                self.assertEqual(package.namelist(), ['evidence/ui-actions.log'])
                self.assertEqual(package.read('evidence/ui-actions.log'), b'current capture')
            self.assertEqual((legacy / 'old.log').read_text(), 'historical result')
