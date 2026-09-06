"""Copy safety tests; set DEBUGGER_JAVA_PACKAGE to exercise a real pinned companion too."""
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import debugger_dependency_update as update

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'debugger/scripts'))
from build_inputs import runtime_dependencies, verify_debugger_java


class CopyJavaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'source'
        (self.source / update.JAR).parent.mkdir(parents=True)
        (self.source / 'Ghidra/application.properties').write_text('application.version=12.1.3\n')
        (self.source / 'student-note.txt').write_text('unchanged')
        self.files = {'rollback/Debugger.jar': b'original', 'Debugger.jar': b'patched'}
        for name, value in [('BASE_SHA', update.digest(b'original')), ('JAR_SHA', update.digest(b'patched'))]:
            mock = patch.object(update, name, value)
            mock.start()
            self.addCleanup(mock.stop)
        self.identity = dict(update.IDENTITY, baselineJarSha256=update.BASE_SHA, jarSha256=update.JAR_SHA)
        mock = patch.object(update, 'IDENTITY', self.identity)
        mock.start()
        self.addCleanup(mock.stop)
        (self.source / update.JAR).write_bytes(b'original')

    def test_copy_verify_rollback_and_source_unchanged(self):
        before = update.snapshot(self.source)
        update.update('install', self.source, self.root / 'installed', self.files)
        installed = self.root / 'installed/distribution'
        update.require_state(installed, True)
        self.assertEqual(update.snapshot(self.source), before)
        requirement = {k: v for k, v in self.identity.items() if k != 'schema'}
        self.assertEqual(verify_debugger_java(installed, requirement)['status'], 'MATCHED')
        (installed / 'student-note.txt').write_text('preserve user edit')
        changed = update.snapshot(installed)
        update.update('rollback', installed, self.root / 'restored', self.files)
        self.assertEqual(update.snapshot(installed), changed)
        restored = self.root / 'restored/distribution'
        update.require_state(restored, False)
        self.assertEqual((restored / 'student-note.txt').read_text(), 'preserve user edit')

    def test_runtime_verifier_resolves_selected_root_alias_but_rejects_internal_links(self):
        update.update('install', self.source, self.root / 'installed', self.files)
        installed = self.root / 'installed/distribution'
        requirement = {k: v for k, v in self.identity.items() if k != 'schema'}
        alias = self.root / 'selected-alias'
        alias.symlink_to(installed, target_is_directory=True)
        self.assertEqual(verify_debugger_java(alias, requirement)['status'], 'MATCHED')
        jar = installed / update.JAR
        external = self.root / 'external.jar'
        jar.rename(external)
        jar.symlink_to(external)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            verify_debugger_java(alias, requirement)

    def test_existing_output_overlap_and_symlinks_refused(self):
        existing = self.root / 'existing'
        existing.mkdir()
        link = self.root / 'linked'
        link.symlink_to(self.source, target_is_directory=True)
        for source, dest in [(self.source, existing), (self.source, self.source / 'child'),
                             (self.source, self.root), (link, self.root / 'copy'),
                             (self.source, link / 'child')]:
            with self.assertRaises(ValueError):
                update.update('install', source, dest, self.files)
        (self.source / 'note-link').symlink_to('student-note.txt')
        with self.assertRaises(ValueError):
            update.update('install', self.source, self.root / 'copy', self.files)
        self.assertFalse((self.root / 'copy').exists())

    def test_existing_output_race_is_not_overwritten(self):
        staged = self.root / 'stage'
        staged.mkdir()
        (staged / 'file').write_text('safe')
        existing = self.root / 'existing'
        existing.mkdir()
        with self.assertRaises(OSError):
            update.publish(staged, existing)
        self.assertEqual(list(existing.iterdir()), [])
        self.assertTrue((staged / 'file').exists())

    def test_unmatched_input_corruption_and_wrong_version_refused(self):
        (self.source / update.JAR).write_bytes(b'unmatched')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            update.update('install', self.source, self.root / 'out', self.files)
        (self.source / update.JAR).write_bytes(b'original')
        update.update('install', self.source, self.root / 'installed', self.files)
        installed = self.root / 'installed/distribution'
        requirement = {k: v for k, v in self.identity.items() if k != 'schema'}
        for relative in (update.JAR, update.MARKER):
            path = installed / relative
            original = path.read_bytes()
            path.write_bytes(original + b'corrupt')
            with self.assertRaises(ValueError):
                update.update('rollback', installed, self.root / 'rollback', self.files)
            with self.assertRaises(ValueError):
                verify_debugger_java(installed, requirement)
            self.assertFalse((self.root / 'rollback').exists())
            path.write_bytes(original)
        with self.assertRaisesRegex(ValueError, 'copy-only updater'):
            verify_debugger_java(self.source, requirement)
        with self.assertRaisesRegex(ValueError, 'rebuild the runtime package'):
            verify_debugger_java(installed, None)
        (self.source / 'Ghidra/application.properties').write_text('application.version=11.3.1\n')
        with self.assertRaisesRegex(ValueError, 'Expected Ghidra'):
            update.update('install', self.source, self.root / 'out', self.files)

    def test_copy_failure_does_not_publish_or_modify_source(self):
        original = update.snapshot(self.source)
        files = dict(self.files, **{'Debugger.jar': b'corrupt'})
        with self.assertRaises(ValueError):
            update.update('install', self.source, self.root / 'out', files)
        self.assertEqual(update.snapshot(self.source), original)
        self.assertFalse((self.root / 'out').exists())
        self.assertEqual(list(self.root.glob('.debugger-java-copy-*')), [])


class PinnedIdentityTests(unittest.TestCase):
    def test_canonical_requirement_matches_updater(self):
        root = Path(__file__).resolve().parents[1] / 'debugger'
        requirement = runtime_dependencies(root)['debugger_java']
        self.assertEqual(dict(requirement, schema='ghidraboy-debugger-java-dependency-v1'), update.IDENTITY)

    @unittest.skipUnless(os.environ.get('DEBUGGER_JAVA_PACKAGE'), 'Set DEBUGGER_JAVA_PACKAGE to validate real companion')
    def test_actual_pinned_package_and_repacked_corruption(self):
        path = Path(os.environ['DEBUGGER_JAVA_PACKAGE'])
        sha = os.environ['DEBUGGER_JAVA_PACKAGE_SHA256']
        files = update.read_package(path, sha)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / 'source'
            (source / update.JAR).parent.mkdir(parents=True)
            (source / 'Ghidra/application.properties').write_text('application.version=12.1.3\n')
            (source / update.JAR).write_bytes(files['rollback/Debugger.jar'])
            original = update.snapshot(source)
            update.update('install', source, root / 'installed', files)
            update.require_state(root / 'installed/distribution', True)
            update.update('rollback', root / 'installed/distribution', root / 'restored', files)
            self.assertEqual(update.snapshot(root / 'restored/distribution'), original)
            self.assertEqual(update.snapshot(source), original)
            bad = root / 'corrupt.zip'
            for name in ['Debugger.jar', 'rollback/Debugger.jar', update.PATCH_NAME, 'source/original.java', 'source/patched.java', 'dependency.json', 'rollback.json', 'build.json']:
                with zipfile.ZipFile(bad, 'w') as z:
                    for key, data in files.items():
                        z.writestr(key, data + b'corrupt' if key == name else data)
                with self.assertRaises(ValueError):
                    update.read_package(bad, update.digest(bad.read_bytes()))
            with self.assertRaises(ValueError):
                update.read_package(path, '0' * 64)
            for name in ['../escape', '/absolute', 'dependency.json']:
                with zipfile.ZipFile(bad, 'w') as z:
                    for key, data in files.items():
                        z.writestr(key, data)
                    z.writestr(name, b'extra')
                with self.assertRaises(ValueError):
                    update.read_package(bad, update.digest(bad.read_bytes()))


if __name__ == '__main__':
    unittest.main()
