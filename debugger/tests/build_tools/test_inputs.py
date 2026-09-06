import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from scripts.build_inputs import artifact_inputs, runtime_dependencies, sha, verify_native_decompiler
from scripts.bootstrap import prepare_archive, prepare_source


class BuildInputTests(unittest.TestCase):
    def test_tool_extraction_preserves_files_behind_existing_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / '.deps/rgbds-bin'
            destination.mkdir(parents=True)
            outside = root / 'preserved.txt'
            outside.write_text('preserve')
            (destination / 'rgbasm').symlink_to(outside)
            archive = root / '.deps/tools.zip'
            with zipfile.ZipFile(archive, 'w') as zipped:
                zipped.writestr('rgbasm', b'replacement')
            with self.assertRaisesRegex(ValueError, 'Unsafe tool destination'):
                prepare_archive(root, archive.name, {'sha256': sha(archive)})
            self.assertEqual(outside.read_text(), 'preserve')

    def test_artifact_integrity_and_repository_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / 'artifact.jar'
            artifact.write_bytes(b'build output')
            entry = {'path': artifact.name, 'sha256': sha(artifact)}
            manifest = root / 'artifacts.json'
            data = {'schema': 1, 'components': {name: {'jar': entry, 'archive': entry}
                    for name in ('GhidraBoy', 'GhiGBC')}}
            manifest.write_text(json.dumps(data))
            self.assertEqual(artifact_inputs(root, manifest)[1]['GhidraBoy']['jar'], artifact.resolve())
            artifact.write_bytes(b'stale output')
            with self.assertRaisesRegex(ValueError, 'Stale'):
                artifact_inputs(root, manifest)
            entry.update(path='../artifact.jar', sha256=sha(artifact))
            manifest.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'escapes'):
                artifact_inputs(root, manifest)

    def test_dependency_view_is_derived_and_package_fallback_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            debugger = root / 'debugger'
            debugger.mkdir()
            (root / 'tools').mkdir()
            lock = root / 'tools/dependencies.json'
            lock.write_text(json.dumps({'primaryGhidra': {'version': 'test', 'sha256': 'digest'},
                'nativeDecompilerPatch': {'dependencyVersion': 'native-test', 'patchSha256': 'patch', 'pristineSourceLockSha256': 'sources'},
                'debuggerRuntime': {'sameboy': {'commit': 'revision'}}}))
            view = runtime_dependencies(debugger)
            self.assertEqual(view['ghidra']['version'], 'test')
            self.assertEqual(view['native_decompiler']['version'], 'native-test')
            (debugger / 'dependencies.lock.json').write_text(json.dumps(view))
            lock.unlink()
            self.assertEqual(runtime_dependencies(debugger), view)

    def test_native_marker_cannot_hide_wrong_platform_or_changed_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            ghidra = Path(directory)
            native = ghidra / 'Ghidra/Features/Decompiler'
            binary = native / 'os/mac_arm_64/decompile'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'fixture executable identity')
            requirement = dict(version='test', patchSha256='patch', sourceLockSha256='sources', baseGhidraVersion='base')
            with self.assertRaisesRegex(ValueError, 'Missing'):
                verify_native_decompiler(ghidra, requirement, 'macos-arm64')
            marker = native / 'ghidraboy-native-dependency.json'
            marker.write_text(json.dumps(dict(nativeDependencyVersion='test', patchSha256='patch', sourceLockSha256='sources',
                baseGhidraVersion='base', schema='ghidraboy-native-dependency-identity-v1', platform='mac_arm_64',
                officialNative=False, binarySha256=sha(binary))))
            self.assertEqual(verify_native_decompiler(ghidra, requirement, 'macos-arm64')['status'], 'MATCHED')
            with self.assertRaisesRegex(ValueError, 'identity'):
                verify_native_decompiler(ghidra, requirement, 'linux-x86_64')
            binary.write_bytes(b'changed executable')
            with self.assertRaisesRegex(ValueError, 'executable'):
                verify_native_decompiler(ghidra, requirement, 'macos-arm64')

    def test_source_verifier_rejects_extra_edits_inside_the_patched_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / '.deps/SameBoy'
            source.mkdir(parents=True)
            def git(*args):
                return subprocess.check_output(['git', '-C', str(source), *args], stderr=subprocess.DEVNULL)
            git('init')
            code = source / 'core.c'
            code.write_text('original\nunchanged\n')
            git('add', 'core.c')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'fixture')
            revision = git('rev-parse', 'HEAD').decode().strip()
            code.write_text('instrumented\nunchanged\n')
            patch = root / 'patch.diff'
            patch.write_bytes(git('diff'))
            git('checkout', '--', 'core.c')
            spec = dict(commit=revision, patch=patch.name, patch_sha256=sha(patch))
            prepare_source(root, spec)
            prepare_source(root, spec)  # Idempotent on the exact patched source.
            code.write_text('instrumented\nunrelated edit\n')
            with self.assertRaisesRegex(ValueError, 'beyond the pinned patch'):
                prepare_source(root, spec)
            self.assertIn('unrelated edit', code.read_text())
