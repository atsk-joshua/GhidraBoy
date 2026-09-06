import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import native_dependency_update as update


class CopyUpdateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.compiled.cleanup)
        root = Path(cls.compiled.name)
        compiler = shutil.which("clang") or shutil.which("cc")
        if not compiler:
            raise unittest.SkipTest("A C compiler is required for native startup/cancellation tests")
        cls.binaries = []
        for tag in (1, 2, 3):
            source, output = root / (str(tag) + ".c"), root / str(tag)
            bytes_c = ",".join(str(value) for value in update.PROBE_OUTPUT)
            source.write_text("#include <stdio.h>\nint main(void){volatile int tag=" + str(tag) + ";unsigned char response[]={" + bytes_c + "};if(tag==3)return 0;fwrite(response,1,sizeof(response),stdout);return 1;}\n")
            subprocess.run([compiler, str(source), "-o", str(output)], check=True, capture_output=True)
            cls.binaries.append(output.read_bytes())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        (self.source / "Ghidra").mkdir(parents=True)
        (self.source / "Ghidra/application.properties").write_text("application.version=12.1.3\n")
        self.relative = "Ghidra/Features/Decompiler/os/" + update.host_target() + "/decompile"
        native = self.source / self.relative
        native.parent.mkdir(parents=True)
        native.write_bytes(self.binaries[0])
        native.chmod(0o755)
        (self.source / "student-note.txt").write_text("preserve this note")
        self.package, self.sha = self.make_package()
        self.loaded = update.read_package(self.package, self.sha)

    def make_package(self, variant="good", extra=None):
        native = self.binaries[2 if variant == "bad-startup" else 1]
        identity = {"schema": "ghidraboy-native-dependency-identity-v1", "officialNative": False,
                    "baseGhidraVersion": update.BASE, "nativeDependencyVersion": update.DEPENDENCY,
                    "patchSha256": update.PATCH_SHA256, "sourceLockSha256": update.SOURCE_LOCK_SHA256,
                    "platform": update.host_target(), "binarySha256": update.digest_bytes(native)}
        marker = json.dumps(identity, sort_keys=True).encode()
        rollback = {"schema": "ghidraboy-native-rollback-v1", "path": self.relative,
                    "baseGhidraVersion": update.BASE, "nativeDependencyVersion": update.DEPENDENCY,
                    "originalExisted": True, "originalSha256": update.digest_bytes(self.binaries[0]),
                    "expectedInstalledSha256": update.digest_bytes(native), "backup": "rollback/decompile.original",
                    "identityMarker": {"path": update.MARKER, "originalExisted": False, "originalSha256": None,
                                       "expectedInstalledSha256": update.digest_bytes(marker)}}
        build = {"status": "PASS_LOCAL_NATIVE_GATES", "nativeBinarySha256": update.digest_bytes(native),
                 "nativeDependencyVersion": update.DEPENDENCY, "platform": update.host_target()}
        repo = Path(__file__).resolve().parents[1]
        members = {self.relative: native, update.MARKER: marker, "native-dependency.json": marker,
                   "rollback.json": json.dumps(rollback).encode(), "build.json": json.dumps(build).encode(),
                   "rollback/decompile.original": self.binaries[0],
                   "ghidra-12.1.3-switch-recovery-2.patch": (repo / "tools/patches/ghidra-12.1.3-switch-recovery-2.patch").read_bytes(),
                   "ghidra-12.1.3-decompiler-source.json": (repo / "tools/patches/ghidra-12.1.3-decompiler-source.json").read_bytes()}
        package = self.root / (variant + ".zip")
        with zipfile.ZipFile(package, "w") as archive:
            for name, data in members.items():
                info = zipfile.ZipInfo(name)
                info.external_attr = (0o100755 if name in (self.relative, "rollback/decompile.original") else 0o100644) << 16
                archive.writestr(info, data)
            if extra:
                info = zipfile.ZipInfo(extra[0])
                info.external_attr = extra[1] << 16
                archive.writestr(info, b"untrusted")
        return package, update.digest(package)

    def test_install_verify_rollback_preserve_source_and_unmanaged_edits(self):
        original = update.tree_snapshot(self.source)
        bundle = self.root / "installed"
        receipt = update.update("install", self.source, bundle, self.loaded)
        self.assertTrue(receipt["runtime"]["runnableNative"])
        self.assertEqual(original, update.tree_snapshot(self.source))
        installed = bundle / "distribution"
        self.assertEqual("VERIFIED_PATCHED_COPY", update.verify(installed, self.loaded)["status"])
        (installed / "student-note.txt").write_text("new student edit")
        changed = update.tree_snapshot(installed)
        restored = self.root / "restored"
        update.update("rollback", installed, restored, self.loaded)
        self.assertEqual(changed, update.tree_snapshot(installed))
        self.assertEqual(self.binaries[0], (restored / "distribution" / self.relative).read_bytes())
        self.assertFalse((restored / "distribution" / update.MARKER).exists())
        self.assertEqual("new student edit", (restored / "distribution/student-note.txt").read_text())

    def test_each_staged_cancellation_leaves_no_half_update(self):
        for mode in ("install", "rollback"):
            source = self.source
            if mode == "rollback":
                update.update("install", self.source, self.root / "seed", self.loaded)
                source = self.root / "seed/distribution"
            baseline = update.tree_snapshot(source)
            for point in ("after-first-file", "before-publish"):
                output = self.root / (mode + point)
                with self.assertRaises(update.Cancelled):
                    update.update(mode, source, output, self.loaded, point)
                self.assertFalse(output.exists())
                self.assertEqual(baseline, update.tree_snapshot(source))
                self.assertEqual([], list(self.root.glob(".ghidraboy-native-stage-*")))

    def test_edited_binary_or_marker_is_refused_without_overwrite(self):
        update.update("install", self.source, self.root / "seed", self.loaded)
        source = self.root / "seed/distribution"
        for relative in (self.relative, update.MARKER):
            path = source / relative
            original = path.read_bytes()
            path.write_bytes(original + b"student edit")
            edited = update.tree_snapshot(source)
            with self.assertRaises(ValueError):
                update.update("rollback", source, self.root / "refused", self.loaded)
            self.assertEqual(edited, update.tree_snapshot(source))
            self.assertFalse((self.root / "refused").exists())
            path.write_bytes(original)

    def test_runtime_failure_prevents_publication(self):
        path, checksum = self.make_package("bad-startup")
        package = update.read_package(path, checksum)
        before = update.tree_snapshot(self.source)
        with self.assertRaises(ValueError):
            update.update("install", self.source, self.root / "bad-runtime", package)
        self.assertFalse((self.root / "bad-runtime").exists())
        self.assertEqual(before, update.tree_snapshot(self.source))

    def test_zip_paths_links_duplicates_and_untrusted_digest_are_rejected(self):
        cases = [("../escape", 0o100644), ("/absolute", 0o100644), ("a\\b", 0o100644),
                 ("link", 0o120777), ("native-dependency.json", 0o100644)]
        for index, case in enumerate(cases):
            package, checksum = self.make_package("unsafe" + str(index), case)
            with self.assertRaises(ValueError):
                update.read_package(package, checksum)
        with self.assertRaises(ValueError):
            update.read_package(self.package, "0" * 64)

    def test_interrupt_after_atomic_rename_reports_complete_pair(self):
        original_publish = update.publish_exclusive
        def publish_then_interrupt(source, destination):
            original_publish(source, destination)
            raise KeyboardInterrupt()
        with patch.object(update, "publish_exclusive", publish_then_interrupt):
            result = update.update("install", self.source, self.root / "interrupted-commit", self.loaded)
        self.assertTrue(result["interruptedAfterPublication"])
        update.require_state(self.root / "interrupted-commit/distribution", self.loaded["after"])
        self.assertEqual([], list(self.root.glob(".ghidraboy-native-stage-*")))

    def test_atomic_publication_never_overwrites_an_existing_empty_directory(self):
        stage, destination = self.root / "staged", self.root / "racing-output"
        stage.mkdir()
        (stage / "new").write_text("staged")
        destination.mkdir()
        with self.assertRaises(OSError):
            update.publish_exclusive(stage, destination)
        self.assertTrue((stage / "new").exists())
        self.assertEqual([], list(destination.iterdir()))


if __name__ == "__main__":
    unittest.main()
