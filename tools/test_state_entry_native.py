"""Self-authored package/lifecycle checks; these do not execute a fake native binary."""
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import native_dependency_update as base
import state_entry_native as state


class StateEntryNativeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = bytes.fromhex("cffaedfe0c000001") + b"self-authored-format-fixture"
        self.identity = {
            "schema": state.SCHEMA, "protocol": state.PROTOCOL, "callingConvention": state.CONVENTION,
            "baseGhidraVersion": state.BASE_VERSION, "nativeDependencyVersion": state.VERSION,
            "baseDependencyVersion": base.DEPENDENCY, "platform": state.TARGET,
            "statePatchSha256": state.PATCH_SHA256, "switchPatchSha256": base.PATCH_SHA256,
            "sourceLockSha256": base.SOURCE_LOCK_SHA256, "officialNative": False,
            "binarySha256": hashlib.sha256(self.binary).hexdigest(),
            "patchedSourcesSha256": hashlib.sha256(b"{}").hexdigest(),
        }
        switch, lock = state.inputs()
        self.files = {
            state.BINARY: self.binary,
            state.MARKER: json.dumps(self.identity).encode(),
            "build.json": json.dumps({"status": state.BUILD_STATUS, "identity": self.identity,
                                      "patchedSources": {}, "semanticQualification": "UNRUN"}).encode(),
            "state-entry.patch": state.PATCH.read_bytes(), "switch-recovery.patch": switch.read_bytes(),
            "pristine-source-lock.json": lock.read_bytes(), "LICENSE": b"self-authored license fixture",
            "Decompiler-LICENSE.txt": b"self-authored decompiler notice fixture",
        }

    def package(self, files=None, special=None):
        path = self.root / "package.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in (self.files if files is None else files).items():
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFREG | (0o755 if name == state.BINARY else 0o644)) << 16
                if name == special:
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, data)
        return path, base.digest(path)

    def source(self):
        root = self.root / "source"
        (root / "Ghidra").mkdir(parents=True)
        (root / "Ghidra/application.properties").write_text("application.version=12.1.3\n")
        binary = root / state.BINARY
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"preserve exact prior binary")
        binary.chmod(0o755)
        (root / base.MARKER).write_text("preserve exact prior switch marker")
        (root / "saved-user-note").write_text("Do not change")
        return root

    def test_reviewed_pins_and_exact_protocol_are_enforced(self):
        state.validate_identity(self.identity)
        self.assertEqual("__ghidraboy_state_entry_v1", state.PROTOCOL)
        for field in ("protocol", "platform", "statePatchSha256", "baseDependencyVersion"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                state.validate_identity(dict(self.identity, **{field: "different"}))

    def test_package_requires_trusted_outer_hash_and_matching_executable(self):
        path, digest = self.package()
        package = state.read_package(path, digest)
        self.assertEqual(self.binary, package["files"][state.BINARY])
        with self.assertRaisesRegex(ValueError, "trusted expected"):
            state.read_package(path, "0" * 64)
        path, digest = self.package(dict(self.files, **{state.BINARY: self.binary + b"tampered"}))
        with self.assertRaisesRegex(ValueError, "payload hashes"):
            state.read_package(path, digest)

    def test_package_rejects_symlinks_and_path_escape(self):
        path, digest = self.package(special=state.BINARY)
        with self.assertRaises(ValueError):
            state.read_package(path, digest)
        files = dict(self.files)
        files["../outside"] = files.pop("LICENSE")
        path, digest = self.package(files)
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            state.read_package(path, digest)

    def test_build_receipt_cannot_claim_unexecuted_qualification(self):
        files = dict(self.files)
        receipt = json.loads(files["build.json"])
        receipt["semanticQualification"] = "PASS"
        files["build.json"] = json.dumps(receipt).encode()
        path, digest = self.package(files)
        with self.assertRaisesRegex(ValueError, "unqualified build receipt"):
            state.read_package(path, digest)

    def test_patch_source_receipt_is_a_consumed_identity(self):
        files = dict(self.files)
        receipt = json.loads(files["build.json"])
        receipt["patchedSources"] = {"flow.cc": {"sha256": "0" * 64}}
        files["build.json"] = json.dumps(receipt).encode()
        path, digest = self.package(files)
        with self.assertRaisesRegex(ValueError, "Patched-source receipt"):
            state.read_package(path, digest)

    def test_copy_install_preserves_source_and_backs_up_retired_marker(self):
        source = self.source()
        before = base.tree_snapshot(source)
        path, digest = self.package()
        destination = self.root / "new-bundle"
        with patch.object(state, "require_host"), patch.object(base, "native_probe", return_value={"scope": "mocked startup"}):
            state.install(source, destination, state.read_package(path, digest))
        self.assertEqual(before, base.tree_snapshot(source))
        self.assertEqual(b"preserve exact prior binary", (destination / "original" / state.BINARY).read_bytes())
        self.assertEqual("preserve exact prior switch marker", (destination / "original" / base.MARKER).read_text())
        copied = destination / "distribution"
        self.assertFalse((copied / base.MARKER).exists())
        self.assertEqual("Do not change", (copied / "saved-user-note").read_text())
        self.assertEqual("VERIFIED_BYTES_ONLY", state.verify(copied)["status"])
        with patch.object(state, "require_host"), self.assertRaisesRegex(ValueError, "new independent"):
            state.install(source, destination, state.read_package(path, digest))
        (copied / state.BINARY).write_bytes(self.binary + b"changed")
        with self.assertRaisesRegex(ValueError, "capability marker"):
            state.verify(copied)

    def test_failed_startup_publishes_nothing_and_preserves_source(self):
        source = self.source()
        before = base.tree_snapshot(source)
        path, digest = self.package()
        with patch.object(state, "require_host"), patch.object(base, "native_probe", side_effect=ValueError("startup failed")):
            with self.assertRaisesRegex(ValueError, "startup failed"):
                state.install(source, self.root / "failed", state.read_package(path, digest))
        self.assertFalse((self.root / "failed").exists())
        self.assertFalse(list(self.root.glob(".state-entry-native-*")))
        self.assertEqual(before, base.tree_snapshot(source))

    def test_distribution_links_are_rejected_without_copy_publication(self):
        source = self.source()
        (source / "linked-note").symlink_to(source / "saved-user-note")
        path, digest = self.package()
        with patch.object(state, "require_host"), self.assertRaisesRegex(ValueError, "links/special"):
            state.install(source, self.root / "rejected", state.read_package(path, digest))
        self.assertFalse((self.root / "rejected").exists())

    def test_build_rejects_changed_pristine_source_before_creating_work(self):
        source = self.source()
        (source / state.SOURCE).mkdir(parents=True)
        (source / state.SOURCE / "flow.cc").write_text("not the pinned native source")
        jdk = self.root / "jdk"
        (jdk / "bin").mkdir(parents=True)
        (jdk / "bin/javac").write_text("never executed")
        (jdk / "release").write_text('JAVA_VERSION="21.0.12"\n')
        work = self.root / "must-not-be-created"
        with patch.object(state, "require_host"), self.assertRaisesRegex(ValueError, "pinned pristine"):
            state.build(source, jdk, work)
        self.assertFalse(work.exists())

    def test_wrong_host_does_not_gain_support_from_binary_format(self):
        with patch.object(state.platform, "system", return_value="Linux"), patch.object(state.platform, "machine", return_value="x86_64"):
            with self.assertRaisesRegex(ValueError, "Only macOS arm64"):
                state.require_host()


if __name__ == "__main__":
    unittest.main()
