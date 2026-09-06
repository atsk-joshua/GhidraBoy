from pathlib import Path
import tempfile
import unittest

from build_native_decompiler import digest, native_binary_kind, platform_settings, require_pristine


class NativeBuildGuardsTest(unittest.TestCase):
    def test_pristine_source_rejects_patch_reapplication_and_extra_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "jumptable.cc"
            source.write_text("pinned source")
            lock = {"files": {"jumptable.cc": digest(source)}}
            self.assertEqual(lock["files"], require_pristine(root, lock))
            source.write_text("patched source")
            with self.assertRaises(ValueError):
                require_pristine(root, lock)
            source.write_text("pinned source")
            (root / "surprise.cc").write_text("unreviewed code")
            with self.assertRaises(ValueError):
                require_pristine(root, lock)

    def test_platform_fails_closed_for_unvalidated_architecture(self):
        self.assertEqual("mac_arm_64", platform_settings("Darwin", "arm64")[0])
        self.assertEqual("linux_x86_64", platform_settings("Linux", "x86_64")[0])
        with self.assertRaises(ValueError):
            platform_settings("Linux", "aarch64")

    def test_packaging_cannot_mistake_host_binary_for_target(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "native"
            header = bytearray(64)
            header[:6] = b"\x7fELF\x02\x01"
            header[18:20] = (62).to_bytes(2, "little")
            binary.write_bytes(header)
            self.assertTrue(native_binary_kind(binary, "linux_x86_64"))
            self.assertFalse(native_binary_kind(binary, "mac_arm_64"))
            header[18:20] = (183).to_bytes(2, "little")
            binary.write_bytes(header)
            self.assertFalse(native_binary_kind(binary, "linux_x86_64"))


if __name__ == "__main__":
    unittest.main()
