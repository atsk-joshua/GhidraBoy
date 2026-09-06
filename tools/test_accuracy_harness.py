"""Negative diagnostic controls for the optional independent accuracy runner."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "accuracy_sameboy", Path(__file__).with_name("accuracy_sameboy.py"))
ACCURACY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACCURACY)


class AccuracyComparatorTests(unittest.TestCase):
    def test_changed_byte_beyond_chunk_boundary_reports_exact_position(self):
        with tempfile.TemporaryDirectory() as directory:
            left, right = Path(directory) / "left", Path(directory) / "right"
            original = b"\x00" * 65537 + b"\x42"
            left.write_bytes(original)
            right.write_bytes(original[:-1] + b"\x43")
            result = ACCURACY.compare_outputs(left, right)
            self.assertFalse(result["matches"])
            self.assertEqual(result["firstDifferenceOffset"], 65537)
            self.assertEqual((result["expectedByte"], result["actualByte"]), (0x42, 0x43))

    def test_truncated_and_missing_streams_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            left, right = Path(directory) / "left", Path(directory) / "right"
            left.write_bytes(b"state")
            self.assertFalse(ACCURACY.compare_outputs(left, right)["matches"])
            right.write_bytes(b"stat")
            result = ACCURACY.compare_outputs(left, right)
            self.assertFalse(result["matches"])
            self.assertEqual(result["firstDifferenceOffset"], 4)
            self.assertIsNone(result["actualByte"])
            right.write_bytes(b"state")
            self.assertEqual(ACCURACY.compare_outputs(left, right), {"matches": True, "bytesCompared": 5})
