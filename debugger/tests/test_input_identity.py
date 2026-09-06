"""Exercise file replacement at the actual Python/native load boundary."""
import ctypes
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ghigbc.native import Machine, ROOT


class InputIdentityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=ROOT / '.local')
        self.addCleanup(self.directory.cleanup)
        self.rom = Path(self.directory.name) / 'fixture.gbc'
        self.boot = Path(self.directory.name) / 'boot.bin'
        self.rom_bytes = (ROOT / 'build/teaching.gbc').read_bytes()
        self.boot_bytes = (ROOT / '.deps/SameBoy/build/bin/BootROMs/cgb_boot.bin').read_bytes()
        self.rom.write_bytes(self.rom_bytes)
        self.boot.write_bytes(self.boot_bytes)

    def test_native_load_uses_the_hashed_input_copies(self):
        load_library = ctypes.CDLL

        def replace_files_before_native_load(*args, **kwargs):
            changed_rom = bytearray(self.rom_bytes)
            changed_rom[0x402a] ^= 0xff
            self.rom.write_bytes(changed_rom)
            changed_boot = bytearray(self.boot_bytes)
            changed_boot[0] ^= 0xff
            self.boot.write_bytes(changed_boot)
            return load_library(*args, **kwargs)

        # Keep the real native library and emulator. Only the timing of an external
        # file replacement is controlled, immediately after Python's reads.
        with patch('ghigbc.native.C.CDLL', side_effect=replace_files_before_native_load):
            with Machine(self.rom, boot=self.boot) as machine:
                capture = machine.capture()
                self.assertEqual(machine.rom_hash, hashlib.sha256(self.rom_bytes).hexdigest())
                self.assertEqual(capture.memory[0x402a], self.rom_bytes[0x402a])
                self.assertEqual(capture.memory[0], self.boot_bytes[0])

    def test_checkpoint_identifies_loaded_boot_not_current_file(self):
        with Machine(self.rom, boot=self.boot) as machine:
            self.boot.write_bytes(bytes(len(self.boot_bytes)))
            checkpoint = Path(self.directory.name) / 'checkpoint'
            machine.checkpoint(checkpoint)
            metadata = json.loads((checkpoint / 'metadata.json').read_text())
            self.assertEqual(metadata['boot_hash'], hashlib.sha256(self.boot_bytes).hexdigest())
            self.boot.unlink()
            machine.restore(checkpoint)
        self.boot.write_bytes(bytes(len(self.boot_bytes)))
        with Machine(self.rom, boot=self.boot) as different_boot:
            with self.assertRaisesRegex(ValueError, 'metadata mismatch'):
                different_boot.restore(checkpoint)
