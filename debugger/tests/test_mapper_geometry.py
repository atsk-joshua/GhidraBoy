"""Advertised mapper geometry boundaries on real SameBoy; synthetic cartridges only.

These inspect selector/bounds behavior, not boot correctness or physical hardware.
The separate boot/device suites qualify actual DMG/CGB operating modes.
"""
from pathlib import Path
import tempfile
import unittest

from ghigbc.backends.sameboy import Machine, ROOT


class MapperGeometryTests(unittest.TestCase):
    def cartridge(self, directory, kind, banks, ram, model):
        image = bytearray(banks * 0x4000)
        image[:0x150] = (ROOT / 'build/teaching.gbc').read_bytes()[:0x150]
        image[0x143] = 0 if model == 'DMG-B' else 0x80
        image[0x147:0x14a] = bytes((kind, banks.bit_length() - 2, ram))
        for bank in range(banks):
            image[bank * 0x4000 + 0x200:bank * 0x4000 + 0x202] = bank.to_bytes(2, 'little')
        path = Path(directory) / 'geometry.gb'
        path.write_bytes(image)
        return path

    def write(self, machine, address, value):
        self.assertEqual(machine.lib.gc_edit_memory(machine.handle, address, value), 0)

    def select(self, machine, family, bank):
        if family == 'MBC1':
            self.write(machine, 0x6000, 0)
            self.write(machine, 0x4000, bank >> 5)
            self.write(machine, 0x2000, bank & 31)
        elif family == 'MBC2':
            self.write(machine, 0x2100, bank)
        elif family == 'MBC3':
            self.write(machine, 0x2000, bank)
        elif family == 'MBC5':
            self.write(machine, 0x2000, bank & 255)
            self.write(machine, 0x3000, bank >> 8)

    def test_rom_geometries_select_last_bank_and_reject_physical_overrun(self):
        rows = [('ROM-only', 0, 2), ('MBC1', 1, 128), ('MBC2', 5, 16),
                ('MBC3', 0x11, 128), ('MBC5', 0x19, 512)]
        count = 0
        with tempfile.TemporaryDirectory() as directory:
            for model in ('DMG-B', 'CGB-E'):
                for family, kind, maximum in rows:
                    for exponent in range(1, maximum.bit_length()):
                        banks = 1 << exponent
                        with self.subTest(model=model, family=family, banks=banks):
                            # SameBoy detects a 32K type-11 image as MMM01; use a
                            # non-ambiguous MBC3+RAM header for the 32K geometry.
                            actual_kind = 0x13 if family == 'MBC3' and banks == 2 else kind
                            ram = 2 if actual_kind == 0x13 else 0
                            rom = self.cartridge(directory, actual_kind, banks, ram, model)
                            with Machine(rom, model=model) as machine:
                                self.write(machine, 0xff50, 1)
                                self.select(machine, family, banks - 1)
                                capture = machine.capture()
                                self.assertEqual(capture.state['romx'], banks - 1)
                                self.assertEqual(int.from_bytes(capture.cpu_bytes[0x4200:0x4202], 'little'), banks - 1)
                                machine.breakpoint('rom', banks - 1, 0x3fff)
                                for bank, offset, length in ((banks, 0, 1), (banks - 1, 0x3fff, 2)):
                                    with self.assertRaises(ValueError):
                                        machine.breakpoint('rom', bank, offset, length=length)
                                if family != 'ROM-only':
                                    self.select(machine, family, 0)
                                    self.assertEqual(machine.capture().state['romx'], 0 if family == 'MBC5' else 1)
                                count += 1
        print('MAPPER_GEOMETRY_ROWS', count)

    def test_detected_controller_fallback_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            # Core content heuristics reinterpret these nominally accepted headers.
            # They must not be advertised with the original, incorrect mapper name.
            for kind, banks in ((0x11, 2), (0, 4)):
                with self.subTest(kind=kind, banks=banks):
                    rom = self.cartridge(directory, kind, banks, 0, 'CGB-E')
                    with self.assertRaisesRegex(RuntimeError, 'mapper unsupported'):
                        Machine(rom)

    def test_ram_bank_edges_and_disabled_visibility(self):
        # Maximum standard non-rumble configurations plus supported smaller RAM geometries.
        with tempfile.TemporaryDirectory() as directory:
            configurations = [('MBC1', 3, [(1, 2048), (2, 8192), (3, 32768)]),
                              ('MBC3', 0x13, [(1, 2048), (2, 8192), (3, 32768)]),
                              ('MBC5', 0x1b, [(1, 2048), (2, 8192), (3, 32768), (5, 65536), (4, 131072)]),
                              ('MBC5-rumble', 0x1e, [(2, 8192), (3, 32768), (5, 65536)])]
            for family, kind, geometries in configurations:
                for ram_code, size in geometries:
                    with self.subTest(family=family, ram=size):
                        rom = self.cartridge(directory, kind, 4, ram_code, 'CGB-E')
                        with Machine(rom) as machine:
                            self.write(machine, 0xff50, 1)
                            self.write(machine, 0, 0x0a)
                            if family == 'MBC1':
                                self.write(machine, 0x6000, 1)
                            last = (size + 8191) // 8192 - 1
                            offset = (size - 1) % 8192
                            self.write(machine, 0x4000, last)
                            self.write(machine, 0xa000 + offset, 0x6d)
                            capture = machine.capture()
                            self.assertEqual(capture.state['cart_size'], size)
                            self.assertEqual(capture.bank_bytes('cart', last)[-1], 0x6d)
                            self.assertEqual(capture.cpu_bytes[0xa000 + offset], 0x6d)
                            machine.breakpoint('cart', last, offset)
                            with self.assertRaises(ValueError):
                                machine.breakpoint('cart', last, offset + 1)
                            with self.assertRaises(ValueError):
                                machine.breakpoint('cart', last + 1, 0)
                            self.write(machine, 0, 0)
                            self.assertIn((0xa000, 8192), machine.capture().unknown_cpu_ranges)

    def test_svbk_zero_alias_echo_and_vram_bank_separation(self):
        with Machine(ROOT / 'build/teaching.gbc') as machine:
            self.write(machine, 0xff50, 1)
            self.write(machine, 0xff40, 0)  # LCD off: make CPU VRAM writes available.
            for bank in range(8):
                self.write(machine, 0xff70, bank)
                self.write(machine, 0xdfff, 0x40 + bank)
                capture = machine.capture()
                self.assertEqual(capture.state['wram'], bank or 1)
                self.assertEqual(capture.cpu_bytes[0xdfff], 0x40 + bank)
                self.write(machine, 0xf034, 0x80 + bank)
                capture = machine.capture()
                self.assertEqual(capture.cpu_bytes[0xd034], 0x80 + bank)
                self.assertEqual(capture.bank_bytes('wram', bank or 1)[0x34], 0x80 + bank)
            for bank in range(2):
                self.write(machine, 0xff4f, bank)
                self.write(machine, 0x9fff, 0xa0 + bank)
            capture = machine.capture()
            self.assertEqual(capture.bank_bytes('vram', 0)[-1], 0xa0)
            self.assertEqual(capture.bank_bytes('vram', 1)[-1], 0xa1)


if __name__ == '__main__':
    unittest.main()
