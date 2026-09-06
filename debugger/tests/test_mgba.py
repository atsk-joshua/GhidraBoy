"""Native adapter integration; run under a subprocess watchdog in CI."""
import dataclasses
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import threading
import time
import unittest

from ghigbc.backend import Button, ROOT, UnsupportedFeature
from ghigbc.backends.mgba import Machine, PATCH_PATH


class MGBATests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def machine(self, code=b'\x00\x18\xfd', *, ram=False):
        # Self-authored CGB MBC5 image; entry jumps over its cartridge header.
        rom = bytearray(65536)
        rom[0x100:0x103] = b'\xc3\x50\x01'
        rom[0x143] = 0x80
        rom[0x147:0x14a] = bytes((0x1b if ram else 0x19, 1, 3 if ram else 0))
        rom[0x150:0x150 + len(code)] = code
        path = self.directory / ('fixture-' + str(len(list(self.directory.iterdir()))) + '.gbc')
        path.write_bytes(rom)
        machine = Machine(path)
        self.addCleanup(machine.close)
        machine.step()
        self.assertEqual(machine.capture().state['pc'], 0x150)
        return machine

    def test_model_boot_mapper_and_identity_rejections(self):
        for options in ({'model': 'DMG-B'}, {'model': 'CGB-E'}, {'boot': '/missing-bios'}):
            with self.assertRaises(UnsupportedFeature):
                Machine('/missing-rom', **options)
        machine = self.machine()
        wrong = self.directory / 'wrong.gbc'
        rom = bytearray(machine.rom_bytes)
        rom[0x147] = 1
        wrong.write_bytes(rom)
        with self.assertRaises(UnsupportedFeature):
            Machine(wrong)
        library = Path(machine.lib._name)
        copied = self.directory / library.name
        shutil.copyfile(library, copied)
        receipt = json.loads(Path(str(library) + '.json').read_text())
        receipt['binarySha256'] = '0' * 64
        Path(str(copied) + '.json').write_text(json.dumps(receipt))
        with self.assertRaisesRegex(RuntimeError, 'build identity mismatch'):
            Machine(machine.rom, library=copied)

    def test_paused_capture_is_frozen_and_nondestructive(self):
        machine = self.machine()
        before = machine._diagnostic_state()
        capture = machine.capture()
        for _ in range(5):
            machine.capture()
            machine.frame()
        self.assertEqual(before, machine._diagnostic_state())
        self.assertEqual(capture.stop_reason, 'step')
        self.assertEqual(capture.descriptor.model, 'CGB')
        self.assertIn((0xfea0, 0xe0), capture.unknown_cpu_ranges)
        self.assertIn((0xffff, 1), capture.unknown_cpu_ranges)
        self.assertIn((0xa000, 8192), capture.unknown_cpu_ranges)
        with self.assertRaises(TypeError):
            capture.state['pc'] = 0
        with self.assertRaises(dataclasses.FrozenInstanceError):
            capture.memory = b''
        machine.step()
        self.assertEqual(capture.state['pc'], 0x150)
        self.assertEqual(capture.cpu_bytes[0x150], 0)

    def test_banked_memory_is_coherent_and_capture_preserves_serialization(self):
        code = bytes.fromhex(
            '3e 00 e0 40 '  # LCD off for safe writes
            '3e 03 e0 70 3e 35 ea 34 d0 '  # WRAM bank 3
            '3e 01 e0 4f 3e 28 ea 00 80 '  # VRAM bank 1
            '3e 00 e0 4f 3e 17 ea 00 80 '  # VRAM bank 0
            '3e 0a ea 00 00 3e 02 ea 00 40 3e 67 ea 10 a0 '  # SRAM bank 2
            '76')
        machine = self.machine(code, ram=True)
        for _ in range(64):
            if machine.step().state['halted']:
                break
        else:
            self.fail('Fixture did not reach HALT')
        before = machine._diagnostic_state()
        capture = machine.capture()
        self.assertEqual(before, machine._diagnostic_state())
        self.assertEqual(capture.state['wram'], 3)
        self.assertEqual(capture.state['cart'], 2)
        self.assertEqual(capture.bank_bytes('wram', 3)[0x34], 0x35)
        self.assertEqual(capture.cpu_bytes[0xd034], 0x35)
        self.assertEqual(capture.cpu_bytes[0xf034], 0x35)
        self.assertEqual(capture.bank_bytes('vram', 0)[0], 0x17)
        self.assertEqual(capture.bank_bytes('vram', 1)[0], 0x28)
        self.assertEqual(capture.bank_bytes('cart', 2)[0x10], 0x67)
        self.assertEqual(capture.cpu_bytes[0xa010], 0x67)
        self.assertNotIn((0xa000, 8192), capture.unknown_cpu_ranges)
        self.assertEqual(len(tuple(capture.mutable_banks())), 14)

    def test_halt_idle_and_atomic_pause_with_ime_on_and_off(self):
        for ime in (False, True):
            with self.subTest(ime=ime):
                code = bytes.fromhex('f3 3e 00 e0 0f 3e 08 ea ff ff')
                code += b'\xfb\x00' if ime else b''
                code += b'\x76\x04'
                machine = self.machine(code)
                for _ in range(20):
                    capture = machine.step()
                    if capture.state['halted']:
                        break
                self.assertTrue(capture.state['halted'])
                pc, bc, instructions = (capture.state[k] for k in ('pc', 'bc', 'execution_boundaries'))
                for _ in range(10):
                    idle = machine.step()
                    self.assertEqual(idle.stop_reason, 'halt-wait')
                    self.assertEqual((idle.state['pc'], idle.state['bc'], idle.state['execution_boundaries']), (pc, bc, instructions))
                self.assertGreater(idle.state['ticks'], capture.state['ticks'])
                started = threading.Event()
                def request_pause():
                    started.wait()
                    time.sleep(0.01)
                    machine.pause()
                requester = threading.Thread(target=request_pause)
                machine.prepare()
                requester.start()
                started.set()
                deadline = time.monotonic() + 1
                while not machine.run_slice() and time.monotonic() < deadline:
                    pass
                requester.join(timeout=1)
                self.assertFalse(requester.is_alive())
                self.assertLess(time.monotonic(), deadline)
                paused = machine.capture()
                self.assertEqual(paused.stop_reason, 'pause')
                self.assertEqual(paused.state['pc'], pc)

    def test_halt_bug_state_copy_rejected_without_consuming_next_opcode(self):
        machine = self.machine(bytes.fromhex('f3 3e 01 e0 0f ea ff ff 76 04 00'))
        for _ in range(5):
            machine.step()
        capture = machine.capture()
        self.assertEqual(capture.state['pc'], 0x159)
        with self.assertRaisesRegex(UnsupportedFeature, 'HALT_BUG'):
            machine._diagnostic_state()
        self.assertEqual(machine.capture().state['pc'], capture.state['pc'])
        repeated = machine.step()
        self.assertEqual(repeated.state['pc'], capture.state['pc'])
        self.assertEqual(repeated.state['bc'], capture.state['bc'] + 0x100)

    def test_plain_stop_is_persistent_and_speed_switch_is_one_boundary(self):
        machine = self.machine(bytes.fromhex('3e 01 e0 4d 10 00 04 10 00 04'))
        machine.step()
        machine.step()
        switch = machine.step()
        self.assertEqual(switch.state['double_speed'], 1)
        self.assertEqual(switch.state['pc'], 0x156)
        self.assertEqual(machine.step().state['bc'], switch.state['bc'] + 0x100)
        stop = machine.step()
        self.assertEqual(stop.stop_reason, 'stop-wait')
        self.assertTrue(stop.state['stopped'])
        before = machine._diagnostic_state()
        for _ in range(4):
            self.assertEqual(machine.step().stop_reason, 'stop-wait')
        self.assertEqual(before, machine._diagnostic_state())

    def test_execution_breakpoint_resume_step_range_and_capability_rejection(self):
        machine = self.machine()
        point = machine.breakpoint('rom', 0, 0x150)
        machine.prepare()
        self.assertEqual(machine.run_slice(), 1)
        self.assertEqual(machine.capture().state['hit_id'], point)
        machine.prepare()
        self.assertEqual(machine.run_slice(), 1)
        self.assertGreater(machine.capture().state['execution_boundaries'], 1)
        self.assertEqual(machine.step().state['pc'], 0x151)
        machine.remove(point)
        for call in (lambda: machine.breakpoint('wram', 0, 0),
                     lambda: machine.breakpoint('rom', 0, 0, kinds=4),
                     lambda: machine.prepare_step(2),
                     lambda: machine.prepare_step(3),
                     lambda: machine.checkpoint(self.directory / 'checkpoint'),
                     lambda: machine.edit(register='BC', value=1, recovery=self.directory / 'recovery')):
            with self.assertRaises(UnsupportedFeature):
                call()
        self.assertFalse((self.directory / 'checkpoint').exists())
        self.assertFalse((self.directory / 'recovery').exists())
        for values in (('cpu', 1, 0), ('rom', 4, 0), ('rom', 0, 16384)):
            with self.assertRaises(ValueError):
                machine.breakpoint(*values)

    def test_physical_rom_breakpoints_distinguish_banks(self):
        fixture = ROOT / 'build/teaching.gbc'
        machine = Machine(fixture)
        self.addCleanup(machine.close)
        first = machine.breakpoint('rom', 1, 0x29)
        second = machine.breakpoint('rom', 2, 0x29)
        for expected, bank in ((first, 1), (second, 2)):
            machine.prepare()
            deadline = time.monotonic() + 1
            while not machine.run_slice() and time.monotonic() < deadline:
                pass
            self.assertLess(time.monotonic(), deadline)
            capture = machine.capture()
            self.assertEqual(capture.stop_reason, 'breakpoint')
            self.assertEqual(capture.state['hit_id'], expected)
            self.assertEqual((capture.state['pc'], capture.state['romx']), (0x4029, bank))
            self.assertEqual(capture.cpu_bytes[0x402a], 0x11 * bank)
            machine.remove(expected)

    def test_run_slice_deadline_and_mapping_generation_without_intermediate_captures(self):
        machine = self.machine(bytes.fromhex('3e 03 e0 70 3e 01 e0 70 18 f6'))
        generation = machine.capture().state['mapping_generation']
        machine.prepare()
        start = time.monotonic()
        self.assertEqual(machine.run_slice(), 0)
        self.assertLess(time.monotonic() - start, 1)
        self.assertGreater(machine.capture().state['mapping_generation'], generation + 2)
        self.assertEqual(machine.step().stop_reason, 'step')

    def test_input_frames_close_and_patch_source_identity(self):
        machine = self.machine()
        for key in Button:
            machine.key(key, True)
            self.assertEqual(machine.key_mask(), (1 << (int(key) + 1)) - 1)
        for key in Button:
            machine.key(key, False)
        self.assertEqual(machine.key_mask(), 0)
        frame = machine.frame()
        self.assertEqual((frame.width, frame.height, len(frame.data)), (160, 144, 92160))
        self.assertEqual(frame.pixel_format, 'ARGB8888')
        self.assertTrue(all(frame.data[i] == 255 for i in range(3, len(frame.data), 4)))
        machine.close()
        machine.pause()
        for call in (machine.frame, machine.capture, machine.ticks, machine.key_mask):
            with self.assertRaisesRegex(RuntimeError, 'closed'):
                call()
        # Source and packaged runs verify the same canonical native inputs.
        receipt=json.loads(Path(str(machine.lib._name)+'.json').read_text())
        for name,digest in receipt['sources'].items():
            self.assertEqual(hashlib.sha256((PATCH_PATH.parent.parent/name).read_bytes()).hexdigest(),digest)

    def test_semantic_input_reaches_native_joypad_lines(self):
        machine = self.machine(bytes.fromhex('3e 20 e0 00 f0 00 ea 00 c0 3e 10 e0 00 f0 00 ea 01 c0 76'))
        machine.key(Button.RIGHT, True)
        machine.key(Button.B, True)
        for _ in range(9):
            machine.step()
        captured = machine.capture()
        self.assertEqual(captured.cpu_bytes[0xc000] & 15, 14)
        self.assertEqual(captured.cpu_bytes[0xc001] & 15, 13)

    def test_interrupt_dispatch_stops_before_vector_opcode(self):
        machine = self.machine(bytes.fromhex('f3 3e 01 e0 0f ea ff ff fb 00 00'))
        for _ in range(6):
            machine.step()
        before = machine.capture()
        vector = machine.step()
        self.assertEqual(vector.state['pc'], 0x40)
        self.assertEqual(vector.state['sp'], before.state['sp'] - 2)
        self.assertEqual(vector.state['execution_boundaries'], before.state['execution_boundaries'] + 1)
        self.assertIsNone(vector.state['instructions'])
        point = machine.breakpoint('rom', 0, 0x40)
        machine.prepare()
        self.assertEqual(machine.run_slice(), 1)
        self.assertEqual(machine.capture().state['hit_id'], point)

    def test_ppu_and_dma_cpu_coverage_preserves_physical_storage(self):
        # Disable LCD, store 5A in VRAM, then sample it with the LCD enabled.
        machine=self.machine(bytes.fromhex('af e0 40 3e 5a ea 00 80 3e 91 e0 40 fa 00 80 18 fb'))
        locked=False
        for _ in range(200):
            capture=machine.step()
            if capture.state['vram_blocked']:
                locked=True
                self.assertIn((0x8000,0x2000),capture.unknown_cpu_ranges)
                self.assertEqual(capture.bank_bytes('vram',0)[0],0x5a)
            if capture.state['oam_blocked']:
                self.assertIn((0xfe00,0xa0),capture.unknown_cpu_ranges)
        self.assertTrue(locked)
        dma=self.machine(bytes.fromhex('3e c0 e0 46 00'))
        dma.step();capture=dma.step()
        self.assertTrue(capture.state['dma_active'])
        self.assertIn((0,0xff80),capture.unknown_cpu_ranges)
        self.assertEqual(len(capture.bank_bytes('wram',0)),4096)

    def test_declared_timebase_accounts_for_speed_switch(self):
        machine=self.machine(bytes.fromhex('00 3e 01 e0 4d 10 00 00'))
        before=machine.capture().state['ticks']
        deltas=[]
        for _ in range(5):
            capture=machine.step();deltas.append(capture.state['ticks']-before);before=capture.state['ticks']
        self.assertEqual(deltas,[8,16,24,16,4])
        self.assertEqual(capture.descriptor.ticks_per_second,8388608)


if __name__ == '__main__':
    unittest.main()
