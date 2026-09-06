"""Authored native-CGB probes against published Pan Docs expectations.

Reference: gbdev/pandocs fe246067b695b5404a4a6a47efb4fd6d921ececb,
src/CGB_Registers.md (KEY1 and HDMA1..5). These are emulator observations,
not locally collected physical-hardware evidence or exact DMA timing claims.
"""
from pathlib import Path
import tempfile
import unittest

from ghigbc.backend import ROOT
from ghigbc.backends.sameboy import Machine


class CGBDeviceTests(unittest.TestCase):
    def machine(self, code):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        rom=bytearray((ROOT/'build/teaching.gbc').read_bytes()[:32768])
        rom[0x100:0x104]=bytes.fromhex('00 c3 50 01')
        rom[0x143]=0xc0;rom[0x147:0x14a]=bytes((0x19,0,0))
        rom[0x150:0x150+len(code)]=code
        checksum=0
        for value in rom[0x134:0x14d]:checksum=(checksum-value-1)&255
        rom[0x14d]=checksum;rom[0x14e:0x150]=b'\x00\x00'
        total=sum(rom)&0xffff;rom[0x14e:0x150]=total.to_bytes(2,'big')
        path=Path(temporary.name)/'cgb-device.gbc';path.write_bytes(rom)
        machine=Machine(path,model='CGB-E');self.addCleanup(machine.close)
        self.until(machine,0x150)
        capture=machine.capture()
        self.assertEqual((capture.descriptor.model,capture.descriptor.mode,capture.state['boot']),('CGB-E','CGB',0))
        return machine

    def until(self,machine,pc):
        point=machine.breakpoint('rom',0,pc);machine.prepare()
        for _ in range(5000):
            if machine.run_slice():
                capture=machine.capture()
                self.assertEqual((capture.stop_reason,capture.state['pc']),('breakpoint',pc))
                machine.remove(point)
                return capture
        self.fail('CGB fixture did not reach its bounded stop')

    def test_key1_stop_switches_speed_and_preserves_time_units(self):
        code=bytes.fromhex('00 f3 af ea ff ff 3e 30 e0 00 3e 01 e0 4d 10 00 00 f0 4d ea 00 c0 18 fe')
        machine=self.machine(code)
        before=machine.capture();normal=machine.step()
        self.assertEqual(normal.state['ticks']-before.state['ticks'],8)
        switched=self.until(machine,0x160)
        self.assertEqual(switched.state['double_speed'],1)
        fast=machine.step()
        self.assertEqual(fast.state['ticks']-switched.state['ticks'],4)
        final=self.until(machine,0x166)
        self.assertEqual(final.cpu_bytes[0xc000]&0x81,0x80)
        self.assertEqual(final.descriptor.ticks_per_second,8388608)

    def test_general_and_hblank_dma_copy_without_cpu_watch_attribution(self):
        for hblank in (False,True):
            with self.subTest(hblank=hblank):
                pattern=bytes((0x39+i*7)&255 for i in range(32))
                code=bytearray.fromhex('f3 af e0 40')  # LCD off while setting source/bank.
                for offset,value in enumerate(pattern):
                    code.extend((0x3e,value,0xea,0x80+offset,0xc0))
                code.extend(bytes.fromhex('3e 01 e0 4f 3e c0 e0 51 3e 8f e0 52 3e 01 e0 53 3e 2f e0 54'))
                if hblank:
                    code.extend(bytes.fromhex('3e 91 e0 40 f0 41 e6 03 fe 02 20 f8'))  # Await OAM phase.
                code.extend((0x3e,0x81 if hblank else 0x01,0xe0,0x55))
                code.extend(bytes.fromhex('f0 55 fe ff 20 fa ea 10 c0'))
                end=0x150+len(code);code.extend(bytes.fromhex('18 fe'))
                machine=self.machine(code)
                machine.breakpoint('vram',1,0x120,kinds=4,length=32)
                capture=self.until(machine,end)
                self.assertEqual(capture.bank_bytes('vram',1)[0x120:0x140],pattern)
                self.assertEqual(capture.cpu_bytes[0xc010],0xff)
                self.assertEqual(capture.events,())
                self.assertEqual(capture.state['dropped'],0)

    def test_mode3_cpu_bus_restrictions_preserve_physical_vram(self):
        # Guest instructions, rather than debugger peeks, exercise CPU lockouts.
        # Polling mode 3 leaves enough of its transfer interval for these accesses.
        code=bytes.fromhex(
            'f3 af e0 40 3e 44 ea 00 80 3e 55 ea 00 fe '
            '3e 91 e0 40 f0 41 e6 03 fe 03 20 f8 '
            'fa 00 80 ea 00 c0 3e 99 ea 00 80 '
            'fa 00 fe ea 01 c0 3e 66 ea 00 fe 18 fe')
        machine=self.machine(code)
        setup=self.until(machine,0x15e)
        self.assertEqual(setup.bank_bytes('vram',0)[0],0x44)
        watch=machine.breakpoint('vram',0,0,kinds=4)
        machine.prepare()
        for _ in range(5000):
            if machine.run_slice():
                capture=machine.capture()
                if capture.stop_reason=='watchpoint':break
        else:self.fail('Blocked VRAM write was not observed within the bound')
        self.assertEqual(capture.cpu_bytes[0xc000],0xff)
        self.assertEqual(capture.bank_bytes('vram',0)[0],0x44)
        event=capture.events[0]
        self.assertEqual((event['value'],event['before'],event['after']),(0x99,0x44,0x44))
        machine.remove(watch)
        final=self.until(machine,0x150+len(code)-2)
        self.assertEqual(final.cpu_bytes[0xc001],0xff)
        self.assertEqual(final.state['dropped'],0)


if __name__=='__main__':unittest.main()
