"""Real SameBoy hardware/mapper tests; all cartridges are local synthetic fixtures."""
import ctypes as C
import dataclasses
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from ghigbc.backend import ROOT, REGIONS, UnsupportedFeature
from ghigbc.backends.sameboy import Machine, Address, State, Event, MEMORY_SIZE
from ghigbc.session import Session


def until(test, machine):
    machine.prepare()
    for _ in range(10000):
        if machine.run_slice():return machine.capture()
    test.fail('Fixture did not reach its breakpoint within bounded execution')


class HardwareModelTests(unittest.TestCase):
    def test_repeated_boot_observations_preserve_exact_engine_state(self):
        # Lazy APU/PPU reads on the live engine used to mutate serialized state.
        # Compare the engine payload itself, independently of captured register values.
        with tempfile.TemporaryDirectory() as directory:
            before=Path(directory)/'before.sbs';after=Path(directory)/'after.sbs'
            for model,rom in [('CGB-E','teaching.gbc'),('CGB-E','teaching-dmg.gb'),('DMG-B','teaching-dmg.gb')]:
                with self.subTest(model=model,rom=rom), Machine(ROOT/'build'/rom,model=model) as machine:
                    machine.prepare()
                    for _ in range(24):
                        machine.lib.gc_run(machine.handle,4096,0xffffffff,0)
                        self.assertEqual(machine.lib.gc_state_save(machine.handle,os.fsencode(before)),0)
                        frame=machine.frame()
                        first=machine.capture();second=machine.capture()
                        self.assertEqual(machine.lib.gc_state_save(machine.handle,os.fsencode(after)),0)
                        self.assertEqual(before.read_bytes(),after.read_bytes())
                        self.assertEqual(first.cpu_bytes,second.cpu_bytes)
                        self.assertEqual(frame,machine.frame())

    def test_actual_dmg_hardware_boot_and_banked_execution(self):
        with Machine(ROOT/'build/teaching-dmg.gb',model='DMG-B') as machine:
            first=machine.capture()
            self.assertEqual((first.descriptor.model,first.descriptor.mode),('DMG-B','DMG'))
            self.assertEqual((first.state['wram_size'],first.state['vram_size']),(8192,8192))
            self.assertEqual(first.boot_ranges,((0,0x100),))
            self.assertEqual([(b.region,b.bank,len(b.data)) for b in first.mutable_banks()],
                [('wram',0,4096),('wram',1,4096),('vram',0,8192)])
            machine.breakpoint('rom',2,0x29)
            after=until(self,machine)
            self.assertEqual((after.state['pc'],after.state['romx']),(0x4029,2))
            self.assertEqual(after.cpu_bytes[0x402a],0x22)
            self.assertEqual(after.boot_ranges,())
            self.assertEqual(after.descriptor.mode,'DMG')
            self.assertEqual(first.boot_ranges,((0,0x100),))
            for region,bank,offset,length in [('wram',2,0,1),('vram',1,0,1),('boot',0,0x100,1),('cart',0,0,1)]:
                with self.subTest(region=region):
                    with self.assertRaises(ValueError):machine.breakpoint(region,bank,offset,length=length)
                    self.assertNotEqual(machine.lib.gc_breakpoint(machine.handle,99,Address(REGIONS.index(region),bank,offset),length,1,1),0)
            self.assertNotEqual(machine.lib.gc_edit_wram(machine.handle,2,0,1),0)

    def test_cgb_native_and_compatibility_modes_restore_across_boot(self):
        for rom,final_mode in [('teaching.gbc','CGB'),('teaching-dmg.gb','DMG-on-CGB')]:
            with self.subTest(rom=rom), Machine(ROOT/'build'/rom) as machine, tempfile.TemporaryDirectory() as directory:
                first=machine.capture();identity=machine._identity()
                self.assertEqual(first.descriptor.mode,'CGB')
                self.assertEqual(first.boot_ranges,((0,0x100),(0x200,0x900)))
                self.assertEqual((first.state['wram_size'],first.state['vram_size']),(32768,16384))
                before=machine.checkpoint(Path(directory)/'before')
                machine.breakpoint('rom',0,0x150)
                after=until(self,machine)
                self.assertEqual(after.boot_ranges,())
                self.assertEqual(after.descriptor.mode,final_mode)
                self.assertEqual(machine._identity(),identity)
                finished=machine.checkpoint(Path(directory)/'after')
                self.assertEqual(json.loads((finished/'metadata.json').read_text())['schema'],2)
                self.assertEqual(machine.restore(before).descriptor.mode,'CGB')
                self.assertEqual(machine.restore(finished).descriptor.mode,final_mode)

    def test_dmg_checkpoint_configuration_and_generic_mode_independence(self):
        with Machine(ROOT/'build/teaching-dmg.gb',model='DMG-B') as machine, tempfile.TemporaryDirectory() as directory:
            checkpoint=machine.checkpoint(Path(directory)/'dmg')
            self.assertEqual(json.loads((checkpoint/'metadata.json').read_text())['schema'],3)
            identity=Session._checkpoint_identity(machine)
            machine.descriptor=dataclasses.replace(machine.descriptor,mode='changed observed mode')
            self.assertEqual(Session._checkpoint_identity(machine),identity)
            self.assertEqual(machine.restore(checkpoint).descriptor.mode,'DMG')

    def test_hardware_and_state_remain_coherent_during_native_restores(self):
        # Exercise the native lock directly, bypassing Session's Python lock:
        # the two saved boundaries differ in both mode and boot mapping.
        with Machine(ROOT/'build/teaching-dmg.gb') as machine, tempfile.TemporaryDirectory() as directory:
            before=machine.checkpoint(Path(directory)/'before')/'state.sbs'
            machine.breakpoint('rom',0,0x150);until(self,machine)
            after=machine.checkpoint(Path(directory)/'after')/'state.sbs'
            errors=[];start=threading.Barrier(2)
            def restore():
                try:
                    start.wait(timeout=5)
                    for _ in range(100):
                        for path in (before,after):
                            if machine.lib.gc_state_load(machine.handle,os.fsencode(path)):
                                raise RuntimeError('Native test restore failed')
                except Exception as error:errors.append(error)
            worker=threading.Thread(target=restore);worker.start()
            try:
                start.wait(timeout=5)
                for _ in range(200):
                    snapshot=machine.capture()
                    self.assertEqual(snapshot.descriptor.mode,'CGB' if snapshot.state['boot'] else 'DMG-on-CGB')
            finally:worker.join(timeout=10)
            self.assertFalse(worker.is_alive());self.assertFalse(errors)

    def test_mismatched_boot_and_old_native_library_fail_explicitly(self):
        boots=ROOT/'.deps/SameBoy/build/bin/BootROMs'
        for model,boot in [('DMG-B','cgb_boot.bin'),('CGB-E','dmg_boot.bin')]:
            with self.subTest(model=model), self.assertRaisesRegex(ValueError,'boot image'):
                Machine(ROOT/'build/teaching-dmg.gb',model=model,boot=boots/boot)
        with Machine(ROOT/'build/teaching.gbc') as machine:
            for model,boot in [(1,machine.boot_bytes),(0,bytes(256)),(2,bytes(256))]:
                self.assertFalse(machine.lib.gc_create_model_buffers(machine.rom_bytes,len(machine.rom_bytes),boot,len(boot),model))
            class LegacyLibrary:
                def __getattr__(self,name):
                    if name=='gc_snapshot_hardware':raise AttributeError(name)
                    return getattr(machine.lib,name)
            with patch('ghigbc.backends.sameboy.C.CDLL',return_value=LegacyLibrary()):
                with self.assertRaisesRegex(UnsupportedFeature,'coherent hardware'):
                    Machine(ROOT/'build/teaching.gbc')

    def test_native_bounds_and_original_snapshot_abi(self):
        with Machine(ROOT/'build/teaching.gbc') as machine:
            for region,bank,offset,length in [('wram',0xffffffff,0,1),('rom',0xffffffff,0,1),
                    ('wram',0,4096,1),('vram',2,0,1),('boot',0,0xff,2),('boot',0,0x100,1),
                    ('boot',1,0,1),('oam',0,160,1),('hram',0,127,1),('io',0,0x80,1)]:
                with self.subTest(region=region,bank=bank,offset=offset):
                    with self.assertRaises(ValueError):machine.breakpoint(region,bank,offset,length=length)
                    self.assertNotEqual(machine.lib.gc_breakpoint(machine.handle,90,Address(REGIONS.index(region),bank,offset),length,1,1),0)
            for region,offset in [('boot',0x200),('oam',159),('hram',126),('io',255)]:
                machine.breakpoint(region,0,offset)
            state=State();memory=(C.c_uint8*MEMORY_SIZE)();events=(Event*64)()
            self.assertEqual(machine.lib.gc_snapshot(machine.handle,C.byref(state),memory,MEMORY_SIZE,events,64),0)
            self.assertEqual(state.abi,1)
            self.assertEqual(bytes(memory),machine.capture().memory)

    def test_partial_non_mbc2_cartridge_bank_has_no_published_padding(self):
        with tempfile.TemporaryDirectory() as directory:
            rom=bytearray((ROOT/'build/teaching.gbc').read_bytes())
            rom[0x147]=2;rom[0x149]=1  # MBC1 + 2 KiB SRAM.
            path=Path(directory)/'partial.gbc';path.write_bytes(rom)
            with Machine(path) as machine:
                snapshot=machine.capture()
                self.assertEqual(len(snapshot.bank_bytes('cart',0)),2048)
                for address,value in [(0xff50,1),(0x0000,0xa),(0x6000,1),(0x4000,1),(0xa7ff,0x37)]:
                    machine.lib.gc_edit_memory(machine.handle,address,value)
                snapshot=machine.capture()
                self.assertEqual(snapshot.state['cart'],0)
                self.assertEqual(snapshot.bank_bytes('cart',0)[2047],0x37)
                self.assertEqual(snapshot.cpu_bytes[0xbfff],0x37)
                machine.breakpoint('cart',0,2047,kinds=4)
                for bank,offset,length in [(0,2048,1),(0,2047,2),(1,0,1)]:
                    with self.assertRaises(ValueError):machine.breakpoint('cart',bank,offset,length=length)
                    self.assertNotEqual(machine.lib.gc_breakpoint(machine.handle,99,Address(4,bank,offset),length,4,1),0)


class Mbc2Tests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        rom=bytearray((ROOT/'build/teaching-dmg.gb').read_bytes())
        rom[0x147]=6;rom[0x149]=0
        rom[0x14d]=(-sum(rom[0x134:0x14d])-25)&255
        path=self.root/'mbc2.gb';path.write_bytes(rom)
        self.machine=Machine(path,model='DMG-B')
        self.addCleanup(self.machine.close)
        self.machine.lib.gc_edit_memory(self.machine.handle,0xff50,1)

    def instruction(self,code):
        machine=self.machine
        for offset,value in enumerate(bytes.fromhex(code)):
            machine.lib.gc_edit_memory(machine.handle,0xc000+offset,value)
        machine.lib.gc_edit_register(machine.handle,5,0xc000)
        return machine.step()

    def store(self,address,value):
        self.machine.lib.gc_edit_register(self.machine.handle,0,value<<8)
        return self.instruction(f'ea {address&255:02x} {address>>8:02x}')

    def test_both_mbc2_types_boot_on_dmg_and_cgb_hardware(self):
        for mapper in (5,6):
            rom=bytearray(self.machine.rom_bytes);rom[0x147]=mapper
            rom[0x14d]=(-sum(rom[0x134:0x14d])-25)&255
            path=self.root/f'mbc2-{mapper}.gb';path.write_bytes(rom)
            for model,mode in [('DMG-B','DMG'),('CGB-E','DMG-on-CGB')]:
                with self.subTest(mapper=mapper,model=model), Machine(path,model=model) as machine:
                    machine.breakpoint('rom',0,0x150)
                    snapshot=until(self,machine)
                    self.assertEqual(snapshot.descriptor.mode,mode)
                    self.assertEqual((snapshot.state['mapper'],snapshot.state['cart_size']),('MBC2',512))

    def test_mapper_address_bit_bank_zero_and_ram_enable(self):
        machine=self.machine
        self.assertIn('MBC2',machine.descriptor.mappers)
        self.assertEqual(machine.capture().state['cart_size'],512)
        self.assertEqual(self.store(0x2100,2).state['romx'],2)
        self.assertEqual(self.store(0x2000,3).state['romx'],2)  # A8 clear selects RAM enable.
        self.assertEqual(self.store(0x2100,0).state['romx'],1)
        self.assertEqual(self.store(0x0000,0x1a).state['cart_enabled'],1)
        self.assertEqual(self.store(0x0100,2).state['romx'],2)
        self.store(0xa001,0x4b)
        disabled=self.store(0x0000,0)
        self.assertIn((0xa000,8192),disabled.unknown_cpu_ranges)
        self.store(0xa001,0x77)
        enabled=self.store(0x0000,0x0a)
        self.assertEqual(enabled.bank_bytes('cart',0)[1],0xb)
        self.assertEqual(enabled.cpu_bytes[0xa001],0xfb)

    def test_mirrored_nibble_watches_cpu_values_and_change_predicate(self):
        machine=self.machine
        self.store(0x0000,0xa);self.store(0xa123,0x2b)
        watch=machine.breakpoint('cart',0,0x123,kinds=4|8)
        same=self.store(0xb923,0x7b)
        self.assertFalse(same.events)  # Upper bits are not physical storage.
        changed=self.store(0xbf23,0xe4)
        event=changed.events[0]
        self.assertEqual((event['target']['region'],event['target']['bank'],event['target']['offset']),(4,0,0x123))
        self.assertEqual((event['cpu_address'],event['value'],event['before'],event['after'],event['valid']),(0xbf23,0xe4,0xb,4,1))
        self.assertEqual(len(changed.bank_bytes('cart',0)),512)
        self.assertEqual(changed.bank_bytes('cart',0)[0x123],4)
        self.assertTrue(all(value<16 for value in changed.bank_bytes('cart',0)))
        self.assertEqual([changed.cpu_bytes[address] for address in range(0xa123,0xc000,512)],[0xf4]*16)
        machine.remove(watch);machine.breakpoint('cart',0,0x123,kinds=2)
        read=self.instruction('fa 23 b9')
        self.assertEqual((read.events[0]['value'],read.events[0]['before'],read.events[0]['after']),(0xf4,4,4))

    def test_small_bank_bounds_checkpoint_and_noninvasive_capture(self):
        machine=self.machine
        self.store(0x0000,0xa);self.store(0xbfff,0x87)
        machine.breakpoint('cart',0,511,kinds=4)
        for bank,offset,length in [(0,512,1),(0,511,2),(1,0,1),(0xffffffff,0,1)]:
            with self.subTest(bank=bank,offset=offset):
                with self.assertRaises(ValueError):machine.breakpoint('cart',bank,offset,kinds=4,length=length)
                self.assertNotEqual(machine.lib.gc_breakpoint(machine.handle,99,Address(4,bank,offset),length,4,1),0)
        before=machine.checkpoint(self.root/'before')
        snapshot=machine.capture()
        for _ in range(5):machine.capture()
        after=machine.checkpoint(self.root/'after')
        self.assertEqual((before/'state.sbs').read_bytes(),(after/'state.sbs').read_bytes())
        self.store(0xa1ff,2)
        restored=machine.restore(before)
        self.assertEqual(restored.bank_bytes('cart',0),snapshot.bank_bytes('cart',0))
        self.assertEqual(restored.cpu_bytes[0xbfff],0xf7)
