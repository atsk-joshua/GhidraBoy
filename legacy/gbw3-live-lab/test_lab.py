"""Integration checks against the user's own ROM. No ROM is bundled.
Run: python test_lab.py /path/to/student-rom.gbc
"""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout

from gbw3_lab import (Address, Lab, Harness, SHA256, PYBOY_VERSION, SCHEMA,
                      check_rom, compare_snapshots, demo, execute)

ROM_PATH = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else None

class LiveLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if ROM_PATH is None: raise RuntimeError('Supply your student ROM path')
        cls.rom = check_rom(ROM_PATH)

    def setUp(self):
        self.h = Harness(ROM_PATH)
        self.lab = Lab(self.rom, pyboy=self.h.p)
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)

    def tearDown(self):
        self.lab.close(); self.h.close(); self.tmp.cleanup()

    def test_bank_reads_include_last_byte_and_preserve_active_bank(self):
        p = self.h.p
        for bank in range(8):
            base = 0xc000 if bank == 0 else 0xd000
            p.memory[bank,base] = bank+11; p.memory[bank,base+4095] = bank+31
        p.memory[0xff70] = 6
        for bank in range(8):
            a = Address('wram',bank,0xc000 if bank == 0 else 0xd000)
            b = self.lab.read(a,4096)
            self.assertEqual((len(b),b[0],b[-1]),(4096,bank+11,bank+31))
        self.assertEqual(p.memory[0xff70]&7,6)
        self.assertEqual(self.lab.read('rom18::4000',16384),self.rom[18*16384:19*16384])
        with self.assertRaises(ValueError): self.lab.read('wram3::dfff',2)
        with self.assertRaises(ValueError): Address.parse('wram8::d000')

    def test_real_byte_and_word_writer_hooks(self):
        p = self.h.p; p.memory[3,0xd004] = 10
        self.lab.trace()
        self.h.call(0x40a1,{'A':0,'C':4,'B':7},bank=18)
        self.h.call(0x40bd,{'A':0,'C':10,'D':1,'E':44},bank=18)
        writes = [x for x in self.lab.events if x['kind']=='unit_write']
        self.assertEqual(len(writes),2)
        self.assertEqual(writes[0]['before'],[10]);self.assertEqual(writes[0]['after'],[7])
        self.assertEqual(writes[0]['registers_before']['executed_hook'],'rom18::40b5')
        self.assertEqual(writes[1]['after'],[44,1]);self.assertTrue(all(x['confirmed'] for x in writes))
        self.assertEqual(self.lab.units(True)[0]['experience'],300)

    def test_verified_far_call_origin(self):
        p=self.h.p;self.lab.trace()
        off=self.rom.index(bytes.fromhex('ef12a140'),12*16384,13*16384)
        addr=0x4000+off%16384
        p.memory[0xff80]=12;p.memory[0x2000]=12;p.memory[0xff82]=4;p.memory[0xff70]=4
        q=p.register_file;q.A=0;q.C=4;q.B=7;q.SP=0xcff0;q.PC=0x3b06
        p.memory[0xcff0:0xcff2]=[(addr+1)&255,(addr+1)>>8]
        p.memory[12,addr+4:addr+7]=[0xc3,0,1]
        p.tick(1,False)
        writes=[x for x in self.lab.events if x['kind']=='unit_write']
        self.assertEqual(writes[0]['caller']['verified_far_call_site'],f'rom12::{addr:04x}')

    def test_until_captures_entry_and_pauses_at_frame_end(self):
        p=self.h.p;p.memory[0x2000]=12;p.memory[0xff80]=12
        q=p.register_file;q.A=19;q.SP=0xcff0;q.PC=0x484a
        p.memory[0xcff0:0xcff2]=[0,1]
        result=self.lab.advance(5,until='initiative')
        self.assertEqual(result['frames_run'],1)
        self.assertEqual(result['hit']['registers']['A'],19)
        self.assertEqual(q.A,10);self.assertEqual(q.PC,0x100)
        self.assertEqual(self.lab.hooks,set())

    def test_snapshot_diff_unit_field_and_inactive_slot(self):
        p=self.h.p;p.memory[3,0xd030:0xd040]=[2,4,5,0,10,0,0,99,9,0,0,0,0,0,0,0]
        before=self.lab.snapshot()
        self.h.call(0x40a1,{'A':3,'C':4,'B':6},bank=18)
        diff=compare_snapshots(before,self.lab.snapshot())
        self.assertIn({'slot':3,'field':'hp','address':'wram3::d034','before':10,'after':6},diff['unit_changes'])
        self.assertEqual(self.lab.units(True)[3]['name'],'GRUNT')
        before['rom_sha256']='wrong'
        with self.assertRaises(ValueError):compare_snapshots(before,self.lab.snapshot())

    def test_scan_and_frame_watch(self):
        p=self.h.p
        for i in range(4096):p.memory[3,0xd000+i]=0
        p.memory[3,0xd004]=10;p.memory[3,0xd014]=10
        self.assertEqual(self.lab.scan_start(3,10)['candidates'],2)
        self.lab.watch=(Address.parse('wram3::d004'),1,bytes([10]))
        self.h.call(0x40a1,{'A':0,'C':4,'B':7},bank=18)
        self.lab.advance(1)
        self.assertEqual(self.lab.scan_filter('decreased')['first_100'],[{'address':'wram3::d004','value':7}])
        self.assertTrue(any(x['kind']=='frame_change' and x['after']==7 for x in self.lab.events))

    def test_state_round_trip_preserves_hooks_and_rejects_wrong_rom(self):
        p=self.h.p;self.lab.trace();p.memory[3,0xd004]=10
        state=self.out/'checkpoint.gbwstate';self.lab.save_state(state)
        self.h.call(0x40a1,{'A':0,'C':4,'B':2},bank=18)
        self.lab.load_state(state)
        self.assertEqual(p.memory[3,0xd004],10)
        self.h.call(0x40a1,{'A':0,'C':4,'B':8},bank=18)
        self.assertEqual([x for x in self.lab.events if x['kind']=='unit_write'][-1]['after'],[8])
        with self.assertRaises(FileExistsError):self.lab.save_state(state)
        with zipfile.ZipFile(state) as z: raw=z.read('state.bin');meta=json.loads(z.read('metadata.json'))
        meta['rom_sha256']='wrong'
        bad=self.out/'bad.gbwstate'
        with zipfile.ZipFile(bad,'w') as z:z.writestr('metadata.json',json.dumps(meta));z.writestr('state.bin',raw)
        with self.assertRaises(ValueError):self.lab.load_state(bad)
        self.assertEqual(p.memory[3,0xd004],8)

    def test_hook_cleanup_restores_execution_bytes(self):
        p=self.h.p;before=p.memory[18,0x40b5];self.lab.trace()
        self.assertEqual(p.memory[18,0x40b5],0xdb)
        self.assertEqual(self.lab.read('rom18::40b5'),bytes([before]))
        self.lab.trace(False);self.assertEqual(p.memory[18,0x40b5],before)

    def test_commands_and_export(self):
        with redirect_stdout(io.StringIO()):
            for cmd in ['help','units','unit 0','template 1','weapon 32','where order','peek wram3::dff0 16',
                        'regs','combat','points','trace on','run 1','trace off','events 1']:
                self.assertTrue(execute(self.lab,cmd))
            self.assertFalse(execute(self.lab,'quit'))
        path=self.out/'events.jsonl';self.lab.save_events(path)
        self.assertEqual(json.loads(path.read_text().splitlines()[0])['rom_sha256'],SHA256)

    def test_wrong_rom_fails_before_emulation(self):
        wrong=self.out/'wrong.gbc';wrong.write_bytes(b'not this game')
        with self.assertRaises(ValueError):check_rom(wrong)

class DemoTests(unittest.TestCase):
    def test_three_original_routine_experiments(self):
        with tempfile.TemporaryDirectory() as path:
            report=demo(ROM_PATH,path)
            self.assertEqual([(r['attacker_hp'],r['defender_hp']) for r in report['results']],[(5,5),(8,5),(5,8)])
            events=[json.loads(x) for x in (Path(path)/'events.jsonl').read_text().splitlines()[1:]]
            writes=[x for x in events if x['kind']=='unit_write']
            self.assertEqual(len(writes),6);self.assertTrue(all(x['confirmed'] for x in writes))

if __name__=='__main__':unittest.main(verbosity=2)
