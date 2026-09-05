import hashlib
import json
from pathlib import Path
import statistics
import tempfile
import threading
import time
import unittest
from ghigbc.native import Machine, ROOT

class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(dir=ROOT/'.local')
        cls.base=Path(cls.temp.name)
        cls.symbols={s.split()[1]:int(s.split()[0].split(':')[1],16) for s in (ROOT/'build/teaching.sym').read_text().splitlines() if s and not s.startswith(';')}
        with Machine(ROOT/'build/teaching.gbc') as m:
            m.breakpoint('rom',0,0x150);m.prepare()
            for _ in range(5000):
                if m.run_slice():break
            assert m.capture().state['pc']==0x150,'Boot did not reach fixture'
            m.checkpoint(cls.base/'start')
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def setUp(self):
        self.m=Machine(ROOT/'build/teaching.gbc',experiment=True);self.m.restore(self.base/'start')
    def tearDown(self):self.m.close()
    def until(self):
        self.m.prepare()
        for _ in range(2000):
            if self.m.run_slice():return self.m.capture()
        self.fail('bounded execution did not stop')
    def test_banks_breakpoints_history(self):
        m=self.m;one=m.breakpoint('rom',1,0x29);two=m.breakpoint('rom',2,0x29)
        a=self.until();self.assertEqual((a.state['romx'],a.state['pc']),(1,0x4029));self.assertEqual(a.memory[0x4029:0x402c],bytes.fromhex('3e11c9'))
        b=self.until();self.assertEqual((b.state['romx'],b.state['pc'],b.state['hit_id']),(2,0x4029,two));self.assertEqual(b.memory[0x4029:0x402c],bytes.fromhex('3e22c9'))
        self.assertEqual(a.memory[0x402a],0x11);self.assertLess(a.state['mapping_generation'],b.state['mapping_generation'])
        c=m.step();self.assertEqual((c.state['pc'],c.state['af']>>8),(0x402b,0x22))
    def test_duplicate_breakpoints_resume_once(self):
        m=self.m;m.breakpoint('rom',1,0x29);m.breakpoint('rom',1,0x29)
        self.until();c=m.step();self.assertEqual((c.state['reason'],c.state['pc']),(1,0x402b))
    def test_inactive_bank(self):
        b=self.m.breakpoint('rom',2,0x29);c=self.until();self.assertEqual((c.state['romx'],c.state['hit_id']),(2,b))
    def test_watches_direct_same_changed_and_other_bank(self):
        m=self.m;m.breakpoint('wram',3,0x34,kinds=4)
        a=self.until();e=a.events[0];self.assertEqual((e['writer']['region'],e['writer']['bank'],e['writer_pc']),(1,0,self.symbols['DirectWriter']));self.assertEqual((e['value'],e['after'],e['origin']),(0x35,0x35,1))
        b=self.until();e=b.events[0];self.assertEqual((e['before'],e['after'],e['writer_pc']),(0x35,0x35,self.symbols['SameWriter']))
        c=self.until();self.assertEqual((c.events[0]['before'],c.events[0]['after']),(0x35,0x36))
        m.breakpoint('rom',2,0x567);d=self.until();self.assertEqual(d.state['reason'],3)
        self.assertEqual((d.bank_bytes('wram',3)[0x34],d.bank_bytes('wram',4)[0x34]),(0x36,0x47))
        self.assertEqual(a.bank_bytes('wram',3)[0x34],0x35)
    def test_change_predicate(self):
        self.m.breakpoint('wram',3,0x34,kinds=4|8)
        self.until();c=self.until();self.assertEqual(c.events[0]['writer_pc'],self.symbols['ChangedWriter'])
    def test_registers_cb_halt_stop_echo(self):
        m=self.m;m.breakpoint('rom',2,0x567);c=self.until()
        self.assertEqual([c.state[k] for k in ('af','bc','de','hl','pc','sp')],[0x12b0,0x3456,0x789a,0xbcde,0x4567,0xcffe])
        self.assertEqual(c.state['wram'],1);self.assertEqual(c.bank_bytes('wram',1)[0x34],0x58);self.assertEqual(c.memory[0xf034],c.memory[0xd034])
        self.assertEqual(m.step().state['pc'],0x4568)
        self.assertEqual(m.step().state['bc'],0x6856)
        for _ in range(4):c=m.step()
        self.assertEqual(c.state['halted'],1)
        n=c.state['instructions'];c=m.step();self.assertEqual((c.state['instructions'],c.state['reason']),(n,5))
    def test_inspector_noninvasive(self):
        m=self.m;m.breakpoint('rom',2,0x567);self.until();m.breakpoint('wram',1,0x34,kinds=2)
        with tempfile.TemporaryDirectory(dir=self.base) as t:
            p=Path(t);m.checkpoint(p/'before')
            for _ in range(10):self.assertEqual(len(m.capture().events),0)
            m.checkpoint(p/'after')
            self.assertEqual((p/'before/state.sbs').read_bytes(),(p/'after/state.sbs').read_bytes())
    def test_checkpoint_edit_epoch_breakpoints(self):
        m=self.m;bp=m.breakpoint('rom',2,0x567);c=self.until()
        with tempfile.TemporaryDirectory(dir=self.base) as t:
            p=Path(t);m.checkpoint(p/'checkpoint');d=m.edit(register='BC',value=0xabcd,recovery=p/'recovery')
            self.assertEqual(d.state['bc'],0xabcd);e=m.restore(p/'checkpoint')
            self.assertEqual(e.state['bc'],0x3456);self.assertGreater(e.state['epoch'],c.state['epoch']);self.assertGreater(e.state['capture_id'],d.state['capture_id']);self.assertFalse(e.events);self.assertIn(bp,m.breakpoints)
        from ghigbc.profile import ProfileSession
        self.assertEqual(ProfileSession(m.rom_bytes).id,'generic')
    def test_pause_and_latency(self):
        m=self.m;m.breakpoint('rom',2,0x567);self.until();samples=[]
        for _ in range(50):
            start=time.perf_counter();m.step();samples.append((time.perf_counter()-start)*1000)
        m.prepare();m.pause();start=time.perf_counter();self.assertEqual(m.run_slice(),2);latency=(time.perf_counter()-start)*1000
        print(json.dumps(dict(native_step_p95_ms=sorted(samples)[47],native_pause_ms=latency,scope='native adapter; excludes Trace RMI and desktop')))
    def test_ordinary_step_over_out(self):
        m=self.m;m.breakpoint('rom',2,0x567);self.until();m.step();m.step()
        c=m.capture();self.assertEqual(c.memory[c.state['pc']],0xcd)
        self.assertEqual(m.lib.gc_prepare_step(m.handle,2),0)
        for _ in range(50):
            if m.run_slice():break
        c=m.capture();self.assertEqual((c.state['pc'],c.state['sp'],c.state['bc']),(0x456d,0xcffe,0x6857))
        # Arrange a second CALL at the previously verified instruction boundary.
        m.lib.gc_edit_register(m.handle,5,0x456a);m.step()
        self.assertEqual(m.lib.gc_prepare_step(m.handle,3),0)
        for _ in range(50):
            if m.run_slice():break
        c=m.capture();self.assertEqual((c.state['pc'],c.state['sp']),(0x456d,0xcffe))
    def test_conditional_call_and_rst_over(self):
        m=self.m;m.lib.gc_edit_register(m.handle,5,self.symbols['ConditionalStart']);m.step()
        for expected in ('Taken','RestartCall'):
            self.assertEqual(m.lib.gc_prepare_step(m.handle,2),0)
            for _ in range(50):
                if m.run_slice():break
            self.assertEqual(m.capture().state['pc'],self.symbols[expected])
        before=m.capture().state['de']
        self.assertEqual(m.lib.gc_prepare_step(m.handle,2),0)
        for _ in range(50):
            if m.run_slice():break
        c=m.capture();self.assertEqual(c.state['pc'],self.symbols['RestartCall']+1);self.assertEqual(c.state['de'],(before&0xff00)|((before+1)&255))
    def test_ordered_two_byte_store(self):
        m=self.m
        for i,value in enumerate(bytes.fromhex('0834d0')):m.lib.gc_edit_memory(m.handle,0xc000+i,value)
        m.lib.gc_edit_memory(m.handle,0xff70,3);m.lib.gc_edit_register(m.handle,5,0xc000);m.lib.gc_edit_register(m.handle,4,0xbeef)
        m.breakpoint('wram',3,0x34,kinds=4,length=2);c=m.step()
        self.assertEqual([(e['target']['offset'],e['value'],e['after'],e['writer_pc']) for e in c.events],[(0x34,0xef,0xef,0xc000),(0x35,0xbe,0xbe,0xc000)])
        self.assertLess(c.events[0]['sequence'],c.events[1]['sequence'])
    def test_blocked_vram_attempt(self):
        m=self.m;m.lib.gc_edit_register(m.handle,5,self.symbols['BlockedStart'])
        m.breakpoint('vram',0,0,kinds=4)
        c=self.until();e=c.events[0]
        self.assertEqual(e['writer_pc'],self.symbols['BlockedWriter'])
        self.assertEqual(e['value'],0x77);self.assertEqual(e['before'],e['after'])
        self.assertNotEqual(e['after'],0x77)
    def test_stop_boundary(self):
        m=self.m;m.lib.gc_edit_memory(m.handle,0xff00,0x30)
        m.lib.gc_edit_register(m.handle,5,self.symbols['StopStart'])
        m.step();c=m.step();self.assertEqual(c.state['stopped'],1)
        n=c.state['instructions'];c=m.step();self.assertEqual((c.state['reason'],c.state['instructions']),(6,n))
    def test_interrupt_has_no_cpu_writer(self):
        m=self.m
        # Test setup intentionally calls ABI to arrange the fixture hardware; production edits are gated.
        for address,value in [(0xffff,1),(0xff0f,1),(0xc000,0xfb),(0xc001,0),(0xc002,0)]:m.lib.gc_edit_memory(m.handle,address,value)
        m.lib.gc_edit_register(m.handle,5,0xc000);m.lib.gc_edit_register(m.handle,4,0xcffe)
        m.breakpoint('wram',0,0xffc,kinds=4,length=2)
        m.step();m.step();c=m.step()
        self.assertEqual((c.state['reason'],c.state['pc']),(7,0x40));self.assertFalse(c.events)

if __name__=='__main__':unittest.main(verbosity=2)
