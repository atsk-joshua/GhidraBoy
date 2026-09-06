"""Mapper register tests against SameBoy, using only the self-authored ROM bytes."""
import tempfile,unittest
from pathlib import Path
from ghigbc.native import Machine,ROOT
class AddressEdges(unittest.TestCase):
    def image(self,mapper,banks,ram=0):
        raw=bytearray((ROOT/'build/teaching.gbc').read_bytes());raw.extend(bytes(banks*16384-len(raw)))
        raw[0x147]=mapper;raw[0x148]=(banks.bit_length()-1)-1;raw[0x149]=ram
        return raw
    def test_mbc5_nine_bit_bank(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
            p=Path(tmp)/'wide.gbc';rom=self.image(0x19,512);rom[256*16384+0x29:256*16384+0x2b]=bytes.fromhex('3eab');p.write_bytes(rom)
            with Machine(p) as m:
                for a,v in [(0xff50,1),(0x2000,0),(0x3000,1)]:m.lib.gc_edit_memory(m.handle,a,v)
                m.lib.gc_edit_register(m.handle,5,0x4029);m.breakpoint('rom',256,0x29);m.prepare();self.assertEqual(m.run_slice(),3)
                c=m.capture();self.assertEqual((c.state['romx'],c.memory[0x402a]),(256,0xab))
                self.assertEqual(m.step().state['af']>>8,0xab)
    def test_mbc1_rom0_and_mbc3_rtc_unknown(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
            p=Path(tmp)/'mbc1.gbc';p.write_bytes(self.image(1,128))
            with Machine(p) as m:
                for a,v in [(0xff50,1),(0x4000,1),(0x6000,1)]:m.lib.gc_edit_memory(m.handle,a,v)
                c=m.capture();self.assertEqual(c.state['rom0'],32)
            p=Path(tmp)/'mbc3.gbc';p.write_bytes(self.image(0x10,4,3))
            with Machine(p) as m:
                for a,v in [(0xff50,1),(0,0xa),(0x4000,8)]:m.lib.gc_edit_memory(m.handle,a,v)
                c=m.capture();self.assertEqual(c.state['rtc_selected'],1)
    def test_boot_coverage_and_read_watch(self):
        with Machine(ROOT/'build/teaching.gbc') as m:
            c=m.capture();self.assertEqual(c.state['boot'],1)
            m.breakpoint('boot',0,0);m.prepare();self.assertEqual(m.run_slice(),3)
            for a,v in [(0xff50,1),(0xc000,0xfa),(0xc001,0x34),(0xc002,0xd0),(0xff70,3),(0xd034,0x5a)]:m.lib.gc_edit_memory(m.handle,a,v)
            m.lib.gc_edit_register(m.handle,5,0xc000);m.breakpoint('wram',3,0x34,kinds=2)
            c=m.step();self.assertEqual(c.state['reason'],4);self.assertEqual((c.events[0]['access'],c.events[0]['value'],c.events[0]['writer_pc']),(2,0x5a,0xc000))

    def test_writer_address_rom0_remap_and_echo_execution(self):
        from ghigbc.agent import physical_writer_address
        with tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
            p=Path(tmp)/'rom0-writer.gbc';rom=self.image(1,128);rom[32*16384+0x29:32*16384+0x2e]=bytes.fromhex('3e55ea34d0');p.write_bytes(rom)
            with Machine(p) as m:
                for a,v in [(0xff50,1),(0xff70,3),(0x4000,1),(0x6000,1)]:m.lib.gc_edit_memory(m.handle,a,v)
                m.lib.gc_edit_register(m.handle,5,0x29);m.breakpoint('wram',3,0x34,kinds=4);m.step();c=m.step();e=c.events[0]
                self.assertEqual(e['writer_pc'],0x2b);a=physical_writer_address(e);self.assertEqual((a.space,a.offset),('rom32',0x402b))
            with Machine(ROOT/'build/teaching.gbc') as m:
                for a,v in [(0xff50,1),(0xff70,1)]:m.lib.gc_edit_memory(m.handle,a,v)
                for i,v in enumerate(bytes.fromhex('3e55ea34d0')):m.lib.gc_edit_memory(m.handle,0xd000+i,v)
                m.lib.gc_edit_register(m.handle,5,0xf000);m.breakpoint('wram',1,0x34,kinds=4);m.step();c=m.step();e=c.events[0]
                self.assertEqual(e['writer_pc'],0xf002);a=physical_writer_address(e);self.assertEqual((a.space,a.offset),('wram1',0xd002))
