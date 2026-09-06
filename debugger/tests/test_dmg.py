import unittest
from ghigbc.native import Machine, ROOT

class DmgTeachingTests(unittest.TestCase):
    def test_self_authored_dmg_boot_and_physical_bank_breakpoint(self):
        rom=ROOT/'build/teaching-dmg.gb'
        self.assertEqual(rom.read_bytes()[0x143],0)
        with Machine(rom) as m:
            m.breakpoint('rom',2,0x29);m.prepare()
            for _ in range(10000):
                if m.run_slice():break
            c=m.capture()
            self.assertEqual(c.state['pc'],0x4029)
            self.assertEqual(c.state['romx'],2)
            self.assertEqual(c.memory[0x402a],0x22)
