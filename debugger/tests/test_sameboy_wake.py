"""Breakpoint continuation after a core call wakes and fetches an opcode."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ghigbc.backend import ROOT
from ghigbc.backends.sameboy import Machine, LEGACY_CGB_PATCH
import test_cgb_devices as devices


class SameBoyWakeTests(unittest.TestCase):
    until=devices.CGBDeviceTests.until

    def machine(self):
        code=bytes.fromhex('00 f3 af ea ff ff 3e 30 e0 00 3e 01 e0 4d 10 00 00 f0 4d ea 00 c0 18 fe')
        return devices.CGBDeviceTests.machine(self,code)

    def test_wake_fetch_checkpoint_and_resume_match_uninterrupted_state(self):
        machine=self.machine()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);start=machine.checkpoint(root/'start')
            before_ticks=machine.ticks()
            stopped=self.until(machine,0x160)
            self.assertEqual(stopped.state['double_speed'],1)
            self.assertFalse(stopped.state['halted'])
            self.assertEqual(stopped.cpu_bytes[0x160],0)
            pending=machine.checkpoint(root/'pending')
            resumed=machine.step()
            self.assertEqual(resumed.state['pc'],0x161)
            self.assertEqual(resumed.state['instructions']-stopped.state['instructions'],1)
            self.assertEqual(resumed.state['ticks']-stopped.state['ticks'],4)
            elapsed=machine.ticks()-before_ticks
            resumed_state=machine.checkpoint(root/'resumed')
            # Restoring the checkpoint must retain the already-arbitrated fetch.
            machine.restore(pending);machine.step()
            restored_state=machine.checkpoint(root/'restored')
            self.assertEqual((resumed_state/'state.sbs').read_bytes(),(restored_state/'state.sbs').read_bytes())
            # With no breakpoint at the wake PC, the guest reaches the same
            # next instruction with identical state and total emulated ticks.
            machine.restore(start);before_ticks=machine.ticks()
            self.until(machine,0x161)
            self.assertEqual(machine.ticks()-before_ticks,elapsed)
            continuous=machine.checkpoint(root/'continuous')
            self.assertEqual((resumed_state/'state.sbs').read_bytes(),(continuous/'state.sbs').read_bytes())

    def test_idle_halt_does_not_hit_next_pc_until_it_wakes(self):
        with Machine(ROOT/'build/teaching.gbc') as machine:
            for address,value in [(0xffff,0),(0xff0f,0),(0xc000,0x76),(0xc001,0)]:
                machine.lib.gc_edit_memory(machine.handle,address,value)
            machine.lib.gc_edit_register(machine.handle,5,0xc000)
            halted=machine.step();self.assertTrue(halted.state['halted'])
            machine.breakpoint('wram',0,1)
            for _ in range(4):
                idle=machine.step()
                self.assertEqual((idle.stop_reason,idle.state['pc']),('halt-wait',0xc001))
                self.assertEqual(idle.state['instructions'],halted.state['instructions'])
            machine.lib.gc_edit_memory(machine.handle,0xffff,1)
            machine.lib.gc_edit_memory(machine.handle,0xff0f,1)
            machine.prepare()
            for _ in range(10):
                if machine.run_slice():break
            awake=machine.capture()
            self.assertEqual((awake.stop_reason,awake.state['pc']),('breakpoint',0xc001))
            self.assertEqual(awake.state['instructions'],halted.state['instructions'])
            self.assertEqual(machine.step().state['pc'],0xc002)

    def test_old_short_section_resets_pending_fetch_and_identity_stays_strict(self):
        machine=self.machine()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);legacy=machine.checkpoint(root/'legacy')
            state=bytearray((legacy/'state.sbs').read_bytes())
            size=int.from_bytes(state[8:12],'little')
            # Exercise the legacy native section shape. The separate retained
            # M5 receipt validates a genuine old writer's complete payload.
            self.assertEqual(state[12+size-8:12+size],bytes(8))
            del state[12+size-8:12+size]
            state[8:12]=(size-8).to_bytes(4,'little')
            (legacy/'state.sbs').write_bytes(state)
            metadata=json.loads((legacy/'metadata.json').read_text())
            metadata.update(patch=LEGACY_CGB_PATCH,state_sha256=hashlib.sha256(state).hexdigest())
            (legacy/'metadata.json').write_text(json.dumps(metadata))
            self.until(machine,0x160)
            pending=machine.checkpoint(root/'pending')
            pending_bytes=(pending/'state.sbs').read_bytes()
            self.assertTrue(int.from_bytes(pending_bytes[12+size-8:12+size],'little')&1)
            machine.restore(legacy)
            reloaded=machine.checkpoint(root/'reloaded')
            self.assertEqual((reloaded/'state.sbs').read_bytes()[12+size-8:12+size],bytes(8))
            for key,value in [('patch','0'*64),('schema',3),('model','DMG-B'),('core','other'),
                    ('config','other'),('rom_hash','0'*64),('boot_hash','0'*64),('backend','other')]:
                with self.subTest(key=key):
                    (legacy/'metadata.json').write_text(json.dumps(dict(metadata,**{key:value})))
                    with patch.object(machine,'_load_state') as load:
                        with self.assertRaisesRegex(ValueError,'metadata mismatch'):machine.restore(legacy)
                        load.assert_not_called()
