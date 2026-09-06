import json
from pathlib import Path
import tempfile
import unittest

from ghigbc.native import Machine, ROOT


class ExperimentEditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.local')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)

    def test_denied_and_invalid_edits_create_no_recovery_artifact(self):
        with Machine(ROOT / 'build/teaching.gbc') as m:
            with self.assertRaisesRegex(RuntimeError, 'experiment mode'):
                m.edit(register='BC', value=1, recovery=self.path/'off')
            m.experiment = True
            for request in ({'register':'bad','value':1}, {'register':'BC','value':65536},
                            {'register':'BC','address':0xc000,'value':1},
                            {'address':0xbfff,'value':1}, {'address':0xc000,'value':1.5}):
                with self.assertRaises(ValueError):
                    m.edit(**request, recovery=self.path/'invalid')
            m.running = True
            with self.assertRaisesRegex(RuntimeError, 'paused'):
                m.edit(register='BC', value=1, recovery=self.path/'running')
            m.running = False
            self.assertEqual(list(self.path.iterdir()), [])

    def test_register_audit_records_architectural_result_and_recovers(self):
        with Machine(ROOT/'build/teaching.gbc', experiment=True) as m:
            old = m.capture().state['af']
            recovery = self.path/'register'
            c = m.edit(register='af', value=0x12bf, recovery=recovery)
            self.assertEqual(c.state['af'], 0x12b0)
            self.assertEqual((c.edit['before'],c.edit['requested'],c.edit['after']), (old,0x12bf,0x12b0))
            self.assertEqual(c.edit['origin'], 'debugger')
            self.assertEqual(c.edit['status'], 'applied')
            self.assertEqual(json.loads((recovery/'edit.json').read_text())['id'],c.edit['id'])
            with self.assertRaises(TypeError):
                c.edit['after'] = 0
            restored = m.restore(recovery)
            self.assertEqual(restored.state['af'], old)
            self.assertGreater(restored.state['epoch'], c.state['epoch'])

    def test_wram_edit_keeps_physical_identity_and_does_not_fire_guest_watch(self):
        with Machine(ROOT/'build/teaching.gbc', experiment=True) as m:
            m.lib.gc_edit_memory(m.handle,0xff70,3)
            before = m.capture().bank_bytes('wram',3)[0x34]
            m.breakpoint('wram',3,0x34,kinds=4)
            recovery = self.path/'memory'
            c = m.edit(address=0xf034,value=0xa6,recovery=recovery)
            self.assertEqual(dict(c.edit['target']),{'region':'wram','bank':3,'offset':0x34,'cpu_address':0xf034})
            self.assertEqual((c.edit['before'],c.edit['after']), (before,0xa6))
            self.assertEqual(c.bank_bytes('wram',3)[0x34],0xa6)
            self.assertFalse(c.events)
            self.assertEqual(m.restore(recovery).bank_bytes('wram',3)[0x34],before)
            self.assertEqual(len(m.breakpoints),1)

    def test_restored_captures_keep_immutable_checkpoint_provenance(self):
        with Machine(ROOT/'build/teaching.gbc', experiment=True) as m:
            original=m.capture()
            first=m.checkpoint(self.path/'first')
            restored=m.restore(first)
            meta=json.loads((first/'metadata.json').read_text())
            self.assertIsNone(original.parent_checkpoint)
            self.assertEqual(restored.parent_checkpoint['path'],str(first.resolve()))
            self.assertEqual(restored.parent_checkpoint['state_sha256'],meta['state_sha256'])
            with self.assertRaises(TypeError):restored.parent_checkpoint['source_epoch']=42
            second=m.checkpoint(self.path/'second')
            second_meta=json.loads((second/'metadata.json').read_text())
            self.assertEqual(second_meta['parent_checkpoint'],dict(restored.parent_checkpoint))
            later=m.restore(second)
            self.assertEqual(later.parent_checkpoint['path'],str(second.resolve()))
            self.assertEqual(restored.parent_checkpoint['path'],str(first.resolve()))
