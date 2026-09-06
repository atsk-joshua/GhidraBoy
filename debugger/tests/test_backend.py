import dataclasses
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ghigbc.backend import ROOT, MemoryBank, VideoFrame, UnsupportedFeature, create_backend
from ghigbc.profile import ProfileSession


class BackendTests(unittest.TestCase):
    def test_generic_imports_do_not_load_an_emulator_adapter(self):
        subprocess.run([sys.executable, '-c',
            'import sys; import ghigbc.backend, ghigbc.profile, ghigbc.agent, ghigbc.display; '
            'assert "ghigbc.backends.sameboy" not in sys.modules; assert "ghigbc.native" not in sys.modules'],
            env=dict(os.environ, PYTHONPATH=str(ROOT/'python')), check=True)

    def test_unknown_backend_is_rejected_before_reading_inputs(self):
        with self.assertRaises(UnsupportedFeature):
            create_backend('not-installed', Path('/no-such-rom'))
        with self.assertRaisesRegex(UnsupportedFeature,'CGB-E only'):
            create_backend('sameboy',Path('/no-such-rom'),model='unsupported-model')

    def test_normalized_capture_matches_legacy_bytes_and_keeps_its_descriptor(self):
        with create_backend('sameboy', ROOT/'build/teaching.gbc') as machine:
            snapshot=machine.capture()
            self.assertEqual(snapshot.cpu_bytes,snapshot.memory[:65536])
            for bank in snapshot.mutable_banks():
                self.assertEqual(bank.data,snapshot.bank_bytes(bank.region,bank.bank))
            self.assertEqual(snapshot.stop_reason,'pause')
            original=snapshot.descriptor
            machine.descriptor=dataclasses.replace(original,mode='test-only metadata change')
            self.assertIs(snapshot.descriptor,original)
            self.assertEqual(snapshot.descriptor.mode,'CGB')

    def test_frame_input_and_closed_handle_contract(self):
        machine=create_backend('sameboy', ROOT/'build/teaching.gbc')
        try:
            frame=machine.frame()
            self.assertEqual((frame.width,frame.height,len(frame.data)),(160,144,160*144*4))
            machine.key(0,True)
            self.assertEqual(machine.key_mask()&1,1)
            machine.key(0,False)
            self.assertEqual(machine.key_mask()&1,0)
        finally:machine.close()
        machine.pause()  # Idempotent late pause during completed shutdown.
        for call in (machine.frame,machine.capture,machine.ticks,machine.key_mask):
            with self.assertRaisesRegex(RuntimeError,'closed'):call()

    def test_missing_capability_rejects_edit_before_recovery_creation(self):
        with create_backend('sameboy', ROOT/'build/teaching.gbc',experiment=True) as machine:
            before=machine.capture()
            machine.descriptor=dataclasses.replace(machine.descriptor,features=machine.descriptor.features-{'register-edit'})
            with tempfile.TemporaryDirectory() as directory:
                recovery=Path(directory)/'must-not-exist'
                with self.assertRaises(UnsupportedFeature):
                    machine.edit(register='BC',value=1,recovery=recovery)
                self.assertFalse(recovery.exists())
            self.assertEqual(machine.capture().state['bc'],before.state['bc'])

    def test_profile_requirements_use_the_selected_backend_capabilities(self):
        rom=b'bounded fixture'
        class Provider:
            fingerprints={hashlib.sha256(rom).hexdigest()}
            api_version=1
            requires={'physical-watch-v1'}
            @staticmethod
            def create(_):raise AssertionError('Unsupported provider must not be instantiated')
        profile=ProfileSession(rom,[Provider()],capabilities=frozenset({'physical-capture-v1'}))
        self.assertEqual(profile.id,'generic')
        self.assertIn('capability',profile.error)

    def test_shared_buffers_copy_mutable_inputs(self):
        data=bytearray(4)
        frame=VideoFrame(1,1,data)
        bank=MemoryBank('wram',0,data)
        data[0]=255
        self.assertEqual(frame.data,bytes(4))
        self.assertEqual(bank.data,bytes(4))
        with self.assertRaises(ValueError):VideoFrame(2,2,bytes(4))
