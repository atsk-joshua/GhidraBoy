import dataclasses
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
from ghigbc.native import Machine, ROOT
from ghigbc.profile import ByteRange, Field, ProfileSession, Observation, ActionContext, installed_providers

ROM=(ROOT/'build/teaching.gbc').read_bytes()

class SyntheticProvider:
    id='teaching-counter';version='1.0.0';api_version=1
    fingerprints=frozenset({hashlib.sha256(ROM).hexdigest()})
    requires=frozenset({'physical-capture-v1'})
    ranges=(ByteRange('wram',1,0x34,1),)
    @staticmethod
    def create(rom):return SyntheticDecoder()

class SyntheticDecoder:
    def decode(self,view):
        r=ByteRange('wram',1,0x34,1)
        yield Field('counter','integer',view.read(r)[0],r,'observed','Self-authored counter byte')

class ProfileTests(unittest.TestCase):
    def setUp(self):self.machine=Machine(ROOT/'build/teaching.gbc')
    def tearDown(self):self.machine.close()
    def test_absent_wrong_exact_independent_identity(self):
        c=self.machine.capture();self.assertEqual(ProfileSession(ROM).id,'generic')
        self.assertEqual(ProfileSession(ROM+b'x',[SyntheticProvider()]).id,'generic')
        p=ProfileSession(ROM,[SyntheticProvider()]);result=p.decode(c)
        self.assertEqual(result['profile'],'teaching-counter');self.assertFalse(result['error'])
        f=result['fields'][0];self.assertEqual(f['capture'],c.state['capture_id']);self.assertEqual(f['session'],c.session)
        self.assertEqual(f['source'],dict(region='wram',bank=1,offset=0x34,length=1))
        # No Program binding is required for valid runtime decoding.
        self.assertEqual(p.decode(c),result)
    def test_failure_capability_and_ambiguity_leave_raw_usable(self):
        class Bad(SyntheticProvider):
            @staticmethod
            def create(rom):raise RuntimeError('deliberate provider failure')
        self.assertIn('deliberate',ProfileSession(ROM,[Bad()]).error)
        class Unsupported(SyntheticProvider):requires={'unsupported-capability'}
        self.assertEqual(ProfileSession(ROM,[Unsupported()]).id,'generic')
        self.assertEqual(ProfileSession(ROM,[SyntheticProvider(),SyntheticProvider()]).id,'generic')
        self.assertEqual(len(self.machine.capture().memory),245760)
    def test_decode_errors_and_bounds(self):
        class BadDecoder:
            def decode(self,view):
                view.read(ByteRange('wram',1,0x35,1))
                return ()
        p=ProfileSession(ROM,[SyntheticProvider()]);p.decoder=BadDecoder()
        self.assertIn('outside declared',p.decode(self.machine.capture())['error'])
        class Infinite:
            def decode(self,view):
                for i in range(4097):yield Field(str(i),'integer',1,ByteRange('wram',1,0x34,1))
        p.decoder=Infinite();self.assertIn('budget',p.decode(self.machine.capture())['error'])
        self.assertTrue(self.machine.capture().rom_hash)
    def test_immutable_observation_and_stale_context(self):
        c=self.machine.capture();view=Observation(c,SyntheticProvider.ranges);before=view.read(SyntheticProvider.ranges[0])
        context=ActionContext.of(c)
        with tempfile.TemporaryDirectory() as d:
            self.machine.checkpoint(Path(d)/'checkpoint');restored=self.machine.restore(Path(d)/'checkpoint')
        self.assertEqual(view.read(SyntheticProvider.ranges[0]),before)
        with self.assertRaisesRegex(RuntimeError,'Stale'):context.validate(restored)
        with self.assertRaises(RuntimeError):context.validate(dataclasses.replace(c,session='replacement'))
        with self.assertRaises(RuntimeError):context.validate(self.machine.capture())
    def test_explicit_manifest_errors_do_not_break_generic(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(installed_providers(d),((),()))
            (Path(d)/'profiles.json').write_text(json.dumps({'schema':1,'modules':['missing_provider']}))
            providers,errors=installed_providers(d)
            self.assertFalse(providers);self.assertTrue(errors)
            self.assertEqual(ProfileSession(ROM,providers,errors).id,'generic')
    def test_queued_action_rejects_epoch_changed_before_execution(self):
        from ghigbc.agent import Agent
        agent=Agent(self.machine);agent.last=self.machine.capture();changed=[];errors=[]
        def request():
            try:agent.submit(lambda:changed.append(True))
            except RuntimeError as error:errors.append(str(error))
        thread=threading.Thread(target=request);thread.start();fn,future=agent.queue.get(timeout=2)
        state=dict(agent.last.state);state['epoch']+=1
        agent.last=dataclasses.replace(agent.last,state=state)
        future.set_running_or_notify_cancel()
        try:future.set_result(fn())
        except Exception as error:future.set_exception(error)
        thread.join(2);agent.executor.shutdown(wait=True)
        self.assertFalse(changed);self.assertTrue(errors)

    def test_batched_persistence_keeps_every_field_within_wire_limit(self):
        from ghigbc.profile import encode_field_batches
        fields=[{'name':str(i),'value':'λ'*100,'source':{'region':'wram','bank':1,'offset':0x34,'length':1},'epoch':2,'capture':7,'version':'1.0.0'} for i in range(4096)]
        batches=encode_field_batches(fields)
        self.assertTrue(all(len(b)<=48000 for b in batches))
        self.assertEqual([field for batch in batches for field in json.loads(batch)],fields)
        self.assertLess(len(batches),len(fields))
