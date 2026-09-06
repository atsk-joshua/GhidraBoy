from concurrent.futures import Future, TimeoutError
import dataclasses
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from ghigbc.backend import ROOT, BackendDescriptor, create_backend
from ghigbc.session import CommandQueue, Session


class SessionTests(unittest.TestCase):
    def test_new_session_rejects_context_from_a_closed_machine(self):
        from ghigbc.profile import ActionContext
        with create_backend('sameboy', ROOT/'build/teaching.gbc') as previous:
            context=ActionContext.of(previous.capture())
        with create_backend('sameboy', ROOT/'build/teaching.gbc') as replacement:
            with self.assertRaisesRegex(RuntimeError,'Stale'):
                context.validate(replacement.capture(),selected=False)

    def test_pause_interrupts_execution_without_waiting_for_the_session_lock(self):
        with create_backend('sameboy', ROOT/'build/teaching.gbc') as machine:
            for address,value in enumerate(bytes.fromhex('f318fe'),0xc000):
                machine.lib.gc_edit_memory(machine.handle,address,value)
            machine.lib.gc_edit_register(machine.handle,5,0xc000)
            machine.prepare();machine.running=True
            entered=threading.Event();errors=[]
            def run():
                try:
                    with machine.lock:
                        entered.set()
                        deadline=time.monotonic()+3
                        while machine.running and time.monotonic()<deadline:
                            machine.run_slice()
                except Exception as error:errors.append(error)
            worker=threading.Thread(target=run);worker.start()
            self.assertTrue(entered.wait(1))
            started=time.monotonic()
            try:
                machine.pause()
                self.assertLess(time.monotonic()-started,1)
                worker.join(2)
                self.assertFalse(worker.is_alive())
                self.assertFalse(errors)
                self.assertEqual(machine.capture().stop_reason,'pause')
            finally:
                machine.lib.gc_request_pause(machine.handle)
                worker.join(4)

    def test_native_event_overflow_retains_a_bounded_prefix_and_loss_count(self):
        with create_backend('sameboy', ROOT/'build/teaching.gbc') as machine:
            for address,value in enumerate(bytes.fromhex('f33e35ea34c018fe'),0xc000):
                machine.lib.gc_edit_memory(machine.handle,address,value)
            machine.lib.gc_edit_register(machine.handle,5,0xc000)
            for index in range(80):
                machine.breakpoint('wram',0,0x34,kinds=4,id=index+1)
            machine.prepare()
            self.assertTrue(machine.run_slice())
            captured=machine.capture()
            self.assertEqual(len(captured.events),64)
            self.assertEqual(captured.state['dropped'],16)
            self.assertEqual(captured.stop_reason,'watchpoint')
            self.assertTrue(all(event['value']==0x35 for event in captured.events))

    def test_agent_publishes_truthful_fault_capture_after_partial_edit(self):
        from ghigbc.agent import Agent
        with create_backend('sameboy', ROOT/'build/teaching.gbc',experiment=True) as machine, tempfile.TemporaryDirectory() as directory:
            agent=Agent(machine)
            captured=[]
            write=machine._write_register
            def partial_write(register,value):
                write(register,value)
                raise RuntimeError('deliberate post-write failure')
            try:
                with patch.object(agent,'publish',side_effect=captured.append), patch.object(machine,'_write_register',side_effect=partial_write):
                    with self.assertRaisesRegex(RuntimeError,'recovery checkpoint retained'):
                        agent.mutate(lambda:machine.edit(register='BC',value=0x3456,recovery=Path(directory)/'recovery'))
                self.assertEqual(len(captured),1)
                self.assertEqual(captured[0].state['bc'],0x3456)
                self.assertTrue(captured[0].state['session_error'])
            finally:
                agent.owner.close()
                agent.executor.shutdown(wait=True)

    def test_generic_envelope_supports_an_unrelated_payload_format_and_unknown_clock(self):
        @dataclasses.dataclass(frozen=True)
        class Observation:
            state: dict
            events: tuple = ()
            session: str = ''
            parent_checkpoint: object = None
            descriptor: object = None
            edit: object = None
            stop_reason: str = 'pause'
        class Fixture(Session):
            state_filename='fixture.json'
            rom_hash='r'*64
            boot_hash='b'*64
            descriptor=BackendDescriptor('fixture','Fixture','core','config','','test','test',None,
                {'checkpoint','register-edit'},('test',),(),'fixture','fixture')
            def __init__(self):
                super().__init__(experiment=True)
                self.value=7
            def _capture(self):return Observation(dict(bc=self.value,ticks=None))
            def _save_state(self,path):path.write_text(json.dumps(self.value))
            def _load_state(self,path):self.value=json.loads(path.read_text())
            def _write_register(self,register,value):self.value=value
            def _close(self):pass
        with Fixture() as fixture, tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'recovery'
            changed=fixture.edit(register='BC',value=9,recovery=path)
            meta=json.loads((path/'metadata.json').read_text())
            self.assertEqual((meta['schema'],meta['backend'],meta['state_file']),(3,'fixture','fixture.json'))
            self.assertIsNone(meta['ticks_per_second'])
            self.assertEqual(changed.edit['after'],9)
            self.assertEqual(fixture.restore(path).state['bc'],7)

    def test_session_identity_does_not_inherit_backend_epoch_counters(self):
        with create_backend('sameboy', ROOT/'build/teaching.gbc') as machine:
            read=machine._capture
            def different_counters():
                raw=read()
                return dataclasses.replace(raw,state=dict(raw.state,epoch=9000,capture_id=9999))
            with patch.object(machine,'_capture',side_effect=different_counters):
                first=machine.capture();second=machine.capture()
            self.assertEqual(first.state['epoch'],0)
            self.assertEqual(second.state['capture_id'],first.state['capture_id']+1)
            self.assertNotEqual(second.state['capture_id'],9999)

    def test_old_sameboy_envelope_remains_readable(self):
        with create_backend('sameboy', ROOT/'build/teaching.gbc') as machine, tempfile.TemporaryDirectory() as directory:
            checkpoint=machine.checkpoint(Path(directory)/'state')
            path=checkpoint/'metadata.json'
            meta=json.loads(path.read_text())
            self.assertEqual(meta['schema'],2)
            for key in ('backend','state_file','ticks_per_second','capture'):
                meta.pop(key)
            path.write_text(json.dumps(meta))
            before=machine.capture()
            after=machine.restore(checkpoint)
            self.assertGreater(after.state['epoch'],before.state['epoch'])
            self.assertEqual(after.state['pc'],before.state['pc'])

    def test_restore_uses_verified_copy_when_original_is_replaced(self):
        with create_backend('sameboy', ROOT/'build/teaching.gbc',experiment=True) as machine, tempfile.TemporaryDirectory() as directory:
            checkpoint=machine.checkpoint(Path(directory)/'state')
            old=machine.capture().state['bc']
            machine._write_register('BC',0x1234)
            load=machine._load_state
            def replace_original(payload):
                self.assertNotEqual(payload.resolve(),(checkpoint/'state.sbs').resolve())
                (checkpoint/'state.sbs').write_bytes(b'replaced after verification')
                load(payload)
            with patch.object(machine,'_load_state',side_effect=replace_original):
                restored=machine.restore(checkpoint)
            self.assertEqual(restored.state['bc'],old)

    def test_failed_write_keeps_recovery_and_blocks_execution_until_restore(self):
        with create_backend('sameboy', ROOT/'build/teaching.gbc',experiment=True) as machine, tempfile.TemporaryDirectory() as directory:
            before=machine.capture()
            recovery=Path(directory)/'recovery'
            write=machine._write_register
            def partial_write(register,value):
                write(register,value)
                raise RuntimeError('failure after native write')
            with patch.object(machine,'_write_register',side_effect=partial_write):
                with self.assertRaisesRegex(RuntimeError,'recovery checkpoint retained'):
                    machine.edit(register='BC',value=0x2468,recovery=recovery)
            audit=json.loads((recovery/'edit.json').read_text())
            self.assertEqual(audit['status'],'failed')
            self.assertTrue((recovery/'metadata.json').is_file())
            self.assertEqual(machine.capture().state['bc'],0x2468)
            self.assertTrue(machine.capture().state['session_error'])
            with self.assertRaisesRegex(RuntimeError,'Restore a recovery'):
                machine.prepare()
            restored=machine.restore(recovery)
            self.assertEqual(restored.state['bc'],before.state['bc'])
            self.assertFalse(restored.state['session_error'])
            machine.prepare()

    def test_wrong_backend_and_state_path_are_rejected_without_loading(self):
        with create_backend('sameboy', ROOT/'build/teaching.gbc') as machine, tempfile.TemporaryDirectory() as directory:
            checkpoint=machine.checkpoint(Path(directory)/'state')
            path=checkpoint/'metadata.json';original=json.loads(path.read_text())
            for key,value in (('backend','other'),('state_file','../other'),('ticks_per_second',1)):
                path.write_text(json.dumps(dict(original,**{key:value})))
                with patch.object(machine,'_load_state') as load:
                    with self.assertRaisesRegex(ValueError,'metadata mismatch'):
                        machine.restore(checkpoint)
                    load.assert_not_called()


class CommandQueueTests(unittest.TestCase):
    def test_disconnect_before_execution_prevents_a_queued_mutation(self):
        disconnected=False
        queue=CommandQueue(lambda:None,lambda:disconnected)
        changes=[]
        pending=queue.enqueue(lambda:changes.append(True))
        disconnected=True
        queue.run_one()
        with self.assertRaisesRegex(RuntimeError,'disconnected'):
            pending.result()
        self.assertFalse(changes)

    def test_inflight_timeout_does_not_claim_cancellation(self):
        queue=CommandQueue(lambda:None)
        running=Future();running.set_running_or_notify_cancel()
        with patch.object(queue,'enqueue',return_value=running):
            with self.assertRaisesRegex(TimeoutError,'completion was not cancelled'):
                queue.submit(lambda:None,timeout=0)
        self.assertFalse(running.cancelled())
        running.set_result('completed')

    def test_timeout_before_execution_cancels_mutation(self):
        queue=CommandQueue(lambda:None)
        changes=[]
        with self.assertRaises(TimeoutError):
            queue.submit(lambda:changes.append(1),timeout=0)
        queue.run_one()
        self.assertEqual(changes,[])

    def test_backlog_close_and_late_requests_are_bounded(self):
        queue=CommandQueue(lambda:None,capacity=1)
        pending=queue.enqueue(lambda:None)
        with self.assertRaisesRegex(RuntimeError,'backlog'):
            queue.enqueue(lambda:None)
        queue.close()
        self.assertTrue(pending.cancelled())
        with self.assertRaisesRegex(RuntimeError,'disconnected'):
            queue.enqueue(lambda:None)

    def test_context_is_checked_when_command_runs_and_termination_can_ignore_it(self):
        from types import SimpleNamespace
        current=SimpleNamespace(session='session',state={'epoch':0,'capture_id':1})
        queue=CommandQueue(lambda:current)
        changes=[]
        stale=queue.enqueue(lambda:changes.append('stale'))
        close=queue.enqueue(lambda:changes.append('close'),bind_context=False)
        current=SimpleNamespace(session='session',state={'epoch':1,'capture_id':2})
        queue.run_one();queue.run_one()
        with self.assertRaisesRegex(RuntimeError,'Stale'):
            stale.result()
        self.assertIsNone(close.result())
        self.assertEqual(changes,['close'])
