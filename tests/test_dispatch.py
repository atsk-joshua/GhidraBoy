import threading
import unittest
from ghigbc.dispatch import OrderedExecutor

class DispatchTests(unittest.TestCase):
    def test_slow_success_cannot_swap_with_fast_error_reply(self):
        entered=threading.Event();release=threading.Event();replies=[]
        executor=OrderedExecutor(lambda:self.fail('unexpected overflow'))
        def first():entered.set();release.wait(2);replies.append('first-success')
        def second():replies.append('second-error')
        a=executor.submit(first);self.assertTrue(entered.wait(1));b=executor.submit(second)
        self.assertFalse(b.done());release.set();a.result(2);b.result(2);executor.shutdown()
        self.assertEqual(replies,['first-success','second-error'])
    def test_backlog_is_bounded_without_blocking_protocol_receiver(self):
        release=threading.Event();overflows=[]
        executor=OrderedExecutor(lambda:overflows.append(True),capacity=2)
        a=executor.submit(lambda:release.wait(2));b=executor.submit(lambda:None)
        with self.assertRaisesRegex(RuntimeError,'backlog'):executor.submit(lambda:None)
        self.assertEqual(overflows,[True]);release.set();a.result(2);b.result(2);executor.shutdown()
