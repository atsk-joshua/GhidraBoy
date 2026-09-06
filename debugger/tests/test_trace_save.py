import unittest
from ghigbc.agent import Agent

class TraceSaveTests(unittest.TestCase):
    def test_busy_mapping_transaction_variants_retry_but_other_errors_propagate(self):
        class Trace:
            def __init__(self,errors):self.errors=list(errors)
            def save(self):
                if self.errors:raise RuntimeError(self.errors.pop(0))
                return 'saved'
        agent=Agent.__new__(Agent)
        agent.trace=Trace(['Unable to lock due to active transaction',"Can't save during transaction"])
        self.assertEqual(agent.save_trace(),'saved')
        agent.trace=Trace(['disk failure'])
        with self.assertRaisesRegex(RuntimeError,'disk failure'):agent.save_trace()
