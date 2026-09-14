"""Controls start from an executed generic real-wrapper trace, not a fabricated PASS."""
import importlib.util,json,unittest
from pathlib import Path
root=Path(__file__).resolve().parent/'public_operations'
spec=importlib.util.spec_from_file_location('public_evidence',root/'check_evidence.py')
checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
class PublicOperationEvidenceTest(unittest.TestCase):
    def test_executed_headless_request_ordering_and_controls(self):
        spec=importlib.util.spec_from_file_location('public_window_evidence',root/'check_window.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        events=json.loads((root/'fixtures/headless-requests.json').read_text())
        self.assertEqual(2,len(module.check_request_ordering(root,events,True)))
        with self.assertRaises(Exception):module.check_request_ordering(root,events,False)
        import tempfile
        with tempfile.TemporaryDirectory() as work:
            path=Path(work);(path/'timeline.json').write_text(json.dumps(events))
            self.assertEqual(7,len(module.ordering_sensitivities(path,True)))
    def test_complete_executed_positive_and_semantic_mutants(self):
        events=json.loads((root/'fixtures/correlated-headless.json').read_text())
        self.assertEqual(3,checker.check(events)['operations'])
        self.assertEqual(9,len(checker.sensitivities(events)))
    def test_missing_base_is_not_execution(self):
        with self.assertRaises(ValueError):checker.check([])
if __name__=='__main__':unittest.main()
