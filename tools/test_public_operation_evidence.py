"""Controls start from an executed generic real-wrapper trace, not a fabricated PASS."""
import importlib.util,json,unittest
from pathlib import Path
root=Path(__file__).resolve().parent/'public_operations'
spec=importlib.util.spec_from_file_location('public_evidence',root/'check_evidence.py')
checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
class PublicOperationEvidenceTest(unittest.TestCase):
    def test_complete_executed_positive_and_semantic_mutants(self):
        events=json.loads((root/'fixtures/correlated-headless.json').read_text())
        self.assertEqual(3,checker.check(events)['operations'])
        self.assertEqual(9,len(checker.sensitivities(events)))
    def test_missing_base_is_not_execution(self):
        with self.assertRaises(ValueError):checker.check([])
if __name__=='__main__':unittest.main()
