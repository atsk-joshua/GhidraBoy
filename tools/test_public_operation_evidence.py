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
    def test_actual_headed_owner_observations_and_sensitive_controls(self):
        import copy
        spec=importlib.util.spec_from_file_location('headed_evidence',root/'check_window.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        original=json.loads((root/'fixtures/headed-owner-observations.json').read_text())
        self.assertEqual(['H0','H1'],module.headed_owners(original)['rows'])
        def row(rows,name):return next(x for x in rows if x['row']==name)
        controls={
            'immediate_submission':lambda r:row(r,'STANDALONE_SCHEDULED_PUBLIC_SCRIPT')['submission'].__setitem__('toolBackground',True),
            'configuration_only':lambda r:row(r,'STANDALONE_SCHEDULED_PUBLIC_SCRIPT')['worker'].__setitem__('stack',[]),
            'never_pending':lambda r:row(r,'TOOL_OWNER_COMMIT')['pending'].__setitem__('terminalDone',True),
            'false_is_not_abort':lambda r:row(r,'TOOL_OWNER_ABORT').__setitem__('rollbackMechanism','applyTo false'),
            'wrong_outer':lambda r:row(r,'TOOL_OWNER_ABORT')['pending'].__setitem__('outer',-1),
            'prior_commit_lost':lambda r:row(r,'TOOL_OWNER_ABORT').__setitem__('priorSurvives',False),
            'owner_write_survives_abort':lambda r:row(r,'TOOL_OWNER_ABORT').__setitem__('insideSurvives',True),
            'abort_published':lambda r:row(r,'TOOL_OWNER_ABORT').__setitem__('presentation','PUBLISHED'),
            'sequential_only':lambda r:r.remove(row(r,'TOOL_OWNER_COMMIT')),
        }
        for name,change in controls.items():
            with self.subTest(name=name):
                rows=copy.deepcopy(original);change(rows)
                with self.assertRaises(module.core.Refusal):module.headed_owners(rows)
    def test_executed_removal_and_immutable_roster_controls(self):
        import copy
        spec=importlib.util.spec_from_file_location('window_roster',root/'check_window.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        evidence=json.loads((root/'fixtures/window-lifecycle-observations.json').read_text());entry=evidence['passive']['entry']
        def removal(e):return module.removed_entry(e['before'],e['after'],e['passive'],entry,evidence['passive']['program_id'],evidence['passive']['program_object'])
        removal(evidence);self.assertEqual(3,len(module.immutable_roster(evidence['saved'],evidence['immutable'])))
        controls={
            'authority_survived':lambda e:e['after']['options']['GhidraBoyStockPredicatedCalls'].__setitem__(entry,None),
            'other_edited_function':lambda e:e['after']['functions'][0].__setitem__('entry','foreign::0'),
            'later_comment_lost':lambda e:e['after']['functions'][0].__setitem__('comment',''),
            'no_passive_refusal':lambda e:e['passive'].__setitem__('highfunction_available',True),
            'unrelated_error':lambda e:e['passive'].__setitem__('error','some unrelated error'),
        }
        for name,change in controls.items():
            with self.subTest(name=name):
                altered=copy.deepcopy(evidence);change(altered)
                with self.assertRaises(module.core.Refusal):removal(altered)
        controls={
            'missing_domain':lambda e:e['immutable'].pop('immutable-2'),
            'missing_first_use':lambda e:e['immutable'].pop('immutable-first'),
            'duplicate_domain':lambda e:e['immutable']['immutable-1'].__setitem__('display_entry',e['immutable']['immutable-0']['display_entry']),
            'mutable_rescue':lambda e:e['immutable']['immutable-0'].__setitem__('read_only',False),
            'wrong_program':lambda e:e['immutable']['immutable-0'].__setitem__('program_id',-1),
        }
        for name,change in controls.items():
            with self.subTest(name=name):
                altered=copy.deepcopy(evidence);change(altered)
                with self.assertRaises(module.core.Refusal):module.immutable_roster(altered['saved'],altered['immutable'])
    def test_complete_roster_does_not_credit_missing_execution(self):
        import tempfile
        spec=importlib.util.spec_from_file_location('complete_evidence',root/'check_window.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as work:
            path=Path(work);(path/'completion-inputs.json').write_text(json.dumps(dict(first='first',second='second',service='service')))
            result=module.completion(path)
            self.assertEqual('INCOMPLETE',result['status'])
            self.assertEqual({'H0/H1','H2','I1','W1','W2','W3','W4','W5','W6','V'},set(result['rows']))
            self.assertFalse(any(row['status']=='PASS' for row in result['rows'].values()))
    def test_missing_base_is_not_execution(self):
        with self.assertRaises(ValueError):checker.check([])
if __name__=='__main__':unittest.main()
