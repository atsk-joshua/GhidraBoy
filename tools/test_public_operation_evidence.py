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

class TopologyReceiptContractTest(unittest.TestCase):
    """Synthetic schema tests only: these do not establish observed W2 or V acceptance."""
    def setUp(self):
        import tempfile
        self.work = tempfile.TemporaryDirectory();self.addCleanup(self.work.cleanup)
        self.path = Path(self.work.name)
        spec=importlib.util.spec_from_file_location('topology_contract',root/'check_window.py')
        self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
        identity=dict(program_id=1,program_object=2,domain='view::20',carrier='carrier2',operation_id=3,transaction_id=4)
        provider=dict(class_='unused',object=5,tool=6,showing=True)
        provider['class']='ghidra.app.plugin.core.decompile.PrimaryDecompilerProvider'
        block=dict(name='carrier',start='20',end='30',space='view',type='DEFAULT',overlay=True,backing=None,initialized=True,permissions='rx')
        self.receipt=dict(schema=1,delta=1,identity=identity,
            before=dict(program_id=1,program_object=2,spaces=['ram'],blocks=[block],domains=['view::10']),
            after=dict(program_id=1,program_object=2,spaces=['ram','view'],blocks=[block],domains=['view::10','view::20']),
            events=[dict(seq=0,kind='observer-installed',mechanism='supported native request hook',coverage_limitations=[],dropped_events=0,provider=provider),
                    dict(seq=1,kind='apply-invoke',action='stock-predicate-apply',identity=identity),
                    dict(seq=2,kind='program-event',identity=identity,types=['MEMORY_BLOCK_ADDED']),
                    dict(seq=3,kind='owner-terminal',identity=identity,mutation='COMMITTED',current=True,presentation='PUBLISHED'),
                    dict(seq=3.5,kind='native-request-start',identity=identity,request_id='request1'),
                    dict(seq=4,kind='native-request',observed_operation_id=3,identity=identity,provider=provider,request_id='request1',eligibility='ELIGIBLE',currentness_evidence={'revision':10,'observed_at_seq':3.5,'current':True},transaction_evidence={'owner_status':'COMMITTED','observed_at_seq':3.5,'owner_transaction_id':4,'active':False},completed=True,error=''),
                    dict(seq=4.5,kind='public-presentation',identity=identity,disposition='PUBLISHED'),
                    dict(seq=5,kind='first-use-capture',request_id='request1',label='topology-first-use')],log='creation.log',errors=[])
        (self.path/'creation.log').write_text('')
        (self.path/'topology-first-use-request.json').write_text(json.dumps(dict(program_id=1,program_object=2,display_entry='view::20',native_request_id='request1')))
    def check(self, receipt=None):
        (self.path/'topology-observation.json').write_text(json.dumps(self.receipt if receipt is None else receipt))
        return self.module.topology_first_use(self.path)
    def test_contract_accepts_complete_synthetic_shape(self):
        self.assertEqual('request1',self.check()['request_id'])
    def test_missing_late_polling_wrong_identity_and_rescue_controls(self):
        import copy
        controls={
            'late_observer':lambda r:r['events'][0].__setitem__('seq',2.5),
            'polling':lambda r:r['events'][0].__setitem__('coverage_limitations',['polling misses completed/abandoned requests']),
            'lost_request':lambda r:r['events'][0].__setitem__('dropped_events',1),
            'no_normal_provider':lambda r:r['events'][0]['provider'].__setitem__('showing',False),
            'wrong_domain':lambda r:r['identity'].__setitem__('domain','foreign::0'),
            'missing_event':lambda r:r['events'].pop(2),
            'rescued':lambda r:r['events'].insert(4,dict(seq=3.5,kind='provider-reset')),
            'replacement_request':lambda r:r['events'][-1].__setitem__('request_id','later'),
            'unbound_currentness':lambda r:next(e for e in r['events'] if e['kind']=='native-request').__setitem__('currentness_evidence',{'attested':True}),
            'unbound_transaction':lambda r:next(e for e in r['events'] if e['kind']=='native-request').__setitem__('transaction_evidence',{'attested':True}),
            'first_failure':lambda r:next(e for e in r['events'] if e['kind']=='native-request').__setitem__('error','Stale predicated graph registration'),
            'missing_topology':lambda r:r['after'].__setitem__('blocks',[]),
            'provisional_positive':lambda r:next(e for e in r['events'] if e['kind']=='native-request').__setitem__('eligibility','PROVISIONAL'),
        }
        for name, mutate in controls.items():
            with self.subTest(name=name):
                receipt=copy.deepcopy(self.receipt);mutate(receipt)
                with self.assertRaises(self.module.core.Refusal):self.check(receipt)
    def test_log_error_cannot_be_hidden_by_later_positive(self):
        (self.path/'creation.log').write_text('Stale predicated graph registration; explicit refresh required\n')
        with self.assertRaisesRegex(self.module.core.Refusal,'unattributed'):self.check()
    def test_native_start_before_owner_terminal_cannot_be_eligible(self):
        import copy
        receipt=copy.deepcopy(self.receipt)
        start=next(e for e in receipt['events'] if e['kind']=='native-request-start');start['seq']=2.5
        request=next(e for e in receipt['events'] if e['kind']=='native-request')
        request['currentness_evidence']['observed_at_seq']=2.5;request['transaction_evidence']['observed_at_seq']=2.5
        receipt['events'].sort(key=lambda e:e['seq'])
        with self.assertRaisesRegex(self.module.core.Refusal,'before eligible'):self.check(receipt)
    def test_generic_injection_error_must_be_attributed(self):
        (self.path/'creation.log').write_text('ERROR Bad inject context for call-fixup\n')
        with self.assertRaisesRegex(self.module.core.Refusal,'unattributed'):self.check()
    def test_earlier_start_with_later_finish_is_first(self):
        import copy
        receipt=copy.deepcopy(self.receipt)
        start=copy.deepcopy(next(e for e in receipt['events'] if e['kind']=='native-request-start'))
        request=copy.deepcopy(next(e for e in receipt['events'] if e['kind']=='native-request'))
        start.update(seq=3.25,request_id='earlier');request.update(seq=4.25,request_id='earlier')
        request['currentness_evidence']['observed_at_seq']=3.25;request['transaction_evidence']['observed_at_seq']=3.25
        receipt['events'] += [start,request];receipt['events'].sort(key=lambda e:e['seq'])
        with self.assertRaisesRegex(self.module.core.Refusal,'first committed new-domain'):self.check(receipt)
    def test_post_commit_stale_authority_is_not_provisional(self):
        import copy
        receipt=copy.deepcopy(self.receipt)
        identity={**receipt['identity'], 'domain':'view::10', 'carrier':'carrier1'}
        native=copy.deepcopy(next(e for e in receipt['events'] if e['kind']=='native-request'))
        native.update(seq=3.3, request_id='old', identity=identity, eligibility='STALE_AUTHORITY', completed=False, error='Stale predicated graph registration')
        native['currentness_evidence'].update(observed_at_seq=3.1, current=False, disposition='STALE_AUTHORITY', registration_sha256='a'*64)
        native['transaction_evidence'].update(observed_at_seq=3.1)
        receipt['events'] += [dict(seq=3.1,kind='native-request-start',request_id='old',identity=identity), native]
        receipt['events'].sort(key=lambda e:e['seq'])
        receipt['errors']=[dict(line=1,text=native['error'],request_id='old',identity=identity,eligibility='STALE_AUTHORITY')]
        (self.path/'creation.log').write_text(native['error']+'\n')
        self.assertEqual(1,self.check(receipt)['attributed_errors'])
        for mutation in ('provisional', 'current', 'active', 'unbound'):
            changed=copy.deepcopy(receipt)
            request=next(e for e in changed['events'] if e.get('request_id')=='old' and e['kind']=='native-request')
            if mutation=='provisional':
                request['eligibility']='PROVISIONAL';changed['errors'][0]['eligibility']='PROVISIONAL'
            elif mutation=='current':request['currentness_evidence']['current']=True
            elif mutation=='active':request['transaction_evidence']['active']=True
            else:request['currentness_evidence'].pop('registration_sha256')
            with self.subTest(mutation=mutation), self.assertRaises(self.module.core.Refusal):self.check(changed)

    def test_first_new_failure_cannot_be_hidden_as_stale_authority(self):
        import copy
        receipt=copy.deepcopy(self.receipt)
        request=copy.deepcopy(next(e for e in receipt['events'] if e['kind']=='native-request'))
        request.update(seq=3.3,request_id='first-new',eligibility='STALE_AUTHORITY',completed=False,error='Stale predicated graph registration')
        request['currentness_evidence'].update(observed_at_seq=3.1,current=False,disposition='STALE_AUTHORITY',registration_sha256='a'*64)
        request['transaction_evidence']['observed_at_seq']=3.1
        receipt['events'] += [dict(seq=3.1,kind='native-request-start',request_id='first-new',identity=receipt['identity']),request]
        receipt['events'].sort(key=lambda e:e['seq'])
        receipt['errors']=[dict(line=1,text=request['error'],request_id='first-new',identity=receipt['identity'],eligibility='STALE_AUTHORITY')]
        (self.path/'creation.log').write_text(request['error']+'\n')
        with self.assertRaises(self.module.core.Refusal):self.check(receipt)
        request['eligibility']='ELIGIBLE';request['currentness_evidence']['current']=True
        request['error']='';receipt['errors']=[];(self.path/'creation.log').write_text('')
        with self.assertRaisesRegex(self.module.core.Refusal,'first committed new-domain'):self.check(receipt)

    def test_physical_navigation_failure_cannot_pass_full_topology(self):
        import copy
        receipt=dict(process_completion='PASS',later_observations=dict(provider_exceptions=[],unmatched_requests=[]))
        proof=dict(boundaries=[dict(kind='RET_DISPATCH',physical='rom2::5210'),dict(kind='MATCHED_CALL_COMPLETION',physical='rom1::4300')])
        timeline=[dict(kind='physical-target-verified',detail=dict(entry='view::20',target='rom2::5210')),dict(kind='physical-continuation-verified',detail=dict(entry='view::20',target='rom1::4300'))]
        data={'topology-observation.json':receipt,'topology-first-use-proof.json':proof,'timeline.json':timeline}
        def validate(items):return self.module.topology_navigation(self.path,dict(identity=self.receipt['identity']),lambda path:items[path.name])
        self.assertEqual('PASS',validate(data)['status'])
        for mutation in ('timeout','physical_error','unfinished','missing_continuation','wrong_target'):
            changed=copy.deepcopy(data)
            if mutation=='timeout':changed['topology-observation.json']['process_completion']='FAIL'
            elif mutation=='physical_error':changed['topology-observation.json']['later_observations']['provider_exceptions']=['Changed stock carrier storage']
            elif mutation=='unfinished':changed['topology-observation.json']['later_observations']['unmatched_requests']=['native13']
            elif mutation=='missing_continuation':changed['timeline.json'].pop()
            else:changed['timeline.json'][0]['detail']['target']='view::20'
            with self.subTest(mutation=mutation), self.assertRaises(self.module.core.Refusal):validate(changed)

    def test_all_mandatory_roster_rows_remain_incomplete_without_real_execution(self):
        (self.path/'completion-inputs.json').write_text(json.dumps(dict(first='first',second='second',service='service')))
        (self.path/'integrated-acceptance.json').write_text(json.dumps(dict(status='PASS',positive_base_and_sensitive_controls=True,unobstructed_screenshots_reviewed=True,exact_candidate_and_driver_identities_verified=True)))
        result=self.module.completion(self.path)
        self.assertEqual('INCOMPLETE',result['status'])
        self.assertEqual('FAIL',result['rows']['V']['status'])
        for name in self.module.LIFECYCLE_ROWS:self.assertNotEqual('PASS',result['rows'][name]['status'])
    def test_sensitive_replay_refuses_missing_positive_baseline(self):
        with self.assertRaisesRegex(self.module.core.Refusal,'real positive roster'):
            self.module.aggregate_sensitivities(self.path,{}, {})
    def test_boolean_only_review_and_identity_mismatch_rejected(self):
        (self.path/'acceptance-manifest.json').write_text(json.dumps(dict(schema=1,checker_sha256='wrong')))
        with self.assertRaisesRegex(self.module.core.Refusal,'identity mismatch'):
            self.module.acceptance_identities(self.path,{})

if __name__=='__main__':unittest.main()
