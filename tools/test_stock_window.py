"""Independent malformed-evidence controls; GUI relations use captured sensitivity."""
import json
from pathlib import Path
import tempfile
import unittest
import check_stock_window as window


class StockWindowEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.record = dict(phase='P2', surface='normal-CodeBrowser-DecompilerProvider',
                           visible=True, program_id=12, entry='gb_ordinary_150::0150',
                           display_program_id=12, display_entry='gb_ordinary_150::0150',
                           display_program_matches=True, display_function_matches=True,
                           completed=False, highfunction_available=False,
                           error='Stale ordinary-entry registration; preview and refresh required')
        (self.root / 'P2-desktop.png').write_bytes(b'evidence-file-for-integrity-test')
        self.record['desktop_sha256'] = window.finite.sha(self.root / 'P2-desktop.png')
        self.write()

    def write(self, bind=True):
        (self.root / 'P2-request.json').write_text(json.dumps(self.record))
        if bind:
            (self.root / 'timeline.json').write_text(json.dumps([
                dict(kind='passive-capture', detail=dict(phase='P2', record_sha256=window.finite.sha(self.root / 'P2-request.json')))]))

    def test_expected_refusal_with_bound_identity(self):
        window.refusal(window.checked_record(self.root, 'P2'))

    def test_foreign_error_identity(self):
        self.record['display_program_id'] = 13
        self.write()
        with self.assertRaisesRegex(window.finite.Refusal, 'foreign displayed identity'):
            window.checked_record(self.root, 'P2')

    def test_native_crash_is_not_authority_refusal(self):
        self.record['error'] = 'Native process unexpectedly terminated'
        self.write()
        with self.assertRaisesRegex(window.finite.Refusal, 'wrong authority refusal'):
            window.refusal(window.checked_record(self.root, 'P2'))

    def test_missing_desktop_key(self):
        del self.record['desktop_sha256']
        self.write()
        with self.assertRaisesRegex(window.finite.Refusal, 'missing actual screenshot'):
            window.checked_record(self.root, 'P2')

    def test_request_edit_without_new_receipt(self):
        self.record['error'] += ' edited'
        self.write(bind=False)
        with self.assertRaisesRegex(window.finite.Refusal, 'changed request receipt'):
            window.checked_record(self.root, 'P2')

    def test_changed_desktop_bytes(self):
        (self.root / 'P2-desktop.png').write_bytes(b'replacement')
        with self.assertRaisesRegex(window.finite.Refusal, 'changed artifact'):
            window.checked_record(self.root, 'P2')



class OperationProtocolTests(unittest.TestCase):
    """Synthetic schedules only: do not stand in for a real Program callback."""
    def fixture(self, before_return):
        target=dict(program_id=1,program_object=2,owner_java_pid=3)
        tx=dict(id=101,description='test outer',active=True,status='NOT_DONE',open_subtransactions=['owned'],db_committed=False)
        base=dict(operation='P-mutation#1',target=target,subtransaction=0,encompassing=tx,pre_revision=4,revision=4,pre_events=2)
        def item(kind,detail):return dict(schema=2,kind=kind,detail=detail)
        import copy
        started=copy.deepcopy(base);entry=copy.deepcopy(base);entry.update(commit_requested=True,revision=5,affected_start='rom3:6000')
        returned=copy.deepcopy(entry);returned.update(returned_committed=True);returned['encompassing'].update(active=False,status='COMMITTED',open_subtransactions=[],db_committed=True)
        event=item('program-event',dict(target=target,revision=5,event_sequence=3,records=[dict(type='MEMORY_BYTES_CHANGED',start='rom3:6000',end='rom3:6000')]))
        ts=[item('operation-begin',dict(operation='P-mutation#1',purpose='P-mutation',target=target,pre_revision=4,pre_events=2)),item('operation-started',started),item('commit-call-enter',entry)]
        if before_return:ts.append(event)
        ts.append(item('commit-call-return',returned))
        if not before_return:ts.append(event)
        ts.extend([item('operation-settled',copy.deepcopy(returned)),item('settled',dict(target=target,entry='carrier:0150',stable_samples=24,transaction_free=True,revision=5,events=3,data_identity=44)),item('passive-capture',dict(phase='P2'))])
        for i,x in enumerate(ts):x['nano']=100+i;x['sequence']=1+i
        record=dict(target,revision=5,events=3,transaction_free=True,data_identity=44,entry='carrier:0150')
        return ts,record

    def test_both_callback_orders(self):
        for order in (True,False):
            with self.subTest(before_return=order):
                ts,r=self.fixture(order);result=window.correlated_operation(ts,'P-mutation',r,'P2')
                self.assertEqual(order,result['callback_before_return_receipt'])

    def test_encompassing_commit_after_nested_return(self):
        ts,r=self.fixture(True)
        ret=next(x['detail'] for x in ts if x['kind']=='commit-call-return')
        ret['returned_committed']=False;ret['encompassing'].update(active=True,status='NOT_DONE',db_committed=False,open_subtransactions=['other tool work'])
        self.assertFalse(window.correlated_operation(ts,'P-mutation',r,'P2')['returned_committed'])

    def test_protocol_negative_controls(self):
        import copy
        for control in ('missing-event','foreign-event','old-event','wrong-range','wrong-type','abort','uncommitted','wrong-operation','early-capture','active-refresh','foreign-settlement','active-transaction'):
            with self.subTest(control=control):
                ts,r=self.fixture(True)
                e=next(x for x in ts if x['kind']=='program-event');done=next(x for x in ts if x['kind']=='operation-settled')
                if control=='missing-event':ts.remove(e)
                elif control=='foreign-event':e['detail']['target']=dict(program_id=90,program_object=91,owner_java_pid=3)
                elif control=='old-event':e['detail']['revision']=4
                elif control=='wrong-range':e['detail']['records'][0]['start']='ram:c200'
                elif control=='wrong-type':e['detail']['records'][0]['type']='RENAMED'
                elif control=='abort':next(x for x in ts if x['kind']=='commit-call-enter')['detail']['commit_requested']=False
                elif control=='uncommitted':done['detail']['encompassing']['status']='NOT_DONE'
                elif control=='wrong-operation':done['detail']['operation']='Q-mutation#1'
                elif control=='early-capture':ts.insert(3,ts.pop())
                elif control=='active-refresh':ts.insert(-1,dict(kind='refresh',detail={}))
                elif control=='foreign-settlement':next(x for x in ts if x['kind']=='settled')['detail']['target']={}
                elif control=='active-transaction':r['transaction_free']=False
                with self.assertRaises(window.finite.Refusal):window.correlated_operation(ts,'P-mutation',r,'P2')

    def test_nested_commit_between_return_and_receipt(self):
        ts,r=self.fixture(True)
        next(x['detail'] for x in ts if x['kind']=='commit-call-return')['returned_committed']=False
        self.assertFalse(window.correlated_operation(ts,'P-mutation',r,'P2')['returned_committed'])

    def test_property_events_are_option_specific(self):
        for purpose in ('proof-write','variant-proof-write','registration-removal','Q-generation'):
            ts,r=self.fixture(True)
            option=('GhidraBoyStockPredicatedCalls.' if purpose=='Q-generation' else 'GhidraBoyStockOrdinaryEntries.')+r['entry']
            for x in ts:
                if 'operation' in x['detail']:x['detail']['operation']=purpose+'#1'
                if 'purpose' in x['detail']:x['detail']['purpose']=purpose
            e=next(x for x in ts if x['kind']=='program-event')
            e['detail']['records']=[dict(type='PROPERTY_CHANGED',old=option,new='null' if purpose=='registration-removal' else 'payload')]
            window.correlated_operation(ts,purpose,r,'P2')
            e['detail']['records'][0]['old']='Program Information.Analysis Times.Times'
            with self.assertRaisesRegex(window.finite.Refusal,'no correlated real event'):
                window.correlated_operation(ts,purpose,r,'P2')

if __name__ == '__main__':
    unittest.main()
