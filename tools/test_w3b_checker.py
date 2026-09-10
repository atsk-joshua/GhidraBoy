"""Sensitive bounded HighFunction loop checks independent of the Java producer."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import check_predicated_calls as core
import check_w3b_cfg as checker
from check_w3b_cfg import DomainMachine

def node(identity,size=1,constant=None):
    return {'id':identity,'size':size,'space':'const' if constant is not None else 'unique','offset':constant if constant is not None else identity*8,'constant':constant is not None,'address':False,'register':False}
def op(code,inputs,output=None):return {'mnemonic':code,'inputs':inputs,'output':output}
class CyclicHighFunctionTest(unittest.TestCase):
    def graph(self):
        x,y,n,xphi,yphi,nphi,left,cond,pair=[node(i,2 if i==18 else 1) for i in range(10,19)]
        blocks=[{'index':0,'in':[],'out':[1],'ops':[op('COPY',[node(1,constant=1)],x),op('COPY',[node(2,constant=2)],y),op('COPY',[node(3,constant=2)],n)]},
                {'index':1,'in':[0,1],'out':[2,1],'ops':[op('MULTIEQUAL',[x,yphi],xphi),op('MULTIEQUAL',[y,xphi],yphi),op('MULTIEQUAL',[n,left],nphi),op('INT_SUB',[nphi,node(4,constant=1)],left),op('INT_NOTEQUAL',[left,node(5,constant=0)],cond),op('CBRANCH',[node(6,constant=0),cond])]},
                {'index':2,'in':[1],'out':[],'ops':[op('PIECE',[xphi,yphi],pair),op('RETURN',[node(7,constant=0),pair])]}]
        return SimpleNamespace(high={'root':blocks},requests={'root':{'parameters':[]}})
    def test_phi_inputs_are_parallel_and_predecessor_sensitive(self):
        self.assertEqual(0x0201,core.Machine(bytes(65536),0).high(self.graph()))
    def test_missing_loop_edge_refuses(self):
        cap=self.graph();cap.high['root'][1]['out']=[2]
        with self.assertRaises(core.Refusal):core.Machine(bytes(65536),0).high(cap)
    def test_wrong_predecessor_refuses_undefined_phi(self):
        cap=self.graph();cap.high['root'][1]['in'].reverse()
        with self.assertRaises(core.Insufficient):core.Machine(bytes(65536),0).high(cap)
class DomainCallEffectsTest(unittest.TestCase):
    def test_disjoint_output_write_preserves_frame_but_frame_write_refuses(self):
        machine=DomainMachine(bytes(65536),0,0x190);frame={'space':'ram','offset':0xc0fe,'size':1}
        data=node(31);data.update(space='ram',offset=0xc210)
        child=[op('COPY',[node(32,constant=0x33)],data)]
        machine.require_indirect_preservation(frame,[],child)
        data['offset']=0xc0fe
        with self.assertRaises(core.Insufficient):machine.require_indirect_preservation(frame,[],child)
        data['high_global']={'space':'ram','offset':0xc210,'size':1}
        with self.assertRaises(core.Insufficient):machine.require_indirect_preservation(frame,[],child)
    def test_only_closed_callee_can_ignore_inferred_actual_arguments(self):
        machine=DomainMachine(bytes(65536),0,0x190)
        cap=SimpleNamespace(high={'leaf':[{'ops':[op('COPY',[node(40,constant=0x33)],node(41))]}]})
        self.assertEqual([],machine.native_arguments(cap,'leaf',[2,0x4100,0,0],[]))
        cap.high['leaf'][0]['ops'][0]['inputs']=[node(42)]
        with self.assertRaises(core.Insufficient):machine.native_arguments(cap,'leaf',[2,0x4100,0,0],[])

class DomainPersistenceAcceptanceTest(unittest.TestCase):
    """Isolate the full-checker evidence gates from the separately tested semantic oracle."""
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.root=Path(temporary.name)
        self.domains=['a'*64,'b'*64]
        self.rows=[{'domain':self.domains[0],'flags':0,'C210':0x33,'bank':3,'outer_return_words':3},
                   {'domain':self.domains[1],'flags':0x80,'C210':0x22,'bank':2,'outer_return_words':3}]
        self.stages={label:{'status':'PASS','same_physical_site':'0200','domains':copy.deepcopy(self.rows)} for label in ['forward','reverse','reopened']}
        self.stages['reverse']['domains'].reverse()
        self.files={
            'persisted-identity.json':{'programId':91,'javaPid':100},
            'reopen-compatibility.json':{'programId':91,'javaPid':101,'version':'software-call-domains-2','registrationUnchanged':True,'readOnly':True},
            'site-only-negative.json':{'rejected':True},
            'stale-domains.json':[{'domain':domain,'reason':'Stale software-call domains'} for domain in self.domains],
            **{f'stale-{domain[:12]}-request.json':{'completed':False,'highfunction_available':False,'error':'Stale software-call domains'} for domain in self.domains}}
        self.reset_files()
    def reset_files(self):
        for name,value in self.files.items():self.write(name,value)
        for name in ['persisted-registration.json','reopened-registration.json']:(self.root/name).write_bytes(b'{"authority":"unchanged"}')
        (self.root/'original-image.gb').write_bytes(b'synthetic image')
    def write(self,name,value):(self.root/name).write_text(json.dumps(value))
    def run_checker(self):
        with patch.object(checker.core,'Capture',side_effect=lambda root,label:label),patch.object(checker,'domains_stage',side_effect=lambda cap,image:self.stages[cap]) as stage:
            result=checker.run(self.root,'domains')
            self.assertEqual(['forward','reverse','reopened'],[call.args[0] for call in stage.call_args_list])
            return result
    def test_complete_workflow_compares_semantics_by_domain(self):
        result=self.run_checker()
        self.assertEqual('PASS',result['persistence']['status'])
        self.assertEqual(self.stages['reopened'],result['reopened'])
    def test_reopened_relation_change_or_missing_domain_refuses(self):
        original=copy.deepcopy(self.stages['reopened'])
        for mutation in ['output','identity','missing','duplicate']:
            with self.subTest(mutation=mutation):
                self.stages['reopened']=copy.deepcopy(original);rows=self.stages['reopened']['domains']
                if mutation=='output':rows[0]['C210']=0x22
                elif mutation=='identity':rows[0]['domain']='c'*64
                elif mutation=='missing':rows.pop()
                else:rows[1]=copy.deepcopy(rows[0])
                with self.assertRaises(core.Refusal):self.run_checker()
    def test_registration_byte_change_refuses_even_with_same_json(self):
        (self.root/'reopened-registration.json').write_bytes(b'{ "authority": "unchanged" }')
        with self.assertRaisesRegex(core.Refusal,'registration changed'):self.run_checker()
    def test_readonly_identity_and_version_evidence_are_required(self):
        for field,value in [('readOnly',False),('registrationUnchanged',False),('programId',92),('javaPid',100),('javaPid',0),('version','software-call-domains-1')]:
            with self.subTest(field=field,value=value):
                self.reset_files();opened=dict(self.files['reopen-compatibility.json']);opened[field]=value;self.write('reopen-compatibility.json',opened)
                with self.assertRaises(core.Refusal):self.run_checker()
    def test_stale_controls_must_cover_both_checked_domains(self):
        valid=self.files['stale-domains.json']
        for refusals in [[],valid[:1],[valid[0],valid[0]],[valid[0],{'domain':'c'*64,'reason':'Stale'}],[valid[0],{'domain':self.domains[1],'reason':'unrelated failure'}]]:
            with self.subTest(refusals=refusals):
                self.write('stale-domains.json',refusals)
                with self.assertRaises(core.Refusal):self.run_checker()
    def test_each_stale_native_request_must_refuse_without_highfunction(self):
        for domain in self.domains:
            name=f'stale-{domain[:12]}-request.json'
            for field,value in [('completed',True),('highfunction_available',True),('error','unrelated failure')]:
                with self.subTest(domain=domain,field=field):
                    self.reset_files();request=dict(self.files[name]);request[field]=value;self.write(name,request)
                    with self.assertRaisesRegex(core.Refusal,'native stale domain'):self.run_checker()
    def test_missing_reopen_and_native_stale_evidence_cannot_pass(self):
        for name in ['reopened-registration.json','reopen-compatibility.json','persisted-identity.json',f'stale-{self.domains[1][:12]}-request.json']:
            with self.subTest(name=name):
                self.reset_files();(self.root/name).unlink()
                with self.assertRaises(FileNotFoundError):self.run_checker()
if __name__=='__main__':unittest.main()
