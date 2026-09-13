import copy,unittest
from types import SimpleNamespace
import check_conditional_calls as check
import check_predicated_calls as core

def const(v):return dict(kind='CONSTANT',width=1,constant=v,opcode=0,inputs=[],table=[])
def inp(name):return dict(kind='INPUT',width=1,input=name,constant=0,opcode=0,inputs=[],table=[])
class BoundaryAuthorityTest(unittest.TestCase):
    def proof(self):
        regs=[dict(offset=i,origin=inp('scope:entry-register-byte@'+str(i))) for i in range(2,8)]
        memory=inp('scope:entry-memory:WRAM:c930@0');physical=dict(region='WRAM',bank=0,offset=0x930)
        entry=dict(kind='CALL_SITE_ENTRY',registers=copy.deepcopy(regs))
        done=dict(kind='MATCHED_CALL_COMPLETION',registers=copy.deepcopy(regs)+[dict(offset=0,origin=const(128))],memory=[dict(physical=physical,value=memory)])
        post=dict(kind='ANALYSIS_BOUNDARY',node='load',registers=copy.deepcopy(done['registers'])+[dict(offset=1,origin=memory)])
        node=dict(id='load',memoryAccesses=[dict(kind='READ',physical=physical,value=memory)])
        return dict(boundaries=[entry,done,post],nodes=[node])
    def test_linked_unknown_memory_and_preserved_origins(self):check.validate_post_link(self.proof())
    def test_unrelated_unknown_or_constant_result_refuses(self):
        for origin in [inp('other:unknown@0'),const(0)]:
            p=self.proof();p['boundaries'][2]['registers'][-1]['origin']=origin
            with self.assertRaisesRegex(core.Refusal,'not linked'):check.validate_post_link(p)
    def test_replaced_flags_and_registers_refuse(self):
        for offset in [0,2,7]:
            p=self.proof();next(b for b in p['boundaries'][2]['registers'] if b['offset']==offset)['origin']=const(0)
            with self.assertRaises(core.Refusal):check.validate_post_link(p)
    def test_wrong_serialized_value_fails_independent_raw_boundary(self):
        b=dict(spDelta=0,cpu=0x1234,mapper=dict(low=1,high=0),registers=[dict(offset=1,origin=const(3))],stack=[],memory=[])
        observed=dict(sp=0,cpu=0x1234,low=1,high=0,reg={1:4},mem={})
        with self.assertRaisesRegex(core.Refusal,'register origin differs'):check.validate_boundary(b,observed,None,{})
if __name__=='__main__':unittest.main()
