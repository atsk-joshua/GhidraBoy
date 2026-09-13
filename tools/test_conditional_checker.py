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

class MapperObservationTest(unittest.TestCase):
    def machine(self, events=(), low=1, high=0, reads=()):
        return SimpleNamespace(low=low,high_bit=high,bank=1,events=list(events),bus_reads=list(reads))
    def test_masked_bank_does_not_hide_changed_high_latch(self):
        raw=self.machine([('mapper',0x2000,2),('mapper',0x2000,1)])
        with self.assertRaisesRegex(core.Refusal,'latch restoration'):
            check.validate_mapper_observation(raw,raw,self.machine(raw.events,high=1))
    def test_wrong_register_missing_restore_and_extra_latch_effect(self):
        raw=self.machine([('mapper',0x2000,2),('mapper',0x2000,1)])
        for events in [[('mapper',0x3000,2),('mapper',0x2000,1)],raw.events[:1],raw.events+[('mapper',0x3000,0)]]:
            with self.assertRaisesRegex(core.Refusal,'ordered mapper bus effects'):
                check.validate_mapper_observation(raw,raw,self.machine(events))
    def test_write_before_use_order_survives_same_final_state_and_value(self):
        raw=self.machine([('mapper',0x2000,2),('write',0xca20,1),('mapper',0x2000,1)])
        check.validate_mapper_observation(raw,raw,raw)
        with self.assertRaisesRegex(core.Refusal,'write moved across mapper'):
            check.validate_mapper_observation(raw,raw,self.machine([*raw.events[::2],raw.events[1]]))
    def test_physical_read_epoch_bytes_and_bank_are_separate(self):
        events=[('mapper',0x2000,2),('mapper',0x2000,1)]
        raw=self.machine(events,reads=[(1,2,0x4000,0x17)])
        check.validate_mapper_observation(raw,raw,raw)
        # Immutable constant folding is permitted; invented retained reads are not.
        check.validate_mapper_observation(raw,raw,self.machine(events))
        for read in [(0,2,0x4000,0x17),(1,1,0x4000,0x17),(1,2,0x4000,0x18)]:
            with self.assertRaisesRegex(core.Refusal,'physical read moved'):
                check.validate_mapper_observation(raw,raw,self.machine(events,reads=[read]))

if __name__=='__main__':unittest.main()
