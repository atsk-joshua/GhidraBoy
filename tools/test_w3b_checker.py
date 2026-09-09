"""Sensitive bounded HighFunction loop checks independent of the Java producer."""
import unittest
from types import SimpleNamespace
import check_predicated_calls as core
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
if __name__=='__main__':unittest.main()
