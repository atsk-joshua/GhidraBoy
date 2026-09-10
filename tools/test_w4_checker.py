import unittest
from check_w4_memory_images import Machine,core

class MemoryBindingTests(unittest.TestCase):
    def machine(self):
        return Machine(bytes(65536),0x53,(0xc800,0x190,0,0x53,0xa6,0xbeef),{'spaces':[{'id':42,'name':'ram','addressable_unit':1}]})
    def node(self,space,offset,size=1,constant=False):
        return {'id':offset,'space':space,'offset':offset,'size':size,'constant':constant}
    def load(self,space=42,width=2):
        return {'mnemonic':'LOAD','inputs':[self.node('const',space,4,True),self.node('const',0xc060,width,True)],'output':self.node('register',1)}
    def test_runtime_memory_is_only_input(self):
        m=self.machine();self.assertNotEqual(m.register(3),0x53);m.ordinary(self.load());self.assertEqual(m.register(1),0x53)
    def test_same_offset_distinct_space_is_not_repaired(self):
        with self.assertRaises(core.Refusal):self.machine().ordinary(self.load(43))
    def test_widened_cpu_pointer_refuses(self):
        with self.assertRaises(core.Refusal):self.machine().ordinary(self.load(width=4))
    def test_echo_has_same_runtime_backing(self):
        m=self.machine();m.store(0xe060,1,0xa7);self.assertEqual(m.load(0xc060,1),0xa7)
    def test_direct_wrong_space_is_not_an_alias(self):
        with self.assertRaises(core.Refusal):self.machine().get(self.node('distinct_storage',0xc060))
    def test_highglobal_cannot_correct_wrong_actual_storage(self):
        n=self.node('ram',0xc061);n['high_global']={'space':'ram','offset':0xc060,'size':1}
        with self.assertRaises(core.Refusal):self.machine().put(n,0x53,{})

    def test_ssa_global_association_is_not_an_actual_memory_write(self):
        m=self.machine();n=self.node('unique',123);n['high_global']={'space':'ram','offset':0xc060,'size':1}
        m.put(n,0xa7,{})
        self.assertEqual(m.mem[0xc060],0x53)
