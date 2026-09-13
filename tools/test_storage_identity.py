import unittest
from types import SimpleNamespace
import check_predicated_calls as core

class StorageIdentityTest(unittest.TestCase):
    def value(self):
        return dict(id=1,space='ram',offset=0xc061,size=1,constant=False,high_global=dict(space='ram',offset=0xc060,size=1))
    def test_get_validates_before_cache_hit(self):
        for cache in [{},{1:42}]:
            m=core.Machine(bytes(65536),0)
            with self.assertRaisesRegex(core.Refusal,'actual storage contradicts'):m.get(self.value(),cache)
    def test_put_does_not_redirect_or_mutate_cache(self):
        m=core.Machine(bytes(65536),0);env={};before=dict(m.mem)
        with self.assertRaises(core.Refusal):m.put(self.value(),42,env)
        self.assertEqual({},env);self.assertEqual(before,m.mem)
    def test_indirect_and_forwarding_validate_before_shortcuts(self):
        for kind in ['INDIRECT','COPY','CALL']:
            m=core.Machine(bytes(65536),0);v=self.value()
            op=dict(mnemonic=kind,output=v,inputs=[dict(v,id=2)],sequence='(owned, 0x100, 9999, 1)')
            cap=SimpleNamespace(high={'root':[dict(index=0,ops=[op,dict(mnemonic='RETURN',inputs=[],output=None)],**{'in':[],'out':[]})]},requests={'root':{}},requested={'root':[]})
            with self.assertRaisesRegex(core.Refusal,'actual storage contradicts'):m.high(cap)
    def test_unique_association_is_temporary_and_partial_is_explicit(self):
        m=core.Machine(bytes(65536),0);v=self.value();v['space']='unique';m.put(v,42,{})
        self.assertEqual([],m.events)
        v=self.value();v['high_global']['size']=2
        with self.assertRaises(core.Insufficient):m.get(v,{1:42})
    def test_matching_byte_association_uses_actual_storage(self):
        m=core.Machine(bytes(65536),0);v=self.value();v['offset']=0xc060
        m.put(v,42,{});self.assertEqual(42,m.mem[0xc060]);self.assertNotIn(0xc061,m.mem)

class NativeIdentityTest(unittest.TestCase):
    def test_emulation_requires_parent_elf_argv_and_executable_mapping(self):
        p=dict(parent=17,argv_native_files=[dict(path='/runtime/decompile',sha256='official')],proc_cmdline='/runtime/decompile ',proc_maps='100-200 r-xp 0 0:0 1 /runtime/decompile')
        self.assertTrue(core.actual_native_process(p,17,{'official'}))
        for change in [dict(parent=18),dict(proc_cmdline='/other/decompile '),dict(proc_maps='100-200 r--p 0 0:0 1 /runtime/decompile'),dict(argv_native_files=[dict(path='/runtime/decompile',sha256='foreign')])]:
            self.assertFalse(core.actual_native_process(dict(p,**change),17,{'official'}))

if __name__=='__main__':unittest.main()
