"""Native collateral effects must fail even if the selected scalar is unchanged."""
import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
import check_finite_dispatch as checker
import check_predicated_calls as core

class NativeEffectsTest(unittest.TestCase):
    def machine(self):
        return SimpleNamespace(events=[],mem={},outputs={})
    def test_extra_store_and_restore_fail(self):
        for values in ([0x55],[0x55,0]):
            raw=self.machine();native=self.machine()
            raw.mem[0xc001]=native.mem[0xc001]=0
            native.events=[('write',0xc001,v) for v in values]
            with self.assertRaisesRegex(core.Refusal,'extra native architectural write'):
                checker.require_native_effects(raw,native)
    def test_reordered_disjoint_writes_and_forwarded_stack_are_valid(self):
        raw=self.machine();native=self.machine()
        raw.events=[('write',0xc100,1),('write',0xc101,2),('write',0xc900,3)]
        native.events=[('write',0xc101,2),('write',0xc100,1)]
        raw.mem={0xc100:1,0xc101:2,0xc900:3};native.mem={0xc100:1,0xc101:2}
        checker.require_native_effects(raw,native,{0xc900})
    def test_duplicate_observable_write_fails(self):
        raw=self.machine();native=self.machine()
        raw.events=[('write',0xc100,1)];native.events=raw.events*2
        raw.mem=native.mem={0xc100:1}
        with self.assertRaises(core.Refusal):checker.require_native_effects(raw,native)
    def test_missing_nonframe_collateral_write_fails(self):
        raw=self.machine();native=self.machine()
        raw.events=[('write',0xc001,0x55)];raw.mem={0xc001:0x55}
        with self.assertRaisesRegex(core.Refusal,'missing native collateral storage'):
            checker.require_native_effects(raw,native)
    def test_source_address_copy_is_not_ssa_forwarding(self):
        machine=core.Machine(bytes(65536),0);machine.mem[0xc060]=0x44
        v=dict(id=91,space='ram',offset=0xc060,size=1,constant=False)
        op=dict(mnemonic='COPY',output=v,inputs=[dict(v,id=92)],sequence='(ram, 0x100, 1, 1)')
        machine.ordinary(op,{},dict(machine.reg))
        self.assertEqual([('write',0xc060,0x44)],machine.events)
    def test_unique_global_association_does_not_write(self):
        machine=core.Machine(bytes(65536),0)
        v=dict(id=91,space='unique',offset=123,size=1,high_global=dict(space='ram',offset=0xc060,size=1))
        machine.put(v,0x44,{})
        self.assertEqual([],machine.events)
        v.update(space='ram',offset=0xc060)
        machine.put(v,0x44,{})
        self.assertEqual([('write',0xc060,0x44)],machine.events)

class PhysicalDebugBindingTest(unittest.TestCase):
    def test_overlay_name_and_id_must_agree(self):
        xml = '<root><injectdebug><inject name="gb_analysis_entry_v1"><addr space="owned" offset="0x100"/><payload>&lt;pcode&gt;&lt;op code="LOAD"&gt;&lt;addr space="unique" offset="0x1" size="1"/&gt;&lt;spaceid name="rom2"/&gt;&lt;addr space="const" offset="0x4123" size="2"/&gt;&lt;/op&gt;&lt;/pcode&gt;</payload></inject></injectdebug></root>'
        emitted=[dict(mnemonic='LOAD',output=dict(space='unique',offset=1,size=1),inputs=[dict(space='const',offset=123,size=4,constant=True),dict(space='const',offset=0x4123,size=2,constant=True)])]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'debug.xml';path.write_text(xml)
            core.base.debug_identity(path,emitted,'owned::0100','gb_analysis_entry_v1',{'rom2':123})
            with self.assertRaisesRegex(core.Refusal,'physical space binding'):
                core.base.debug_identity(path,emitted,'owned::0100','gb_analysis_entry_v1',{'rom2':456,'rom1':123})
            with self.assertRaisesRegex(core.Refusal,'physical space binding'):
                core.base.debug_identity(path,emitted,'owned::0100','gb_analysis_entry_v1',{'rom1':123})

if __name__=='__main__':unittest.main()
