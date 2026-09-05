"""Reuse the supplied pure decoders, gated on the exact reviewed ROM hash."""
import importlib.util
from pathlib import Path
import sys
from .native import PROFILE,ROOT

def load_legacy(name):
    if name in sys.modules:return sys.modules[name]
    file=ROOT/'legacy/gbw3-live-lab'/f'{name}.py'
    spec=importlib.util.spec_from_file_location(name,file);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module
class Profile:
    def __init__(self,machine):
        if machine.rom_hash!=PROFILE:raise ValueError('ROM does not match reviewed GBW3 profile')
        core=load_legacy('gbw3_core');self.lab=load_legacy('gbw3_lab');self.tables=core.inspect_rom(machine.rom_bytes)
        if machine.rom_bytes[18*16384+0xb5]!=0x70:raise ValueError('Expected LD (HL),B writer opcode absent')
    def capture(self,c):
        raw=c.bank_bytes('wram',3);combat=c.bank_bytes('wram',4)
        return {'units':[self.lab.decode_unit(raw[i*16:(i+1)*16],i,self.tables) for i in range(100)],'combat':{k:combat[a-0xd000] for k,a in self.lab.COMBAT.items()},'precision':'stopped instruction boundary','battle_verified':False}
