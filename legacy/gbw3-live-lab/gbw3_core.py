"""Core routines for the reviewed student GZF ROM version.
Read-only ROM inspection and isolated execution of identified GBW3 routines.
Python 3.10+. `inspect` uses the standard library; `verify` requires PyBoy 2.7.0.
ROM overrides during verification exist only in emulator memory.
"""
from pathlib import Path
import argparse, hashlib, json, random, io
SHA256 = 'e779a6b56575a2afafb7e1e99411b23d7400a8fddbda8bd52c660b7903c3b451'

def decode(values):
    glyphs = {0x80:' ', 0x7c:'*', 0xa7:'-', 0xa6:'/', 0x79:'(', 0x7a:')'}
    return ''.join(chr(v-0x8b+65) if 0x8b <= v <= 0xa4 else glyphs.get(v, f'<{v:02X}>') for v in values).rstrip()

def inspect_rom(rom):
    units=[]
    for i in range(53):
        off=0x48aad+37*i;b=rom[off:off+37]
        assert int.from_bytes(rom[0x48a43+2*i:0x48a45+2*i],'little') == off % 0x4000+0x4000
        units.append(dict(index=i,rom_offset=f'0x{off:06X}',name=decode(b[:10]),max_hp=b[10],fuel=b[11],movement=b[12],funds_raw=int.from_bytes(b[16:18],'little'),materials_raw=int.from_bytes(b[18:20],'little'),weapon_1=b[20],ammo_1=b[21],weapon_2=b[22],ammo_2=b[23],target_class=b[24],defense_by_attacker_class=list(b[30:35]),initiative=b[35],initiative_cost=b[36],raw_hex=b.hex(' ')))
    weapons=[]
    for i in range(33):
        off=0x49298+16*i;b=rom[off:off+16]
        assert int.from_bytes(rom[0x49256+2*i:0x49258+2*i],'little') == off%0x4000+0x4000
        weapons.append(dict(index=i,rom_offset=f'0x{off:06X}',name=decode(b[:8]),range_min=b[8],range_max=b[9],attack_by_target_class=list(b[10:15]),unknown_15=b[15],raw_hex=b.hex(' ')))
    return dict(sha256=hashlib.sha256(rom).hexdigest(),size_bytes=len(rom),class_order=['armored land','soft land','air','ship','submarine'],notes=['Class names are semantic labels inferred from roster and lookup code.','* denotes glyph 0x7C; other undecoded glyphs remain <XX>.','Special action weapons with zero ordinary attack values require separate handlers.','funds_raw is stored in hundreds of displayed funds; UI conversion not exhaustively traced.'],units=units,weapons=weapons)

def modifier(rank,bonus,flank,defense=False):
    if defense:rank,bonus,flank=rank//2,bonus//2,flank//2
    return ((100+rank+bonus-flank)*256)//100

def remaining_hp(hp,attack,attacker_hp,defense,rank=0,support=0,flank=0,defender_rank=0,terrain=0,defender_flank=0):
    """Ordinary strike, valid positive defense and normal-range inputs.
    Integer reconstruction of 0C:4A26; returns remaining defender HP.
    Does not resolve weapon eligibility, terrain IDs, neighbors or special attacks.
    """
    if defense <= 0:raise ValueError('Resolve attack eligibility before damage; defense must be positive.')
    attack_power=attacker_hp*attack*modifier(rank,support,flank)//256
    defense_power=2*hp*defense*modifier(defender_rank,terrain,defender_flank,True)//256
    return min(hp,max(0,(defense_power-attack_power+2*defense-1)//(2*defense)))

class Harness:
    def __init__(self,path):
        from pyboy import PyBoy
        self.p=PyBoy(io.BytesIO(Path(path).read_bytes()),window='null',sound_emulated=False)
        p=self.p;p.set_emulation_speed(0)
        # Run normal emulator boot into an isolated, LCD-enabled idle loop.
        p.memory[0,0x100:0x104]=[0xc3,0x50,1,0]
        p.memory[0,0x150:0x157]=[0xf3,0x3e,0x91,0xe0,0x40,0x18,0xfe]
        p.tick(150,False)
        p.memory[0,0x100:0x103]=[0xc3,0,1]
    def call(self,addr,regs=None,mem=None,bank=12):
        p=self.p;p.memory[0xffff]=0;p.memory[0xff0f]=0
        p.memory[0x2000]=bank;p.memory[0xff80]=bank;p.memory[0xff70]=4;p.memory[0xff82]=4
        for k,v in (mem or {}).items():p.memory[k]=v
        q=p.register_file
        for k in ['A','F','B','C','D','E','HL']:setattr(q,k,0)
        for k,v in (regs or {}).items():setattr(q,k,v)
        q.SP=0xcff0;p.memory[0xcff0:0xcff2]=[0,1];q.PC=addr
        p.tick(1,False)
        assert q.PC==0x100, f'Unexpected return PC: {q.PC:04X}'
        return {k:getattr(q,k) for k in ['A','F','B','C','D','E','HL','SP','PC']}
    def close(self):self.p.stop(save=False)

def verify(path):
    h=Harness(path)
    try:
        for v in range(256):assert h.call(0x484a,{'A':v})['A']==max(1,(v//10)*10)
        for addr,half in [(0x49a2,False),(0x49cc,True)]:
            for a,b,c in [(0,0,0),(10,20,30),(70,40,50),(30,10,25)]:
                assert h.call(addr,{'A':a,'B':b,'C':c})['HL']==modifier(a,b,c,half)
        rng=random.Random(3)
        for _ in range(150):
            hp,ahp=rng.randint(1,10),rng.randint(1,10)
            atk,df=rng.randint(1,99),rng.randint(1,80)
            rank,drank=rng.choice([0,10,20,30,40]),rng.choice([0,10,20,30,40])
            support=rng.randint(0,50);flank,dflank=rng.choice([0,25,35,50]),rng.choice([0,25,35,50]);terrain=rng.choice([0,10,20,30,40,50,70])
            m={0xdbd7:rank,0xdbd8:flank,0xdbd9:support,0xdbd4:atk,0xdbd3:ahp,0xdbec:drank,0xdbed:dflank,0xdbeb:terrain,0xdbea:df,0xdbe8:hp}
            want=remaining_hp(hp,atk,ahp,df,rank,support,flank,drank,terrain,dflank)
            assert h.call(0x4a26,mem=m)['A']==want
        base={0xdbd7:0,0xdbd8:0,0xdbd9:0,0xdbd4:10,0xdbd3:10,0xdbec:0,0xdbed:0,0xdbeb:0,0xdbea:10,0xdbe8:10,0xdbe9:10,0xdbd5:10,0xdbd6:0,0xdbee:0}
        order=[]
        for a,b,want in [(10,10,(5,5)),(10,1,(8,5)),(1,10,(5,8))]:
            h.call(0x4b0a,mem=base|{0xdbcf:a,0xdbe4:b})
            got=(h.p.memory[0xdbd3],h.p.memory[0xdbe8]);assert got==want
            order.append(dict(attacker_initiative_band=a,defender_initiative_band=b,attacker_hp=got[0],defender_hp=got[1]))
        return dict(passed=True,initiative_inputs=256,damage_inputs=150,modifier_inputs=8,order_cases=order,scope='Isolated original ROM routines with synthetic inputs; not complete map battles.')
    finally:h.close()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rom',type=Path);parser.add_argument('action',choices=['inspect','verify'])
    args=parser.parse_args();rom=args.rom.read_bytes()
    if hashlib.sha256(rom).hexdigest()!=SHA256:parser.error('ROM hash differs from the analyzed upload; offsets may not match.')
    print(json.dumps(inspect_rom(rom) if args.action=='inspect' else verify(args.rom),indent=2))
    assert hashlib.sha256(args.rom.read_bytes()).hexdigest()==SHA256
if __name__=='__main__':main()
