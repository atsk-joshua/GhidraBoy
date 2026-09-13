#!/usr/bin/env python3
"""Retained self-authored switch bytes in a normal MBC5 cartridge envelope."""
import argparse
import hashlib
import json
from pathlib import Path

NORMALIZED = bytes.fromhex('fa80fffe063803afc9d30600fe0338060603d6031800210002856f7cce00677e3d8021030287856f7cce00672a666fe9')
NIBBLE = bytes.fromhex('7ee6f0cb37875f16002ae5e60f210002195e2356626be9')

def fixtures(source, output):
    output.mkdir(parents=True, exist_ok=True)
    base = (source/'src/test/resources/ordinary/PREDICATED_CALLS.gb').read_bytes()
    result = {}
    for name, nibble, relocated in [('normalized',False,False),('normalized-relocated',False,True),('nibble',True,False),('nibble-relocated',True,True)]:
        data = bytearray([0xd3] * len(base))
        data[0x134:0x150] = base[0x134:0x150]
        code = bytearray(NIBBLE if nibble else NORMALIZED)
        table = 0x2f8 if relocated else 0x200 if nibble else 0x203
        if nibble:
            code[14:16] = table.to_bytes(2,'little')
            order = list(range(128))
            if relocated: order[:16] = [15,4,4,0,3,9,2,7,11,1,10,6,12,13,14,8]
            for i, target in enumerate(order): data[table+2*i:table+2*i+2] = (0x1000+target*8).to_bytes(2,'little')
            for i in range(128): data[0x1000+i*8:0x1007+i*8] = bytes([0xe1,0x3e,i,0xea,0,0xc0,0xc9])
        else:
            lookup = 0x1fe if relocated else 0x200
            # Relocated index lookup and pointer table are disjoint, both cross a low-byte boundary.
            table = 0x3fa if relocated else 0x203
            code[23:25] = lookup.to_bytes(2,'little')
            code[35:37] = table.to_bytes(2,'little')
            data[lookup:lookup+3] = bytes([1,2,3])
            order = [5,2,2,0,4,1] if relocated else list(range(6))
            for i, target in enumerate(order): data[table+2*i:table+2*i+2] = (0x300+target*3).to_bytes(2,'little')
            for i in range(6): data[0x300+i*3:0x303+i*3] = bytes([0x3e,10*(i+1),0xc9])
        data[0x100:0x100+len(code)] = code
        data[0x14d] = (-sum(data[0x134:0x14d])-25)&255
        data[0x14e:0x150] = b'\0\0'
        data[0x14e:0x150] = (sum(data)&65535).to_bytes(2,'big')
        (output/(name+'.gb')).write_bytes(data)
        result[name] = dict(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),root=256,code=code.hex(),table=table,physical_entries=128 if nibble else 6,order=order,
            envelope='MBC5 header 0134..014F from retained generic cartridge; nonexecuted filler D3; original consumed instructions/tables retained in unrelocated fixtures')
    for name, code in [('physical-banks','fa80ffe60120043e0118023e02ea0020210040e9'),('zero','fa80ffe6006f2603e9')]:
        data=bytearray([0xd3]*len(base));data[0x134:0x150]=base[0x134:0x150]
        data[0x100:0x100+len(bytes.fromhex(code))]=bytes.fromhex(code)
        if name=='physical-banks':data[0x4000:0x4003]=bytes.fromhex('3e11c9');data[0x8000:0x8003]=bytes.fromhex('3e22c9')
        else:data[0x300:0x303]=bytes.fromhex('3e44c9')
        data[0x14d]=(-sum(data[0x134:0x14d])-25)&255;data[0x14e:0x150]=b'\0\0';data[0x14e:0x150]=(sum(data)&65535).to_bytes(2,'big')
        (output/(name+'.gb')).write_bytes(data);result[name]=dict(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),code=code,root=256)
    (output/'fixtures.json').write_text(json.dumps(result,indent=2)+'\n')
    return result

if __name__ == '__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); fixtures(Path(__file__).resolve().parents[1],args.output)
