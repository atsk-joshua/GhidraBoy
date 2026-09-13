#!/usr/bin/env python3
"""Independently authored inline-call fixture; no commercial image inputs."""
from pathlib import Path
import json,hashlib

def make(root=0x42fd,helper=0x800,stub=0x880,target=0x5210,bank=2,indirect=False):
    image=bytearray(0x10000);image[0x147]=0x19;image[0x148]=1
    spans=[]
    def put(physical,cpu,data):
        data=bytes.fromhex(data) if isinstance(data,str) else data
        offset=physical*0x4000+(cpu&0x3fff);image[offset:offset+len(data)]=data
        spans.append(dict(bank=physical,cpu=cpu,bytes=data.hex()))
    def word(x):return x.to_bytes(2,'little').hex()
    put(0,0x30,'c3'+word(helper))
    # Save the original registers; adjust the live return word through HL; read
    # all three payload bytes through DE before selecting the target bank.
    body='e0a0f0a1f5c5d5e5f8082a5f7e577bc6032b227ace00771ae0a2131ae0a3131ae0a4e1d1c17de0a57ce0a6f0a2e0a1ea0020f0a36ff0a467cd'+word(stub)
    cleanup=helper+len(bytes.fromhex(body))
    body+='f5e5f8057ee0a1ea0020e1f13333c9'
    put(0,helper,body)
    put(0,stub,'e5f0a56ff0a667f0a0c9')
    put(1,root,'f7'+bytes([bank]).hex()+word(target))
    continuation=root+4
    put(1,continuation,'280478ea21cac9')
    # ADC discriminates the helper-produced incoming carry; INC leaves a live Z.
    # The continuation consumes that Z before any instruction overwrites it.
    put(bank,target,'ce003c472120ea77c9' if indirect else 'ce003cea20ca47c9')
    put(1,target,'3e99c9')
    return bytes(image),dict(site=f'rom1::{root:04x}',helper=helper,stub=stub,cleanup=cleanup,target=f'rom{bank}::{target:04x}',continuation=f'rom1::{continuation:04x}',spans=spans)

if __name__=='__main__':
    out=Path(__file__).resolve().parents[1]/'src/test/resources/conditional';out.mkdir(exist_ok=True)
    manifest={}
    for name,kw in [('carry',{}),('relocated',dict(root=0x4600,helper=0x900,stub=0x980,target=0x5300)),('indirect',dict(indirect=True))]:
        image,meta=make(**kw);(out/(name+'.gb')).write_bytes(image);meta['sha256']=hashlib.sha256(image).hexdigest();manifest[name]=meta
    (out/'fixtures.json').write_text(json.dumps(manifest,indent=2)+'\n')
