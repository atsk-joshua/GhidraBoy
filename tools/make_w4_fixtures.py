#!/usr/bin/env python3
"""Self-authored W4 symbolic WRAM and two explicit initializer images."""
import hashlib,json,argparse
from pathlib import Path
A='fa60c0ea70c03cea60e0fa60c0ea71c0c9'
I1='3e31ea74c0c9'
I2='3ea7ea74c0c9'
def create(output):
    image=bytearray((Path(__file__).resolve().parents[1]/'src/test/resources/ordinary/PREDICATED_CALLS.gb').read_bytes())
    for at,code in [(0x150,A),(0x300,I1),(0x320,I2)]:image[at:at+len(bytes.fromhex(code))]=bytes.fromhex(code)
    image[0x14d]=(-sum(image[0x134:0x14d])-25)&255
    image[0x14e:0x150]=b'\0\0';image[0x14e:0x150]=(sum(image)&65535).to_bytes(2,'big')
    output.mkdir(parents=True,exist_ok=True);(output/'W4_MEMORY_IMAGE.gb').write_bytes(image)
    data={'sha256':hashlib.sha256(image).hexdigest(),'A':{'cpu':0x150,'bytes':A,'input':0xc060,'echo':0xe060,'outputs':[0xc070,0xc071]},'I1':{'cpu':0x300,'bytes':I1},'I2':{'cpu':0x320,'bytes':I2},'execution':0xc200,'image_output':0xc074,'frame':[0xc800,0xcffc]}
    (output/'fixture.json').write_text(json.dumps(data,indent=2)+'\n')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);create(p.parse_args().output)
