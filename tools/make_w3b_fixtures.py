#!/usr/bin/env python3
"""Self-authored W3b fixtures; explicit SM83 bytes, no private ROM inputs."""
from pathlib import Path
import argparse, hashlib, json
LOOP='78e6074f1600b72804140d20fc7aea64c0e60120043e0118023e02ea0020cd0040ea65c0c9'
HELPER='ea0020e9'
def fixtures(source, output):
 output.mkdir(parents=True,exist_ok=True)
 loop=bytearray((source/'src/test/resources/ordinary/PREDICATED_CALLS.gb').read_bytes());loop[0x150:0x150+len(bytes.fromhex(LOOP))]=bytes.fromhex(LOOP)
 files={'W3B_LOOP.gb':loop}
 domain=bytearray(0x10000);domain[0x100:0x150]=loop[0x100:0x150];domain[0x100:0x104]=bytes.fromhex('00c30002');domain[0x147]=0x13;domain[0x148]=1
 for offset,code in {0x28:HELPER,0x200:'efc9',0x8100:'ca20413e03ea0020',0xc108:'c30042',0x8120:'3e02ea0020c30042',0x8200:'3e22ea10c2c9',0xc200:'3e33ea10c2c9'}.items():domain[offset:offset+len(bytes.fromhex(code))]=bytes.fromhex(code)
 files['W3B_DOMAINS.gb']=domain
 order=bytearray(0x10000);order[0x100:0x150]=loop[0x100:0x150];order[0x100:0x104]=bytes.fromhex('00c38001');order[0x147]=0x13;order[0x148]=1
 for offset,code in {0x28:HELPER,0x180:'cd2800c35301',0x150:'cd4002c35001',0x240:'c9',0x8000:'c9'}.items():order[offset:offset+len(bytes.fromhex(code))]=bytes.fromhex(code)
 files['W3B_ORDER.gb']=order
 result={}
 for name,data in files.items():
  data[0x14d]=(-sum(data[0x134:0x14d])-25)&255
  data[0x14e:0x150]=b'\x00\x00';checksum=sum(data)&65535;data[0x14e:0x150]=checksum.to_bytes(2,'big')
  (output/name).write_bytes(data);result[name]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
 (output/'fixtures.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();print(json.dumps(fixtures(Path(__file__).resolve().parents[1],args.output),indent=2))
