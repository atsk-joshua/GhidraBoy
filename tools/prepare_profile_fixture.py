#!/usr/bin/env python3
"""Create an explicit synthetic/failing profile fixture from a generic archive."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

PROVIDER = '''from ghigbc.profile import ByteRange, Field
class Decoder:
    def decode(self,view):
        source=ByteRange('wram',1,0x34,1)
        yield Field('counter','integer',view.read(source)[0],source,'observed','Synthetic compatibility fixture')
class Provider:
    id='synthetic-counter'; version='1.0.0'; api_version=1
    fingerprints=frozenset({ROM_HASH})
    requires=frozenset({'physical-capture-v1'})
    ranges=(ByteRange('wram',1,0x34,1),)
    def create(self,rom):CREATE_BODY
provider=Provider()
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--mode',choices=('synthetic','failing'),required=True)
    args=parser.parse_args()
    args.work.mkdir(parents=True,exist_ok=False)
    with tarfile.open(args.archive) as archive:
        roots=set()
        for member in archive.getmembers():
            path=Path(member.name)
            if not member.isfile() or path.is_absolute() or '..' in path.parts:
                raise ValueError('Unsafe fixture archive member')
            roots.add(path.parts[0])
        if len(roots)!=1:raise ValueError('Expected one package root')
        archive.extractall(args.work)
    root=args.work/roots.pop()
    manifest=json.loads((root/'suite.json').read_text())
    if manifest.get('kind')!='generic' or manifest.get('schema')!=1 or (root/'profiles.json').exists():
        raise ValueError('Use a generic package without installed profiles')
    for name,expected in manifest['files'].items():
        relative=Path(name)
        if relative.is_absolute() or '..' in relative.parts:raise ValueError('Unsafe manifest path')
        if hashlib.sha256((root/relative).read_bytes()).hexdigest()!=expected:raise ValueError('Base package digest mismatch')
    fingerprint=hashlib.sha256((root/'build/teaching.gbc').read_bytes()).hexdigest()
    body='return Decoder()' if args.mode=='synthetic' else "raise RuntimeError('deliberate profile failure')"
    module=PROVIDER.replace('ROM_HASH',repr(fingerprint)).replace('CREATE_BODY',body)
    files={'python/synthetic_profile.py':module,'profiles.json':json.dumps({'schema':1,'modules':['synthetic_profile']})+'\n'}
    for name,data in files.items():
        (root/name).write_text(data)
        manifest['runtime_files'].append(name)
        manifest['files'][name]=hashlib.sha256(data.encode()).hexdigest()
    manifest['test_fixture']={'mode':args.mode,'base_archive_sha256':hashlib.sha256(args.archive.read_bytes()).hexdigest(),'scope':'Self-authored compatibility fixture; not a release package'}
    (root/'suite.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'root':str(root),'manifest':str(root/'suite.json'),'mode':args.mode}))


if __name__=='__main__':main()
