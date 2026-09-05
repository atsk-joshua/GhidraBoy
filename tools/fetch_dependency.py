#!/usr/bin/env python3
"""Explicit maintenance/CI download from the checked-in official-source lock; never used at runtime."""
import argparse,hashlib,json,pathlib,urllib.request
p=argparse.ArgumentParser();p.add_argument('name');p.add_argument('output',type=pathlib.Path);a=p.parse_args()
lock=json.loads((pathlib.Path(__file__).with_name('dependencies.json')).read_text())[a.name]
if a.output.exists(): data=a.output.read_bytes()
else: data=urllib.request.urlopen(lock['url']).read()
actual=hashlib.sha256(data).hexdigest()
if actual!=lock['sha256']: raise SystemExit(f'Digest mismatch for {a.name}: {actual}')
a.output.parent.mkdir(parents=True,exist_ok=True)
if not a.output.exists(): a.output.write_bytes(data)
print(json.dumps({'dependency':a.name,'sha256':actual,'verified':True}))
