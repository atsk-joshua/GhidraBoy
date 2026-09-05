#!/usr/bin/env python3
"""Read-only installation/package doctor; no network or project mutation."""
import argparse, hashlib, pathlib, subprocess, zipfile
p=argparse.ArgumentParser()
p.add_argument('--ghidra',type=pathlib.Path,required=True)
p.add_argument('--jdk',type=pathlib.Path,required=True)
p.add_argument('--zip',type=pathlib.Path,required=True)
a=p.parse_args()
properties=(a.ghidra/'Ghidra/application.properties').read_text()
assert 'application.version=12.1.3\n' in properties, 'Ghidra 12.1.3 required'
java=subprocess.check_output([str(a.jdk/'bin/java'),'-version'],stderr=subprocess.STDOUT).decode()
assert 'version "21.' in java, 'JDK 21 required'
with zipfile.ZipFile(a.zip) as z:
 names=z.namelist()
 for required in ['Module.manifest','extension.properties','data/languages/sm83.sla','data/languages/sm83.ldefs','ghidra_scripts/GhidraBoyTools.java','ghidra_scripts/GhidraBoyImport.java','docs/mapping-schema.json','LICENSE']:
  assert 'GhidraBoy/'+required in names, 'Missing '+required
 assert not any('/src/test/' in n or '/vectors/' in n for n in names), 'Test fixture leaked into release'
 props=z.read('GhidraBoy/extension.properties').decode()
 assert 'version=12.1.3\n' in props
 assert sum(n.endswith('.jar') for n in names)==1, 'Unexpected runtime dependency jars'
 print('Package entries:',len(names))
print(java.strip())
print('SHA256',hashlib.sha256(a.zip.read_bytes()).hexdigest(),a.zip)
print('DOCTOR_PASS (installed discovery requires installed_smoke.py)')
