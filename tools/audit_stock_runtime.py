#!/usr/bin/env python3
"""Independently compare installed stock runtime bytes with the pinned release and exact extension."""
import argparse,hashlib,json,zipfile
from pathlib import Path
PIN='93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54'
def digest(data):return hashlib.sha256(data).hexdigest()
def audit(release,runtime,extension,native):
    assert digest(release.read_bytes())==PIN,'Wrong pinned official release'
    z=zipfile.ZipFile(release);prefix=z.namelist()[0].split('/')[0]+'/'
    checked={};mismatches=[]
    for info in z.infolist():
        if info.is_dir():continue
        name=info.filename[len(prefix):];expected=digest(z.read(info));path=runtime/name
        if not path.is_file() or digest(path.read_bytes())!=expected:mismatches.append(name)
        checked[name]=expected
    assert not mismatches, 'Release file substitutions: '+str(mismatches)
    jars={str(p.relative_to(runtime)):digest(p.read_bytes()) for p in runtime.rglob('*.jar')}
    extra=[p for p in jars if p not in checked and not p.startswith('Ghidra/Extensions/GhidraBoy/lib/')]
    assert not extra,'Extra classpath JARs: '+str(extra)
    e=zipfile.ZipFile(extension);payload={}
    for name in e.namelist():
        if name.endswith('/'):continue
        path=runtime/'Ghidra/Extensions'/name
        assert path.is_file() and digest(path.read_bytes())==digest(e.read(name)), 'Changed provider payload '+name
        payload[name]=digest(e.read(name))
        if name.endswith('.jar'):
            import io
            classes=zipfile.ZipFile(io.BytesIO(e.read(name))).namelist()
            assert not any(c.startswith('ghidra/') and c.endswith('.class') for c in classes),'Core class shadow in provider'
    actual_provider={str(p.relative_to(runtime/'Ghidra/Extensions')) for p in (runtime/'Ghidra/Extensions/GhidraBoy').rglob('*') if p.is_file()}
    assert actual_provider==set(payload),'Unexpected installed provider files'
    providers=list(runtime.glob('Ghidra/**/data/languages/sm83.ldefs'));assert len(providers)==1,'Duplicate providers'
    native_path=runtime/native
    expected_files=set(checked)|{'Ghidra/Extensions/'+n for n in payload}|{native}
    extras={str(p.relative_to(runtime)) for p in runtime.rglob('*') if p.is_file()}-expected_files
    assert not extras,'Unexpected runtime files, including possible classpath shadow: '+str(sorted(extras))
    return {'status':'PASS','release_sha256':PIN,'release_files_checked':len(checked),'release_files':checked,'runtime':str(runtime),'core_jars':{k:v for k,v in jars.items() if k in checked},'extension_sha256':digest(extension.read_bytes()),'provider':payload,'native_path':str(native_path),'native_sha256':digest(native_path.read_bytes()),'core_shadow_classes':False}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('release','runtime','extension','out'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--native',required=True);a=p.parse_args();r=audit(a.release,a.runtime,a.extension,a.native);a.out.write_text(json.dumps(r,indent=2)+'\n');print('STOCK_RUNTIME_PURITY_PASS',r['release_files_checked'],r['native_sha256'])
