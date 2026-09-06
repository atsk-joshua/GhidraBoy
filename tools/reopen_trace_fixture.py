#!/usr/bin/env python3
"""Reopen copied synthetic trace fixtures in independent Java-only processes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'debugger/scripts'))
from build_inputs import artifact_inputs


def tree_hash(path):
    result=hashlib.sha256()
    for file in sorted(path.rglob('*')):
        if file.is_file():
            result.update(str(file.relative_to(path)).encode())
            result.update(file.read_bytes())
    return result.hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('ghidra','jdk','acceptance','work'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--fixture',type=Path,action='append',required=True)
    parser.add_argument('--artifacts',type=Path,default=ROOT/'build/integration/artifacts.json')
    args=parser.parse_args()
    _,artifacts=artifact_inputs(ROOT,args.artifacts)
    work=args.work.resolve();work.mkdir(parents=True,exist_ok=False)
    ghidra=work/'ghidra'
    shutil.copytree(args.ghidra,ghidra)
    extensions=ghidra/'Ghidra/Extensions'
    if extensions.exists():shutil.rmtree(extensions)
    extensions.mkdir()
    for component in ('GhidraBoy','GhiGBC'):
        with zipfile.ZipFile(artifacts[component]['archive']) as archive:
            archive.extractall(extensions)
    assert not list(ghidra.rglob('libghigbc.*'))
    assert not list(ghidra.rglob('profiles.json'))
    classpath=os.pathsep.join([str(args.acceptance.resolve()),*[str(p) for p in ghidra.rglob('*.jar') if 'yajsw' not in str(p)]])
    results=[]
    for index,fixture_path in enumerate(args.fixture):
        fixture=json.loads(fixture_path.read_text())
        source=Path(fixture['directory']);name=fixture['project']
        if Path(name).name!=name or name in ('.','..'):raise ValueError('Invalid fixture project name')
        source_db=source/(name+'.rep');source_project=source/(name+'.gpr')
        before=(tree_hash(source_db),hashlib.sha256(source_project.read_bytes()).hexdigest())
        case=work/str(index);projects=case/'projects';projects.mkdir(parents=True)
        shutil.copytree(source_db,projects/source_db.name)
        shutil.copy2(source_project,projects/source_project.name)
        profile=case/'home';profile.mkdir()
        command=[str(args.jdk/'bin/java'),'-Duser.home='+str(profile),'-cp',classpath,'ReopenTraceFixture',str(fixture_path.resolve()),str(projects)]
        if fixture.get('legacyBooleanMapping'):
            with (case/'seed-legacy.log').open('w') as output:
                seeded=subprocess.run([*command,'seed-legacy'],env=dict(os.environ,GHIDRA_INSTALL_DIR=str(ghidra)),stdout=output,stderr=subprocess.STDOUT)
            if seeded.returncode or 'LEGACY_BOOLEAN_FIXTURE_SAVED' not in (case/'seed-legacy.log').read_text():
                raise RuntimeError('Legacy fixture preparation failed: '+str(case/'seed-legacy.log'))
        with (case/'reopen.log').open('w') as output:
            result=subprocess.run(command,env=dict(os.environ,GHIDRA_INSTALL_DIR=str(ghidra)),stdout=output,stderr=subprocess.STDOUT)
        log=(case/'reopen.log').read_text()
        after=(tree_hash(source_db),hashlib.sha256(source_project.read_bytes()).hexdigest())
        status='PASS' if result.returncode==0 and 'STANDALONE_TRACE_REOPEN_PASS' in log and 'ERROR ' not in log and before==after else 'FAIL'
        results.append(dict(status=status,fixture=str(fixture_path),fixtureSha256=hashlib.sha256(fixture_path.read_bytes()).hexdigest(),sourceUnchanged=before==after,sourceTreeSha256=before[0],command=command,exitCode=result.returncode,log=str(case/'reopen.log')))
        if status!='PASS':
            print(log[-6000:])
            break
    receipt=dict(schema=1,status='PASS' if len(results)==len(args.fixture) and all(r['status']=='PASS' for r in results) else 'FAIL',emulatorRuntimeAbsent=True,optionalProfilesAbsent=True,results=results)
    (work/'results.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'status':receipt['status'],'fixtures':len(results),'evidence':str(work/'results.json')}))
    if receipt['status']!='PASS':raise SystemExit(1)


if __name__=='__main__':main()
