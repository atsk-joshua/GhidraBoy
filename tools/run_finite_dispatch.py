#!/usr/bin/env python3
"""Task-owned installed capture and strict replay for the bounded dispatch slice."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import check_finite_dispatch as checker
import check_finite_dispatch_sensitivity as sensitivity

SCRIPTS=['GhidraBoyFiniteDispatch','GhidraBoyFiniteDispatchImport','GhidraBoyPredicatedCalls','GhidraBoyW2eFinite']

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def write(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def snapshot(path):return {str(f.relative_to(path)):sha(f) for f in sorted(path.rglob('*')) if f.is_file()}

def run(runtime,jdk,work,suite):
    repo=Path(__file__).resolve().parents[1]
    work.mkdir(parents=True,exist_ok=False)
    scripts=work/'scripts';scripts.mkdir();fixtures=work/'fixtures';shutil.copytree(repo/'src/test/resources/dispatch',fixtures)
    for name in SCRIPTS:shutil.copy2(repo/'src/test/scripts'/(name+'.java'),scripts)
    profile=work/'profile';profile.mkdir();projects=work/'projects';projects.mkdir()
    env=dict(os.environ,JAVA_HOME=str(jdk),JAVA_TOOL_OPTIONS='-Duser.home='+str(profile),XDG_CACHE_HOME=str(profile))
    extension=runtime/'Ghidra/Extensions/GhidraBoy'
    write(work/'identities.json',dict(extension=snapshot(extension),scripts=snapshot(scripts),fixtures=snapshot(fixtures),suite=suite,checkers={name:sha(repo/'tools'/name) for name in ['run_finite_dispatch.py','check_finite_dispatch.py','check_finite_dispatch_sensitivity.py','check_predicated_calls.py','check_w2e_native.py']}))
    commands=[];results={}
    def command(label,args,marker):
        write(work/'progress.json',dict(active=label,completed=list(results)))
        argv=[str(runtime/'support/analyzeHeadless'),str(projects),*map(str,args)]
        started=time.time()
        with (work/(label+'.log')).open('w') as log:child=subprocess.run(argv,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=420)
        text=(work/(label+'.log')).read_text()
        commands.append(dict(label=label,argv=argv,exit=child.returncode,seconds=time.time()-started,marker=marker,observed=marker in text))
        write(work/'commands.json',commands)
        if child.returncode or marker not in text:raise RuntimeError('Failed child '+label)
    cases=[('normalized-lifecycle','normalized','normalized-lifecycle',None),('nibble','nibble','nibble',0xc060)]
    if suite=='mac':cases += [('nibble-h2','nibble','nibble',0xc7ff),('normalized-relocated','normalized-relocated','normalized',None),('nibble-relocated','nibble-relocated','nibble',0xc060),('physical-banks','physical-banks','physical-banks',None),('physical-banks-reverse','physical-banks','physical-banks-reverse',None),('zero','zero','zero',None)]
    for label,fixture,mode,h in cases:
        output=work/label
        command(label,[label,'-scriptPath',scripts,'-preScript','GhidraBoyFiniteDispatchImport.java',fixtures/(fixture+'.gb'),output,mode,*([hex(h)] if h is not None else [])],'FINITE_DISPATCH_SAVED')
        order=checker.shared.read(fixtures/'fixtures.json')[fixture].get('order')
        if h is not None:order=order[:16]
        result=checker.check(output,nibble=h is not None,h=h or 0xc060,order=order,physical=mode.startswith('physical-banks'),zero=mode=='zero')
        write(work/(label+'-replay.json'),result);results[label]=dict(status=result['status'],cases=result['cases'],native=result['native_target_provenance'])
        if mode.startswith('physical-banks'):
            for bank in [2,1]:
                selected='selection-bank'+str(bank)
                write(work/(label+'-'+selected+'-replay.json'),checker.check(output,label=selected,physical=True))
        if label=='normalized-lifecycle':
            stale=checker.shared.read(output/'stale-root-request.json')
            if stale['completed'] or stale['highfunction_available'] or 'Stale predicated graph' not in stale['error']:raise RuntimeError('Actual stale authority was not refused')
            write(work/'refreshed-replay.json',checker.check(output,label='refreshed',order=[1,1,2,3,4,5]))
            before=snapshot(projects);write(work/'project-before-reopen.json',before)
            reopened=work/'reopen'
            command('reopen',[label,'-process','normalized.gb','-noanalysis','-readOnly','-scriptPath',scripts,'-postScript','GhidraBoyFiniteDispatch.java',reopened,'reopen'],'FINITE_DISPATCH_CAPTURE_COMPLETE reopen')
            after=snapshot(projects);write(work/'project-after-reopen.json',after)
            changes={name:dict(before=before.get(name),after=after.get(name)) for name in sorted(before.keys()|after.keys()) if before.get(name)!=after.get(name)}
            write(work/'project-reopen-differences.json',changes)
            if (output/'refreshed-registration.json').read_bytes()!=(reopened/'reopen-registration.json').read_bytes():raise RuntimeError('Current record changed at first reopen')
            if (output/'refreshed-fixture.gb').read_bytes()!=(reopened/'reopen-fixture.gb').read_bytes():raise RuntimeError('Program bytes changed at first reopen')
            write(work/'reopen-replay.json',checker.check(reopened,label='reopen',order=[1,1,2,3,4,5]))
            results['lifecycle']=dict(status='PASS',record_identical=True,bytes_identical=True,housekeeping_changes=list(changes))
        if label in {'normalized-lifecycle','nibble','physical-banks'}:
            write(work/(label+'-sensitivity.json'),sensitivity.run(output,nibble=h is not None,physical=mode.startswith('physical-banks')))
        write(work/'results.json',results)
    write(work/'progress.json',dict(active=None,completed=list(results)))
    return results

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--runtime',type=Path,required=True);parser.add_argument('--jdk',type=Path,required=True);parser.add_argument('--work',type=Path,required=True);parser.add_argument('--suite',choices=['mac','linux'],default='mac');a=parser.parse_args()
    print(json.dumps(run(a.runtime.resolve(),a.jdk.resolve(),a.work.resolve(),a.suite),indent=2))
