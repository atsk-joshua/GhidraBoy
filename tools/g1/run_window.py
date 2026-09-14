#!/usr/bin/env python3
"""Compile the headed driver against a selected installed runtime; run one normal session.
No import/setup, install, proof repair, or private decompiler occurs in this launcher.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import zipfile
import time


def main():
    p=argparse.ArgumentParser()
    for name in ('runtime','profile','project-dir','out','jdk'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--project-name',required=True);p.add_argument('--mode',choices=['readiness','initial','full','reopen','suffix-rehearsal','conditional'],required=True)
    p.add_argument('--compile-only',action='store_true');p.add_argument('--public-lifecycle',action='store_true');p.add_argument('--public-reopen',action='store_true');p.add_argument('--rehearsal',action='store_true');p.add_argument('--program')
    p.add_argument('--candidate',type=Path);p.add_argument('--saved-captures',type=Path);a=p.parse_args()
    if a.public_lifecycle and a.mode!='conditional':p.error('public lifecycle requires conditional mode')
    if a.public_reopen and (not a.public_lifecycle or a.saved_captures is None):p.error('public reopen requires --public-lifecycle and --saved-captures')
    if a.mode=='conditional' and not a.program:p.error('conditional mode requires --program')
    if a.mode=='suffix-rehearsal' and (not a.rehearsal or a.saved_captures is None):p.error('suffix requires rehearsal and saved captures')
    if a.mode=='reopen' and a.saved_captures is None:p.error('reopen requires --saved-captures')
    repo=Path(__file__).resolve().parents[2];a.out.mkdir(parents=True,exist_ok=False)
    classes=a.out/'classes';boot=a.out/'bootstrap';classes.mkdir();boot.mkdir()
    for child in ('home','settings','cache','temp'):(a.profile/child).mkdir(parents=True,exist_ok=True)
    utility=a.runtime/'Ghidra/Framework/Utility/lib/Utility.jar';scripts=a.runtime/'Ghidra/Extensions/GhidraBoy/ghidra_scripts'
    assert (scripts/'GhidraBoyTools.java').is_file(),scripts
    def run_compile(name,files,target,cp,sourcepath=None):
        cmd=[str(a.jdk/'bin/javac'),'-proc:none','-cp',cp,'-d',str(target)]
        if sourcepath:cmd+=['-sourcepath',sourcepath]
        cmd+=list(map(str,files));q=subprocess.run(cmd,capture_output=True,text=True)
        (a.out/(name+'.json')).write_text(json.dumps({'argv':cmd,'exit':q.returncode,'stdout':q.stdout,'stderr':q.stderr},indent=2));q.check_returncode()
    sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
    source_files=[repo/'tools/g1/run_window.py',repo/'tools/g1/run_prepared.py',repo/'tools/g1/G1StockBootstrap.java',repo/'tools/g1/G1StockNormalLaunch.java',scripts/'GhidraBoyTools.java',*sorted((repo/'src/test/scripts').glob('GhidraBoy*.java')),repo/'src/test/scripts/Sm83PreservationInventory.java']
    inputs={str(f):sha(f) for f in source_files};snapshots={}
    for f in source_files:
        relative=f.relative_to(repo) if f.is_relative_to(repo) else Path('installed')/f.name
        destination=a.out/'sources'/relative;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,destination);snapshots[str(f)]=str(destination.relative_to(a.out))
        if sha(destination)!=inputs[str(f)]:raise RuntimeError('Source changed during preparation: '+str(f))
    (a.out/'driver-inputs.json').write_text(json.dumps(inputs,indent=2));(a.out/'source-snapshots.json').write_text(json.dumps(snapshots,indent=2))
    runtime_files=[*a.runtime.rglob('*.jar'),*filter(Path.is_file,(a.runtime/'Ghidra/Extensions/GhidraBoy').rglob('*')),*a.runtime.glob('Ghidra/Features/Decompiler/os/*/decompile'),a.runtime/'support/launch.properties',a.jdk/'bin/java',a.jdk/'bin/javac']
    if a.candidate:
        with zipfile.ZipFile(a.candidate) as archive:
            for member in archive.infolist():
                if not member.is_dir() and archive.read(member)!=(a.runtime/'Ghidra/Extensions'/member.filename).read_bytes():raise RuntimeError('Installed candidate mismatch: '+member.filename)
        runtime_files.append(a.candidate)
        (a.out/'candidate.json').write_text(json.dumps({'archive':str(a.candidate),'sha256':sha(a.candidate)},indent=2))
    (a.out/'runtime-inputs.json').write_text(json.dumps({str(f):sha(f) for f in runtime_files},indent=2))
    run_compile('compile-bootstrap',[repo/'tools/g1/G1StockBootstrap.java'],boot,str(utility))
    run_compile('compile-driver',[repo/'tools/g1/G1StockNormalLaunch.java'],classes,os.pathsep.join(map(str,a.runtime.rglob('*.jar'))),os.pathsep.join(map(str,[repo/'src/test/scripts',scripts])))
    if any(sha(Path(f))!=expected for f,expected in inputs.items()):raise RuntimeError('Source changed while compiling driver')
    (a.out/'compiled-classes.json').write_text(json.dumps({str(f.relative_to(a.out)):sha(f) for directory in (classes,boot) for f in directory.rglob('*.class')},indent=2))
    vm=[l.split('=',1)[1] for l in (a.runtime/'support/launch.properties').read_text().splitlines() if l.startswith('VMARGS=')]
    vm += [f'-Duser.home={a.profile}/home',f'-Dapplication.settingsdir={a.profile}/settings',f'-Dapplication.cachedir={a.profile}/cache',f'-Dapplication.tempdir={a.profile}/temp',f'-Djava.io.tmpdir={a.profile}/temp','-Xdock:name='+('GhidraBoy Conditional Call' if a.mode=='conditional' else 'G1 Stock Normal Window')]
    if a.rehearsal:vm+=['-Dg1.rehearsal=true']
    if a.public_lifecycle:vm+=['-Dghidraboy.publicLifecycle=true']
    if a.public_reopen:vm+=['-Dghidraboy.publicReopen=true','-Dghidraboy.publicBaseline='+str(a.saved_captures/'saved-authority.json')]
    cap=a.out/'captures';cap.mkdir()
    cmd=[str(a.jdk/'bin/java'),*vm,'-cp',str(utility)+os.pathsep+str(boot),'ghidra.Ghidra','G1StockBootstrap',str(classes),str(a.project_dir),a.project_name,str(cap),a.mode,str(repo/'src/test/scripts'),str(scripts),str(a.program if a.mode=='conditional' else a.saved_captures or '')]
    (a.out/'attended-command.json').write_text(json.dumps(cmd,indent=2))
    (a.out/'prepared-command-sha256.txt').write_text(sha(a.out/'attended-command.json')+'\n')
    if a.compile_only:return 0
    receipt={'argv':cmd,'start_ns':time.time_ns(),'mode':a.mode,'rehearsal':a.rehearsal,'no_setup_in_launcher':True,'public_lifecycle':a.public_lifecycle,'public_reopen':a.public_reopen}
    with (a.out/'launch.log').open('w') as log:
        process=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT);receipt['pid']=process.pid
        (a.out/'process-start.json').write_text(json.dumps(receipt,indent=2))
        try:receipt['exit']=process.wait(timeout=600)
        except subprocess.TimeoutExpired:
            process.terminate();receipt['exit']=process.wait(timeout=20);receipt['timeout']=True
    receipt['end_ns']=time.time_ns();receipt['exited']=True
    receipt['tool_closure_marker']=(cap/'tool-closed.json').exists()
    (a.out/'process-exit.json').write_text(json.dumps(receipt,indent=2))
    print(json.dumps({k:v for k,v in receipt.items() if k!='argv'},indent=2))
    return 0 if (a.mode!='conditional' or (cap/('public-window-complete.json' if a.public_lifecycle else 'conditional-complete.json')).exists()) and receipt['exit']==0 and receipt['tool_closure_marker'] and not receipt.get('timeout') else 1

if __name__=='__main__':raise SystemExit(main())
