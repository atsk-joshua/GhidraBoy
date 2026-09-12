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
import time


def main():
    p=argparse.ArgumentParser()
    for name in ('runtime','profile','project-dir','out','jdk'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--project-name',required=True);p.add_argument('--mode',choices=['readiness','initial','full','reopen','suffix-rehearsal'],required=True)
    p.add_argument('--rehearsal',action='store_true')
    p.add_argument('--saved-captures',type=Path);a=p.parse_args()
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
    run_compile('compile-bootstrap',[repo/'tools/g1/G1StockBootstrap.java'],boot,str(utility))
    run_compile('compile-driver',[repo/'tools/g1/G1StockNormalLaunch.java'],classes,os.pathsep.join(map(str,a.runtime.rglob('*.jar'))),os.pathsep.join(map(str,[repo/'src/test/scripts',scripts])))
    sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
    inputs={str(f):sha(f) for f in [repo/'tools/g1/G1StockBootstrap.java',repo/'tools/g1/G1StockNormalLaunch.java',scripts/'GhidraBoyTools.java',*sorted((repo/'src/test/scripts').glob('GhidraBoy*.java'))]}
    (a.out/'driver-inputs.json').write_text(json.dumps(inputs,indent=2))
    vm=[l.split('=',1)[1] for l in (a.runtime/'support/launch.properties').read_text().splitlines() if l.startswith('VMARGS=')]
    vm += [f'-Duser.home={a.profile}/home',f'-Dapplication.settingsdir={a.profile}/settings',f'-Dapplication.cachedir={a.profile}/cache',f'-Dapplication.tempdir={a.profile}/temp',f'-Djava.io.tmpdir={a.profile}/temp','-Xdock:name=G1 Stock Normal Window']
    if a.rehearsal:vm+=['-Dg1.rehearsal=true']
    cap=a.out/'captures';cap.mkdir()
    cmd=[str(a.jdk/'bin/java'),*vm,'-cp',str(utility)+os.pathsep+str(boot),'ghidra.Ghidra','G1StockBootstrap',str(classes),str(a.project_dir),a.project_name,str(cap),a.mode,str(repo/'src/test/scripts'),str(scripts),str(a.saved_captures or '')]
    receipt={'argv':cmd,'start_ns':time.time_ns(),'mode':a.mode,'rehearsal':a.rehearsal,'no_setup_in_launcher':True}
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
    return 0 if receipt['exit']==0 and receipt['tool_closure_marker'] and not receipt.get('timeout') else 1

if __name__=='__main__':raise SystemExit(main())
