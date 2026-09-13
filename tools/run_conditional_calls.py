#!/usr/bin/env python3
"""Serial conditional-family capture/lifecycle on an already prepared task-owned runtime."""
import argparse,hashlib,json,os,shutil,subprocess,time
from pathlib import Path

def snapshot(root):return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file()}
def main(a):
    repo=Path(__file__).resolve().parents[1];w=a.work.resolve();w.mkdir(parents=True,exist_ok=False)
    for name in ['projects','profile','scripts']:(w/name).mkdir()
    for name in ['GhidraBoyConditionalCalls','GhidraBoyConditionalLifecycle','GhidraBoyPredicatedCalls','GhidraBoyW2eFinite','Sm83PreservationInventory']:
        shutil.copy2(repo/'src/test/scripts'/(name+'.java'),w/'scripts'/(name+'.java'))
    env=dict(os.environ,JAVA_HOME=str(a.jdk),JAVA_TOOL_OPTIONS=f'-Xmx2g -Duser.home={w}/profile -Dapplication.settingsdir={w}/profile -Djava.io.tmpdir={w}')
    commands=[]
    def run(name,arguments,marker):
        command=[str(a.runtime/'support/analyzeHeadless'),str(w/'projects'),*map(str,arguments),'-scriptPath',str(w/'scripts')]
        start=time.monotonic()
        with (w/(name+'.log')).open('w') as log:result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=180)
        text=(w/(name+'.log')).read_text();row=dict(name=name,argv=command,exit=result.returncode,seconds=time.monotonic()-start,marker=marker in text,script_error='REPORT SCRIPT ERROR' in text)
        commands.append(row);(w/'commands.json').write_text(json.dumps(commands,indent=2))
        if row['exit'] or not row['marker'] or row['script_error']:raise RuntimeError('Capture failed: '+name)
    name=a.fixture
    run('create',[name,'-preScript','GhidraBoyConditionalCalls.java',w/'original',repo/'src/test/resources/conditional'/(name+'.gb'),name],'CONDITIONAL_NATIVE_CAPTURE_COMPLETE')
    (w/'project-before-reopen.json').write_text(json.dumps(snapshot(w/'projects'),indent=2))
    run('reopen',[name,'-process',name+'.gb','-noanalysis','-readOnly','-postScript','GhidraBoyConditionalLifecycle.java',w/'reopen','reopen'],'CONDITIONAL_LIFECYCLE_COMPLETE reopen')
    (w/'project-after-reopen.json').write_text(json.dumps(snapshot(w/'projects'),indent=2))
    if (w/'original/original-registration.json').read_bytes()!=(w/'reopen/reopen-registration.json').read_bytes():raise RuntimeError('Stored authority changed on immutable reopen')
    if a.faults:
        for suffix,mode in [('fault','stale-refresh'),('mapper-fault','mapper-stale'),('remove','remove')]:
            project=name+'-'+suffix;shutil.copy2(w/'projects'/(name+'.gpr'),w/'projects'/(project+'.gpr'));shutil.copytree(w/'projects'/(name+'.rep'),w/'projects'/(project+'.rep'))
            run(suffix,[project,'-process',name+'.gb','-noanalysis','-postScript','GhidraBoyConditionalLifecycle.java',w/suffix,mode],'CONDITIONAL_LIFECYCLE_COMPLETE '+mode)
    print('CONDITIONAL_REHEARSAL_PASS')
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ['runtime','jdk','work']:p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--fixture',choices=['carry','relocated','indirect'],default='carry');p.add_argument('--faults',action='store_true');main(p.parse_args())
