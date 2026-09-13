#!/usr/bin/env python3
"""Attended execution of a compiled normal-window command, with unchanged source/class checks."""
import argparse,hashlib,json,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('command',type=Path)
p.add_argument('--attended',action='store_true',help='Operator confirms an attended desktop session with capture permission')
a=p.parse_args()
if not a.attended:p.error('Only run after attended desktop/capture permission is confirmed')
root=a.command.resolve().parent
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
for name in ('driver-inputs.json','compiled-classes.json'):
    for path,expected in json.loads((root/name).read_text()).items():
        actual=Path(path) if name=='driver-inputs.json' else root/path
        if sha(actual)!=expected:raise RuntimeError('Changed prepared input: '+str(actual))
command=json.loads(a.command.read_text())
receipt={'argv':command,'start_ns':time.time_ns(),'attended_operator_start':True}
with (root/'launch.log').open('x') as log:
    process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT);receipt['pid']=process.pid
    (root/'process-start.json').write_text(json.dumps(receipt,indent=2))
    try:receipt['exit']=process.wait(timeout=600)
    except subprocess.TimeoutExpired:
        process.terminate();receipt['exit']=process.wait(timeout=20);receipt['timeout']=True
receipt['end_ns']=time.time_ns()
(root/'process-exit.json').write_text(json.dumps(receipt,indent=2))
if receipt['exit'] or receipt.get('timeout') or not (root/'captures/public-window-complete.json').exists():raise SystemExit(1)
