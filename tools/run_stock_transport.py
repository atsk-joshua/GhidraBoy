#!/usr/bin/env python3
"""Serial installed qualification of self-authored fixtures, with explicit process/exit receipts."""
import argparse,datetime,json,os,subprocess,hashlib
from pathlib import Path
from make_w3b_fixtures import fixtures
from make_w4_fixtures import create
REPO=Path(__file__).resolve().parents[1]
def hashes(root):return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
def main(a):
    e=a.evidence.resolve();e.mkdir(parents=True,exist_ok=True);(e/'projects').mkdir(exist_ok=True);(e/'profile').mkdir(exist_ok=True)
    if a.phase in ('setup','all') and (e/'g2-command.json').exists():raise FileExistsError('Use a fresh qualification output directory')
    records=[]
    fixtures(REPO,e/'fixtures');create(e/'fixtures')
    env=os.environ.copy();env['JAVA_HOME']=str(a.jdk);env['JAVA_TOOL_OPTIONS']='-Duser.home='+str(e/'profile')
    common=[str(a.ghidra/'support/analyzeHeadless'),str(e/'projects')]
    def run(name,project,input,script,args,readonly=False):
        command=common+[project]+(['-process',input,'-readOnly'] if readonly else ['-import',str(input),'-processor','SM83:LE:16:default'])+['-noanalysis','-scriptPath',str(REPO/'src/test/scripts'),'-postScript',script,str(e/name),*args]
        record={'argv':command,'started':datetime.datetime.now(datetime.timezone.utc).isoformat()}
        with (e/(name+'.log')).open('w') as log:result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
        text=(e/(name+'.log')).read_text();record.update(exit=result.returncode,finished=datetime.datetime.now(datetime.timezone.utc).isoformat(),script_error='REPORT SCRIPT ERROR' in text,completion_marker=any(m in text for m in ['CAPTURE_COMPLETE','PERSIST_COMPLETE','DOMAIN_REOPEN_COMPLETE','DOMAIN_PERSISTENCE_REOPEN_COMPLETE']))
        records.append(record)
        (e/(name+'-command.json')).write_text(json.dumps(record,indent=2)+'\n');print(name,json.dumps({k:v for k,v in record.items() if k!='argv'}),flush=True)
    if a.phase in ('setup','all'):
        for name,project,fixture,script,args in [
            ('g2','G2',REPO/'src/test/resources/ordinary/PREDICATED_CALLS.gb','GhidraBoyStockEntry.java',[]),
            ('loop','Loop',e/'fixtures/W3B_LOOP.gb','GhidraBoyStockEntry.java',['loop']),
            ('ordinary','Ordinary',REPO/'src/test/resources/ordinary/F1234.gb','GhidraBoyW2eFinite.java',['stock']),
            ('memory','Memory',e/'fixtures/W4_MEMORY_IMAGE.gb','GhidraBoyMemoryImages.java',['memory','stock']),
            ('source','Source',e/'fixtures/W4_MEMORY_IMAGE.gb','GhidraBoyMemoryImages.java',['source','stock']),
            ('image','Current',e/'fixtures/W4_MEMORY_IMAGE.gb','GhidraBoyMemoryImages.java',['image','stock']),
            ('domains','Current',e/'fixtures/W3B_DOMAINS.gb','GhidraBoyW3bDomains.java',['persist-canonical','stock']),
            ('order','Order',e/'fixtures/W3B_ORDER.gb','GhidraBoyW3bOrder.java',['stock'])]:run(name,project,fixture,script,args)
    if a.phase in ('reopen','all'):
        before=hashes(e/'projects/Current.rep');(e/'project-before-reopen.json').write_text(json.dumps(before,indent=2))
        run('image-reopen','Current','W4_MEMORY_IMAGE.gb','GhidraBoyMemoryImages.java',['reopen','stock'],True)
        run('domains-reopen','Current','W3B_DOMAINS.gb','GhidraBoyW3bDomains.java',['reopen','stock',str(e/'domains')],True)
        after=hashes(e/'projects/Current.rep');(e/'project-after-reopen.json').write_text(json.dumps(after,indent=2))
        (e/'project-reopen-differences.json').write_text(json.dumps({k:{'before':before.get(k),'after':after.get(k)} for k in before.keys()|after.keys() if before.get(k)!=after.get(k)},indent=2))
    return all(r['exit']==0 and not r['script_error'] and r['completion_marker'] for r in records)
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('ghidra','evidence','jdk'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--phase',choices=['setup','reopen','all'],default='all');raise SystemExit(0 if main(p.parse_args()) else 1)
