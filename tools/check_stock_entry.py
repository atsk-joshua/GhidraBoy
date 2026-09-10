#!/usr/bin/env python3
"""Bounded stock mechanism oracle; inherited architectural checks retain original semantics."""
import argparse,json,re
from pathlib import Path
import check_predicated_calls as core
import check_w3b_cfg as loops

class StockCapture(core.Capture):
    def __init__(self,root,receipt,label="original"):
        super().__init__(root,label);self.runtime=core.read(receipt)
    def verify_native(self,tag):
        r=self.runtime;req=self.requests[tag]
        core.require((r.get('build_exit')==0 and r.get('source_unchanged') and r.get('core_unchanged')) or (r.get('status')=='PASS' and r.get('release_files_checked',0)>5000),'unverified pristine runtime')
        core.require(r['release_sha256']=='93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54','wrong release')
        core.require(core.sha(Path(r['native_path']))==r['native_sha256'],'changed stock executable')
        execution=r.get('native_execution_path',r['native_path'])
        def actual_process(p):
            if p.get('parent')!=req['owner_java_pid']:return False
            if p.get('command')==execution and p.get('binary_sha256')==r['native_sha256']:return True
            # Rosetta reports its interpreter as command. Require the actual ELF argv,
            # executable file-backed mapping, and independently hashed read-only mounted file.
            return (p.get('proc_cmdline','').split(' ')[0]==execution
                and any(x.get('path')==execution and x.get('sha256')==r['native_sha256'] for x in p.get('argv_native_files',[]))
                and any(re.search(r'\br-xp\b',line) and line.endswith(' '+execution) for line in p.get('proc_maps','').splitlines()))
        core.require(any(actual_process(p) for p in req['processes_after']),'wrong actual stock process')
        debug=self.root/f'{self.label}-{tag}-debug.xml'
        core.require(core.sha(debug)==req['debug']['sha256'],'changed native debug')
        return core.base.debug_identity(debug,self.requested[tag],req['entry'],inject_name='gb_analysis_entry_v1')

def run(args):
    cap=StockCapture(args.capture,args.runtime);image=args.fixture.read_bytes()
    result={'runtime':cap.runtime['native_sha256'],'surface':'Actual stock HighFunction plus debug replay, not packed wire capture'}
    try:
        core.require(core.read(args.capture/'canonical-before.json')==core.read(args.capture/'canonical-after-install.json'),'canonical source changed during installation')
        for view in cap.views:
            ops=core.read(args.capture/f"original-{view['tag']}-carrier.json")
            entry=view['view']['entry'];space,offset=entry.split('::')
            core.require(len(ops)==2 and ops[0]['mnemonic']=='CALLOTHER' and ops[0].get('userop_name')=='gb_analysis_entry_v1' and len(ops[0]['inputs'])==1,'carrier contains extra or missing effects')
            core.require(ops[1]['mnemonic']=='BRANCH' and ops[1]['inputs'][0]['space']==space and ops[1]['inputs'][0]['offset']==int(offset,16),'carrier lacks initial raw self bound')
        result['canonical_and_carriers']='PASS'
        result['positive']=loops.loop_stage(cap,image) if args.loop else core.run_stage(cap,image)
        result['mutants']=loops.loop_negatives(cap,image) if args.loop else core.mutants(cap,image)
        invalid=core.read(args.capture/'missing-authority-root-request.json')
        core.require(not invalid['completed'] and not invalid['highfunction_available'] and 'Missing predicated graph registration' in invalid['error'],'missing authority exposed a native result')
        result['missing_authority']='REFUSED_ACTUAL_NATIVE_RESULT';result['status']='PASS'
    except (core.Refusal,core.Insufficient) as e:
        result['status']='ORACLE_INSUFFICIENT' if isinstance(e,core.Insufficient) else 'FAIL';result['reason']=str(e)
    args.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
    return result['status']=='PASS'
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('capture','fixture','runtime','out'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--loop',action='store_true')
    raise SystemExit(0 if run(p.parse_args()) else 1)
