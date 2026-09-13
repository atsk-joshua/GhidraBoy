#!/usr/bin/env python3
"""Replay the source-derived physical direct/indirect discriminator on stock captures."""
import argparse
import json
from pathlib import Path
import check_predicated_calls as core

NATIVES={'c5e9775345e6841c717995a85f0bc33a972acc84b0990ad0d6fbccd6db0ae77d',
         '4a97ff9a3dbac5757c7240a664571e82345e4abc4f67cd211cd9d402abe4543d'}

def check(root):
    results={}
    for bank,expected in [(1,0x35),(2,0xca)]:
        for form in ['direct','indirect']:
            label=f'bank{bank}-{form}';folder=root/label;cap=core.Capture(folder,'original')
            proof=cap.proof
            core.require(proof['coverageComplete'] and not proof['frontier'],'incomplete source proof')
            reads=[r for n in proof['nodes'] for r in n['reads']]
            core.require(len(reads)==1,'ambiguous read provenance')
            read=reads[0];alts=read['alternatives']
            core.require(len(alts)==1 and alts[0]['cpu']==0x4123,'wrong CPU read')
            src=alts[0]['sources'][0]
            core.require(src['physical']==dict(region='ROM',bank=bank,offset=0x123) and src['value']==expected,'wrong physical source byte')
            requested=cap.requested['root']
            if form=='direct':
                operands=[v for o in requested for v in o['inputs'] if v['address'] and v['offset']==0x4123]
                core.require(len(operands)==1 and operands[0]['space']==f'rom{bank}','unbound direct physical operand')
            else:
                loads=[o for o in requested if o['mnemonic']=='LOAD' and o['inputs'][1]['constant'] and o['inputs'][1]['offset']==0x4123]
                core.require(len(loads)==1,'missing qualified indirect LOAD')
            request=cap.requests['root']
            core.require(request['completed'] and request['highfunction_available'],'native request unavailable')
            core.require(any(p.get('parent')==request['owner_java_pid'] and p.get('binary_sha256') in NATIVES for p in request['processes_after']),'unverified native identity')
            debug=folder/'original-root-debug.xml'
            core.require(core.sha(debug)==request['debug']['sha256'],'changed native capture')
            core.base.debug_identity(debug,requested,request['entry'],'gb_analysis_entry_v1')
            machine=core.Machine(bytes(65536),0)
            actual=machine.high(cap)
            core.require(actual==expected and machine.bank==bank,'native physical read mismatch')
            core.require(machine.events==[('mapper',0x2000,bank)],'extra native memory effect')
            results[label]=dict(status='PASS',value=actual,bank=machine.bank,cost=core.read(folder/'cost.json'))
    return results

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('capture',type=Path);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    try:result=dict(status='PASS',cases=check(args.capture))
    except Exception as error:
        args.output.write_text(json.dumps(dict(status='FAIL',error=str(error)),indent=2)+'\n');raise
    args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS')
