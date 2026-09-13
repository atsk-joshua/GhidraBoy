#!/usr/bin/env python3
"""Mutate passing decisive captures; unsupported oracle paths never count as rejection."""
import argparse
import copy
import json
from pathlib import Path
import check_finite_dispatch as oracle
from check_predicated_calls import Capture, Refusal, Insufficient

def run(root,nibble=False,physical=False):
    original=Capture(root,'original')
    baseline=oracle.check(root,nibble=nibble,physical=physical)
    if baseline['native_target_provenance']!='PASS':raise RuntimeError('Passing native provenance baseline required')
    cases={}
    def trial(name,mutate):
        cap=copy.deepcopy(original);mutate(cap)
        try:oracle.check(root,nibble=nibble,physical=physical,capture=cap)
        except Insufficient as error:raise RuntimeError('ORACLE_INSUFFICIENT '+name+': '+str(error)) from error
        except Refusal as error:cases[name]=dict(status='REJECTED',reason=str(error));return
        raise RuntimeError('SURVIVED '+name)
    def requested(cap):return cap.requested['root']
    def high(cap):return [o for b in cap.high['root'] for o in b['ops']]
    def wrong_space(cap):
        op=next(o for o in requested(cap) if o['mnemonic']=='LOAD');op['inputs'][0]['offset']=987654
    def wrong_order(cap):
        op=next(o for o in requested(cap) if o['mnemonic']=='LOAD' and o['inputs'][1]['constant'] and o['inputs'][1]['offset']<0x8000)
        op['inputs'][1]['offset']+=1
    def missing(cap):
        n=next(n for n in cap.proof['nodes'] if n['transfer']=='BRANCHIND');n['edges'].pop()
    def extra(cap):
        n=next(n for n in cap.proof['nodes'] if n['transfer']=='BRANCHIND');n['edges'].append(copy.deepcopy(n['edges'][0]))
    def native_foreign(cap):
        op=next(o for o in high(cap) if o['mnemonic']=='RETURN');parts=op['sequence'].split(',');parts[-2]=' 987654';op['sequence']=','.join(parts)
    def frame(cap):
        op=next(o for o in requested(cap) if o['mnemonic']=='INT_ADD' and o.get('output',{}).get('space')=='register' and o['output']['offset']==10)
        op['inputs'][1]['offset']+=1
    trial('wrong-actual-memory-space',wrong_space)
    trial('missing-feasible-edge',missing);trial('extra-feasible-edge',extra)
    trial('native-foreign-terminal-with-unchanged-result',native_foreign)
    trial('extra-hardware-frame-effect',frame)
    if not physical:trial('ordered-low-high-byte-confusion',wrong_order)
    if nibble:
        def pointer(cap):
            op=next(o for o in high(cap) if o['mnemonic']=='COPY' and o['inputs'][0]['constant'] and o['inputs'][0]['offset']==0xc061)
            op['inputs'][0]['offset']=0xc062
        trial('lost-saved-HL',pointer)
    elif not physical:
        def guard(cap):
            op=next(o for o in high(cap) if o['mnemonic']=='INT_LESS' and any(v['constant'] and v['offset']==5 for v in o['inputs']))
            next(v for v in op['inputs'] if v['constant'] and v['offset']==5)['offset']=255
        def phase(cap):
            op=next(o for o in high(cap) if o['mnemonic']=='INT_ADD' and o['output']['size']==1 and any(v['constant'] and v['offset']==2 for v in o['inputs']))
            next(v for v in op['inputs'] if v['constant'] and v['offset']==2)['offset']=255
        trial('guard-default-loss',guard);trial('phase-loss',phase)
    else:
        def bank(cap):
            node=next(n for n in cap.proof['nodes'] if n['source']=='rom2::4000');node['fetch'][0]['physical']['bank']=1
        trial('same-CPU-wrong-physical-bank',bank)
        def native_bank(cap):
            op=next(o for o in high(cap) if o['mnemonic']=='CALLOTHER' and o['inputs'][1]['offset']==0x2000)
            op['inputs'][2]['offset']=2 if op['inputs'][2]['offset']==1 else 1
        trial('native-wrong-mapper-with-unchanged-result',native_bank)
    return dict(status='PASS',baseline_cases=baseline['cases'],cases=cases)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('capture',type=Path);parser.add_argument('--nibble',action='store_true');parser.add_argument('--physical',action='store_true');parser.add_argument('--output',type=Path,required=True);a=parser.parse_args()
    result=run(a.capture,a.nibble,a.physical);a.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS',len(result['cases']))
