#!/usr/bin/env python3
"""Check actual normal-window captures separately from capture completion.

The initial witness is deliberately PARTIAL even when its passive safety passes.
Uses the maintained finite all-input/effect oracle without another CPU interpreter.
"""
import argparse
import copy
import json
from pathlib import Path
import check_w2e_native as finite


def check_initial(root, records=None, timeline=None, highs=None):
    require = finite.require
    records = records or {p: finite.read(root / f'{p}-request.json') for p in ('P0', 'P1', 'P2')}
    timeline = timeline if timeline is not None else finite.read(root / 'timeline.json')
    highs = highs or {p: finite.read(root / f'{p}-high.json') for p in ('P0', 'P1')}
    mutation = finite.read(root / 'P-mutation.json')
    require(mutation['changed_file_offsets'] == [0xe000] and mutation['old'] == 0xd3 and mutation['new'] == 0xe4 and mutation['old_registration_retained'] and mutation['read_only_ROM'], 'invalid consumed-byte witness')
    first = records['P0']
    require(first['entry'] == 'gb_ordinary_150::0150', 'foreign fixture entry')
    stages = {}
    for phase, r in records.items():
        require(r['surface'] == 'normal-CodeBrowser-DecompilerProvider' and r['visible'], 'not a visible normal window')
        for key in ('program_id', 'program_object', 'owner_java_pid', 'java_start', 'controller_identity', 'entry', 'function_id'):
            require(r[key] == first[key], 'foreign/replaced ' + key)
        require(r['phase'] == phase, 'mislabeled phase')
        for suffix, key in (('-desktop.png','desktop_sha256'),('.c','c_sha256'),('-high.json','high_sha256')):
            if key in r: require(finite.sha(root / (phase + suffix)) == r[key], 'changed captured ' + key)
        if phase != 'P2':
            require(r['completed'] and r['highfunction_available'] and r['display_program_matches'] and r['display_program_id'] == first['program_id'] and r['display_function_matches'] and r['display_entry'] == first['entry'], 'positive identity/result unavailable')
            stages[phase] = finite.check_domain(finite.flatten(highs[phase]), 0xd3, True)
    captures = [x['detail']['phase'] for x in timeline if x['kind'] == 'passive-capture']
    require(captures == ['P0', 'P1', 'P2'], 'missing/duplicate/out-of-order passive phase')
    kinds = [x['kind'] for x in timeline]
    require(kinds.count('P-mutation-committed') == 1, 'missing/duplicate mutation')
    start = kinds.index('P-mutation-committed')
    end = next(i for i,x in enumerate(timeline) if x['kind']=='passive-capture' and x['detail']['phase']=='P2')
    require(start < end, 'passive phase predates mutation')
    allowed = {'program-event', 'settled', 'passive-capture'}
    require(all(x['kind'] in allowed for x in timeline[start+1:end+1]), 'active intervention before passive observation')
    require(any(x['kind']=='program-event' for x in timeline[start+1:end]), 'no real event delivery')
    require(any(x['kind']=='settled' and x['detail']['stable_samples'] >= 16 for x in timeline[start+1:end]), 'unsettled passive observation')
    p2=records['P2']
    require(p2['revision'] > first['revision'] and p2['events'] > first['events'], 'mutation not delivered')
    # This driver does not manufacture a stale badge. Retained output needs separately
    # captured unmistakable shipped stale UI; absent that, valid old output is a failure.
    require(not p2['highfunction_available'] and not p2['completed'] and 'c_sha256' not in p2, 'passive stale result still apparently current')
    return {'status':'PARTIAL','primary_passive_safety':'PASS','positive_relations':stages,
            'remaining':['explicit proof/window refresh','image generations','Program switching','missing registration','actual process-exit/read-only reopen','final candidate full tests']}


def sensitivity(root):
    base={p:finite.read(root/f'{p}-request.json') for p in ('P0','P1','P2')}
    highs={p:finite.read(root/f'{p}-high.json') for p in ('P0','P1')}
    timeline=finite.read(root/'timeline.json'); results={}
    if any(x['kind']=='initial-witness-complete' for x in timeline):timeline=timeline[:next(i for i,x in enumerate(timeline) if x['kind']=='initial-witness-complete')+1]
    for name in ('replay','foreign-program','missing-passive','duplicate-passive','active-before-passive','missing-high','malformed-high'):
        rs=copy.deepcopy(base);ts=copy.deepcopy(timeline);hs=copy.deepcopy(highs)
        if name=='replay': rs['P2'].update(completed=True,highfunction_available=True)
        elif name=='foreign-program':rs['P1']['display_program_id']+=1
        elif name=='missing-passive':ts=[x for x in ts if not (x['kind']=='passive-capture' and x['detail']['phase']=='P2')]
        elif name=='duplicate-passive':ts.append(next(x for x in ts if x['kind']=='passive-capture' and x['detail']['phase']=='P2'))
        elif name=='active-before-passive':ts.insert(next(i for i,x in enumerate(ts) if x['kind']=='P-mutation-committed')+1,{'kind':'refresh'})
        elif name=='missing-high':rs['P0']['highfunction_available']=False
        elif name=='malformed-high':
            op=next(op for b in hs['P0'] for op in b['ops'] if op['mnemonic']=='CALLOTHER')
            op['inputs'][2]=dict(id=-100,space='const',offset=0,size=1,constant=True,address=False,register=False)
        try:check_initial(root,rs,ts,hs)
        except finite.Refusal as exc:results[name]={'status':'REJECTED','reason':str(exc)}
        else:raise finite.Refusal('sensitivity failed '+name)
    return results


def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    try:
        result=check_initial(args.root);result['sensitivity']=sensitivity(args.root)
    except (finite.Refusal,finite.Insufficient) as exc:
        result={'status':'ORACLE_INSUFFICIENT' if isinstance(exc,finite.Insufficient) else 'FAIL','reason':str(exc)}
    args.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
    return 0 if result['status']=='PARTIAL' else 1



def checked_record(root,phase):
    r=finite.read(root/f'{phase}-request.json')
    finite.require(r['phase']==phase and r['surface']=='normal-CodeBrowser-DecompilerProvider' and r['visible'],'foreign/invisible phase')
    finite.require('desktop_sha256' in r,'missing actual screenshot')
    if r['highfunction_available']:finite.require('high_sha256' in r and 'c_sha256' in r,'missing positive artifacts')
    for suffix,key in (('-desktop.png','desktop_sha256'),('.c','c_sha256'),('-high.json','high_sha256')):
        if key in r:finite.require(finite.sha(root/(phase+suffix))==r[key],'changed artifact '+phase+key)
    finite.require(r['display_program_matches'] and r['display_function_matches'] and r['display_entry']==r['entry'] and r['display_program_id']==r['program_id'],'foreign displayed identity, including refusal')
    if r['highfunction_available']:
        finite.require(r['completed'] and r['display_program_matches'] and r['display_function_matches'] and r['display_entry']==r['entry'] and r['display_program_id']==r['program_id'],'foreign displayed identity')
    return r


def refusal(r):
    finite.require(not r['completed'] and not r['highfunction_available'] and 'c_sha256' not in r,'invalid authority exposed current native output')


def image_relation(root,phase,source_root,source_label,value):
    import types
    import check_w4_memory_images as image
    from make_w4_fixtures import I1,I2
    bindings=finite.read(source_root/'Q-bindings.json');image.validate_bindings(bindings)
    cap=types.SimpleNamespace(high={'root':finite.read(root/f'{phase}-high.json')},requests={'root':finite.read(root/f'{phase}-request.json')},raw=finite.read(source_root/f'{source_label}-raw.json'))
    proof=finite.read(source_root/f'{source_label}-proof.json')
    finite.require(proof['coverageComplete'] and not proof['frontier'] and proof['memory']['image'],'unqualified image source')
    frames=[(0xc800,0x190,0,0x53,0xa6,0xbeef),(0xc8fe,0x1234,0xa0,0x81,0x1234,0x7654),(0xcffc,0xffff,0xe0,0x19,0x8765,0xabcd)]
    for frame in frames:
        for carry in (0,0x10):
            frame=(*frame[:2],frame[2]|carry,*frame[3:])
            raw=image.Machine(b'',0,frame,bindings,I1 if value==0x31 else I2,0xc200);raw.raw(cap)
            native=image.Machine(b'',0,frame,bindings,I1 if value==0x31 else I2,0xc200);native.high(cap)
            finite.require(raw.mem==native.mem and native.mem[0xc074]==value,'image native/physical relation mismatch')
    return {'cases':6,'C074':value,'generation':proof['memory']['image']}


def check_full(root,reopen_root):
    require=finite.require
    timeline=finite.read(root/'timeline.json')
    cutoff=next(i for i,x in enumerate(timeline) if x['kind']=='initial-witness-complete')
    initial=check_initial(root,timeline=timeline[:cutoff+1])
    phases=['P0','P1','P2','P3','canonical-control','Q0','Q1','Q2','Q-old-generation','switch-P','switch-Q','switch-P-return','quick-P-settled','missing-warm','missing-passive','missing-active']
    records={phase:checked_record(root,phase) for phase in phases}
    require([x['detail']['phase'] for x in timeline if x['kind']=='passive-capture']==phases,'skipped/duplicated workflow phase')
    for item in timeline:
        if item['kind']=='passive-capture':
            require(item['detail']['record_sha256']==finite.sha(root/(item['detail']['phase']+'-request.json')),'changed phase receipt')
    p=records['P0'];q=records['Q0'];require(p['program_id']!=q['program_id'],'P/Q not distinct Programs')
    require(len({r['controller_identity'] for r in records.values()})==1 and len({r['owner_java_pid'] for r in records.values()})==1,'window/controller replaced')
    result={'initial':initial,'ordinary':{},'images':{}}
    for phase in ('P3','switch-P','switch-P-return','quick-P-settled','missing-warm'):
        r=records[phase];require(r['highfunction_available'],'missing current ordinary result')
        if phase!='missing-warm':require(r['program_id']==p['program_id'] and r['entry']==p['entry'],'P switched identity')
        result['ordinary'][phase]=finite.check_domain(finite.flatten(finite.read(root/f'{phase}-high.json')),0xe4,True)
    require(finite.read(root/'P-source-before.json')==finite.read(root/'P-source-after.json'),'canonical source specialized')
    c=(root/'canonical-control.c').read_text();require('ordinary-entry-access-experiment' not in c and 'Physical invocation premise' not in c,'canonical inherited conditional header')
    for phase,source,value in [('Q0','Q0',0x31),('Q2','Q2',0xa7),('switch-Q','Q2',0xa7)]:
        r=records[phase];require(r['highfunction_available'] and r['program_id']==q['program_id'],'image positive identity')
        result['images'][phase]=image_relation(root,phase,root,source,value)
    require(result['images']['Q0']['generation']!=result['images']['Q2']['generation'],'generation substitution')
    mutation=finite.read(root/'Q-mutation.json');require(mutation['old_image_retained'] and mutation['old_proof_retained'] and mutation['cpu']==0xc200 and mutation['bytes']=='3ea7ea74c0c9' and mutation['generation']==result['images']['Q0']['generation'],'invalid physical image replacement witness')
    for phase in ('P2','Q1','Q-old-generation','missing-passive','missing-active'):refusal(records[phase])
    require(records['Q-old-generation']['entry']==q['entry'] and records['Q-old-generation']['entry']!=records['Q2']['entry'],'historical generation redirected')
    for mutation,passive in [('Q-mutation-committed','Q1'),('registration-removed','missing-passive')]:
        start=next(i for i,x in enumerate(timeline) if x['kind']==mutation)
        end=next(i for i,x in enumerate(timeline) if x['kind']=='passive-capture' and x['detail']['phase']==passive)
        require(start<end and all(x['kind'] in {'program-event','settled','passive-capture'} for x in timeline[start+1:end+1]),'intervention before '+passive)
        require(any(x['kind']=='program-event' for x in timeline[start+1:end]),'no event delivery '+passive)
    for name in ('P','Q'):
        saved=(root/f'{name}-saved-authority.json').read_bytes()
        require(saved==(reopen_root/f'{name}-before-authority.json').read_bytes()==(reopen_root/f'{name}-after-authority.json').read_bytes(),'saved authority changed '+name)
    for base in (root,reopen_root):
        closures=finite.read(base/'program-closures.json');require(all(x['closed'] and x['consumers']==0 for x in closures),'retained Programs')
        require(not finite.read(base/'tool-closed.json')['tool_visible'],'tool not closed')
    reopened={phase:checked_record(reopen_root,phase) for phase in ('reopen-P','reopen-Q','reopen-Q-old')}
    require(all(r['read_only'] for r in reopened.values()),'writable reopen')
    reopen_timeline=finite.read(reopen_root/'timeline.json')
    require([x['detail']['phase'] for x in reopen_timeline if x['kind']=='passive-capture']==['reopen-P','reopen-Q','reopen-Q-old'],'skipped/duplicated reopen captures')
    for item in reopen_timeline:
        if item['kind']=='passive-capture':require(item['detail']['record_sha256']==finite.sha(reopen_root/(item['detail']['phase']+'-request.json')),'changed reopen phase receipt')
    require(all(x['kind'] in {'navigate','settled','passive-capture'} for x in reopen_timeline),'reopen performed an active establishment/refresh')
    require(len({r['controller_identity'] for r in reopened.values()})==1 and len({r['owner_java_pid'] for r in reopened.values()})==1 and len({r['java_start'] for r in reopened.values()})==1,'mixed second-session captures')
    full_exit=finite.read(root.parent/'process-exit.json');new_exit=finite.read(reopen_root.parent/'process-exit.json')
    require(full_exit['exited'] and full_exit['exit']==0 and not full_exit.get('timeout') and full_exit['tool_closure_marker'],'first JVM not cleanly exited')
    require(new_exit['exited'] and new_exit['exit']==0 and not new_exit.get('timeout') and new_exit['tool_closure_marker'],'second JVM not cleanly exited')
    require(full_exit['pid']==p['owner_java_pid'] and new_exit['pid']==reopened['reopen-P']['owner_java_pid'] and full_exit['end_ns']<new_exit['start_ns'],'fake reopen chronology/process')
    for r in reopened.values():require(r['owner_java_pid']!=p['owner_java_pid'] and r['java_start']!=p['java_start'],'fake same-process reopen')
    require(reopened['reopen-P']['program_id']==p['program_id'] and reopened['reopen-P']['entry']==p['entry'],'reopened P identity')
    require(reopened['reopen-Q']['program_id']==q['program_id'] and reopened['reopen-Q']['entry']==records['Q2']['entry'],'reopened Q current generation identity')
    result['ordinary']['reopen-P']=finite.check_domain(finite.flatten(finite.read(reopen_root/'reopen-P-high.json')),0xe4,True)
    result['images']['reopen-Q']=image_relation(reopen_root,'reopen-Q',root,'Q2',0xa7)
    refusal(reopened['reopen-Q-old']);require(reopened['reopen-Q-old']['entry']==q['entry'],'old generation substitution at reopen')
    result['status']='CAPTURE_CHECKS_PASS_PENDING_PROCESS_AND_VISIBLE_REVIEW'
    return result

def full_sensitivity(root,reopened):
    import tempfile,shutil
    outcomes={}
    for kind in ('old-generation-substitution','fake-same-process-reopen','skipped-reopen-phase','foreign-refusal'):
        with tempfile.TemporaryDirectory(prefix='g1-window-mutant-') as tmp:
            dst=Path(tmp)
            for name,source in [('full',root),('reopen',reopened)]:
                shutil.copytree(source,dst/name/'captures')
                shutil.copy2(source.parent/'process-exit.json',dst/name/'process-exit.json')
            full=dst/'full/captures';second=dst/'reopen/captures'
            target=full if kind in ('old-generation-substitution','foreign-refusal') else second
            phase='Q2' if kind=='old-generation-substitution' else 'Q-old-generation' if kind=='foreign-refusal' else 'reopen-P'
            record=finite.read(target/f'{phase}-request.json')
            if kind=='old-generation-substitution':
                shutil.copy2(full/'Q0-high.json',full/'Q2-high.json');shutil.copy2(full/'Q0.c',full/'Q2.c')
                record['high_sha256']=finite.sha(full/'Q2-high.json');record['c_sha256']=finite.sha(full/'Q2.c')
            elif kind=='fake-same-process-reopen':record['owner_java_pid']=finite.read(full/'P0-request.json')['owner_java_pid'];record['java_start']=finite.read(full/'P0-request.json')['java_start']
            elif kind=='foreign-refusal':record['display_program_id']=finite.read(full/'P0-request.json')['program_id']
            (target/f'{phase}-request.json').write_text(json.dumps(record))
            timeline=finite.read(target/'timeline.json')
            if kind=='skipped-reopen-phase':timeline=[x for x in timeline if not (x['kind']=='passive-capture' and x['detail']['phase']=='reopen-P')]
            for item in timeline:
                if item['kind']=='passive-capture' and item['detail']['phase']==phase:item['detail']['record_sha256']=finite.sha(target/f'{phase}-request.json')
            (target/'timeline.json').write_text(json.dumps(timeline))
            try:check_full(full,second)
            except finite.Refusal as exc:outcomes[kind]={'status':'REJECTED','reason':str(exc)}
            else:raise finite.Refusal('full sensitivity failed '+kind)
    return outcomes

if __name__=='__main__':
    import sys
    if '--reopen' in sys.argv:
        parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--reopen',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);a=parser.parse_args()
        try:
            r=check_full(a.root,a.reopen);r['initial_sensitivity']=sensitivity(a.root);r['sensitivity']=full_sensitivity(a.root,a.reopen)
        except FileNotFoundError as exc:r={'status':'INCOMPLETE','reason':str(exc)}
        except (finite.Refusal,finite.Insufficient) as exc:r={'status':'ORACLE_INSUFFICIENT' if isinstance(exc,finite.Insufficient) else 'FAIL','reason':str(exc)}
        a.out.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2));raise SystemExit(0 if r['status'].startswith('CAPTURE_CHECKS_PASS') else 1)
    raise SystemExit(main())
