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


# Diagnostics are observations only. Mutation/action/navigation kinds remain forbidden.
OBSERVATIONS = {'program-event', 'transaction-sample', 'transaction-callback',
                'operation-settled', 'settled', 'snapshot-discarded', 'passive-capture'}


def correlated_operation(timeline, purpose, record, phase, allowed_after=()):
    """Correlate a real source-qualified event, never a post-return log order.

    TransactionInfo identifies the encompassing DB transaction; subtransaction IDs
    identify only the driver's entries. Synthetic scheduling tests are not GUI evidence.
    """
    require = finite.require
    matches = [(i,x) for i,x in enumerate(timeline) if x['kind']=='operation-begin' and x['detail']['purpose']==purpose]
    require(len(matches)==1, 'missing/duplicate qualified operation '+purpose)
    begin_i, begin = matches[0]; b=begin['detail']; operation=b['operation']; target=b['target']
    require(all(target[k]==record[k] for k in ('program_id','program_object','owner_java_pid')), 'foreign operation Program')
    def one(kind):
        found=[(i,x) for i,x in enumerate(timeline) if x['kind']==kind and x['detail'].get('operation')==operation]
        require(len(found)==1,'missing/duplicate '+kind+' '+operation);return found[0]
    started_i,started=one('operation-started');enter_i,enter=one('commit-call-enter');ret_i,ret=one('commit-call-return');done_i,done=one('operation-settled')
    cap=[(i,x) for i,x in enumerate(timeline) if x['kind']=='passive-capture' and x['detail']['phase']==phase]
    require(len(cap)==1,'missing operation passive capture');cap_i,_=cap[0]
    require(begin_i<started_i<enter_i<ret_i<done_i<cap_i,'capture before operation completion')
    bracket=[begin,started,enter,ret,done]
    require(all(x.get('schema')==2 for x in bracket),'historical trace lacks protocol schema')
    require(all(x['nano']<y['nano'] for x,y in zip(bracket,bracket[1:])), 'noncausal operation timestamps')
    for x in (started,enter,ret,done):
        d=x['detail'];require(d['target']==target and d['pre_revision']==b['pre_revision'] and d['pre_events']==b['pre_events'],'wrong operation provenance')
        require(d['subtransaction']==started['detail']['subtransaction'] and d['encompassing']['id']==started['detail']['encompassing']['id'],'wrong transaction identity')
    require(enter['detail']['commit_requested'] and ret['detail']['commit_requested'],'aborted operation')
    final_tx=done['detail']['encompassing']
    require(final_tx['status']=='COMMITTED' and final_tx['db_committed'] and not final_tx['active'] and not final_tx['open_subtransactions'],'uncommitted encompassing transaction')
    returned_tx=ret['detail']['encompassing']
    require(not ret['detail']['returned_committed'] or returned_tx['status']=='COMMITTED','inconsistent returned commit status')
    revision=ret['detail']['revision']
    require(revision>b['pre_revision'] and record['revision']>=revision and record['events']>b['pre_events'],'old operation revision/event')
    require(all(x['kind'] in OBSERVATIONS | set(allowed_after) for x in timeline[ret_i+1:cap_i+1]),'active intervention before '+phase)
    during=OBSERVATIONS | {'operation-started','commit-call-enter','commit-call-return'}
    if purpose in ('proof-write','variant-proof-write'):during |= {'explicit-provider-action','provider-action-listing-context'}
    require(all(x['kind'] in during for x in timeline[begin_i+1:ret_i+1]),'active intervention during measured operation '+phase)
    events=[]
    for i,x in enumerate(timeline[begin_i+1:cap_i],begin_i+1):
        if x['kind']!='program-event':continue
        d=x['detail']
        if d.get('target')!=target or d.get('revision',-1)<revision or d.get('event_sequence',-1)<=b['pre_events']:continue
        require(x.get('schema')==2 and begin['nano']<x['nano']<timeline[cap_i]['nano'],'noncausal event observation')
        types={r['type'] for r in d['records']}
        if purpose in ('P-mutation','Q-mutation'):
            # Use the actual changed physical address supplied by the operation.
            expected=enter['detail'].get('affected_start')
            require(expected is not None,'missing physical operation address')
            if not any(r['type']=='MEMORY_BYTES_CHANGED' and r.get('start')==expected for r in d['records']):continue
        elif purpose in ('proof-write','variant-proof-write','registration-removal'):
            option='GhidraBoyStockOrdinaryEntries.'+record['entry']
            if not any(r['type']=='PROPERTY_CHANGED' and r.get('old')==option and (r.get('new')=='null')==(purpose=='registration-removal') for r in d['records']):continue
        elif purpose=='Q-generation':
            option='GhidraBoyStockPredicatedCalls.'+record['entry']
            if not any(r['type']=='PROPERTY_CHANGED' and r.get('old')==option and r.get('new')!='null' for r in d['records']):continue
        events.append((i,x))
    require(events,'no correlated real event delivery '+phase)
    settled=[(i,x['detail']) for i,x in enumerate(timeline) if x['kind']=='settled' and ret_i<i<cap_i and x['detail'].get('target')==target]
    require(settled,'no target settlement '+phase)
    si,st=settled[-1]
    require(st['transaction_free'] and st['stable_samples']>=24 and st['revision']==record['revision'] and st['events']==record['events'] and st['data_identity']==record['data_identity'] and st['entry']==record['entry'],'unstable/foreign settled capture')
    require(any(i<si for i,x in events) and record['transaction_free'],'capture before relevant event settlement')
    return {'operation':operation,'event_sequences':[x['detail']['event_sequence'] for i,x in events],
            'callback_before_return_receipt':any(i<ret_i for i,x in events),'returned_committed':ret['detail']['returned_committed']}


def check_initial(root, records=None, timeline=None, highs=None):
    require = finite.require
    timeline = timeline if timeline is not None else finite.read(root / 'timeline.json')
    records = records or {p: checked_record(root, p, timeline) for p in ('P0', 'P1', 'P2')}
    for phase, record in records.items():
        checked_record(root, phase, timeline, record)
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
    correlated_operation(timeline,'P-mutation',records['P2'],'P2',{'P-mutation-committed'})
    p2=records['P2']
    require(p2['revision'] > first['revision'] and p2['events'] > first['events'], 'mutation not delivered')
    # This driver does not manufacture a stale badge. Retained output needs separately
    # captured unmistakable shipped stale UI; absent that, valid old output is a failure.
    refusal(p2)
    return {'status':'PARTIAL','primary_passive_safety':'PASS','positive_relations':stages,
            'remaining':['explicit proof/window refresh','image generations','Program switching','missing registration','actual process-exit/read-only reopen','final candidate full tests']}


def sensitivity(root):
    import tempfile, shutil
    check_initial(root,timeline=finite.read(root/'timeline.json')[:next(i for i,x in enumerate(finite.read(root/'timeline.json')) if x['kind']=='initial-witness-complete')+1])
    results={}
    names=('replay','foreign-program','missing-passive','duplicate-passive','active-before-passive','missing-high','malformed-high',
           'foreign-P2','unrelated-native-error','missing-desktop','changed-request-hash')
    for name in names:
        with tempfile.TemporaryDirectory(prefix='g1-initial-control-') as tmp:
            dst=Path(tmp)/'captures';shutil.copytree(root,dst)
            ts=finite.read(dst/'timeline.json')
            if any(x['kind']=='initial-witness-complete' for x in ts):ts=ts[:next(i for i,x in enumerate(ts) if x['kind']=='initial-witness-complete')+1]
            phase='P1' if name=='foreign-program' else 'P0' if name in ('missing-high','malformed-high') else 'P2'
            rs=finite.read(dst/f'{phase}-request.json')
            if name=='replay':rs.update(completed=True,highfunction_available=True)
            elif name=='foreign-program':rs['display_program_id']+=1
            elif name=='foreign-P2':rs.update(display_program_id=-1,display_entry='ram:1234',display_program_matches=False,display_function_matches=False)
            elif name=='unrelated-native-error':rs['error']='Native process terminated unexpectedly'
            elif name=='missing-desktop':rs.pop('desktop_sha256',None)
            elif name=='changed-request-hash':rs['revision']+=1
            elif name=='missing-passive':ts=[x for x in ts if not (x['kind']=='passive-capture' and x['detail']['phase']=='P2')]
            elif name=='duplicate-passive':ts.append(next(x for x in ts if x['kind']=='passive-capture' and x['detail']['phase']=='P2'))
            elif name=='active-before-passive':ts.insert(next(i for i,x in enumerate(ts) if x['kind']=='P-mutation-committed')+1,{'kind':'refresh'})
            elif name=='missing-high':rs['highfunction_available']=False
            elif name=='malformed-high':
                hs=finite.read(dst/'P0-high.json')
                op=next(op for b in hs for op in b['ops'] if op['mnemonic']=='CALLOTHER')
                op['inputs'][2]=dict(id=-100,space='const',offset=0,size=1,constant=True,address=False,register=False)
                (dst/'P0-high.json').write_text(json.dumps(hs));rs['high_sha256']=finite.sha(dst/'P0-high.json')
            (dst/f'{phase}-request.json').write_text(json.dumps(rs))
            if name!='changed-request-hash':
                for x in ts:
                    if x['kind']=='passive-capture' and x['detail']['phase']==phase:x['detail']['record_sha256']=finite.sha(dst/f'{phase}-request.json')
            (dst/'timeline.json').write_text(json.dumps(ts))
            try:check_initial(dst)
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



def checked_record(root,phase,timeline=None,record=None):
    r=record if record is not None else finite.read(root/f'{phase}-request.json')
    timeline=timeline if timeline is not None else finite.read(root/'timeline.json')
    receipts=[x for x in timeline if x['kind']=='passive-capture' and x['detail']['phase']==phase]
    finite.require(len(receipts)==1 and receipts[0]['detail']['record_sha256']==finite.sha(root/f'{phase}-request.json'),'missing/changed request receipt '+phase)
    finite.require(r==finite.read(root/f'{phase}-request.json'),'unbound supplied request '+phase)
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
    finite.require(not r['completed'] and not r['highfunction_available'] and 'c_sha256' not in r and 'high_sha256' not in r,'invalid authority exposed current native output')
    reasons={'P2':('Stale ordinary-entry registration; preview and refresh required',), 'Q1':('Established RAM bytes replaced; explicit establishment required',),
             'Q-old-generation':('Noncurrent executable generation ',), 'reopen-Q-old':('Noncurrent executable generation ',),
             'missing-passive':('Unavailable stock analysis entry: Missing predicated graph registration or stock software carrier',), 'missing-active':('Unavailable stock analysis entry: Missing predicated graph registration or stock software carrier',)}
    expected=reasons.get(r['phase'],())
    finite.require(expected and any(reason in (r.get('error') or '') for reason in expected),'wrong authority refusal reason '+r['phase'])


def check_actions(root,timeline,records):
    require=finite.require
    def index(kind,phase=None):
        items=[i for i,x in enumerate(timeline) if x['kind']==kind and (phase is None or x.get('detail',{}).get('phase')==phase)]
        require(len(items)==1,'missing/duplicate action event '+kind+str(phase));return items[0]
    for phase in ('P3','missing-active'):
        r=finite.read(root/f'{phase}-refresh-action.json')
        require(r['phase']==phase and r['requested'] and r['owner']=='DecompilePlugin' and r['action']=='Refresh' and (r['context_provider_matches'] or (not r['context_available'] and not r['enabled'] and phase=='missing-active')),'foreign action/context')
        require(r['provider_program_id']==r['program_id']==records[phase]['program_id'] and r['controller_identity']==records[phase]['controller_identity'],'foreign action owner')
        d=index('ordinary-refresh-disposition',phase)
        require(timeline[d]['detail']==r,'unbound action receipt')
        require(index('ordinary-refresh-requested',phase)<index('ordinary-refresh-enablement',phase)<d<index('passive-capture',phase),'wrong action chronology')
        if r['enabled']:
            require(r['invoked'] and r['completed'] and r['status']=='DISPATCH_COMPLETED','attempted without dispatch')
            require(index('ordinary-refresh-enablement',phase)<index('ordinary-refresh-invoked',phase)<d,'missing dispatch')
        else:
            require(phase=='missing-active' and not r['invoked'] and not r['completed'] and r['status']=='NOT_AVAILABLE_ON_ERROR','unavailable positive refresh')
            require(not any(x['kind']=='ordinary-refresh-invoked' and x['detail']['phase']==phase for x in timeline),'forced disabled action')
            require(d<index('ACTIVE_NAVIGATION_REFUSAL')<index('navigate','missing-away')<index('navigate','missing-back')<index('passive-capture',phase),'missing labelled active navigation')
        if phase=='missing-active':
            require(index('passive-capture','missing-passive')<index('ordinary-refresh-requested',phase),'active negative before passive')
            require(records[phase]['data_identity']!=records['missing-passive']['data_identity'],'negative reused passive result')
    proof=index('proof-write-completed');post=index('passive-capture','P-post-proof');request=index('ordinary-refresh-requested','P3')
    require(proof<post<request,'post-proof snapshot not before toolbar')
    require(records['P3']['data_identity']!=records['P-post-proof']['data_identity'],'P3 reused pre-refresh result')
    p3=index('passive-capture','P3')
    require(all(x['kind'] in OBSERVATIONS | {'ordinary-refresh-requested','ordinary-refresh-enablement','ordinary-refresh-invoked','ordinary-refresh-disposition'} for x in timeline[post+1:p3+1]),'intervention rescuing P3')
    correlated_operation(timeline,'proof-write',records['P-post-proof'],'P-post-proof',{'proof-write-completed'})
    write=timeline[proof]['detail']
    require(write['revision']>write['before_revision'] and records['P-post-proof']['events']>write['before_events'],'no proof write/event')
    require(any(x['kind']=='settled' for x in timeline[proof+1:post]),'post-proof not settled')
    require(all(x['kind'] in OBSERVATIONS for x in timeline[proof+1:post+1]),'intervention before post-proof snapshot')


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
    phases=['P0','P1','P2','P-post-proof','P3','canonical-control','Q0','Q1','Q2','Q-old-generation','switch-P','switch-Q','switch-P-return','quick-P-settled','missing-warm','missing-passive','missing-active']
    records={phase:checked_record(root,phase) for phase in phases}
    require([x['detail']['phase'] for x in timeline if x['kind']=='passive-capture']==phases,'skipped/duplicated workflow phase')
    for item in timeline:
        if item['kind']=='passive-capture':
            require(item['detail']['record_sha256']==finite.sha(root/(item['detail']['phase']+'-request.json')),'changed phase receipt')
    check_actions(root, timeline, records)
    p=records['P0'];q=records['Q0'];require(p['program_id']!=q['program_id'],'P/Q not distinct Programs')
    require(len({r['controller_identity'] for r in records.values()})==1 and len({r['owner_java_pid'] for r in records.values()})==1,'window/controller replaced')
    variant=records['missing-warm']
    require(variant['program_id'] not in (p['program_id'],q['program_id']) and variant['program_object'] not in (p['program_object'],q['program_object']),'negative is not a distinct copied Program')
    for phase in ('missing-passive','missing-active'):
        require(all(records[phase][k]==variant[k] for k in ('program_id','program_object','entry','function_id','controller_identity','owner_java_pid')),'foreign negative variant '+phase)
    setups=[x['detail'] for x in timeline if x['kind']=='variant-setup']
    require(len(setups)==1 and all(setups[0]['variant'][k]==variant[k] and setups[0]['source'][k]==p[k] for k in ('program_id','program_object','owner_java_pid')),'unbound copied variant setup')
    result={'initial':initial,'ordinary':{},'images':{}}
    for phase in ('P-post-proof','P3','switch-P','switch-P-return','quick-P-settled','missing-warm'):
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
    correlated_operation(timeline,'Q-mutation',records['Q1'],'Q1',{'Q-mutation-committed'})
    correlated_operation(timeline,'variant-proof-write',records['missing-warm'],'missing-warm')
    correlated_operation(timeline,'registration-removal',records['missing-passive'],'missing-passive',{'registration-removed'})
    correlated_operation(timeline,'Q-generation',records['Q2'],'Q2',{'explicit-image-generation','navigate'})
    for name in ('P','Q'):
        saved=(root/f'{name}-saved-authority.json').read_bytes()
        require(saved==(reopen_root/f'{name}-before-authority.json').read_bytes()==(reopen_root/f'{name}-after-authority.json').read_bytes(),'saved authority changed '+name)
    for base in (root,reopen_root):
        closures=finite.read(base/'program-closures.json');require(len(closures)==(3 if base==root else 2) and all(x['closed'] and x['consumers']==0 for x in closures),'retained/missing Programs')
        expected={p['program_id'],q['program_id'],variant['program_id']} if base==root else {p['program_id'],q['program_id']}
        require({x['target']['program_id'] for x in closures}==expected,'foreign closure identities')
        require(not finite.read(base/'tool-closed.json')['tool_visible'],'tool not closed')
    reopened={phase:checked_record(reopen_root,phase) for phase in ('reopen-P','reopen-Q','reopen-Q-old')}
    require(all(r['read_only'] for r in reopened.values()),'writable reopen')
    reopen_timeline=finite.read(reopen_root/'timeline.json')
    require([x['detail']['phase'] for x in reopen_timeline if x['kind']=='passive-capture']==['reopen-P','reopen-Q','reopen-Q-old'],'skipped/duplicated reopen captures')
    for item in reopen_timeline:
        if item['kind']=='passive-capture':require(item['detail']['record_sha256']==finite.sha(reopen_root/(item['detail']['phase']+'-request.json')),'changed reopen phase receipt')
    require(all(x['kind'] in OBSERVATIONS | {'navigate'} for x in reopen_timeline),'reopen performed an active establishment/refresh')
    require(len({r['controller_identity'] for r in reopened.values()})==1 and len({r['owner_java_pid'] for r in reopened.values()})==1 and len({r['java_start'] for r in reopened.values()})==1,'mixed second-session captures')
    full_exit=finite.read(root.parent/'process-exit.json');new_exit=finite.read(reopen_root.parent/'process-exit.json')
    require(not full_exit.get('rehearsal',False) and not new_exit.get('rehearsal',False),'rehearsal cannot qualify final workflow')
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
    check_full(root,reopened)  # Sensitivity has meaning only on a complete passing base.
    outcomes={}
    for kind in ('old-generation-substitution','fake-same-process-reopen','skipped-reopen-phase','foreign-refusal','attempted-without-dispatch','P3-navigation-rescue','P3-reused-result'):
        with tempfile.TemporaryDirectory(prefix='g1-window-mutant-') as tmp:
            dst=Path(tmp)
            for name,source in [('full',root),('reopen',reopened)]:
                shutil.copytree(source,dst/name/'captures')
                shutil.copy2(source.parent/'process-exit.json',dst/name/'process-exit.json')
            full=dst/'full/captures';second=dst/'reopen/captures'
            if kind=='P3-reused-result':
                rec=finite.read(full/'P3-request.json');rec['data_identity']=finite.read(full/'P-post-proof-request.json')['data_identity']
                (full/'P3-request.json').write_text(json.dumps(rec));ts=finite.read(full/'timeline.json')
                for x in ts:
                    if x['kind']=='passive-capture' and x['detail']['phase']=='P3':x['detail']['record_sha256']=finite.sha(full/'P3-request.json')
                (full/'timeline.json').write_text(json.dumps(ts))
                try:check_full(full,second)
                except finite.Refusal as exc:outcomes[kind]={'status':'REJECTED','reason':str(exc)}
                else:raise finite.Refusal('full sensitivity failed '+kind)
                continue
            if kind=='P3-navigation-rescue':
                ts=finite.read(full/'timeline.json')
                pos=next(i for i,x in enumerate(ts) if x['kind']=='ordinary-refresh-requested' and x['detail']['phase']=='P3')
                ts.insert(pos,{'kind':'navigate','detail':{'phase':'rescue-P3'}})
                (full/'timeline.json').write_text(json.dumps(ts))
                try:check_full(full,second)
                except finite.Refusal as exc:outcomes[kind]={'status':'REJECTED','reason':str(exc)}
                else:raise finite.Refusal('full sensitivity failed '+kind)
                continue
            if kind=='attempted-without-dispatch':
                action=finite.read(full/'P3-refresh-action.json');action.update(invoked=False,completed=False)
                (full/'P3-refresh-action.json').write_text(json.dumps(action))
                ts=finite.read(full/'timeline.json')
                ts=[x for x in ts if not (x['kind']=='ordinary-refresh-invoked' and x['detail']['phase']=='P3')]
                for x in ts:
                    if x['kind']=='ordinary-refresh-disposition' and x['detail']['phase']=='P3':x['detail']=action
                (full/'timeline.json').write_text(json.dumps(ts))
                try:check_full(full,second)
                except finite.Refusal as exc:outcomes[kind]={'status':'REJECTED','reason':str(exc)}
                else:raise finite.Refusal('full sensitivity failed '+kind)
                continue
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
