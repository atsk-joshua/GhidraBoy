#!/usr/bin/env python3
"""Replay actual normal-provider HighFunctions with the maintained conditional semantic kernel.
No Debug/Refresh request, replacement interface or second interpreter is introduced.
"""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import check_conditional_calls as conditional
import check_stock_window as window
core=conditional.core

def check(root,label,delta=1):
    timeline=core.read(root/'timeline.json')
    record=window.checked_record(root,label,timeline)
    binding=core.read(root/f'{label}-source-binding.json')
    identity=core.read(root/f'{label}-before-identity.json')
    for key in ('program_id','program_object','owner_java_pid'):
        core.require(binding['program'][key]==record[key],'wrong normal consumer Program')
    core.require(identity['program_id']==record['program_id'] and identity['live_object_identity']==record['program_object'],'wrong source Program object')
    core.require(binding['revision']==record['revision']==identity['live_modification_number'],'stale source token')
    for key,suffix in [('record_sha256','-request.json'),('high_sha256','-root-high.json'),('raw_sha256','-raw.json'),('proof_sha256','-proof.json'),('emitted_sha256','-root-requested.json'),('image_sha256','-fixture.gb')]:
        core.require(core.sha(root/(label+suffix))==binding[key],'changed source/native binding: '+key)
    cap=core.Capture(root,label);native=cap.requests['root']
    core.require(native['normal_window_capture'] and native['completed'] and native['highfunction_available'] and not native['error'],'missing normal native positive')
    core.require(native['entry']==record['display_entry']==cap.views[0]['view']['entry'],'wrong normal domain entry')
    hashes={'c5e9775345e6841c717995a85f0bc33a972acc84b0990ad0d6fbccd6db0ae77d','4a97ff9a3dbac5757c7240a664571e82345e4abc4f67cd211cd9d402abe4543d'}
    core.require(any(core.actual_native_process(p,record['owner_java_pid'],hashes) for p in native['processes_after']),'unverified normal native process')
    return conditional.replay(cap,(root/f'{label}-fixture.gb').read_bytes(),delta=delta)



def check_request_ordering(root,timeline=None,headless_state=False):
    timeline=core.read(root/'timeline.json') if timeline is None else timeline;rows=[]
    relevant=[x for x in timeline if x['kind'] in ('request-B-published','request-A-disposition')]
    core.require(all((x.get('consumer_mode')=='HEADLESS_STATE')==headless_state for x in relevant),'wrong consumer evidence mode')
    for switched in (False,True):
        begins=[(i,e['detail']) for i,e in enumerate(timeline) if e['kind']=='request-B-published' and e['detail']['switchAway']==switched]
        ends=[(i,e['detail']) for i,e in enumerate(timeline) if e['kind']=='request-A-disposition' and e['detail']['switchAway']==switched]
        core.require(len(begins)==len(ends)==1,'missing/duplicate actual ordered request trace')
        bi,b=begins[0];ei,e=ends[0];a=b['A'];later=b['B']
        core.require(bi<ei and a['operationId']!=later['operationId'] and e['operation']==a['operationId'],'replayed/wrong request timeline')
        core.require(all(a[k]==later[k] for k in ('programId','programObject','entry','sourceRevision')),'wrong Program/domain or changed source in ordering witness')
        core.require(a['current'] and later['current'] and a['sourceRevision']==b['revision']==e['revision'],'stale/unfinished ordering result')
        core.require(a['mutation']==later['mutation']=='NO_DATABASE_CHANGE','ordering test changed durable authority')
        for outcome in (a,later):
            returns=[(i,x['detail']) for i,x in enumerate(timeline) if x['kind']=='public-action-return' and x['detail']['operation']==outcome['operationId']]
            core.require(len(returns)==1 and returns[0][0]<bi,'missing actual public wrapper return')
            d=returns[0][1];core.require(d['program']['program_id']==outcome['programId'] and d['program']['program_object']==outcome['programObject'],'wrong public request consumer')
            core.require(len(d['arguments'])==2 and d['arguments'][0] in ('conditional-call-explain','conditional-call-target','conditional-call-continuation') and d['arguments'][1]==outcome['entry'],'wrong requested domain')

        expected='ACTIVATION_SUPERSEDED' if switched and not headless_state else 'REQUEST_SUPERSEDED'
        core.require(e['disposition']==expected,'superseded request published')
        rows.append(dict(switched=switched,older=a['operationId'],newer=later['operationId'],disposition=e['disposition']))
    return rows


def ordering_sensitivities(root,headless_state=False):
    import copy
    original=core.read(root/'timeline.json');check_request_ordering(root,original,headless_state);results={}
    def older(trace):return next(x['detail'] for x in trace if x['kind']=='request-A-disposition')
    def pair(trace):return next(x['detail'] for x in trace if x['kind']=='request-B-published')
    changes={
        'superseded-publication':lambda x:older(x).__setitem__('disposition','PUBLISHED'),
        'wrong-program':lambda x:pair(x)['B'].__setitem__('programObject',-1),
        'wrong-domain':lambda x:pair(x)['B'].__setitem__('entry','foreign::0'),
        'stale-source':lambda x:pair(x)['B'].__setitem__('sourceRevision',-1),
        'wrong-request':lambda x:older(x).__setitem__('operation',pair(x)['B']['operationId']),
        'replayed-timeline':lambda x:x.extend(copy.deepcopy(x)),
        'missing-positive-base':lambda x:x.clear(),
    }
    for name,change in changes.items():
        trace=copy.deepcopy(original);change(trace)
        try:check_request_ordering(root,trace,headless_state)
        except Exception as e:results[name]=str(e)
        else:raise AssertionError('Accepted ordering semantic mutant: '+name)
    return results


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('--label');p.add_argument('--ordering',action='store_true');p.add_argument('--headless-state',action='store_true');p.add_argument('--delta',type=int,choices=[-1,1],default=1);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.headless_state and not a.ordering:p.error('--headless-state is only valid with --ordering')
    if a.ordering:result=dict(scope='HEADLESS_SCRIPT_STATE_ORDERING' if a.headless_state else 'ACTUAL_TOOL_REQUEST_ORDERING',rows=check_request_ordering(a.root,headless_state=a.headless_state),sensitivities=ordering_sensitivities(a.root,a.headless_state))
    elif a.label:result=check(a.root,a.label,a.delta)
    else:p.error('select --label for native semantic replay or --ordering for actual request traces')
    a.output.write_text(json.dumps(result,indent=2));print(json.dumps(result))
