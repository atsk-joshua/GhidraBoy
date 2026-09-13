#!/usr/bin/env python3
"""Check correlated public wrapper traces; does not certify GUI or universal isolation."""
import argparse,copy,json,xml.etree.ElementTree as ET
from pathlib import Path

def check(events):
    if not events:raise ValueError('missing positive event base')
    run=events[0]['run'];active={};resolved=set();commits=aborts=late=0
    for sequence,event in enumerate(events,1):
        if event['run']!=run or event['sequence']!=sequence:raise ValueError('replayed/mixed timeline')
        outcome=event['outcome'];op=outcome['operationId']
        identity=tuple(outcome[k] for k in ('programId','programObject','entry','transactionId'))
        if outcome['transactionId']!=event['actualTransaction']:raise ValueError('wrong-transaction completion')
        if event['kind']=='RETURN_PENDING':
            if op in active or op in resolved:raise ValueError('replayed operation')
            if outcome['mutation']!='PENDING_IN_OWNER' or event['actualStatus']!='NOT_DONE' or outcome['current'] or outcome['databaseCommit'] or event['publication']!='PENDING':raise ValueError('completion-before-commit')
            active[op]=dict(identity=identity,late=False)
        else:
            if op not in active or active[op]['identity']!=identity:raise ValueError('wrong Program/domain or unbound result')
            if event['kind']=='LATER_EDIT_COMMITTED':
                if event['actualStatus']!='COMMITTED' or outcome['mutation']!='COMMITTED':raise ValueError('late cancellation lacks actual commit')
                active[op]['late']=True;continue
            if event['kind']!='OUTER_RESOLVED':raise ValueError('unknown event')
            if event['actualStatus']=='ABORTED':
                if outcome['mutation']!='ABORTED' or outcome['current'] or outcome['databaseCommit'] or event['publication']!='OUTER_ABORTED':raise ValueError('missing rollback observation')
                aborts+=1
            elif event['actualStatus']=='COMMITTED':
                if outcome['mutation']!='COMMITTED' or not outcome['databaseCommit']:raise ValueError('false rollback after commit')
                if active[op]['late']:
                    if event['publication']!='CANCELLED_PUBLICATION':raise ValueError('late cancelled publication')
                    late+=1
                elif event['publication']!='PUBLISHED' or not outcome['current']:raise ValueError('missing positive committed publication')
                commits+=1
            else:raise ValueError('notification is not a completed transaction')
            del active[op];resolved.add(op)
    if active or min(commits,aborts,late)==0:raise ValueError('missing positive/abort/late-cancel base')
    return dict(operations=len(resolved),commits=commits,aborts=aborts,late_cancellations=late,scope='HEADLESS_CORRELATED_WRAPPER_TRACES_ONLY')

def extract(path):
    text='\n'.join(n.text or '' for n in ET.parse(path).getroot().findall('system-out'))
    return [json.loads(line.split('LIFECYCLE_EVENT ',1)[1]) for line in text.splitlines() if 'LIFECYCLE_EVENT ' in line]

def sensitivities(events):
    check(events);results={}
    changes={
      'wrong-program':lambda x:x[-1]['outcome'].__setitem__('programId',-1),
      'wrong-domain':lambda x:x[-1]['outcome'].__setitem__('entry','foreign::0'),
      'wrong-transaction':lambda x:x[-1].__setitem__('actualTransaction',-1),
      'completion-before-commit':lambda x:x[0]['outcome'].__setitem__('mutation','COMMITTED'),
      'false-rollback-after-commit':lambda x:next(e for e in x if e['kind']=='OUTER_RESOLVED' and e['actualStatus']=='COMMITTED')['outcome'].__setitem__('mutation','ABORTED'),
      'missing-abort-observation':lambda x:next(e for e in x if e['actualStatus']=='ABORTED').__setitem__('actualStatus','NOT_DONE'),
      'obsolete-publication':lambda x:next(e for e in x if e['publication']=='CANCELLED_PUBLICATION').__setitem__('publication','PUBLISHED'),
      'replayed-timeline':lambda x:x.append(copy.deepcopy(x[0])),
      'missing-positive-base':lambda x:x.clear(),
    }
    for name,change in changes.items():
        mutant=copy.deepcopy(events);change(mutant)
        try:check(mutant)
        except ValueError as error:results[name]=str(error)
        else:raise AssertionError('accepted semantic mutant: '+name)
    return results

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('xml',type=Path);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    events=extract(a.xml);result=dict(result=check(events),sensitivities=sensitivities(events),events=events)
    a.out.write_text(json.dumps(result,indent=2));print(json.dumps(result['result']))
