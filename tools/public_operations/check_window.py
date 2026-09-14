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
        except core.Refusal as e:results[name]=str(e)
        else:raise AssertionError('Accepted ordering semantic mutant: '+name)
    return results


def headed_owners(rows):
    def row(name):
        found=[x for x in rows if x.get('row')==name]
        core.require(len(found)==1,'missing/duplicate headed row: '+name)
        return found[0]
    tool=row('ANALYSIS_TOOL')
    core.require('ghidra.app.plugin.core.analysis.AutoAnalysisPlugin' in tool['plugins'],'analysis plugin absent')
    scheduled=row('STANDALONE_SCHEDULED_PUBLIC_SCRIPT');submission=scheduled['submission'];worker=scheduled['worker']
    core.require(scheduled['waitingMessage'] and not submission['toolBackground'] and not submission['edt'],'not standalone scheduled submission')
    core.require(worker['toolBackground'] and not worker['edt'] and worker['id']!=submission['id'],'immediate worker path')
    for frame in ('GhidraBoyTools.run(', 'AutoAnalysisManager$AnalysisWorkerCommand.applyTo(', 'BackgroundCommandTask.run('):
        core.require(any(frame in x for x in worker['stack']),'missing actual worker stack: '+frame)
    for abort in (False,True):
        owner=row('TOOL_OWNER_ABORT' if abort else 'TOOL_OWNER_COMMIT');pending=owner['pending'];provisional=pending['provisional'];outcome=owner['outcome']
        core.require(pending['status']=='NOT_DONE' and not pending['terminalDone'] and provisional['mutation']=='PENDING_IN_OWNER','never-pending owner result')
        core.require(pending['thread']['toolBackground'] and any('BackgroundCommandTask.run(' in x for x in pending['thread']['stack']),'not genuine tool owner')
        for key in ('operationId','programId','programObject','transactionId','entry'):
            core.require(provisional[key]==outcome[key],'wrong correlated owner '+key)
        core.require(pending['outer']==outcome['transactionId'],'wrong encompassing transaction')
        core.require(owner['outerStatus']==('ABORTED' if abort else 'COMMITTED'),'wrong actual owner outcome')
        core.require(owner['rollbackMechanism']==('RollbackException' if abort else 'normal return'),'false return is not rollback')
        core.require(owner['priorSurvives'] and owner['insideSurvives']==(not abort),'wrong preservation boundary')
        core.require(outcome['mutation']==('ABORTED' if abort else 'COMMITTED') and outcome['databaseCommit']==(not abort),'wrong database outcome')
        core.require(outcome['current']==(not abort) and (owner['presentation']!='PUBLISHED' if abort else owner['presentation']=='PUBLISHED'),'invalid owner publication')
    return {'scope':'HEADED_SCHEDULE_AND_TOOL_OWNER_ONLY','rows':['H0','H1']}


def chooser(root):
    import copy,re
    labels=('chooser-cancel','chooser-inspect-recovery','chooser-file-cancel','chooser-refresh','chooser-explain','chooser-target')
    records=[core.read(root/(label+'.json')) for label in labels]
    program=records[0]['program'];script_hash=records[0]['script_sha256']
    for label,record in zip(labels,records):
        core.require(record['script_arguments']==[] and record['entrypoint']=='GhidraScriptService / real Script Manager','not real no-argument Script Manager')
        core.require(record['program']==program and record['script_sha256']==script_hash,'chooser changed source Program or script')
        core.require(record['interactions'] and record['interactions'][0]['dialog']=='GhidraBoy','missing actual action chooser')
        core.require((root/(label+'-action-desktop.png')).is_file(),'missing dialog screenshot')
        core.require(all(x['program']==program for x in record['interactions']),'wrong dialog Program')
        resources=record['resources'];core.require(resources['operations']['observations']==resources['operations']['gateUsers']==resources['operations']['cancellationListeners']==resources['publication']['requests']==0,'chooser leaked owned resources')
        text=(root/(label+'-console.txt')).read_text()
        core.require('Error running script' not in text,'real Script Manager error')
        if label in ('chooser-cancel','chooser-file-cancel'):
            interaction=record['interactions'][0] if label=='chooser-cancel' else record['interactions'][-1]
            core.require(interaction.get('choice',interaction.get('action'))=='CANCEL','no actual cancel action')
            core.require('PUBLISHED' not in text and '"operationId"' not in text,'cancelled chooser performed a public operation')
            before=copy.deepcopy(core.read(root/(label+'-before.json')));after=copy.deepcopy(core.read(root/(label+'-after.json')))
            for inventory in (before,after):
                timing=inventory['options']['Program Information'].pop('Analysis Times.Times',None)
                core.require(timing is None or timing['type']=='CUSTOM_TYPE','unexpected timing metadata type')
            core.require(before==after,'chooser cancellation changed preserved Program state')
        elif label!='chooser-inspect-recovery':
            outcomes=[json.loads(x) for x in re.findall(r'\{[^{}]*"operationId"[^{}]*\}',text)]
            terminal=[x for x in outcomes if x['mutation']!='PENDING_IN_OWNER']
            core.require(len(terminal)==1 and terminal[0]['current'] and not terminal[0]['cancelled'] and 'PUBLISHED' in text,'no current no-argument public result')
            core.require(terminal[0]['programId']==program['program_id'] and terminal[0]['programObject']==program['program_object'],'wrong no-argument outcome Program')
            core.require(terminal[0]['entry']==record['selected_entry'],'wrong selected no-argument domain')
    return {'scope':'REAL_NO_ARGUMENT_CHOOSER','rows':['I1'],'script_sha256':script_hash}


def removed_entry(before,after,passive,entry,program_id,program_object):
    registry='GhidraBoyStockPredicatedCalls'
    core.require(entry in before['options'].get(registry,{}) and entry not in after['options'].get(registry,{}),'removed entry authority did not retire')
    original=[x for x in before['functions'] if x['entry']==entry];surviving=[x for x in after['functions'] if x['entry']==entry]
    core.require(len(original)==len(surviving)==1 and original[0]['comment']=='Later user explanation' and original==surviving,'same edited function was not preserved')
    core.require(passive['entry']==passive['display_entry']==entry and passive['program_id']==program_id and passive['program_object']==program_object,'wrong removal consumer')
    core.require(not passive['highfunction_available'] and not passive['completed'] and 'Unavailable stock analysis entry: Missing predicated graph registration or stock software carrier' in passive['error'],'missing actual passive removal refusal')
    return {'entry':entry,'edited_function_preserved':True,'authority_retired':True}


def immutable_roster(saved,records):
    expected=set(saved['GhidraBoyStockPredicatedCalls'])
    core.require('immutable-first' in records,'missing first immutable observation')
    later=[x['display_entry'] for label,x in records.items() if label!='immutable-first']
    core.require(len(later)==len(expected) and len(set(later))==len(later) and set(later)==expected,'incomplete/duplicate immutable saved-domain roster')
    for record in records.values():
        core.require(record['read_only'] and record['program_id']==saved['program_id'] and record['display_entry'] in expected,'wrong immutable Program/domain')
    return sorted(expected)


def completion(root):
    """Mandatory R3 roster. Missing evidence is UNRUN, never a negative semantic success."""
    inputs=core.read(root/'completion-inputs.json');first=root/inputs['first'];second=root/inputs['second'];service=root/inputs['service']
    cap=first/'captures';reopen=second/'captures';results={}
    def run(name,check):
        try:results[name]={'status':'PASS','evidence':check()}
        except FileNotFoundError as failure:results[name]={'status':'UNRUN','reason':str(failure)}
        except (core.Refusal,ValueError,AssertionError) as failure:results[name]={'status':'FAIL','reason':str(failure)}
        except Exception as failure:results[name]={'status':'ERROR','reason':type(failure).__name__+': '+str(failure)}
    def services():
        exit_record=core.read(service/'exit.json');core.require(exit_record['exit']==0 and not exit_record.get('timeout'),'service child failed')
        return headed_owners(core.read(service/'evidence/service-results.json')['rows'])
    def contention():
        busy=core.read(service/'evidence/busy-deferral.json');core.require(busy['status']=='NOT_DONE' and not busy['ownedWrites'] and 'foreign transaction pending' in busy['rejection'],'unobserved busy deferral')
        for abort in (False,True):
            edit=core.read(service/('evidence/foreground-abort.json' if abort else 'evidence/foreground-commit.json'))
            core.require(edit['submission']['edt'] and edit['command']=='ghidra.app.cmd.comments.SetCommentCmd' and edit['accepted'],'no accepted normal foreground edit')
            core.require(edit['commentInside']=='R3 real foreground tool edit' and edit['commentAfter']==('null' if abort else 'R3 real foreground tool edit'),'foreground edit owner outcome lost')
        follow=core.read(service/'evidence/analysis-follow-on.json');core.require(follow['tasks'] and any('GhidraBoyTools' not in task for task in follow['tasks']),'no actual analysis follow-on')
        return busy
    def warm():
        stale=core.read(cap/'public-passive-stale-request.json');core.require(not stale['highfunction_available'] and 'Stale' in stale['error'],'missing passive stale refusal')
        timeline=core.read(cap/'timeline.json')
        def phase(label):
            matches=[i for i,x in enumerate(timeline) if x['kind']=='passive-capture' and x['detail']['phase']==label]
            core.require(len(matches)==1,'missing/duplicate warm capture: '+label);return matches[0]
        initial=phase('public-initial');passive=phase('public-passive-stale');recovery=phase('public-event-recovery');toolbar=phase('public-toolbar-refresh')
        begins=[(i,x['detail']) for i,x in enumerate(timeline) if x['kind']=='operation-begin' and x['detail']['purpose']=='consumed-source-edit']
        core.require(len(begins)==1,'missing real consumed edit');begin,operation=begins[0]
        returns=[(i,x['detail']) for i,x in enumerate(timeline) if x['kind']=='commit-call-return' and x['detail']['operation']==operation['operation']]
        core.require(len(returns)==1,'missing actual edit commit');ended,receipt=returns[0]
        settled=[(i,x['detail']) for i,x in enumerate(timeline) if x['kind']=='operation-settled' and x['detail']['operation']==operation['operation']]
        core.require(len(settled)==1,'missing terminal edit-owner observation');settled_index,terminal=settled[0]
        core.require(initial<begin<ended<settled_index<passive<recovery<toolbar and receipt['commit_requested'] and terminal['encompassing']['status']=='COMMITTED' and terminal['encompassing']['db_committed'],'incorrect warm edit/commit/capture sequence')
        core.require(receipt['encompassing']['id']==terminal['encompassing']['id'] and receipt['target']==terminal['target']==operation['target'],'wrong terminal edit owner')
        core.require(any(x['kind']=='program-event' and x['detail']['target']==operation['target'] for x in timeline[begin:passive]),'missing source Program event in causal mutation bracket')
        core.require(not any(x['kind'] in ('navigate','public-action-invoke','ordinary-refresh-requested','ordinary-refresh-invoked','explicit-provider-action') for x in timeline[begin:passive]),'active rescue before passive stale observation')
        core.require(any(x['kind']=='public-action-invoke' and x['detail']['action']=='stock-predicate-refresh' for x in timeline[passive:recovery]),'no explicit proof refresh after stale capture')
        refresh=core.read(cap/'public-enabled-refresh-refresh-action.json')
        core.require(refresh['enabled'] and refresh['invoked'] and refresh['completed'] and refresh['context_provider_matches'] and refresh['owner']=='DecompilePlugin' and refresh['action']=='Refresh','missing actual enabled ordinary Refresh')
        return {label:check(cap,label,delta) for label,delta in [('public-initial',1),('public-event-recovery',-1),('public-toolbar-refresh',-1)]}
    def topology():
        labels=sorted(x.name.removesuffix('-source-binding.json') for x in cap.glob('domain-order-*-source-binding.json'))
        core.require(len(labels)==4,'missing domain reversals')
        entries=[core.read(cap/(label+'-request.json'))['display_entry'] for label in labels]
        core.require(len(set(entries))==2 and entries[0]==entries[3] and entries[1]==entries[2] and entries[0]!=entries[1],'incorrect domain reversal')
        return {label:check(cap,label,-1) for label in labels}
    def supersession():
        ordered=check_request_ordering(cap);only=core.read(cap/'activation-only.json')
        core.require(only['disposition']=='ACTIVATION_SUPERSEDED' and not only['new_public_request'] and only['unchanged'],'missing activation-only P/Q/P witness')
        timeline=core.read(cap/'timeline.json');starts=[i for i,x in enumerate(timeline) if x['kind']=='activation-only-A-return'];ends=[i for i,x in enumerate(timeline) if x['kind']=='activation-only-A-disposition']
        core.require(len(starts)==len(ends)==1 and starts[0]<ends[0],'missing activation-only causal trace')
        segment=timeline[starts[0]:ends[0]+1];core.require(not any(x['kind']=='public-action-invoke' for x in segment),'new request substituted for activation-only supersession')
        core.require([x['kind'] for x in segment if x['kind'] in ('activation-only-Q','activation-only-P')]==['activation-only-Q','activation-only-P'],'missing actual P/Q/P activation sequence')
        return {'ordering':ordered,'activation_only':only,'Q':check(cap,'Q-positive',-1)}
    def outstanding():
        native=core.read(cap/'native-outstanding-switch.json')
        core.require(native['normal_provider_count']==1 and native['native_work_phase']=='RUNNING_REQUEST_AT_SAMPLE' and native['native_worker_stacks'] and native['outstanding_at_switch'],'unobserved native outstanding work')
        core.require(native['source_revision_before']==native['source_revision_at_switch'],'native source changed before switch')
        for item in native['native_worker_stacks']:
            core.require(any('DecompileRunnable.' in frame for frame in item['stack']) and any('DecompileProcess.' in frame for frame in item['stack']),'unbound normal native stack')
        close=core.read(cap/'close-during-computation.json')
        if close['initial_close_accepted']:
            core.require(close['route']=='ACCEPTED_CLOSE_CANCELLED_REQUEST' and close['cancelled_before_owner'] and not close['cancelled_by_owner'],'driver cancel credited as accepted close')
        else:core.require(close['route']=='DEFERRED_CLOSE_THEN_OWNER_CANCEL' and close['cancelled_by_owner'],'deferred close mislabelled')
        return {'native':native,'close':close,'Q':check(cap,'native-after-switch-Q',-1)}
    def removal():
        core.require((cap/'removal-current-before.gb').read_bytes()==(cap/'removal-current-after.gb').read_bytes(),'removal changed original bytes')
        before=core.read(cap/'removal-before.json');after=core.read(cap/'removal-after.json')
        timeline=core.read(cap/'timeline.json');returns=[x['detail'] for x in timeline if x['kind']=='public-action-return' and x['detail']['action']=='stock-predicate-remove']
        core.require(len(returns)==1 and len(returns[0]['arguments'])==2,'missing exact public removal request');request=returns[0]
        retired=removed_entry(before,after,core.read(cap/'removal-passive-request.json'),request['arguments'][1],request['program']['program_id'],request['program']['program_object'])
        outcomes=[x['detail'] for x in timeline if x['kind']=='public-action-outcome' and x['detail']['operationId']==request['operation']]
        core.require(len(outcomes)==1 and outcomes[0]['current'] and outcomes[0]['mutation']=='COMMITTED','removal did not commit')
        for index in range(8):
            resources=core.read(cap/f'close-resources-{index}.json');core.require(resources['operations']['observations']==resources['operations']['cancellationListeners']==resources['operations']['gateUsers']==resources['operations']['programGates']==resources['publication']['requests']==0,'owned resources remain after repeated close')
        disposed=core.read(cap/'public-tool-disposed.json');core.require(all(value==0 for value in disposed['operations'].values()) and all(value==0 for value in disposed['publication'].values()),'resources remain after tool disposal');return {'repeated_closes':8,'removal':retired}
    def persistence():
        for run_root in (first,second):
            exited=core.read(run_root/'process-exit.json');core.require(exited['exit']==0 and not exited.get('timeout'),'normal JVM did not exit successfully')
            closed=core.read(run_root/'captures/tool-closed.json');core.require(closed['program_closed'] and closed['remaining_consumers']==0,'actual Program closure not established')
        a=core.read(first/'process-start.json');b=core.read(second/'process-start.json');core.require(a['pid']!=b['pid'],'not a second JVM')
        result=core.read(reopen/'public-window-complete.json');core.require(result['immutable'] and result['unchanged'] and result['authority']==core.read(cap/'saved-authority.json'),'immutable first-use mismatch')
        labels=sorted(x.name.removesuffix('-source-binding.json') for x in reopen.glob('immutable-*-source-binding.json'));core.require('immutable-first' in labels,'missing first immutable native use')
        immutable_roster(json.loads(core.read(cap/'saved-authority.json')),{label:core.read(reopen/(label+'-request.json')) for label in labels})
        timeline=core.read(reopen/'timeline.json');captures=[x for x in timeline if x['kind']=='passive-capture'];core.require(captures and captures[0]['detail']['phase']=='immutable-first','initial immutable use was not captured first')
        core.require(not any(x['kind'] in ('public-action-invoke','ordinary-refresh-invoked','operation-begin') for x in timeline),'immutable session used rescue/mutation')
        return {label:check(reopen,label,-1) for label in labels}
    run('H0/H1',services);run('H2',contention);run('I1',lambda:chooser(cap));run('W1',warm);run('W2',topology);run('W3',supersession);run('W4',outstanding);run('W5',removal);run('W6',persistence)
    run('V',lambda:core.read(root/'integrated-acceptance.json'))
    if results['V']['status']=='PASS':
        v=results['V']['evidence']
        if v.get('status')!='PASS' or not v.get('positive_base_and_sensitive_controls') or not v.get('unobstructed_screenshots_reviewed') or not v.get('exact_candidate_and_driver_identities_verified'):
            results['V']={'status':'FAIL','reason':'independent acceptance/evidence obligations incomplete'}
    return {'status':'PASS' if all(x['status']=='PASS' for x in results.values()) else 'INCOMPLETE','scope':'R3_PUBLIC_OPERATIONS_LIFECYCLE_NOT_RELEASE_APPROVAL','rows':results}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('--label');p.add_argument('--complete',action='store_true');p.add_argument('--headed-owners',action='store_true');p.add_argument('--chooser',action='store_true');p.add_argument('--ordering',action='store_true');p.add_argument('--headless-state',action='store_true');p.add_argument('--delta',type=int,choices=[-1,1],default=1);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.headless_state and not a.ordering:p.error('--headless-state is only valid with --ordering')
    if a.complete:result=completion(a.root)
    elif a.headed_owners:result=headed_owners(core.read(a.root/'partial-rows.json'))
    elif a.chooser:result=chooser(a.root)
    elif a.ordering:result=dict(scope='HEADLESS_SCRIPT_STATE_ORDERING' if a.headless_state else 'ACTUAL_TOOL_REQUEST_ORDERING',rows=check_request_ordering(a.root,headless_state=a.headless_state),sensitivities=ordering_sensitivities(a.root,a.headless_state))
    elif a.label:result=check(a.root,a.label,a.delta)
    else:p.error('select --label for native semantic replay or --ordering for actual request traces')
    a.output.write_text(json.dumps(result,indent=2));print(json.dumps(result))
    if a.complete and result['status']!='PASS':raise SystemExit(1)
