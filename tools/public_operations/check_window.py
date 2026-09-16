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
_CHECK_CACHE = {}


def check_fingerprint(root, label):
    files = {root/'timeline.json', *root.glob(label+'*')}
    return tuple(sorted((str(path.relative_to(root)), core.sha(path)) for path in files if path.is_file()))

def nonvisual_record(root, label, timeline):
    """Bounded native-support validation; never used by default W2/V acceptance."""
    record = core.read(root/f'{label}-request.json')
    core.require(record.get('visual_inspection') == 'UNOBSERVED' and 'desktop_sha256' not in record, 'support-only capture must preserve unobserved visual status')
    captures = [e for e in timeline if e['kind'] == 'passive-capture' and e['detail']['phase'] == label]
    core.require(len(captures) == 1 and captures[0]['detail']['record_sha256'] == core.sha(root/f'{label}-request.json'), 'missing/changed support request')
    core.require(record['phase'] == label and record['surface'] == 'normal-CodeBrowser-DecompilerProvider' and record['visible'], 'foreign/nonshowing provider')
    core.require(record['display_program_matches'] and record['display_function_matches'] and record['display_entry'] == record['entry'] and record['display_program_id'] == record['program_id'], 'foreign support display')
    for suffix, key in (('.c', 'c_sha256'), ('-high.json', 'high_sha256')):
        core.require(key in record and core.sha(root/(label+suffix)) == record[key], 'changed native support artifact')
    display = core.read(root/(record['retained_display_prefix']+'.json'))
    core.require(display['data_object'] == record['data_identity'] and display['c_sha256'] == record['c_sha256'] and display['high_sha256'] == record['high_sha256'], 'substituted retained native result')
    starts = [e for e in timeline if e['kind'] == 'native-api-boundary' and e['detail']['request_id'] == record['native_request_id'] and e['detail']['boundary'] == 'start']
    returns = [e for e in timeline if e['kind'] == 'native-api-boundary' and e['detail']['request_id'] == record['native_request_id'] and e['detail']['boundary'] == 'terminal']
    core.require(len(starts) == len(returns) == 1 and starts[0]['sequence'] < returns[0]['sequence'] < captures[0]['sequence'] and returns[0]['detail']['result_object'] == display['result_object'], 'unbound retained native request')
    return record


def validated_capture(root,label,*,support_only=False):
    timeline=core.read(root/'timeline.json')
    record=nonvisual_record(root,label,timeline) if support_only else window.checked_record(root,label,timeline)
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
    return cap


def check(root,label,delta=1,*,support_only=False):
    key=(str(root.resolve()),label,delta,support_only,check_fingerprint(root,label))
    if key in _CHECK_CACHE:return _CHECK_CACHE[key]
    cap=validated_capture(root,label,support_only=support_only)
    result=conditional.replay(cap,(root/f'{label}-fixture.gb').read_bytes(),delta=delta)
    _CHECK_CACHE[key]=result
    return result



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


# Receipt version 1 is deliberately required: old post-refresh captures cannot qualify W2.
RESCUE_KINDS = {'ordinary-refresh-requested', 'ordinary-refresh-invoked',
                'explicit-provider-action', 'provider-reset', 'analysis-start',
                'analysis-rescue', 'navigate'}
LIFECYCLE_ROWS = {'H0/H1', 'H2', 'I1', 'W1', 'W2', 'W3', 'W4', 'W5', 'W6'}


def immutable_no_rescue(timeline):
    captures = [(i, event) for i, event in enumerate(timeline) if event['kind'] == 'passive-capture']
    core.require(captures and captures[0][1]['detail']['phase'] == 'immutable-first', 'initial immutable use was not captured first')
    first = captures[0][0]
    # Visiting the other saved domains after the immutable first observation is
    # required roster collection, not a rescue of that first observation.
    core.require(not any(event['kind'] == 'navigate' for event in timeline[:first]), 'immutable first use required navigation rescue')
    forbidden = (RESCUE_KINDS - {'navigate'}) | {'public-action-invoke', 'operation-begin'}
    core.require(not any(event['kind'] in forbidden for event in timeline), 'immutable session used rescue/mutation')


def topology_first_use(root, read=core.read):
    receipt = read(root/'topology-observation.json')
    core.require(receipt['schema'] == 1, 'unsupported topology observation schema')
    for name, digest in receipt.get('raw_sha256', {}).items():
        core.require(core.sha(root.parent/name) == digest, 'changed raw topology/native observation: '+name)
    events = receipt['events']
    core.require(events and [e['seq'] for e in events] == sorted(set(e['seq'] for e in events)), 'unordered/duplicate observer events')
    def one(kind):
        found = [e for e in events if e['kind'] == kind]
        core.require(len(found) == 1, 'missing/duplicate topology event: '+kind)
        return found[0]
    observer, apply, terminal, capture = [one(k) for k in ('observer-installed', 'apply-invoke', 'owner-terminal', 'first-use-capture')]
    core.require(observer['seq'] < apply['seq'] < terminal['seq'] < capture['seq'], 'observation did not start before apply')
    core.require(observer['mechanism'] and observer['coverage_limitations'] == [] and observer['dropped_events'] == 0, 'first native request coverage unobserved')
    provider = observer['provider']
    core.require(provider['class'] in ('ghidra.app.plugin.core.decompile.DecompilerProvider', 'ghidra.app.plugin.core.decompile.PrimaryDecompilerProvider') and provider['showing'] and provider['tool'] and provider['object'], 'missing preexisting real normal provider')
    identity = receipt['identity']
    for key in ('program_id', 'program_object', 'domain', 'carrier', 'operation_id', 'transaction_id'):
        core.require(identity[key] not in (None, ''), 'missing topology identity: '+key)
    core.require(apply['action'] == 'stock-predicate-apply' and apply['identity'] == terminal['identity'] == identity, 'wrong public topology operation/owner')
    core.require(terminal['mutation'] == 'COMMITTED' and terminal['current'], 'ineligible topology publication')
    publication = one('public-presentation')
    core.require(terminal['seq'] < publication['seq'] <= capture['seq'] and publication['identity'] == identity and publication['disposition'] == 'PUBLISHED', 'missing current public presentation')
    before, after = receipt['before'], receipt['after']
    for topology in (before, after):
        core.require(topology['program_id'] == identity['program_id'] and topology['program_object'] == identity['program_object'], 'wrong topology Program')
        core.require(topology['spaces'] and topology['blocks'], 'missing Memory/address-space topology')
        for block in topology['blocks']:
            core.require(set(('name', 'start', 'end', 'space', 'type', 'overlay', 'backing', 'initialized', 'permissions')) <= block.keys(), 'incomplete physical topology block')
    core.require(before['domains'] and identity['domain'] not in before['domains'] and identity['domain'] in after['domains'] and before != after, 'second domain creation not observed')
    core.require(any(e['kind'] == 'program-event' and e['identity'] == identity and e['types'] for e in events if apply['seq'] < e['seq'] < capture['seq']), 'missing correlated topology Program event')
    bracket = [e for e in events if apply['seq'] < e['seq'] <= capture['seq']]
    core.require(not any(e['kind'] in RESCUE_KINDS or (e['kind'] == 'public-action-invoke') for e in bracket), 'topology first use rescued')
    requests = [e for e in bracket if e['kind'] == 'native-request']
    core.require(requests and len({e['request_id'] for e in requests}) == len(requests), 'missing/duplicate native request observation')
    starts = [e for e in bracket if e['kind'] == 'native-request-start']
    core.require(len(starts) == len(requests) and {e['request_id'] for e in starts} == {r['request_id'] for r in requests}, 'unobserved/abandoned native request')
    eligible = []
    pre_native_cancelled = []
    def cancelled_before_native(request):
        status = request.get('native_status', {})
        return (request.get('eligibility') == 'ELIGIBLE'
            and request.get('currentness_evidence', {}).get('disposition') == 'ELIGIBLE'
            and status.get('monitor_cancelled_at_entry') is False
            and status.get('monitor_cancelled_at_return') is True
            and status.get('return_code_index') == 61
            and status.get('cancelled') is True
            and status.get('timed_out') is False
            and status.get('failed_to_start') is False
            and request.get('completed') is False and request.get('error') == '')
    for request in requests:
        actual = request['identity']
        core.require(all(actual[key] == identity[key] for key in ('program_id', 'program_object')) and request['provider'] == provider and request['observed_operation_id'] == identity['operation_id'], 'wrong native Program/provider or creation correlation')
        start = next(e for e in starts if e['request_id'] == request['request_id'])
        core.require(start['seq'] < request['seq'] and start['identity'] == actual, 'unbound native request start')
        core.require(request['eligibility'] in ('ELIGIBLE', 'PROVISIONAL', 'STALE_AUTHORITY', 'SUPERSEDED', 'CANCELLED'), 'unclassified native eligibility')
        currentness, transaction = request['currentness_evidence'], request['transaction_evidence']
        core.require(currentness.get('observed_at_seq') == start['seq'] and transaction.get('observed_at_seq') == start['seq'], 'eligibility not observed at native start')
        core.require(transaction.get('owner_transaction_id') == actual['transaction_id'] and isinstance(transaction.get('active'), bool) and isinstance(currentness.get('current'), bool), 'unbound native eligibility')
        classification = 'PRE_NATIVE_CANCELLED' if cancelled_before_native(request) else request['eligibility']
        if classification == 'PRE_NATIVE_CANCELLED':
            core.require(start['seq'] > terminal['seq'] and currentness['current'] and not transaction['active'] and transaction.get('owner_status') == 'COMMITTED', 'pre-native cancellation lacks eligible committed authority')
            pre_native_cancelled.append(request)
        elif request['eligibility'] == 'ELIGIBLE':
            core.require(start['seq'] > terminal['seq'] and currentness['current'] and not transaction['active'] and transaction.get('owner_status') == 'COMMITTED', 'native request started before eligible owner/currentness')
        elif request['eligibility'] == 'PROVISIONAL':
            core.require(transaction['active'] and transaction.get('owner_status') in ('NOT_DONE', 'NOT_DONE_BUT_ABORTED'), 'provisional request lacks active owner evidence')
        elif request['eligibility'] == 'STALE_AUTHORITY':
            core.require(actual['domain'] in before['domains'] and actual['domain'] != identity['domain'] and not transaction['active'] and not currentness['current'] and currentness.get('disposition') == 'STALE_AUTHORITY' and currentness.get('registration_sha256') and 'Stale predicated graph registration' in request['error'], 'unproven post-commit stale authority')
        else:
            core.require(currentness.get('disposition') == request['eligibility'], 'unobserved native cancellation/supersession')
        if classification == 'ELIGIBLE' and actual['domain'] == identity['domain'] and actual['carrier'] == identity['carrier']:eligible.append(request)
    target_requests = [r for r in requests if not cancelled_before_native(r) and r['identity']['domain'] == identity['domain'] and r['identity']['carrier'] == identity['carrier'] and next(e['seq'] for e in starts if e['request_id'] == r['request_id']) > terminal['seq']]
    target_requests.sort(key=lambda r: next(e['seq'] for e in starts if e['request_id'] == r['request_id']))
    core.require(target_requests and capture['request_id'] == target_requests[0]['request_id'], 'first committed new-domain request missed regardless of result')
    eligible.sort(key=lambda r: next(e['seq'] for e in starts if e['request_id'] == r['request_id']))
    core.require(eligible and capture['request_id'] == eligible[0]['request_id'], 'first eligible request missed')
    first = eligible[0]
    core.require(first['seq'] > terminal['seq'] and first['completed'] and not first['error'], 'first eligible native use failed')
    core.require(capture['label'] == 'topology-first-use', 'wrong first-use capture')
    record = read(root/'topology-first-use-request.json')
    core.require(record['program_id'] == identity['program_id'] and record['program_object'] == identity['program_object'] and record['display_entry'] == identity['domain'], 'wrong first-use Program/domain')
    core.require(record['native_request_id'] == first['request_id'], 'settled result substituted for first request')
    # Each matching log line is retained separately, even when several belong to one job.
    lines = (root/receipt['log']).read_text().splitlines()
    import re
    injection_failure = re.compile(r'(stale predicated graph registration|missing predicated graph registration or stock software carrier|(?:error|exception|refus|fail|unavailable|bad|invalid).*?(?:inject|call.fixup|registration)|(?:inject|call.fixup).*?(?:error|exception|refus|fail|unavailable|bad|invalid))', re.IGNORECASE)
    headings = {i+1 for i, line in enumerate(lines) if injection_failure.search(line)}
    errors = receipt['errors']
    core.require(len(errors) == len(headings) and {e['line'] for e in errors} == headings, 'unattributed registration/injection error')
    for error in errors:
        matching = [r for r in requests if r['request_id'] == error['request_id']]
        core.require(len(matching) == 1 and error['text'] == lines[error['line']-1], 'unbound injection error')
        request = matching[0]
        core.require(error['identity'] == request['identity'] and error['eligibility'] == request['eligibility'] and request['eligibility'] != 'ELIGIBLE' and request['error'], 'eligible/unclassified creation error')
    core.require(all(not r['error'] or any(e['request_id'] == r['request_id'] for e in errors) for r in requests), 'unattributed native request error')
    core.require(receipt['delta'] in (-1, 1), 'unsupported fixture delta')
    return {'request_id':first['request_id'], 'identity':identity, 'attributed_errors':len(errors), 'delta':receipt['delta'], 'pre_native_cancelled':[r['request_id'] for r in pre_native_cancelled]}


def topology_navigation(cap, first_use, read=core.read):
    receipt=read(cap/'topology-observation.json')
    core.require(receipt.get('process_completion') == 'PASS', 'topology run completion unobserved')
    later=receipt.get('later_observations', {})
    core.require(later.get('provider_exceptions') == [] and later.get('unmatched_requests') == [], 'later topology/navigation native work failed or unobserved')
    proof=read(cap/'topology-first-use-proof.json'); timeline=read(cap/'timeline.json')
    for kind, boundary in [('physical-target-verified','RET_DISPATCH'),('physical-continuation-verified','MATCHED_CALL_COMPLETION')]:
        observed=[e['detail'] for e in timeline if e['kind']==kind]
        expected={b['physical'] for b in proof['boundaries'] if b['kind']==boundary}
        core.require(len(observed)==1 and len(expected)==1 and observed[0]['entry']==first_use['identity']['domain'] and observed[0]['target'] in expected, 'missing/wrong proved physical navigation: '+kind)
    return {"status":"PASS"}


def acceptance_identities(root, inputs, read=core.read):
    manifest = read(root/'acceptance-manifest.json')
    core.require(manifest['schema'] == 1 and manifest['checker_sha256'] == core.sha(Path(__file__)), 'candidate/support checker identity mismatch')
    candidates = []
    for lane in ('first', 'second', 'service', *(['topology'] if 'topology' in inputs else [])):
        run_root = root/inputs[lane]
        supplied = manifest['sessions'][lane]
        core.require(Path(supplied['root']).resolve() == run_root.resolve(), 'wrong acceptance evidence root')
        core.require(supplied['pid'] == read(run_root/'process-start.json')['pid'], 'wrong acceptance JVM identity')
        for name in ('candidate.json', 'driver-inputs.json', 'runtime-inputs.json', 'source-snapshots.json', 'compiled-classes.json'):
            core.require(core.sha(run_root/name) == supplied['manifests'][name], 'changed candidate/support manifest: '+name)
        candidate = read(run_root/'candidate.json')
        core.require(core.sha(Path(candidate['archive'])) == candidate['sha256'] == manifest['candidate_sha256'], 'candidate mismatch')
        candidates.append(candidate['sha256'])
        evidence_files = {str(path.relative_to(run_root)):core.sha(path) for directory in ('captures', 'evidence') for path in (run_root/directory).rglob('*') if path.is_file()}
        core.require(evidence_files and evidence_files == supplied['evidence'], 'changed/incomplete lifecycle evidence inventory')
        drivers = read(run_root/'driver-inputs.json'); snapshots = read(run_root/'source-snapshots.json')
        core.require(drivers and set(drivers) == set(snapshots), 'incomplete saved driver snapshots')
        for original, digest in drivers.items():
            core.require(core.sha(run_root/snapshots[original]) == digest, 'changed saved driver source: '+original)
        for name in ('runtime-inputs.json', 'compiled-classes.json'):
            artifacts = read(run_root/name)
            core.require(artifacts, 'empty candidate/support inventory')
            for path, digest in artifacts.items():
                artifact = Path(path) if name == 'runtime-inputs.json' else run_root/path
                core.require(core.sha(artifact) == digest, 'changed candidate/support artifact: '+path)
    review = read(root/'integrated-acceptance.json')
    core.require(review['schema'] == 1 and review['status'] == 'PASS' and review['reviewer'] and review['manifest_sha256'] == core.sha(root/'acceptance-manifest.json'), 'unbound independent review')
    core.require(set(review['rows']) == LIFECYCLE_ROWS and all(review['rows'][row]['status'] == 'PASS' and review['rows'][row]['finding'] for row in LIFECYCLE_ROWS), 'incomplete independent row review')
    core.require(review['screenshots'], 'missing visual review evidence')
    for shot in review['screenshots']:
        core.require(shot['finding'] and shot['unobstructed'] and core.sha(root/shot['path']) == shot['sha256'], 'missing/changed screenshot review')
    return manifest


def aggregate_sensitivities(root, inputs, baseline, read=core.read):
    """Replay targeted receipt mutations against the same real positive baseline; no asserted control PASS."""
    import copy
    core.require(set(baseline) == LIFECYCLE_ROWS and all(r['status'] == 'PASS' for r in baseline.values()), 'sensitive controls lack real positive roster')
    cap = root/inputs['first']/'captures'; topology = root/inputs.get('topology', inputs['first'])/'captures'; reopen = root/inputs['second']/'captures'; service = root/inputs['service']/'evidence'
    def owner(rows, name):return next(r for r in rows['rows'] if r['row'] == name)
    controls = {
        'missing-pre-refresh':('W2', topology/'topology-observation.json', None),
        'missing-provider':('W2', topology/'topology-observation.json', lambda r:next(e for e in r['events'] if e['kind']=='observer-installed')['provider'].__setitem__('showing', False)),
        'wrong-program-domain':('W2', topology/'topology-observation.json', lambda r:r['identity'].__setitem__('domain', 'foreign::0')),
        'configuration-only':('H0/H1', service/'service-results.json', lambda r:owner(r,'STANDALONE_SCHEDULED_PUBLIC_SCRIPT')['worker'].__setitem__('stack', [])),
        'sequential-owner':('H0/H1', service/'service-results.json', lambda r:owner(r,'TOOL_OWNER_COMMIT')['pending'].__setitem__('terminalDone', True)),
        'false-return-rollback':('H0/H1', service/'service-results.json', lambda r:owner(r,'TOOL_OWNER_ABORT').__setitem__('rollbackMechanism', 'applyTo false')),
        'driver-cancel-close':('W4', cap/'close-during-computation.json', lambda r:r.update(initial_close_accepted=True, cancelled_by_owner=True)),
        'missing-outstanding':('W4', cap/'native-outstanding-switch.json', lambda r:r.__setitem__('outstanding_at_switch', False)),
        'stale-publication':('W3', cap/'activation-only.json', lambda r:r.__setitem__('disposition', 'PUBLISHED')),
        'rescued-topology':('W2', topology/'topology-observation.json', lambda r:r['events'].insert(next(i for i,e in enumerate(r['events']) if e['kind']=='first-use-capture'), {'seq':next(e['seq'] for e in r['events'] if e['kind']=='first-use-capture')-0.5, 'kind':'provider-reset'})),
        'missing-first-close':('W6', cap/'tool-closed.json', None),
        'rescued-reopen':('W6', reopen/'timeline.json', lambda r:r.insert(0, {'kind':'analysis-rescue'})),
    }
    result = {}
    for name, (row, path, mutate) in controls.items():
        altered = copy.deepcopy(read(path)) if mutate else None
        if mutate:mutate(altered)
        def overlay(candidate):
            if candidate.resolve() == path.resolve():
                if mutate is None:raise FileNotFoundError(str(path))
                return copy.deepcopy(altered)
            return read(candidate)
        checked = completion(root, read=overlay, include_v=False)
        core.require(checked['status'] != 'PASS' and checked['rows'][row]['status'] in ('FAIL', 'NOT_RUN'), 'accepted mandatory mutant: '+name)
        core.require(all(checked['rows'][key]['status'] == 'PASS' for key in LIFECYCLE_ROWS-{row}), 'control failed unrelated row: '+name)
        result[name] = checked['rows'][row]
    return result


def completion(root, read=core.read, include_v=True):
    """Mandatory R3 roster. Missing evidence is UNRUN, never a negative semantic success."""
    inputs=read(root/'completion-inputs.json');first=root/inputs['first'];second=root/inputs['second'];service=root/inputs['service']
    cap=first/'captures';reopen=second/'captures';results={}
    def run(name,check):
        try:results[name]={'status':'PASS','evidence':check()}
        except FileNotFoundError as failure:results[name]={'status':'NOT_RUN','reason':str(failure)}
        except (core.Refusal,ValueError,AssertionError) as failure:results[name]={'status':'FAIL','reason':str(failure)}
        except Exception as failure:results[name]={'status':'FAIL','reason':type(failure).__name__+': '+str(failure)}
    def services():
        exit_record=read(service/'exit.json');core.require(exit_record['exit']==0 and not exit_record.get('timeout'),'service child failed')
        return headed_owners(read(service/'evidence/service-results.json')['rows'])
    def contention():
        busy=read(service/'evidence/busy-deferral.json');core.require(busy['status']=='NOT_DONE' and not busy['ownedWrites'] and 'foreign transaction pending' in busy['rejection'],'unobserved busy deferral')
        for abort in (False,True):
            edit=read(service/('evidence/foreground-abort.json' if abort else 'evidence/foreground-commit.json'))
            core.require(edit['submission']['edt'] and edit['command']=='ghidra.app.cmd.comments.SetCommentCmd' and edit['accepted'],'no accepted normal foreground edit')
            core.require(edit['commentInside']=='R3 real foreground tool edit' and edit['commentAfter']==('null' if abort else 'R3 real foreground tool edit'),'foreground edit owner outcome lost')
        follow=read(service/'evidence/analysis-follow-on.json');core.require(follow['tasks'] and any('GhidraBoyTools' not in task for task in follow['tasks']),'no actual analysis follow-on')
        return busy
    def warm():
        stale=read(cap/'public-passive-stale-request.json');core.require(not stale['highfunction_available'] and 'Stale' in stale['error'],'missing passive stale refusal')
        timeline=read(cap/'timeline.json')
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
        refresh=read(cap/'public-enabled-refresh-refresh-action.json')
        core.require(refresh['enabled'] and refresh['invoked'] and refresh['completed'] and refresh['context_provider_matches'] and refresh['owner']=='DecompilePlugin' and refresh['action']=='Refresh','missing actual enabled ordinary Refresh')
        return {label:check(cap,label,delta) for label,delta in [('public-initial',1),('public-event-recovery',-1),('public-toolbar-refresh',-1)]}
    def topology():
        cap=root/inputs.get('topology', inputs['first'])/'captures'
        first_use=topology_first_use(cap, read)
        topology_navigation(cap, first_use, read)
        labels=sorted(x.name.removesuffix('-source-binding.json') for x in cap.glob('domain-order-*-source-binding.json'))
        core.require(len(labels)==4,'missing domain reversals')
        entries=[read(cap/(label+'-request.json'))['display_entry'] for label in labels]
        core.require(len(set(entries))==2 and entries[0]==entries[3] and entries[1]==entries[2] and entries[0]!=entries[1],'incorrect domain reversal')
        return {'first_use':first_use, 'semantics':{label:check(cap,label,first_use['delta']) for label in ['topology-first-use', *labels]}}
    def supersession():
        ordered=check_request_ordering(cap);only=read(cap/'activation-only.json')
        core.require(only['disposition']=='ACTIVATION_SUPERSEDED' and not only['new_public_request'] and only['unchanged'],'missing activation-only P/Q/P witness')
        timeline=read(cap/'timeline.json');starts=[i for i,x in enumerate(timeline) if x['kind']=='activation-only-A-return'];ends=[i for i,x in enumerate(timeline) if x['kind']=='activation-only-A-disposition']
        core.require(len(starts)==len(ends)==1 and starts[0]<ends[0],'missing activation-only causal trace')
        segment=timeline[starts[0]:ends[0]+1];core.require(not any(x['kind']=='public-action-invoke' for x in segment),'new request substituted for activation-only supersession')
        core.require([x['kind'] for x in segment if x['kind'] in ('activation-only-Q','activation-only-P')]==['activation-only-Q','activation-only-P'],'missing actual P/Q/P activation sequence')
        return {'ordering':ordered,'activation_only':only,'Q':check(cap,'Q-positive',-1)}
    def outstanding():
        native=read(cap/'native-outstanding-switch.json')
        core.require(native['normal_provider_count']==1 and native['native_work_phase']=='RUNNING_REQUEST_AT_SAMPLE' and native['native_worker_stacks'] and native['outstanding_at_switch'],'unobserved native outstanding work')
        core.require(native['source_revision_before']==native['source_revision_at_switch'],'native source changed before switch')
        for item in native['native_worker_stacks']:
            core.require(any('DecompileRunnable.' in frame for frame in item['stack']) and any('DecompileProcess.' in frame for frame in item['stack']),'unbound normal native stack')
        close=read(cap/'close-during-computation.json')
        if close['initial_close_accepted']:
            core.require(close['route']=='ACCEPTED_CLOSE_CANCELLED_REQUEST' and close['cancelled_before_owner'] and not close['cancelled_by_owner'],'driver cancel credited as accepted close')
        else:core.require(close['route']=='DEFERRED_CLOSE_THEN_OWNER_CANCEL' and close['cancelled_by_owner'],'deferred close mislabelled')
        return {'native':native,'close':close,'Q':check(cap,'native-after-switch-Q',-1)}
    def removal():
        core.require((cap/'removal-current-before.gb').read_bytes()==(cap/'removal-current-after.gb').read_bytes(),'removal changed original bytes')
        before=read(cap/'removal-before.json');after=read(cap/'removal-after.json')
        timeline=read(cap/'timeline.json');returns=[x['detail'] for x in timeline if x['kind']=='public-action-return' and x['detail']['action']=='stock-predicate-remove']
        core.require(len(returns)==1 and len(returns[0]['arguments'])==2,'missing exact public removal request');request=returns[0]
        retired=removed_entry(before,after,read(cap/'removal-passive-request.json'),request['arguments'][1],request['program']['program_id'],request['program']['program_object'])
        outcomes=[x['detail'] for x in timeline if x['kind']=='public-action-outcome' and x['detail']['operationId']==request['operation']]
        core.require(len(outcomes)==1 and outcomes[0]['current'] and outcomes[0]['mutation']=='COMMITTED','removal did not commit')
        for index in range(8):
            resources=read(cap/f'close-resources-{index}.json');core.require(resources['operations']['observations']==resources['operations']['cancellationListeners']==resources['operations']['gateUsers']==resources['operations']['programGates']==resources['publication']['requests']==0,'owned resources remain after repeated close')
        disposed=read(cap/'public-tool-disposed.json');core.require(all(value==0 for value in disposed['operations'].values()) and all(value==0 for value in disposed['publication'].values()),'resources remain after tool disposal');return {'repeated_closes':8,'removal':retired}
    def persistence():
        for run_root in (first,second):
            exited=read(run_root/'process-exit.json');core.require(exited['exit']==0 and not exited.get('timeout'),'normal JVM did not exit successfully')
            closed=read(run_root/'captures/tool-closed.json');core.require(closed['program_closed'] and closed['remaining_consumers']==0,'actual Program closure not established')
        a=read(first/'process-start.json');b=read(second/'process-start.json');core.require(a['pid']!=b['pid'],'not a second JVM')
        result=read(reopen/'public-window-complete.json');core.require(result['immutable'] and result['unchanged'] and result['authority']==read(cap/'saved-authority.json'),'immutable first-use mismatch')
        labels=sorted(x.name.removesuffix('-source-binding.json') for x in reopen.glob('immutable-*-source-binding.json'));core.require('immutable-first' in labels,'missing first immutable native use')
        immutable_roster(json.loads(read(cap/'saved-authority.json')),{label:read(reopen/(label+'-request.json')) for label in labels})
        immutable_no_rescue(read(reopen/'timeline.json'))
        return {label:check(reopen,label,-1) for label in labels}
    run('H0/H1',services);run('H2',contention);run('I1',lambda:chooser(cap));run('W1',warm);run('W2',topology);run('W3',supersession);run('W4',outstanding);run('W5',removal);run('W6',persistence)
    if include_v:
        def acceptance():
            core.require(set(results) == LIFECYCLE_ROWS and all(x['status']=='PASS' for x in results.values()), 'mandatory lifecycle roster incomplete')
            manifest=acceptance_identities(root, inputs, read)
            controls=aggregate_sensitivities(root, inputs, results, read)
            review=read(root/'integrated-acceptance.json')
            core.require(set(review['controls']) == set(controls), 'missing sensitive control review')
            for control in controls:
                core.require(review['controls'][control], 'empty sensitive control finding: '+control)
            return {'manifest':manifest, 'controls':controls}
        run('V',acceptance)
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
