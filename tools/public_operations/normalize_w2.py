#!/usr/bin/env python3
"""Normalize public JDI/native W2 observations; replay support without visual acceptance.

Raw timeline, JDI stream and launch log remain authoritative. This narrow fixture
normalizer refuses changed source across measured native work or incomplete coverage.
It cannot produce default W2/V acceptance without the separate desktop gate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import check_window as checker


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize(run, *, bounded_prefix=False):
    cap = run/'captures'
    read = lambda name: json.loads((cap/name).read_text())
    require = checker.core.require
    timeline = read('timeline.json')
    raw = (run/'native-events.tsv').read_text().splitlines()
    exit_record = json.loads((run/'process-exit.json').read_text())
    require(exit_record['observer_exit'] == 0, 'incomplete native observer')
    process_complete = exit_record['exit'] == 0 and not exit_record.get('timeout')
    require(process_complete or bounded_prefix, 'incomplete observer/target run; bounded prefix requires explicit separate scope')
    require(raw[0].startswith('observer-installed\t') and raw[-1].startswith(('vm-death\t', 'vm-disconnect\t')), 'unclosed native observer')
    def one(kind, predicate=lambda d: True):
        found = [e for e in timeline if e['kind'] == kind and predicate(e['detail'])]
        require(len(found) == 1, 'missing/duplicate raw event '+kind)
        return found[0]
    observed = one('observer-installed')
    apply = one('public-action-invoke', lambda d: d['action'] == 'stock-predicate-apply')
    # Later refreshes share an entry. Bind the first measured apply operation explicitly.
    applied = one('measured-apply-terminal')
    operation = applied['detail']['operation']
    outcomes = [e for e in timeline if e['kind'] == 'public-action-outcome' and e['detail']['operationId'] == operation]
    require(len(outcomes) == 1, 'unbound creation outcome')
    outcome = outcomes[0]
    o = outcome['detail']
    identity = dict(program_id=o['programId'], program_object=o['programObject'], domain=o['entry'], carrier=o['entry'], operation_id=operation, transaction_id=o['transactionId'])
    require(o['mutation'] == 'COMMITTED' and o['databaseCommit'] and o['current'] and not o['cancelled'], 'creation not current/committed')
    publication = one('public-action-presentation', lambda d: d['operation'] == operation)
    captured = one('passive-capture', lambda d: d['phase'] == 'topology-first-use')
    comparison = one('explicit-comparison-begin')
    require(captured['sequence'] < comparison['sequence'], 'post-comparison first result')
    before, after = read('topology-before.json'), read('topology-after.json')
    record = read('topology-first-use-request.json')
    provider = dict(class_=observed['detail']['normal_provider_class'])
    provider = {'class':provider['class_'], 'showing':observed['detail']['showing'], 'tool':'CodeBrowser', 'object':observed['detail']['provider_object']}
    require(provider['class'] == record['provider_class'] and before['program'] == after['program'] == observed['detail']['program'], 'foreign provider/Program topology')
    # Bind actual terminal callback to its earlier started transaction, then independently
    # check the public completion receipt's durable commit decision for the same owner.
    owner_start = one('transaction-callback', lambda d: d['callback'] == 'started' and d['transaction'].get('id') == o['transactionId'])
    ended = [e for e in timeline if e['kind'] == 'transaction-callback' and e['detail']['callback'] == 'ended-observation' and owner_start['sequence'] < e['sequence'] <= outcome['sequence'] and not e['detail']['transaction']['active']]
    require(len(ended) == 1, 'ambiguous owner terminal callback')
    terminal = ended[0]
    events = []
    def event(source, kind, **detail):
        events.append(dict(seq=source['sequence'], kind=kind, **detail))
    event(observed, 'observer-installed', mechanism='public DecompInterface entry/return breakpoints + DecompileResults constructor + provider exceptions; synchronous public snapshots and display listener', coverage_limitations=[], dropped_events=0, provider=provider)
    event(apply, 'apply-invoke', action='stock-predicate-apply', identity=identity)
    event(terminal, 'owner-terminal', identity=identity, mutation=o['mutation'], current=o['current'], completion_receipt_seq=outcome['sequence'])
    event(publication, 'public-presentation', identity=identity, disposition=publication['detail']['disposition'])
    event(captured, 'first-use-capture', label='topology-first-use', request_id=record['native_request_id'])
    event(comparison, 'explicit-provider-action', detail='comparison only after retained first result')
    for e in timeline:
        if apply['sequence'] < e['sequence'] < captured['sequence']:
            if e['kind'] == 'program-event':
                require(e['detail']['target'] == before['program'], 'foreign Program event')
                event(e, 'program-event', identity=identity, types=[r['type'] for r in e['detail']['records']])
            elif e['kind'] in checker.RESCUE_KINDS or e['kind'] == 'public-action-invoke':
                event(e, e['kind'], raw_detail=e['detail'])
    boundaries = [e for e in timeline if e['kind'] == 'native-api-boundary']
    starts = {e['detail']['request_id']:e for e in boundaries if e['detail']['boundary'] == 'start'}
    returns = {e['detail']['request_id']:e for e in boundaries if e['detail']['boundary'] == 'terminal'}
    require(len(boundaries) == len(starts)+len(returns) and returns.keys() <= starts.keys(), 'missing/duplicate native boundary')
    for kind, entries in [('request-start', starts), ('request-terminal', returns)]:
        ids = [line.split('\t')[2] for line in raw if line.startswith(kind+'\t')]
        require(len(ids) == len(set(ids)) and set(ids) == entries.keys(), 'JDI/target request mismatch')
    requests = {}
    for request_id, start in starts.items():
        if not apply['sequence'] < start['sequence'] < captured['sequence']:
            continue
        require(request_id in returns, 'unclosed measured native request')
        end = returns[request_id]
        require(end['sequence'] < captured['sequence'], 'unclosed first-use work')
        s, t = start['detail'], end['detail']
        require(s['program'] == t['program'] == before['program'] and s['entry'] == t['entry'] and s['function_id'] == t['function_id'], 'foreign native result')
        require(s['revision'] == t['revision'] and s['registration'] == t['registration'], 'source changed across native currentness validation')
        displays = [e['detail'] for e in timeline if e['kind'] == 'display-data' and e['detail'].get('result_object') == t['result_object']]
        require(len(displays) <= 1 and (not t['completed'] or len(displays) == 1), 'unbound native/display result')
        if displays:
            require(displays[0]['completed'] == t['completed'] and displays[0]['error'] == t['error'] and displays[0]['provider_object'] == provider['object'], 'foreign native/display result')
        actual = {**identity, 'domain':s['entry'], 'carrier':s['entry']}
        active = s['transaction']['active']
        if active:
            require(s['transaction']['id'] == o['transactionId'], 'foreign provisional owner')
            eligibility = 'PROVISIONAL'
        elif s['entry'] == identity['domain']:
            # Successful output does not determine request eligibility. The committed
            # new authority must pass on its very first post-terminal request.
            require(start['sequence'] > terminal['sequence'], 'new authority used before commit')
            eligibility = 'ELIGIBLE'
        else:
            require(s['entry'] in before['domains'] and 'Stale predicated graph registration' in t['error'], 'unclassified native refusal')
            eligibility = 'STALE_AUTHORITY'
        currentness = dict(observed_at_seq=start['sequence'], current=(s['entry'] == identity['domain'] and s['revision'] == o['sourceRevision'] and start['sequence'] > terminal['sequence']), disposition=eligibility,
            registration_sha256=hashlib.sha256(s['registration'].encode()).hexdigest(), revision=s['revision'], validation_return_seq=end['sequence'],
            basis='New authority uses committed public current outcome at identical source revision; old stale authority uses actual native refusal with unchanged start/return registration and revision')
        transaction = dict(observed_at_seq=start['sequence'], owner_transaction_id=o['transactionId'], active=active, owner_status=s['transaction'].get('status', 'COMMITTED'), raw=s['transaction'])
        event(start, 'native-request-start', request_id=request_id, identity=actual)
        event(end, 'native-request', native_status=dict(monitor_cancelled_at_entry=s.get('monitor_cancelled'),monitor_cancelled_at_return=t.get('monitor_cancelled'),return_code_index=t.get('return_code_index'),cancelled=t.get('cancelled'),timed_out=t.get('timed_out'),failed_to_start=t.get('failed_to_start')), request_id=request_id, identity=actual, observed_operation_id=operation, provider=provider, eligibility=eligibility, completed=t['completed'], error=t['error'], currentness_evidence=currentness, transaction_evidence=transaction)
        requests[request_id] = events[-1]
    # Keep the complete stream; bound the W2 log to all measured requests. Later
    # comparison/navigation work is separately classified, never claimed complete.
    measured_lines = [line for line in raw if len(line.split('\t')) > 2 and line.split('\t')[2] in requests]
    (cap/'measured-native-events.tsv').write_text('\n'.join(measured_lines)+'\n')
    outside_errors = [line for line in raw if line.startswith('provider-exception\t') and line.split('\t')[2] not in requests]
    errors = []
    for line_number, line in enumerate(measured_lines, 1):
        if line.startswith('provider-exception\t'):
            request_id = line.split('\t')[2]
            require(request_id in requests, 'provider error outside measured scope')
            request = requests[request_id]
            errors.append(dict(line=line_number, text=line, request_id=request_id, identity=request['identity'], eligibility=request['eligibility']))
    # Preserve full target log as well. Match each printed exception group in causal order
    # to the actual native request with the identical outer/inner exception messages.
    launch = (run/'launch.log').read_text().splitlines()
    stale_groups = [i for i,line in enumerate(launch) if line.startswith('ERROR Unexpected Exception:')]
    failed = sorted((r for r in requests.values() if r['error']), key=lambda r:r['seq'])
    all_failed = sorted((e for e in returns.values() if e['detail'].get('error')), key=lambda e:e['sequence'])
    require(len(stale_groups) == len(all_failed), 'unclassified target exception group')
    printed_groups=[]
    for index, end in zip(stale_groups, all_failed):
        request_id=end['detail']['request_id']
        message=end['detail']['error'].split('Injection error: ')[-1].strip()
        require(message in launch[index], 'target/native exception group differs')
        printed_groups.append(dict(line=index+1,request_id=request_id,scope='measured' if request_id in requests else 'later-comparison-navigation'))
    injection_failure = re.compile(r'(stale predicated graph registration|missing predicated graph registration or stock software carrier|(?:error|exception|refus|fail|unavailable|bad|invalid).*?(?:inject|call.fixup|registration)|(?:inject|call.fixup).*?(?:error|exception|refus|fail|unavailable|bad|invalid))', re.IGNORECASE)
    attributed_launch_lines=[]
    for number, line in enumerate(launch,1):
        if not injection_failure.search(line):
            continue
        groups=[g for g in printed_groups if g['line'] <= number]
        require(groups, 'unattributed target registration/injection line')
        group=groups[-1]
        messages=[r.split('\tmessage=',1)[1] for r in raw if r.startswith('provider-exception\t') and r.split('\t')[2] == group['request_id']]
        require(any(message in line for message in messages), 'unattributed target registration/injection line')
        attributed_launch_lines.append(dict(line=number, text=line, request_id=group['request_id'], scope=group['scope']))
    def topology(source):
        return dict(program_id=source['program']['program_id'], program_object=source['program']['program_object'], spaces=source['spaces'], domains=source['domains'], blocks=[{**b, 'backing':b['sources'], 'permissions':{k:b[k] for k in ('read','write','execute')}} for b in source['blocks']])
    receipt = dict(process_completion='PASS' if process_complete else 'FAIL', bounded_prefix=bounded_prefix, schema=1, identity=identity, delta=1, before=topology(before), after=topology(after), events=sorted(events,key=lambda e:e['seq']), log='measured-native-events.tsv', errors=errors,
        attribution_basis='Public native exceptions and exact result objects; post-commit stale authority is distinct from active provisional work',
        raw_sha256={name:sha(run/name) for name in ('captures/timeline.json','native-events.tsv','launch.log','process-start.json','process-exit.json','captures/topology-before.json','captures/topology-after.json')},
        printed_exception_groups=printed_groups, attributed_launch_lines=attributed_launch_lines, visual='UNOBSERVED',
        coverage_scope='measured apply through retained first-use capture only; full raw stream retained',
        later_observations=dict(provider_exceptions=outside_errors, unmatched_requests=sorted(starts.keys()-returns.keys()), terminal_observer_record=raw[-1], navigation='FAIL' if outside_errors else 'UNOBSERVED'))
    (cap/'topology-observation.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    parser.add_argument('--bounded-prefix', action='store_true', help='Validate only the completed creation interval despite a separately failed later process; never full-run acceptance')
    parser.add_argument('--receipt-only', action='store_true', help='Bind and check causal receipt without claiming semantic replay')
    args = parser.parse_args()
    receipt=normalize(args.run,bounded_prefix=args.bounded_prefix)
    cap = args.run/'captures'
    first = checker.topology_first_use(cap)
    labels = ['topology-first-use', *['domain-order-'+str(i) for i in range(4)]]
    entries = [json.loads((cap/(label+'-request.json')).read_text())['display_entry'] for label in labels[1:]]
    checker.core.require(len(set(entries)) == 2 and entries[0] == entries[3] and entries[1] == entries[2] and entries[0] != entries[1], 'missing actual domain reversal')
    if args.receipt_only:
        print(json.dumps(dict(first_use=first, process_completion=receipt['process_completion'], semantic_replay='NOT_RUN', visual='UNOBSERVED', W2_acceptance='UNOBSERVED'),indent=2))
        return
    result = dict(process_completion=receipt['process_completion'], later_observations=receipt['later_observations'], native_creation_support='PASS', visual='UNOBSERVED', W2_acceptance='UNOBSERVED', first_use=first,
                  semantics={label:checker.check(cap,label,1,support_only=True) for label in labels})
    (args.run/'native-support-replay.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__ == '__main__':
    main()
