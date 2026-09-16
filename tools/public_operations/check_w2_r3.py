#!/usr/bin/env python3
"""Fail-closed checker for the bounded AUTH-R3 headed/native qualification."""
import argparse
import hashlib
import json
from pathlib import Path

EXPECTED = "54fc048798025691789da706508d9c5fd674c2655b8192152a65eb146899e07c"
NATIVE = "c5e9775345e6841c717995a85f0bc33a972acc84b0990ad0d6fbccd6db0ae77d"
FROZEN_WORKTREE = "529467d7f3f1a4e4874a2ed9b956f8a4aca54e58758374b01227c1ccccce17c9"


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def native_stream(run):
    lines=(run/'native-events.tsv').read_text().splitlines()
    require(lines and lines[0].startswith('observer-installed\t'), 'native observer not installed')
    require(lines[-1].endswith('active_requests=0'), 'native observer closed with active requests')
    starts={};terminals={};injections={};exceptions=[]
    for line in lines:
        parts=line.split('\t');kind=parts[0]
        if kind=='request-start':starts[parts[2]]=line
        elif kind=='request-terminal':terminals[parts[2]]=line
        elif kind=='injection-request':injections.setdefault(parts[2],[]).append(line)
        elif kind=='provider-exception':exceptions.append(line)
    require(starts.keys()==terminals.keys(), 'unmatched native request')
    return dict(lines=lines,starts=starts,terminals=terminals,injections=injections,exceptions=exceptions)


def manifests(run):
    candidate=read(run/'candidate.json')
    require(candidate['sha256']==EXPECTED and sha(Path(candidate['archive']))==EXPECTED, 'candidate mismatch')
    for name in ('source-inputs.json','driver-inputs.json','runtime-inputs.json'):
        for path,digest in read(run/name).items():require(sha(Path(path))==digest, 'changed input: '+path)
    for path,digest in read(run/'compiled-classes.json').items():require(sha(run/path)==digest, 'changed class: '+path)
    snapshots=read(run/'source-snapshots.json')
    for path,digest in read(run/'source-inputs.json').items():require(sha(run/snapshots[path])==digest, 'changed source snapshot: '+path)
    exit_record=read(run/'process-exit.json')
    require(exit_record['exit']==exit_record['observer_exit']==0 and not exit_record.get('timeout'), 'process/observer failed')
    closed=read(run/'captures/tool-closed.json')
    require(closed['program_closed'] and closed['remaining_consumers']==0, 'Program/resource closure failed')
    return candidate


def physical(cap,timeline,stream,label,expected_entry):
    record=read(cap/(label+'-request.json'));require(record['label']==label, 'wrong physical label')
    require(record['entry']==record['code_viewer_location']==expected_entry, 'wrong physical location')
    require(record['completed'] and record['high_available'] and not record['error'], 'unusable physical native result')
    function=record['function']
    require(function['class']=='ghidra.util.UndefinedFunction' and function['id']==-1
            and function['calling_convention_name']=='unknown' and function['calling_convention_model']=='__asm'
            and function['call_fixup']=='NONE' and not any(function[k] for k in ('thunk','inline','no_return','custom_storage')),
            'wrong physical Function/__asm contract')
    authority=record['authority'];membership=authority['production_membership'];block=authority['block']
    require(not authority['function_at']['present'] and not authority['function_containing']['present'], 'stored/containing physical Function')
    require(not membership['stock_entry_owned'] and not membership['predicated_registered'] and not membership['ordinary_registered'], 'physical address owned')
    require(block['present'] and block['overlay'] and not block['mapped'] and block['initialized']
            and block['read'] and not block['write'] and block['execute'] and block['comment']=='NONE', 'wrong physical ROM storage')
    request=record['native_request_id'];require(request in stream['starts'] and request in stream['terminals'], 'unbound physical native request')
    inject='\n'.join(stream['injections'].get(request,[]));require('name=__asm@@inject_uponentry\ttype=3' in inject, 'physical request did not reach native __asm injection')
    boundaries=[e for e in timeline if e['kind']=='native-api-boundary' and e['detail']['request_id']==request]
    require(len(boundaries)==2 and boundaries[0]['detail']['boundary']=='start' and boundaries[1]['detail']['boundary']=='terminal'
            and boundaries[1]['detail']['completed'] and boundaries[1]['detail']['result_object']==record['result_object'], 'physical API/result identity mismatch')
    for suffix,key in (('.c','c_sha256'),('-high.json','high_sha256'),('-raw.json','raw_sha256')):
        require(sha(cap/(label+suffix))==record[key], 'changed physical artifact: '+label+suffix)
    return dict(entry=record['entry'],request_id=request,revision=record['revision'],c_sha256=record['c_sha256'],high_sha256=record['high_sha256'],raw_sha256=record['raw_sha256'])


def carrier(cap,timeline,stream,label):
    record=read(cap/(label+'-request.json'));authority=record['entry_authority'];membership=authority['production_membership'];block=authority['block'];function=record['function']
    require(record['provider_class']=='ghidra.app.plugin.core.decompile.PrimaryDecompilerProvider' and record['completed'] and record['highfunction_available'] and not record['error'], 'unusable normal carrier result')
    require(record['native_sha256']==NATIVE and record['entry']==record['display_entry']==record['code_viewer_location'], 'wrong carrier native/display identity')
    require(membership['stock_entry_owned'] and membership['predicated_registered'] and membership['predicated_stock_registered'] and not membership['predicated_companion_registered'], 'genuine stock membership absent/confused')
    require(block['start']==block['end']==record['entry'] and block['comment']=='GhidraBoy stock carrier storage v3' and block['initialized'] and block['read'] and not block['write'] and block['execute'] and not block['mapped'], 'invalid one-byte stock storage')
    require(function['calling_convention_model']=='__ghidraboy_stock_entry_v1' and authority['gb_analysis_entry']=='1', 'wrong stock convention/context')
    request=record['native_request_id'];inject='\n'.join(stream['injections'].get(request,[]));require('name=gb_analysis_entry_v1\ttype=2' in inject and 'name=__ghidraboy_stock_entry_v1@@inject_uponentry\ttype=3' in inject, 'carrier did not reach stock native injection')
    return dict(entry=record['entry'],request_id=request,revision=record['revision'],native_sha256=record['native_sha256'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=Path);parser.add_argument('--repo',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    first=args.root/'first-jvm-final';second=args.root/'second-jvm-final';cap=first/'captures';reopen=second/'captures'
    first_candidate=manifests(first);second_candidate=manifests(second);require(first_candidate['sha256']==second_candidate['sha256']==EXPECTED,'cross-JVM candidate mismatch')
    a=read(first/'process-start.json');b=read(second/'process-start.json');require(a['pid']!=b['pid'],'not separate JVMs')
    stream=native_stream(first);reopen_stream=native_stream(second);timeline=read(cap/'timeline.json');reopen_timeline=read(reopen/'timeline.json')
    pollution=read(cap/'physical-pollution-control.json');before=pollution['before'];after=pollution['after'];membership=after['production_membership']
    require(pollution['label']=='INTENTIONAL_NEGATIVE_CONTROL_ONLY' and pollution['typed_read_result']=='NULL' and pollution['revision_before']==pollution['revision_after'], 'invalid pollution control')
    require(not before['stock_predicate_cache_present'] and after['stock_predicate_cache_present'] and not membership['stock_entry_owned'] and not membership['predicated_registered'] and not membership['ordinary_registered'], 'pollution changed executable authority')
    rows={}
    rows['physical_target_after_pollution']=physical(cap,timeline,stream,'physical-target-after-pollution','rom2::5210')
    rows['physical_continuation_after_pollution']=physical(cap,timeline,stream,'physical-continuation-after-pollution','rom1::4301')
    rows['genuine_carrier']=carrier(cap,timeline,stream,'genuine-carrier-positive')
    rows['physical_target_after_carrier']=physical(cap,timeline,stream,'physical-target-after-carrier','rom2::5210')
    rows['physical_continuation_after_carrier']=physical(cap,timeline,stream,'physical-continuation-after-carrier','rom1::4301')
    require(rows['physical_target_after_pollution']['c_sha256']==rows['physical_target_after_carrier']['c_sha256'] and rows['physical_target_after_pollution']['high_sha256']==rows['physical_target_after_carrier']['high_sha256'], 'target changed after carrier')
    require(rows['physical_continuation_after_pollution']['c_sha256']==rows['physical_continuation_after_carrier']['c_sha256'] and rows['physical_continuation_after_pollution']['high_sha256']==rows['physical_continuation_after_carrier']['high_sha256'], 'continuation changed after carrier')
    topology=read(cap/'topology-observation.json');support=read(first/'native-support-replay.json');first_use=support['first_use']
    require(topology['process_completion']=='PASS' and not topology['later_observations']['provider_exceptions'] and not topology['later_observations']['unmatched_requests'], 'topology/later native coverage incomplete')
    require(first_use['request_id']=='native-8' and first_use['pre_native_cancelled']==[] and support['semantics']['topology-first-use']['status']=='PASS', 'wrong first actual new-domain execution')
    requests=[e for e in topology['events'] if e['kind']=='native-request'];sequence=[dict(request_id=e['request_id'],entry=e['identity']['domain'],eligibility=e['eligibility'],completed=e['completed'],error=e['error']) for e in requests]
    require([x['request_id'] for x in sequence]==['native-6','native-7','native-8'] and sequence[0]['eligibility']=='PROVISIONAL' and sequence[1]['eligibility']=='STALE_AUTHORITY' and sequence[2]['eligibility']=='ELIGIBLE' and sequence[2]['completed'] and not sequence[2]['error'], 'wrong retained first-use API/native sequence')
    stale=topology['later_observations']['old_domain_stale'];require(stale['native_request_id']=='native-9' and stale['old_entry']!=stale['current_entry'] and 'Stale predicated graph registration' in stale['error'], 'old-domain stale control misattributed')
    semantics=read(args.root/'semantic-replay-summary.json');require(semantics['status']=='PASS' and semantics['total_cases']==49152 and all(x['status']=='PASS' and x['cases']==12288 for x in semantics['labels'].values()), 'semantic replay incomplete')
    for path,digest in semantics['checker_sources'].items():require(sha(Path(path))==digest,'changed semantic checker source: '+path)
    for files in semantics['inputs'].values():
        for relative,digest in files.items():require(sha(args.root/relative)==digest,'changed semantic replay input: '+relative)
    support['postprocessor_sources']
    for path,digest in support['postprocessor_sources'].items():require(sha(Path(path))==digest,'changed normalizer/checker source: '+path)
    immutable=read(reopen/'w2-r3-immutable-result.json');request=read(reopen/'immutable-first-request.json');saved=read(cap/'saved-current-authority.json');actual=read(reopen/'immutable-authority.json')
    require(immutable['status']=='PASS' and immutable['unchanged'] and saved==actual and request['read_only'] and request['completed'] and request['highfunction_available'] and not request['error'], 'immutable first use failed/currentness changed')
    require(request['native_request_id']=='native-1' and request['native_sha256']==NATIVE and not reopen_stream['exceptions'], 'immutable native request unbound/failed')
    forbidden={'ordinary-refresh-requested','ordinary-refresh-invoked','explicit-provider-action','provider-reset','analysis-start','analysis-rescue','public-action-invoke','operation-begin'}
    require(not any(e['kind'] in forbidden for e in reopen_timeline), 'immutable run used rescue/mutation')
    navigations=[e for e in reopen_timeline if e['kind']=='navigate'];markers=[e for e in reopen_timeline if e['kind']=='immutable-first-request-navigation']
    require(len(navigations)==len(markers)==1 and navigations[0]['detail']['entry']==markers[0]['detail']['entry']==request['entry'], 'immutable first request was not the sole initiating navigation')
    freeze=read(args.root/'candidate-freeze.json');manifest=args.root/'frozen-worktree-manifest.json';require(freeze['dirty_worktree_identity']==FROZEN_WORKTREE and freeze['worktree_manifest_sha256']==sha(manifest),'wrong frozen worktree receipt')
    frozen=read(manifest);require(frozen['head']==freeze['head'] and frozen['head_tree']==freeze['head_tree'],'wrong frozen HEAD/tree')
    production={path:digest for path,digest in frozen['worktree_sha256'].items() if path.startswith('src/main/')};require(len(production)==65,'unexpected frozen production inventory')
    changed=[]
    for relative,digest in production.items():
        actual=sha(args.repo/relative)
        if actual!=digest:changed.append(dict(path=relative,expected=digest,actual=actual))
    require(not changed,'production changed after AUTH-R3 freeze')
    checker_sources={str(path):sha(path) for path in (Path(__file__).resolve(),Path(__file__).with_name('normalize_w2.py').resolve(),Path(__file__).with_name('check_window.py').resolve(),Path(__file__).with_name('record_w2_r3_semantics.py').resolve())}
    result=dict(status='PASS',candidate_sha256=EXPECTED,installed_candidate_sha256=first_candidate['sha256'],native_sha256=NATIVE,frozen_worktree_identity=FROZEN_WORKTREE,frozen_head=freeze['head'],frozen_head_tree=freeze['head_tree'],production_files_verified=len(production),production_changes=changed,checker_sources=checker_sources,first_pid=a['pid'],second_pid=b['pid'],pollution_control='PASS',rows=rows,first_new_domain_sequence=sequence,first_actual_new_domain=first_use,old_domain_stale=stale,semantic_replay=semantics,separate_jvm=dict(status='PASS',request_id=request['native_request_id'],entry=request['entry'],saved_authority_equal=True,no_rescue=True),resources=dict(first=read(cap/'tool-closed.json'),second=read(reopen/'tool-closed.json'),first_native_terminal=stream['lines'][-1],second_native_terminal=reopen_stream['lines'][-1]),visual='UNOBSERVED',production_changed=False)
    args.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
