#!/usr/bin/env python3
"""Bounded exact production continuation identity and native rooted loop acceptance."""
import argparse,copy,json,re
from pathlib import Path
import check_predicated_calls as core
require=core.require

def successor(graph,call):
    by_id={s['index']:s for s in graph['steps']};seen=set();cursor=call.get('successor')
    while cursor is not None and cursor not in seen:
        seen.add(cursor);step=by_id[cursor]
        if step['callDepth']==call['callDepth']:
            require(step['before']==call['afterCall'] and step['nativeFunctionEntry']==call['nativeFunctionEntry'],'wrong resumed execution/frame domain')
            return cursor
        cursor=step.get('successor')
    raise core.Refusal('missing matched continuation edge')

def check(root,unit):
    graph=core.read(root/'producer-continuations.json')['0180'];calls=[s for s in graph['steps'] if s['transfer']=='CALL']
    require(len(calls)==2 and all(c.get('afterCall') and not c.get('callOutcome') for c in calls),'callee incorrectly classified nonreturning')
    pairs=[(c['index'],successor(graph,c)) for c in calls];require(any(b<a for a,b in pairs),'production did not create lower-ID continuation')
    by_id={s['index']:s for s in graph['steps']}
    for call in calls:
        require(call['physicalTarget']=='0240' and call['after']['sp']==0xc0fe and call['afterCall']['sp']==0xc100 and call['afterCall']['cpu']==0x153,'wrong physical CALL/return destination')
        require([(a['cpu'],a['value']) for a in call['accesses'] if a['write']]==[(0xc0ff,1),(0xc0fe,0x53)],'CALL lost actual stack writes')
        cursor=call['successor'];ret=by_id[cursor]
        require(ret['transfer']=='RETURN' and [(a['cpu'],a['value']) for a in ret['accesses'] if not a['write']]==[(0xc0fe,0x53),(0xc0ff,1)],'callee lost actual RET stack reads')
    renamed=copy.deepcopy(graph);ids={s['index']:3000-i*7 for i,s in enumerate(graph['steps'])};renamed['entryStep']=ids[graph['entryStep']]
    renamed['steps'].reverse()
    for step in renamed['steps']:
        step['index']=ids[step['index']]
        if step.get('successor') is not None:step['successor']=ids[step['successor']]
    for call,(old,target) in zip(calls,pairs):
        counterpart=next(c for c in renamed['steps'] if c['index']==ids[old]);require(successor(renamed,counterpart)==ids[target],'renumbering changed continuation')
    emitted=core.read(root/'root-requested.json');require(not any(o['mnemonic']=='RETURN' for o in emitted),'synthesized root RETURN')
    require(sum(o['mnemonic']=='CALL' and o['inputs'][0]['offset']==0x240 for o in emitted)==2,'lost ordinary CALL in exact lowering')
    require(sum(o['mnemonic']=='STORE' for o in emitted)>=4,'lowering lost real call frame writes')
    require(any(o['mnemonic']=='BRANCH' and o['inputs'][0]['constant'] and o['inputs'][0]['offset']&0x80000000 for o in emitted),'lowering dropped local backedge')
    request=core.read(root/'root-request.json');require(request['completed'] and request['highfunction_available'] and not request['error'],'native root request failed')
    require(any(p.get('parent')==request['owner_java_pid'] and p.get('binary_sha256')==core.base.NATIVE for p in request['processes_after']),'wrong native binary')
    blocks={b['index']:b for b in core.read(root/'root-high.json')};reachable=set();queue=[0]
    while queue:
        n=queue.pop()
        if n in reachable:continue
        require(n in blocks,'native edge escapes CFG');reachable.add(n);queue.extend(blocks[n]['out'])
    require(all(blocks[n]['out'] and not any(o['mnemonic']=='RETURN' for o in blocks[n]['ops']) for n in reachable),'native synthesized termination or dropped backedge')
    cyclic=[]
    for start in reachable:
        todo=list(blocks[start]['out']);seen=set()
        while todo:
            n=todo.pop()
            if n==start:cyclic.append(start);break
            if n not in seen:seen.add(n);todo.extend(blocks[n]['out'])
    require(any(any(o['mnemonic']=='CALL' and o['inputs'][0]['space']=='ram' and o['inputs'][0]['offset']==0x240 for o in blocks[n]['ops']) for n in cyclic),'native cycle no longer contains real physical call')
    leaf=[]
    for path in root.glob('callee-*-request.json'):
        r=core.read(path)
        if r['entry']=='0240':leaf.append((path,r))
    require(len(leaf)==1 and leaf[0][1]['completed'] and leaf[0][1]['highfunction_available'],'missing actual returning native leaf')
    high=core.read(root/(leaf[0][0].name.replace('-request.json','-high.json')));require(any(o['mnemonic']=='RETURN' for b in high for o in b['ops']),'native leaf does not normally return')
    proof=core.read(unit);require(proof['originalPayload']==proof['permutedPayload'],'production graph permutation changed emitted payload')
    return {'status':'PASS','active_route':core.read(root/'active-route.json'),'native_production_call_successors':pairs,'renumbered_successors':[(ids[a],ids[b]) for a,b in pairs], 'unit_payload_permutation':'IDENTICAL','native_loop_blocks':cyclic,'native_real_return_leaf':leaf[0][1]['entry'],'root_return_synthesized':False}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('unit',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:r=check(a.root,a.unit)
    except core.Refusal as error:r={'status':'FAIL','reason':str(error)}
    a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2));raise SystemExit(0 if r['status']=='PASS' else 1)
