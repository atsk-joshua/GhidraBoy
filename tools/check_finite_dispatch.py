#!/usr/bin/env python3
"""Independent dispatch replay through maintained raw, emitted and HighFunction evaluators."""
import argparse
from collections import Counter
import json
from pathlib import Path
import check_predicated_calls as shared

class Machine(shared.Machine):
    ROOT_CPU=0x100
    OUTPUT_RANGE=range(0xc000,0xc001)
    GLOBAL_RANGE=range(0x8000,0x10000)
    def __init__(self,image,u,spaces,nibble=False,h=0xc060,frame=(0xc802,0x190,0,0x53,0x12a6,0xbeef)):
        super().__init__(image,0x37,frame)
        self.spaces={v['id']:k for k,v in spaces.items()}
        self.mem[h if nibble else 0xff80]=u
        if nibble:self.set_register(6,2,h)
    def get(self,v,env=None,entry=None):
        if not v['constant'] and v['space']=='ram' and (env is None or v['id'] not in env):
            return self.load(v['offset'],v['size'],env is None)
        return super().get(v,env,entry)
    def ordinary(self,op,env=None,entry=None):
        if op['mnemonic'] in {'LOAD','STORE'}:
            nodes=op['inputs'];space=self.spaces.get(self.get(nodes[0],env,entry))
            shared.require(space=='ram','wrong actual LOAD/STORE space '+str(space))
        return super().ordinary(op,env,entry)

def require_native_effects(raw,native,frame_bytes=()):
    """Check observable writes separately from raw/emitted architectural ordering.

    Optimized native code may forward values or eliminate frame temporaries; it may
    not invent writes, including writes that later restore a cell's prior value.
    Only actual STORE/address outputs enter events; HighGlobal-associated UNIQUE
    values are SSA computation, not architectural writes.
    """
    permitted=Counter(e for e in raw.events if e[0]=='write')
    actual=Counter(e for e in native.events if e[0]=='write')
    shared.require(not (actual-permitted),'extra native architectural write: '+str(actual-permitted))
    for _,at,_ in actual:
        shared.require(native.mem.get(at)==raw.mem.get(at),'native collateral storage differs at '+hex(at))
    for _,at,_ in permitted:
        if at not in frame_bytes:
            shared.require(native.mem.get(at)==raw.mem.get(at),'missing native collateral storage at '+hex(at))
    for at in raw.outputs:
        shared.require(native.outputs.get(at)==raw.outputs[at],'missing native observable output at '+hex(at))

def proof_trace(cap,initial):
    names={op['opcode']:op['mnemonic'] for ins in cap.raw.values() for op in ins['ops']}
    names.update({62:'PIECE',63:'SUBPIECE'})
    memo={}
    def value(origin):
        key=id(origin)
        if key in memo:return memo[key]
        kind=origin['kind']
        if kind=='CONSTANT':v=origin['constant']
        elif kind=='INPUT':
            name=origin['input']
            if ':entry-register-byte@' in name:v=initial.register(int(name.rsplit('@',1)[1]))
            elif ':entry-memory:' in name:
                at=int(name.rsplit(':',1)[1].split('@')[0],16)
                shared.require(at in initial.mem,'foreign input storage');v=initial.mem[at]
            elif ':outer-return-byte@' in name:v=(initial.outer_ret>>(8*int(name.rsplit('@',1)[1])))&255
            else:raise shared.Insufficient('unobserved proof input '+name)
        else:
            args=[value(c) for c in origin['inputs']]
            if origin['opcode']==-1:
                rows=[r for r in origin['table'] if r['keys']==args]
                shared.require(len(rows)==1,'undefined/ambiguous feasible table row');v=rows[0]['value']
            else:
                shared.supported(origin['opcode'] in names,'uncaptured origin operation')
                v=shared.arithmetic(names[origin['opcode']],[dict(size=c['width']) for c in origin['inputs']],args,origin['width'])
        memo[key]=v;return v
    def matches(condition):return all(value(t['origin'])==t['value'] for t in condition['terms'])
    nodes={n['id']:n for n in cap.proof['nodes']};cursor=cap.proof['root'];trace=[];reads=[]
    for _ in range(512):
        shared.require(cursor in nodes,'missing proof successor');node=nodes[cursor]
        shared.require(matches(node['predicate']),'infeasible proof node')
        physical=node['fetch'][0]['physical']
        trace.append((physical['bank'],node['cpu']))
        for read in node.get('reads',[]):
            alternatives=[a for a in read['alternatives'] if matches(a['predicate'])]
            shared.require(len(alternatives)==1,'missing/extra feasible immutable read')
            alt=alternatives[0]
            shared.require(value(read['pointer'])==alt['cpu'],'wrong read pointer provenance')
            for octet in alt['sources']:
                physical=octet['physical']
                shared.require(physical['region']=='ROM','mutable proof table')
                expected=initial.image[physical['bank']*0x4000+physical['offset']]
                shared.require(expected==octet['value'],'wrong physical table byte/order')
                reads.append(('read',(alt['cpu']+octet['byteIndex'])&65535,expected))
        if node['transfer']=='EXTERNAL_RETURN':return trace,reads
        edges=[e for e in node['edges'] if matches(e['condition'])]
        shared.require(len(edges)==1,'missing/extra feasible graph edge')
        cursor=edges[0]['target']
    raise shared.Refusal('proof trace budget')

def check(root,label='original',nibble=False,h=0xc060,order=None,physical=False,zero=False,capture=None):
    cap=capture or shared.Capture(root,label);image=(root/(f'{label}-fixture.gb' if (root/f'{label}-fixture.gb').exists() else 'fixture.gb')).read_bytes();spaces=shared.read(root/'spaces.json')
    proof=cap.proof
    shared.require(proof['version']=='predicated-ordinary-graph-5' and proof['coverageComplete'] and not proof['frontier'],'incomplete proof')
    request=cap.requests['root'];shared.require(request['completed'] and request['highfunction_available'],'actual native request failed')
    def actual_process(process):
        if process.get('parent')!=request['owner_java_pid']:return False
        if process.get('binary_sha256') in {'c5e9775345e6841c717995a85f0bc33a972acc84b0990ad0d6fbccd6db0ae77d','4a97ff9a3dbac5757c7240a664571e82345e4abc4f67cd211cd9d402abe4543d'}:return True
        # Same strict Rosetta boundary as the maintained stock checker: argv, file hash and executable mapping.
        for native in process.get('argv_native_files',[]):
            if native.get('sha256')!='4a97ff9a3dbac5757c7240a664571e82345e4abc4f67cd211cd9d402abe4543d':continue
            path=native['path']
            if process.get('proc_cmdline','').split(' ')[0]==path and any('r-xp' in line and line.endswith(' '+path) for line in process.get('proc_maps','').splitlines()):return True
        return False
    shared.require(any(actual_process(p) for p in request['processes_after']),'unverified actual native')
    shared.require(shared.sha(root/f'{label}-root-debug.xml')==request['debug']['sha256'],'changed debug capture')
    if capture is None:shared.base.debug_identity(root/f'{label}-root-debug.xml',cap.requested['root'],request['entry'],'gb_analysis_entry_v1')
    nodes={n['id']:n for n in proof['nodes']}
    targets={(nodes[e['target']]['fetch'][0]['physical']['bank'],nodes[e['target']]['cpu']) for n in nodes.values() for e in n['edges'] if e['kind']=='DISPATCH'}
    order=order or list(range(16 if nibble else 6))
    expected_targets={(0,0x1000+8*i if nibble else 0x300+3*i) for i in order}
    if physical:expected_targets={(1,0x4000),(2,0x4000)}
    if zero:expected_targets={(0,0x300)}
    shared.require(targets==expected_targets,'extra/missing feasible physical target')
    placements_file=root/f'{label}-placements.json'
    placements=shared.read(placements_file) if placements_file.exists() else None
    shared.require(placements is not None,"Native terminal provenance capture absent")
    native_targets=set()
    if placements is not None:
        carrier=shared.read(root/'carrier-raw.json')
        shared.require([o['mnemonic'] for o in carrier]==['CALLOTHER','BRANCH'],'unproved native sequence allocation prefix')
        shared.require(request.get('jump_tables')==[],'unexpected or uncaptured native jump-table publication outside explicit graph')
        all_ops=[o for b in cap.high['root'] for o in b['ops']]
        terminals={n['source'] for n in nodes.values() if n['transfer']=='EXTERNAL_RETURN'}
        static_native_terminals=set()
        for op in all_ops:
            shared.require(op['mnemonic']!='BRANCHIND','native indirect target publication outside explicit graph')
            if op['mnemonic']=='RETURN':
                index=int(op['sequence'].split(',')[-2].strip())-len(carrier)
                sites=[r for r in placements if r['start']<=index<r['end']]
                shared.require(0<=index<len(cap.requested['root']) and cap.requested['root'][index]['mnemonic']=='RETURN' and len(sites)==1,'unproved native terminal provenance')
                static_native_terminals.add(sites[0]['source'])
        shared.require(static_native_terminals==terminals,'extra/missing native physical terminal')
        defined={o['output']['id'] for o in all_ops if o.get('output')}
        for op in all_ops:
            for v in op['inputs']:
                if not v['constant'] and v['id'] not in defined:
                    shared.require(v['space']=='ram','unqualified native input dependence '+v['space'])
                    shared.require(v['offset']<0x8000 or v['offset'] in [i['cpu'] for i in proof['memory']['inputs']],'undeclared native memory input')
    rows=[]
    frames=[(0xc802,0x190,0,0x53,0x12a6,0xbeef),(0xcffc,0x3a01,0xf0,0xd4,0x7788,0x1234),(0xc903,0x10,0xb0,0x91,0x55ff,0xaa07)]
    for frame in frames:
        f=frame[2]
        for u in range(256):
            raw=Machine(image,u,spaces,nibble,h,frame);emitted=Machine(image,u,spaces,nibble,h,frame);native=Machine(image,u,spaces,nibble,h,frame)
            trace,reads=proof_trace(cap,Machine(image,u,spaces,nibble,h,frame))
            raw.raw(cap);emitted.emitted(cap);result=native.high(cap)
            require_native_effects(raw,native,range(raw.root_sp-2,raw.root_sp+2))
            shared.require(trace==raw.fetches,f'wrong physical graph path U={u}')
            if placements is not None:
                starts={r['start']:r for r in placements}
                path=[starts[index]['source'] for tag,index in emitted.emitted_trace if index in starts]
                shared.require(path==[f'{cpu:04x}' if bank==0 else f'rom{bank}::{cpu:04x}' for bank,cpu in trace],f'emitted physical control path U={u}')
            if placements is not None:
                terminal=native.high_trace[-1][2]
                shared.require(terminal['mnemonic']=='RETURN','native did not reach a return')
                time=int(terminal['sequence'].split(',')[-2].strip())
                index=time-len(carrier)
                shared.require(0<=index<len(cap.requested['root']) and cap.requested['root'][index]['mnemonic']=='RETURN','native return has no retained requested provenance')
                sites=[r for r in placements if r['start']<=index<r['end']]
                shared.require(len(sites)==1,'ambiguous native source interval')
                bank,cpu=raw.fetches[-1]
                source=f'{cpu:04x}' if bank==0 else f'rom{bank}::{cpu:04x}'
                shared.require(sites[0]['source']==source,f'wrong native physical terminal U={u}')
                native_targets.add((bank,cpu))
            shared.require(reads==[e for e in raw.events if e[0]=='read' and e[1]<0x8000],f'ordered physical table reads U={u}')
            shared.require(raw.reg==emitted.reg,f'raw/emitted registers U={u}: {raw.reg} != {emitted.reg}')
            shared.require(raw.bank==emitted.bank==native.bank,f'native mapper control effect U={u}')
            shared.require(raw.events==emitted.events,f'raw/emitted ordered effects U={u}: {raw.events} != {emitted.events}')
            if nibble:
                expected=order[u>>4]
                shared.require(raw.outputs.get(0xc000)==emitted.outputs.get(0xc000)==native.outputs.get(0xc000)==expected,f'nibble output U={u}')
                shared.require(raw.register(6,2)==emitted.register(6,2)==result==(h+1)&65535,f'lost HL U={u}: {result}')
            else:
                expected=(0x11 if u%2==0 else 0x22) if physical else 0x44 if zero else 10*(order[u]+1) if u<6 else 0
                shared.require(raw.register(1)==emitted.register(1)==result==expected,f'phase/default result U={u}: {result} expected {expected}')
            rows.append(dict(u=u,f=f,sp=frame[0],return_cpu=frame[1],expected=expected,native=result,native_bank=native.bank,raw_steps=raw.steps,emitted_steps=emitted.steps,native_steps=native.steps))
    return dict(status='PASS',native_terminal_sources=sorted(native_targets),native_target_provenance='PASS' if placements is not None else 'UNRUN',cases=len(rows),targets=sorted(targets),nodes=len(nodes),proof_bytes=(root/f'{label}-proof.json').stat().st_size,rows=rows)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('capture',type=Path);parser.add_argument('--label',default='original');parser.add_argument('--nibble',action='store_true');parser.add_argument('--h',type=lambda x:int(x,0),default=0xc060);parser.add_argument('--physical',action='store_true');parser.add_argument('--zero',action='store_true');parser.add_argument('--order',type=lambda s:list(map(int,s.split(','))));parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args()
    try: result=check(a.capture,a.label,a.nibble,a.h,a.order,a.physical,a.zero)
    except (shared.Refusal,shared.Insufficient,Exception) as error:
        a.output.write_text(json.dumps(dict(status='FAIL',error=str(error)),indent=2)+'\n');raise
    a.output.write_text(json.dumps(result,indent=2)+'\n');print(result['status'],result['cases'])
