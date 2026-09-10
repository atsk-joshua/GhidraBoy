#!/usr/bin/env python3
"""Independent bounded diamond/ordinary-call capture interpreter. No provider evaluator or expected-return stubs.
Arithmetic forms extend the retained W2 checker. Raw physical fetch and frames are separate from
local emitted control and native CFG/Function calls. Unknown forms are ORACLE_INSUFFICIENT.
"""
import argparse
import collections
import copy
import hashlib
import json
import re
import zipfile
from pathlib import Path
import check_w2e_native as base
Refusal, Insufficient = base.Refusal, base.Insufficient
require, read, sha = base.require, base.read, base.sha

def supported(ok,reason):
    if not ok: raise Insufficient(reason)

def arithmetic(code, nodes, args, width):
    if any(a is None for a in args): raise Insufficient('unresolved arithmetic input '+code)
    a=args[0];b=args[1] if len(args)>1 else None
    if code in {'COPY','CAST','INT_ZEXT'}:v=a
    elif code=='INT_SEXT':v=a-(1<<(8*nodes[0]['size'])) if a&(1<<(8*nodes[0]['size']-1)) else a
    elif code=='INT_ADD':v=a+b
    elif code=='INT_SUB':v=a-b
    elif code=='INT_MULT':v=a*b
    elif code in {'INT_AND','BOOL_AND'}:v=a&b
    elif code in {'INT_OR','BOOL_OR'}:v=a|b
    elif code in {'INT_XOR','BOOL_XOR'}:v=a^b
    elif code=='INT_LEFT':v=a<<b
    elif code=='INT_RIGHT':v=a>>b
    elif code=='INT_EQUAL':v=int(a==b)
    elif code=='INT_NOTEQUAL':v=int(a!=b)
    elif code=='INT_LESS':v=int(a<b)
    elif code=='INT_LESSEQUAL':v=int(a<=b)
    elif code=='BOOL_NEGATE':v=int(not a)
    elif code=='INT_NEGATE':v=~a
    elif code=='INT_CARRY':v=int(a+b>=1<<(8*nodes[0]['size']))
    elif code=='PIECE':v=(a<<(8*nodes[1]['size']))|b
    elif code=='SUBPIECE':v=a>>(8*b)
    else:raise Insufficient('unobserved arithmetic '+code)
    return v&((1<<(8*width))-1)

class Capture:
    def __init__(self,root,label):
        self.root=root;self.label=label;self.proof=read(root/f'{label}-proof.json');self.raw=read(root/f'{label}-raw.json')
        self.views=read(root/f'{label}-views.json');self.by_entry={i['view']['entry']:i for i in self.views}
        self.requested={i['tag']:read(root/f"{label}-{i['tag']}-requested.json") for i in self.views}
        self.high={i['tag']:read(root/f"{label}-{i['tag']}-high.json") for i in self.views}
        self.requests={i['tag']:read(root/f"{label}-{i['tag']}-request.json") for i in self.views}
    def target(self,node):
        entry=f"{node['space']}::{node['offset']:04x}"
        require(entry in self.by_entry,'CALL has foreign/unqualified Function '+entry)
        return self.by_entry[entry]
    def physical(self,view):
        segment=view['view']['segments'][0];source=segment['source'];m=re.match(r'rom(\d+)::',source)
        return (int(m[1]) if m else 0,segment['cpu'])
    def actual_request(self,view):return self.requests[view['tag']]

class Machine:
    OUTPUT_RANGE=range(0xc060,0xc063)
    ROOT_CPU=0x150
    BYTE_A_CONTRACT=True
    def __init__(self,image,b,frame=(0xc200,0x190,0xf0,0x53,0xa6,0xbeef)):
        sp,ret,f,c,de,hl=frame;require(0xc082<=sp<=0xcffc,'frame outside declared domain')
        self.image=image;self.root_sp=sp;self.outer_ret=ret;self.bank=None;self.steps=0
        self.reg={0:f,1:0x95,2:c,3:b,4:de&255,5:de>>8,6:hl&255,7:hl>>8,8:0x50,9:1,10:sp&255,11:sp>>8}
        self.mem={sp:ret&255,sp+1:ret>>8};self.unique={};self.events=[];self.high_trace=[];self.outputs={};self.fetches=[];self.calls=[]
    def register(self,offset,size=1):return sum(self.reg[offset+i]<<(8*i) for i in range(size))
    def set_register(self,offset,size,value):
        for i in range(size):self.reg[offset+i]=(value>>(8*i))&255
    def load(self,cpu,size,trace=True):
        require(cpu is not None and 0<=cpu<65536,'unknown/widened CPU load')
        result=0
        for i in range(size):
            at=(cpu+i)&65535
            if at<0x8000:
                bank=0 if at<0x4000 else self.bank;require(bank is not None,'unresolved raw ROM mapping')
                v=self.image[bank*0x4000+(at&0x3fff)]
            else:
                require(at in self.mem,'uninitialized frame/memory read '+hex(at));v=self.mem[at]
            if trace:self.events.append(('read',at,v))
            result|=v<<(8*i)
        return result
    def store(self,cpu,size,value,trace=True):
        require(cpu is not None and value is not None and 0<=cpu<65536,'unknown/widened CPU store')
        for i in range(size):
            at=(cpu+i)&65535;v=(value>>(8*i))&255;self.mem[at]=v
            if trace:self.events.append(('write',at,v))
            if at in self.OUTPUT_RANGE:self.outputs[at]=v
    def get(self,v,env=None,entry=None):
        if v['constant']:return v['offset']&((1<<(v['size']*8))-1)
        if env is not None and v['id'] in env:return env[v['id']]
        space,offset,size=v['space'],v['offset'],v['size']
        if space=='register':
            src=entry if env is not None else self.reg
            octets=[src.get(offset+i) for i in range(size)]
        elif space=='unique':octets=[self.unique.get(offset+i) for i in range(size)]
        elif space=='ram':return self.load(offset,size,False) if offset in self.mem else None
        else:raise Insufficient('unobserved value storage '+space)
        return None if any(x is None for x in octets) else sum(v<<(8*i) for i,v in enumerate(octets))
    def put(self,v,value,env=None,write=True):
        if env is not None:supported(value is not None,'unknown defined native SSA output')
        else:require(value is not None,'unknown defined output')
        value&=(1<<(8*v['size']))-1
        if env is not None:env[v['id']]=value
        global_storage=v.get('high_global') if env is not None else None
        if global_storage is not None:
            supported(global_storage['space']=='ram' and global_storage['size']==v['size']==1 and global_storage['offset'] in getattr(self,'GLOBAL_RANGE',self.OUTPUT_RANGE),'unobserved HighGlobal storage binding')
            if write:self.store(global_storage['offset'],1,value)
        if v['space']=='register':self.set_register(v['offset'],v['size'],value)
        elif v['space']=='unique':
            if env is None:
                for i in range(v['size']):self.unique[v['offset']+i]=(value>>(8*i))&255
        elif v['space']=='ram':
            if write and global_storage is None:
                # Native SSA final copies can re-expose the same already-written rooted cell.
                self.store(v['offset'],v['size'],value)
        else:raise Insufficient('unobserved output storage '+v['space'])
    def ordinary(self,op,env=None,entry=None):
        self.steps+=1;require(self.steps<20000,'oracle bounded execution exhausted')
        code=op['mnemonic'];nodes=op['inputs'];out=op.get('output');args=[self.get(v,env,entry) for v in nodes]
        if code=='CALLOTHER':
            supported(op.get('userop_name') in {'gb_direct_write8','gb_cartridge_write8'},'unknown userop')
            require(len(args)==3 and nodes[1]['size']==2 and nodes[2]['size']==1,'unexpected bus effect widths')
            cpu,value=args[1:];require(value is not None,'unknown bus value')
            if cpu==0x2000:self.bank=value&3;self.events.append(('mapper',cpu,value))
            else:require(0xc000<=cpu<0xc080 or cpu in self.OUTPUT_RANGE,'unsupported device/observable write');self.store(cpu,1,value)
        elif code=='LOAD':
            supported(len(args)==2 and nodes[1]['size']==2,'unsupported CPU load form');self.put(out,self.load(args[1],out['size']),env)
        elif code=='STORE':
            supported(len(args)==3 and nodes[1]['size']==2,'unsupported CPU store form');self.store(args[1],nodes[2]['size'],args[2])
        else:
            value=arithmetic(code,nodes,args,out['size'])
            same_global=out.get('high_global') is not None and out.get('high_global')==nodes[0].get('high_global')
            same_cell=out['space']=='ram' and nodes[0]['space']=='ram' and out['offset']==nodes[0]['offset'] and out['size']==nodes[0]['size']
            rooted_offset=out['high_global']['offset'] if same_global else out['offset']
            terminal_copy=env is not None and code=='COPY' and (same_global or same_cell) and nodes[0]['id'] in env and self.outputs.get(rooted_offset)==value
            self.put(out,value,env,not terminal_copy)
    def raw(self,cap):
        cpu=self.ROOT_CPU;frames=[]
        for _ in range(256):
            bank=0 if cpu<0x4000 else self.bank;require(bank is not None,'unresolved actual instruction bank')
            key=f'{cpu:04x}' if bank==0 and cpu<0x4000 else f'rom{bank}::{cpu:04x}'
            require(key in cap.raw,'missing actual physical instruction '+key)
            ins=cap.raw[key];require(bytes.fromhex(ins['bytes'])==self.image[bank*0x4000+(cpu&0x3fff):bank*0x4000+(cpu&0x3fff)+len(ins['bytes'])//2], 'raw source does not match actual image')
            self.fetches.append((bank,cpu));self.unique={};next_cpu=(cpu+len(ins['bytes'])//2)&65535
            for op in ins['ops']:
                code=op['mnemonic']
                if code in {'BRANCH','CBRANCH'}:
                    supported(not op['inputs'][0]['constant'],'unobserved raw p-code-local branch')
                    taken=code=='BRANCH' or bool(self.get(op['inputs'][1]))
                    if taken:next_cpu=op['inputs'][0]['offset']&65535
                elif code=='BRANCHIND':
                    next_cpu=self.get(op['inputs'][0]);supported(next_cpu is not None and op['inputs'][0]['size']==2,'unknown raw indirect target')
                elif code=='CALL':
                    target=op['inputs'][0]['offset']&65535;sp=self.register(10,2);word=self.load(sp,2,False)
                    require(word==next_cpu,'actual CALL return word incorrect')
                    self.calls.append((cpu,self.bank,target,word));self.events.append(('call',self.bank,target,word,sp));frames.append(word);next_cpu=target
                elif code=='RETURN':
                    target=self.get(op['inputs'][0]);self.events.append(('return',target,self.register(10,2)))
                    if frames:require(target==frames.pop(),'raw unmatched return continuation');next_cpu=target
                    else:require(target==self.outer_ret,'wrong outer return');return
                else:self.ordinary(op)
            cpu=next_cpu
        raise Refusal('raw instruction budget/backedge')
    def emitted(self,cap,tag='root',depth=0):
        require(depth<=1,'unexpected emitted call depth');ops=cap.requested[tag];index=0
        while index<len(ops):
            op=ops[index];code=op['mnemonic'];self.steps+=1;require(self.steps<20000,'emitted execution budget')
            if code in {'BRANCH','CBRANCH'}:
                supported(op['inputs'][0]['constant'] and op['inputs'][0]['size']==4,'unobserved emitted machine branch')
                taken=code=='BRANCH' or bool(self.get(op['inputs'][1]))
                if taken:
                    offset=op['inputs'][0]['offset']&0xffffffff;offset=offset-(1<<32) if offset&(1<<31) else offset
                    index+=offset;require(0<=index<len(ops),'emitted local branch escapes graph');continue
            elif code=='CALL':
                target=cap.target(op['inputs'][0]);bank,cpu=cap.physical(target);require(bank==self.bank,'qualified target does not match live mapper')
                sp=self.register(10,2);word=self.load(sp,2,False);self.calls.append(((word-3)&65535,bank,cpu,word));self.events.append(('call',bank,cpu,word,sp))
                self.emitted(cap,target['tag'],depth+1);require(self.register(8,2)==word,'emitted callee resumes wrong continuation')
            elif code=='RETURN':
                destination=self.get(op['inputs'][0]);self.events.append(('return',destination,self.register(10,2)))
                if depth==0:require(destination==self.outer_ret,'emitted outer return word')
                return
            else:self.ordinary(op)
            index+=1
        raise Refusal('emitted invocation fell off without RETURN')
    def native_arguments(self,cap,tag,parameters,declared):return parameters
    def require_indirect_preservation(self,out,raw_ops,child_ops):
        supported(all(x['mnemonic'] not in {'STORE','CALLOTHER','CALL'} and not (x.get('output',{}).get('space')=='ram') for x in child_ops),'unproved memory clobber across call')
        if out['space']=='register':
            def overlaps(v):return v and v['space']=='register' and v['offset']<out['offset']+out['size'] and out['offset']<v['offset']+v['size']
            supported(all(not overlaps(x.get('output')) for x in raw_ops+child_ops),'INDIRECT register is not preserved by actual callee p-code')
        else:
            supported(all(x['mnemonic'] not in {'STORE','CALLOTHER','CALL'} and not (x.get('output',{}).get('space')=='ram') for x in raw_ops),'INDIRECT memory not preserved by actual callee p-code')
    def high(self,cap,tag='root',parameters=None,depth=0):
        require(depth<=1,'unobserved native call depth');blocks={b['index']:b for b in cap.high[tag]};env={};entry=dict(self.reg) if depth==0 else {};pred=None;current=0
        declared=cap.requests[tag].get('parameters',[])
        if parameters is not None:
            parameters=self.native_arguments(cap,tag,parameters,declared)
            supported(len(parameters)==len(declared),'native call argument/prototype mismatch')
            for value,param in zip(parameters,declared):
                supported(value is not None,'unresolved native argument')
                storage=param['storage'];supported(len(storage)==1 and storage[0]['space']=='register','unobserved native parameter storage')
                v=storage[0]
                for i in range(v['size']):entry[v['offset']+i]=(value>>(8*i))&255
        for _ in range(128):
            require(current in blocks,'native CFG edge missing');block=blocks[current];next_block=None;phi_env=dict(env)
            for op in block['ops']:
                self.high_trace.append((tag,current,op))
                code=op['mnemonic'];nodes=op['inputs'];out=op.get('output')
                if code=='MULTIEQUAL':
                    require(pred in block['in'] and len(nodes)==len(block['in']),'unobserved phi predecessor')
                    self.put(out,self.get(nodes[block['in'].index(pred)],phi_env,entry),env)
                elif code=='INDIRECT':
                    # A preserved storage value around a captured CALL; never an arbitrary INDIRECT interpretation.
                    same_storage=out and out['space']==nodes[0]['space'] and out['offset']==nodes[0]['offset'] and out['size']==nodes[0]['size']
                    same_global=out and out.get('high_global') is not None and out.get('high_global')==nodes[0].get('high_global')
                    supported(out and out['space'] in {'ram','register'} and (same_storage or same_global),'unobserved INDIRECT storage')
                    reference=nodes[1]['offset'];calls=[x for x in block['ops'] if x['mnemonic']=='CALL' and int(re.search(r', (\d+), \d+\)',x['sequence'])[1])==reference]
                    supported(len(calls)==1,'INDIRECT not tied to actual call')
                    child=cap.target(calls[0]['inputs'][0]);child_ops=[x for b in cap.high[child['tag']] for x in b['ops']]
                    raw_ops=cap.requested[child['tag']]
                    self.require_indirect_preservation(out,raw_ops,child_ops)
                    env[out['id']]=self.get(nodes[0],env,entry)
                elif code=='CALL':
                    child=cap.target(nodes[0]);bank,cpu=cap.physical(child);require(bank==self.bank,'native physical Function mismatches mapper')
                    self.events.append(('call',bank,cpu));self.calls.append((bank,cpu,cap.requests[child['tag']]['function_id']))
                    value=self.high(cap,child['tag'],[self.get(v,env,entry) for v in nodes[1:]],depth+1)
                    if self.BYTE_A_CONTRACT:supported(out is not None and out['size']==1,'native callee result not actual byte return')
                    if out is not None:self.put(out,value,env)
                elif code=='CBRANCH':
                    require(len(block['out'])==2,'native condition lacks two ordered successors')
                    condition=self.get(nodes[1],env,entry);supported(condition is not None,'unknown native predicate')
                    next_block=block['out'][1 if condition else 0];break
                elif code=='BRANCH':
                    require(len(block['out'])==1,'native unconditional edge ambiguous');next_block=block['out'][0];break
                elif code=='RETURN':
                    if depth and self.BYTE_A_CONTRACT: supported(len(nodes)==2 and nodes[1]['size']==1,'native return lacks actual A byte')
                    value=self.get(nodes[1],env,entry) if len(nodes)>1 else None
                    if depth and self.BYTE_A_CONTRACT:supported(value is not None,'unresolved native return/undeclared input')
                    return value
                else:self.ordinary(op,env,entry)
            if next_block is None:
                require(len(block['out'])==1,'native block lacks terminal or unique successor');next_block=block['out'][0]
            pred,current=current,next_block
        raise Refusal('native CFG budget/backedge')

FRAMES=[(0xc082,0x190,0,0x53,0x12a6,0xbeef),(0xcffc,0x3a01,0xf0,0xd4,0x7788,0x1234),(0xc283,0x10,0xb0,0x91,0x55ff,0xaa07)]

def validate_capture(cap,image,reuse=False):
    proof=cap.proof;require(proof['version'] in {'predicated-ordinary-graph-1','predicated-ordinary-graph-2','predicated-ordinary-graph-3','predicated-ordinary-graph-4'} and proof['coverageComplete'] and not proof['frontier'],'incomplete/unexpected producer')
    require(proof['domain']['stackMin']==0xc082 and proof['domain']['stackMax']==0xcffc,'changed declared frame domain')
    require(len(proof['invocations'])==2,'missing feasible physical callee')
    require({i['target'] for i in proof['invocations']}==({'rom1::4000'} if reuse else {'rom1::4000','rom2::4000'}),'physical call targets collapsed')
    node_by_id={n['id']:n for n in proof['nodes']};require(len(node_by_id)==len(proof['nodes']),'CPU-only/duplicate graph identity')
    calls=[n for n in proof['nodes'] if n['transfer']=='CALL'];require(len(calls)==2 and {n['cpu'] for n in calls}==({0x155,0x15c} if reuse else {0x15e}),'wrong root shared call site')
    for node in calls:
        require([a['delta'] for a in node['frameAccesses']]==[-1,-2] and [a['value'] for a in node['frameAccesses']]==[(node['cpu']+3)>>8,(node['cpu']+3)&255], 'missing/duplicated actual graph push')
        require({e['kind'] for e in node['edges']}=={'CALL','RESUME'},'omitted feasible invocation/return edge')
    for inv in proof['invocations']:
        require(inv['entry'] in node_by_id and inv['returnNode'] in node_by_id and inv['continuation'] in node_by_id and inv['returnCpu'] in ({0x158,0x15f} if reuse else {0x161}) and inv['byteAContract'],'unmatched producer invocation')
        require(node_by_id[inv['entry']]['source']==inv['target'] and node_by_id[inv['continuation']]['cpu']==inv['returnCpu'],'swapped physical target/continuation')
    for view in cap.views:
        req=cap.requests[view['tag']];require(req['completed'] and req['highfunction_available'] and not req['error'],'native request failed')
        require(req['entry']==view['view']['entry'],'wrong requested native Function')
        if view['view']['byteAContract'] and proof['version'] in {'predicated-ordinary-graph-2','predicated-ordinary-graph-3','predicated-ordinary-graph-4'}:
            expected=view['view']['inputBytes'];parameters=req.get('parameters',[])
            require(len(parameters)==len(expected),'native live-in parameter count differs')
            for parameter,offset in zip(parameters,expected):
                storage=parameter['storage'];require(len(storage)==1 and storage[0]['space']=='register' and storage[0]['offset']==offset and storage[0]['size']==1,'native argument storage differs')
        require(any(p.get('parent')==req['owner_java_pid'] and p.get('binary_sha256')==base.NATIVE for p in req['processes_after']),'wrong actual companion')
        # CALL operands in the native debug stream use overlay transport widths; compare the full replay manually below.
        debug=cap.root/f"{cap.label}-{view['tag']}-debug.xml";require(sha(debug)==req['debug']['sha256'],'changed native debug')
        base.debug_identity(debug,cap.requested[view['tag']],req['entry'])
    return node_by_id

def run_stage(cap,image,invert=False):
    validate_capture(cap,image);counts=collections.Counter();digest=hashlib.sha256()
    for b in range(256):
        bank=((b&1)^int(invert))+1;value=0x31 if bank==1 else (image[0x8001]+1)&255
        for frame in FRAMES:
            raw=Machine(image,b,frame);raw.raw(cap)
            emitted=Machine(image,b,frame);emitted.emitted(cap)
            require(raw.reg==emitted.reg and raw.mem==emitted.mem and raw.events==emitted.events,'raw/emitted frame/register/effect mismatch B='+str(b))
            require(raw.outputs=={0xc060:value} and raw.bank==bank,'wrong branch result/bank B='+str(b))
            require(raw.calls==[(0x15e,bank,0x4000,0x161)],'wrong input-to-physical CALL/return association')
            require((bank,0x4000) in raw.fetches and all(x[0] in {0,bank} for x in raw.fetches),'competing physical bytes mixed')
            require(raw.register(10,2)==frame[0]+2 and raw.register(8,2)==frame[1],'wrong outer SP/PC')
            native=Machine(image,b,frame);native.high(cap)
            require(native.outputs=={0xc060:value} and native.bank==bank,'wrong native call result B='+str(b))
            require(native.events==[('mapper',0x2000,bank),('call',bank,0x4000),('write',0xc060,value)],'native call/effect order differs')
        counts[(bank,value)]+=1;digest.update(f'{b}:{bank}:{value};'.encode())
    return dict(status='PASS',B_inputs=256,frame_register_witnesses=len(FRAMES),cases=256*len(FRAMES),outputs=[dict(bank=k[0],C060=k[1],count=v) for k,v in sorted(counts.items())],digest=digest.hexdigest())

def run_reuse(cap,image):
    validate_capture(cap,image,True)
    require(len({v['view']['entry'] for v in cap.views if v['tag']!='root'})==2,'repeated invocation entries collapsed')
    require(all(i['inputBytes']==[3] for i in cap.proof['invocations']),'callee input is not actual current B')
    digest=hashlib.sha256()
    for b in range(256):
        expected={0xc061:(b+1)&255,0xc062:(b+2)&255}
        for frame in FRAMES:
            raw=Machine(image,b,frame);raw.raw(cap);emitted=Machine(image,b,frame);emitted.emitted(cap)
            require(raw.reg==emitted.reg and raw.mem==emitted.mem and raw.events==emitted.events,'repeated invocation raw/emitted frame or definition mismatch')
            require(raw.outputs==expected and raw.calls==[(0x155,1,0x4000,0x158),(0x15c,1,0x4000,0x15f)],'wrong current input/continuation result')
            require(raw.register(10,2)==frame[0]+2 and raw.register(8,2)==frame[1] and raw.reg[3]==((b+1)&255),'wrong final caller frame/register state')
            native=Machine(image,b,frame);native.high(cap)
            require(native.outputs==expected,'native repeated invocation froze prior definition')
            require(native.events==[('mapper',0x2000,1),('call',1,0x4000),('write',0xc061,expected[0xc061]),('call',1,0x4000),('write',0xc062,expected[0xc062])],'native repeated call/effect order')
            require(len({c[2] for c in native.calls})==2,'native continuation contexts reused one Function identity')
        digest.update(f'{b}:{expected[0xc061]}:{expected[0xc062]};'.encode())
    return dict(status='PASS',B_inputs=256,frame_register_witnesses=3,cases=768,digest=digest.hexdigest(),wrap={'B254':[255,0],'B255':[0,1]})

def reuse_mutants(cap,image):
    results=[]
    changed=copy.deepcopy(cap);inv=changed.proof['invocations'];inv[0]['continuation']=inv[1]['continuation']
    try:validate_capture(changed,image,True)
    except Refusal as e:results.append(dict(name='swapped-continuation',status='REJECTED',reason=str(e)))
    else:raise Refusal('swapped continuation escaped')
    for b in [0,254,255]:
        machine=Machine(image,b);machine.high(cap)
        reused=dict(machine.outputs);reused[0xc062]=reused[0xc061]
        require(reused!={0xc061:(b+1)&255,0xc062:(b+2)&255},'reused first result escaped')
    results.append(dict(name='reused-first-result',status='REJECTED',scope='synthetic output mutant'))
    return results

def mutants(cap,image):
    results=[]
    def reject(name,action):
        try:action()
        except Refusal as e:results.append(dict(name=name,status='REJECTED',reason=str(e)))
        else:raise Refusal('negative escaped '+name)
    for name in ['missing-push','duplicated-push','swapped-physical-call','omitted-feasible-edge']:
        m=copy.deepcopy(cap);ops=m.requested['root']
        if name=='missing-push':
            op=next(o for o in ops if o['mnemonic']=='STORE');op.update(mnemonic='COPY',output=dict(space='unique',offset=0x7fff0000,size=1,constant=False,address=False,register=False,id=999999),inputs=[dict(space='const',offset=0,size=1,constant=True,address=False,register=False,id=999998)])
        elif name=='duplicated-push':
            # Keep local edge positions: replace a generated no-effect marker with a duplicate store.
            at=next(i for i,o in enumerate(ops) if o['mnemonic']=='STORE');slot=next(i for i in range(at+1,len(ops)) if ops[i]['mnemonic']=='COPY' and ops[i]['inputs'][0]['constant'] and ops[i]['inputs'][0]['offset']==0)
            ops[slot]=copy.deepcopy(ops[at])
        elif name=='swapped-physical-call':
            calls=[o for o in ops if o['mnemonic']=='CALL'];calls[0]['inputs'][0],calls[1]['inputs'][0]=calls[1]['inputs'][0],calls[0]['inputs'][0]
        else:
            op=next(o for o in ops if o['mnemonic']=='CBRANCH');op['inputs'][1]=dict(space='const',offset=0,size=1,constant=True,address=False,register=False,id=99999)
        def check():
            for b in [0,1]:
                raw=Machine(image,b);raw.raw(cap);machine=Machine(image,b);machine.emitted(m)
                require(machine.reg==raw.reg and machine.events==raw.events,'mutated control/frame graph differs')
        reject(name,check)
    for name in ['cpu-PC-only-identity','missing-return-edge']:
        m=copy.deepcopy(cap)
        if name=='cpu-PC-only-identity':
            for n in m.proof['nodes']:n['id']=str(n['cpu'])
        else:next(n for n in m.proof['nodes'] if n['transfer']=='CALL')['edges'].pop()
        reject(name,lambda m=m:validate_capture(m,image))
    return results

def checker_controls(cap,image):
    from types import SimpleNamespace
    def v(id,space,offset,size=1):return dict(id=id,space=space,offset=offset,size=size,constant=space=='const',register=space=='register',address=space=='ram')
    def op(name,inputs,output=None):return dict(mnemonic=name,inputs=inputs,**({'output':output} if output else {}))
    b=v(1,'register',3);bit=v(2,'unique',10);even=v(10,'unique',20);odd=v(20,'unique',30);phi=v(30,'unique',40)
    blocks=[dict(index=0,**{'in':[],'out':[1,2]},ops=[op('COPY',[v(11,'const',0x31)],even),op('COPY',[v(21,'const',0xa7)],odd),op('INT_AND',[b,v(3,'const',1)],bit),op('CBRANCH',[v(4,'const',0),bit])]),
            dict(index=1,**{'in':[0],'out':[3]},ops=[]),
            dict(index=2,**{'in':[0],'out':[3]},ops=[]),
            dict(index=3,**{'in':[2,1],'out':[]},ops=[op('MULTIEQUAL',[odd,even],phi),op('COPY',[phi],v(31,'ram',0xc060)),op('RETURN',[v(32,'const',0)])])]
    synthetic=SimpleNamespace(high={'root':blocks},requests={'root':{}})
    for n in [0,1]:
        machine=Machine(image,n);machine.high(synthetic);require(machine.outputs=={0xc060:0x31 if n==0 else 0xa7},'phi did not follow actual predecessor')
    reversed_phi=copy.deepcopy(synthetic);reversed_phi.high['root'][3]['in']=[1,2]
    wrong=Machine(image,0);wrong.high(reversed_phi)
    require(wrong.outputs!={0xc060:0x31},'swapped PHI predecessor escaped')
    require(Machine(image,0).get(v(99,'ram',0xc010),{}, {}) is None,'unknown RAM was fabricated')
    child=next(view for view in cap.views if view['tag']!='root');mutant=copy.deepcopy(cap)
    copied=next(o for block in mutant.high[child['tag']] for o in block['ops'] if o['mnemonic']=='COPY')
    copied['inputs']=[v(100000,'register',3)]
    rejected=False
    for n in [0,1]:
        try:Machine(image,n).high(mutant)
        except Insufficient:rejected=True
    require(rejected,'undeclared child B input was silently supplied')
    return {'phi_predecessor':'PASS','swapped_phi_predecessor':'REJECTED','unknown_RAM':'UNKNOWN_PRESERVED','undeclared_child_input':'ORACLE_INSUFFICIENT',
            'scope':'synthetic checker controls, separate from actual captured native runs'}

def persistence_check(root,receipts,image,reuse=False):
    identities=[];registrations=[];stages={}
    for label in ['saved','reopened']:
        command=read(receipts/label/'result.json');argv=command['argv']
        require(command['exit_code']==0 and command['completion_marker'] and '-process' in argv and '-noanalysis' in argv and '-import' not in argv,'invalid persistent process')
        require(('-readOnly' in argv)==(label=='reopened'),'incorrect persistent mode')
        identity=read(root/f'{label}-before-identity.json');require(identity==read(root/f'{label}-after-identity.json'),'native read changed live Program identity')
        raw=(root/f'{label}-registration.json').read_bytes();require(raw==(root/f'{label}-registration-after.json').read_bytes(),'native read changed registration')
        record=json.loads(raw);require(record['programId']==identity['program_id'],'foreign stored Program authority')
        require(record['proof']==read(root/('original-proof.json' if reuse else 'refreshed-proof.json'))==read(root/f'{label}-proof.json'),'stored graph changed across process')
        require(identity['current_image_sha256']==hashlib.sha256(image).hexdigest(),'different reopened image')
        capture=Capture(root,label)
        for view in capture.views:
            tag=view['tag'];require(capture.requested[tag]==read(root/f"{'original' if reuse else 'refreshed'}-{tag}-requested.json"),'persistent emitted graph changed')
        stages[label]=run_reuse(capture,image) if reuse else run_stage(capture,image);identities.append(identity);registrations.append(raw)
    require(registrations[0]==registrations[1],'stored registration changed after reopen')
    for key in ['program_id','domain_file','domain_file_id','original_image_sha256','current_image_sha256','provider_location','provider_jar_sha256','views']:
        require(identities[0][key]==identities[1][key],'persistent identity mismatch '+key)
    require(identities[0]['java_pid']!=identities[1]['java_pid'] and identities[0]['java_start']!=identities[1]['java_start'],'not separate Java processes')
    require(read(receipts/'saved/result.json')['end_utc']<read(receipts/'reopened/result.json')['start_utc'],'reopen before save process exit')
    require('Save succeeded for processed file:' in (receipts/'saved/output.log').read_text(),'actual save missing')
    return dict(status='PASS',registration_sha256=hashlib.sha256(registrations[0]).hexdigest(),identities=identities,stages=stages,
                note='Stored graph and Function identities compare exactly; live Java/object/modification identities remain separately reported.')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['capture','fixture','extension','out']:parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--invert',action='store_true')
    parser.add_argument('--receipts',type=Path)
    parser.add_argument('--reuse',action='store_true')
    args=parser.parse_args()
    try:
        image=args.fixture.read_bytes();require(len(image)==0x10000 and image[0x147]==0x19,'wrong MBC5 fixture')
        with zipfile.ZipFile(args.extension) as z:
            jar=next(n for n in z.namelist() if re.search(r'/lib/GhidraBoy-[^/]+\.jar$',n));jar_hash=hashlib.sha256(z.read(jar)).hexdigest()
        identity=read(args.capture/'original-before-identity.json');require(identity['original_image_sha256']==sha(args.fixture) and identity['provider_jar_sha256']==jar_hash,'wrong installed input/artifact')
        original=Capture(args.capture,'original')
        result=dict(status='PASS',fixture_sha256=sha(args.fixture),extension_sha256=sha(args.extension),provider_jar_sha256=jar_hash,checker_sha256=sha(Path(__file__)))
        if args.reuse:
            result['reuse']=run_reuse(original,image);result['negative_controls']=reuse_mutants(original,image)
            if args.receipts:result['persistence']=persistence_check(args.capture,args.receipts,image,True)
        else:
            result.update(original=run_stage(original,image,args.invert),negative_controls=mutants(original,image),checker_controls=checker_controls(original,image))
            mutation=read(args.capture/'mutation.json');require(mutation['file_offsets']==[0x8001] and mutation['old']==0xa6 and mutation['new']==0xb6 and mutation['registration_retained'],'wrong consumed callee mutation')
            stale=read(args.capture/'stale-root-request.json');require(not stale['completed'] and not stale['highfunction_available'] and 'Stale predicated graph' in stale['error'],'stale graph produced native result')
            changed=bytearray(image);changed[0x8001]=0xb6;result['refreshed']=run_stage(Capture(args.capture,'refreshed'),changed,args.invert)
            if args.receipts:result['persistence']=persistence_check(args.capture,args.receipts,changed)
    except Insufficient as e:result=dict(status='ORACLE_INSUFFICIENT',reason=str(e))
    except (Refusal,KeyError,ValueError) as e:result=dict(status='FAIL',reason=str(e))
    args.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result));raise SystemExit(0 if result['status']=='PASS' else 1)
if __name__=='__main__':main()
