#!/usr/bin/env python3
"""W4 extension of the maintained p-code/HighFunction oracle; actual spaces bind runtime RAM."""
import argparse,copy,json
from pathlib import Path
import check_predicated_calls as core
from make_w4_fixtures import A,I1,I2
require,supported=core.require,core.supported

class Machine(core.Machine):
    OUTPUT_RANGE=range(0xc060,0xc075)
    GLOBAL_RANGE=OUTPUT_RANGE
    BYTE_A_CONTRACT=False
    def __init__(self,image,u,frame,bindings,code=A,cpu=0x150):
        super().__init__(image,0x27,frame)
        self.ROOT_CPU=cpu;self.code=bytes.fromhex(code);self.spaces={x['id']:x for x in bindings['spaces']}
        ram=[x for x in bindings['spaces'] if x['name']=='ram'];require(len(ram)==1 and ram[0]['addressable_unit']==1,'independent native RAM space missing')
        self.ram_id=ram[0]['id'];self.mem[0xc060]=u
        self.input_reads=[]
        self.distinct=bindings.get("negative_storage")
    def load(self,cpu,size,trace=True):
        cpu=cpu-0x2000 if cpu is not None and 0xe000<=cpu<=0xefff else cpu
        if cpu==0xc060:self.input_reads.append((cpu,size))
        return super().load(cpu,size,trace)
    def store(self,cpu,size,value,trace=True):
        cpu=cpu-0x2000 if cpu is not None and 0xe000<=cpu<=0xefff else cpu
        return super().store(cpu,size,value,trace)
    def get(self,v,env=None,entry=None):
        core.validate_storage(v)
        if self.distinct and v['space']==self.distinct['space']:
            require(v['offset']==self.distinct['offset'] and v['size']==1,'wrong distinct storage slice');return self.distinct['value']
        if not v['constant'] and v['space'] not in {'ram','unique','register'}:
            raise core.Refusal('wrong actual value storage '+v['space'])
        return super().get(v,env,entry)
    def put(self,v,value,env=None,write=True):
        if v['space']=='unique':
            v=dict(v);v.pop('high_global',None) # SSA symbol association is not a memory write.
        g=v.get('high_global')
        if g is not None:require(g['space']==v['space']=='ram' and g['offset']==v['offset'] and g['size']==v['size'],'wrong actual HighGlobal binding')
        return super().put(v,value,env,write)
    def ordinary(self,op,env=None,entry=None):
        code=op['mnemonic'];nodes=op['inputs']
        if code in {'LOAD','STORE'}:
            require(nodes[0]['constant'] and nodes[0]['offset']==self.ram_id,'wrong actual LOAD/STORE address space')
            require(nodes[1]['size']==2,'widened actual CPU memory pointer')
        if code=='CALLOTHER' and op.get('userop_name')=='gb_direct_write8':
            args=[self.get(v,env,entry) for v in nodes];cpu,value=args[1:]
            require(nodes[1]['size']==2 and nodes[2]['size']==1,'wrong raw bus access width')
            require(cpu in {0xc070,0xc071,0xc074,0xe060},'unobserved bus destination');self.store(cpu,1,value);return
        return super().ordinary(op,env,entry)
    def raw(self,cap):
        # Only fetch selection differs from the retained oracle. All operations use its semantics.
        cpu=self.ROOT_CPU
        for ins in sorted(cap.raw.values(),key=lambda i:int(i['address'].split('::')[-1],16)):
            at=int(ins['address'].split('::')[-1],16);require(at==cpu,'wrong actual instruction boundary')
            octets=bytes.fromhex(ins['bytes']);require(octets==self.code[cpu-self.ROOT_CPU:cpu-self.ROOT_CPU+len(octets)],'raw bytes disagree with independently authored fixture')
            self.unique={}
            for op in ins['ops']:
                if op['mnemonic']=='RETURN':
                    destination=self.get(op['inputs'][0]);require(destination==self.outer_ret,'wrong raw real return');self.events.append(('return',destination,self.register(10,2)));return
                require(op['mnemonic'] not in {'BRANCH','CBRANCH','CALL','CALLIND','BRANCHIND'},'unexpected fixture control');self.ordinary(op)
            cpu+=len(octets)
        raise core.Refusal('raw artifact lacks actual RET')

def validate_bindings(bindings):
    cells={x['cpu']:x for x in bindings['cells']}
    d=bindings['negative_storage'];require(d['space']=='w4_distinct' and d['offset']==0xc060 and d['value']==0x9a and not d['mapped'],'distinct negative is not independently backed fixture storage')
    for cpu,offset in [(0xc060,0x60),(0xe060,0x60),(0xc070,0x70),(0xc071,0x71),(0xc074,0x74),(0xc200,0x200),(0xe201,0x201)]:
        require(cells[cpu]['space']=='ram' and cells[cpu]['physical']==[{'region':'WRAM','bank':0,'offset':offset}],'fixture topology disagrees with independent WRAM binding')

def evaluate(root,label,mode,fixture,bindings,cap=None):
    cap=cap if cap is not None else core.Capture(root,label);validate_bindings(bindings)
    for view in cap.views:
        req=cap.requests[view['tag']];require(req['completed'] and req['highfunction_available'] and not req['error'],'native request failed')
        require(req['entry']==view['view']['entry'],'wrong requested native Function')
        cap.verify_native(view['tag'])
    require(cap.proof['version'] in {'predicated-ordinary-graph-4','predicated-ordinary-graph-5'} and cap.proof['coverageComplete'] and not cap.proof['frontier'],'incomplete production proof')
    declaration=cap.proof['memory'];require(declaration is not None,'missing production memory authority')
    if mode=='A':
        require(len(declaration['inputs'])==1 and declaration['inputs'][0]['cpu']==0xc060 and declaration['inputs'][0]['storage']=='c060' and declaration['inputs'][0]['width']==1,'wrong production memory input binding')
    code=A if mode=='A' else I1 if mode=='I1' else I2;cpu=0x150 if mode=='A' else 0xc200
    frames=[(0xc800,0x190,0,0x53,0xa6,0xbeef),(0xc8fe,0x1234,0xa0,0x81,0x1234,0x7654),(0xcffc,0xffff,0xe0,0x19,0x8765,0xabcd)]
    cases=0
    def run(cap,u,frame):
        raw=Machine(fixture,u,frame,bindings,code,cpu);raw.raw(cap)
        emitted=Machine(fixture,u,frame,bindings,code,cpu);emitted.emitted(cap)
        native=Machine(fixture,u,frame,bindings,code,cpu);native.high(cap)
        require(raw.reg==emitted.reg,'raw/emitted register flag PC/SP mismatch')
        require(raw.mem==emitted.mem,'raw/emitted final physical memory mismatch')
        require(raw.events==emitted.events,'raw/emitted ordered byte/frame effects mismatch')
        expected={0xc070:u,0xc071:(u+1)&255,0xc060:(u+1)&255} if mode=='A' else {0xc074:0x31 if mode=='I1' else 0xa7}
        for at,value in expected.items():require(raw.mem.get(at)==emitted.mem.get(at)==native.mem.get(at)==value,'observable physical relation mismatch at '+hex(at))
        require(native.mem==raw.mem,'native collateral physical-memory corruption or missing effect')
        if mode=='A':require(native.input_reads,'native artifact lost actual runtime memory input dependency')
    for u in range(256) if mode=='A' else [0]:
        for frame in frames:
            for carry in [0,0x10]:
                frame=(*frame[:2],frame[2]|carry,*frame[3:]);run(cap,u,frame);cases+=1
    negatives={}
    if mode=='A':
        # Mutate actual requested/native artifacts. No metadata-only failure can discharge these controls.
        for target in ['requested','high']:
            original=getattr(cap,target)
            ops=original['root'] if target=='requested' else [op for block in original['root'] for op in block['ops']]
            for mutation in ['zero','wrong-space','wrong-alias','drop-store','fabricated-input']:
                changed=copy.deepcopy(cap);ops2=changed.requested['root'] if target=='requested' else [op for block in changed.high['root'] for op in block['ops']]
                applied=False
                for op in ops2:
                    if mutation in {'zero','wrong-space','fabricated-input'}:
                        for v in op['inputs']:
                            if v['space']=='ram' and v['offset']==0xc060:
                                if mutation=='wrong-space':v['space']=bindings['negative_storage']['space']
                                elif mutation=='fabricated-input':v.update(space='register',offset=3,register=True,address=False)
                                else:v.update(space='const',offset=0,constant=True,register=False,address=False)
                                applied=True
                    if op['mnemonic']=='STORE' and op['inputs'][1]['offset']==0xc060:
                        if mutation=='wrong-alias':op['inputs'][1]['offset']=0xc063;applied=True
                        if mutation=='drop-store':
                            value=op['inputs'][2];op.update(mnemonic='COPY',inputs=[value],output={'id':-71,'space':'unique','offset':0x70000000,'size':1,'constant':False});applied=True
                    if op.get('output') and op['output']['space']=='ram' and op['output']['offset']==0xc060 and mutation in {'wrong-alias','drop-store'}:
                        if mutation=='wrong-alias':
                            op['output']['offset']=0xc063
                            if op['output'].get('high_global'):op['output']['high_global']['offset']=0xc063
                        else:op['output']['space']='unique';op['output'].pop('high_global',None)
                        applied=True
                require(applied,'negative lacks a matching actual artifact operation '+target+'/'+mutation)
                failed=False
                for u in [0,1,0x53,0xff]:
                    try:run(changed,u,frames[0])
                    except core.Refusal:failed=True;break
                require(failed,'malformed actual artifact escaped '+target+'/'+mutation);negatives[target+'/'+mutation]='counterexample'
        changed=copy.deepcopy(cap);block=changed.high['root'][0]
        extra={'mnemonic':'STORE','inputs':[{'id':-10,'space':'const','offset':Machine(fixture,0,frames[0],bindings).ram_id,'size':4,'constant':True},{'id':-11,'space':'const','offset':0xc072,'size':2,'constant':True},{'id':-12,'space':'const','offset':0x99,'size':1,'constant':True}]}
        block['ops'].insert(0,extra)
        try:run(changed,0,frames[0]);raise AssertionError('collateral corruption escaped')
        except core.Refusal:negatives['high/collateral-store']='counterexample'
        changed=copy.deepcopy(cap);ops=changed.requested['root'];stores=[i for i,op in enumerate(ops) if op['mnemonic']=='STORE' and op['inputs'][1]['offset']==0xc060]
        require(len(stores)==1,'late-store control lacks unique actual echo effect')
        index=stores[0];store=copy.deepcopy(ops[index]);ops[index]={'mnemonic':'COPY','output':{'id':-1,'space':'unique','offset':0x70000000,'size':1,'constant':False},'inputs':[{'id':-2,'space':'const','offset':0,'size':1,'constant':True}]}
        witness=Machine(fixture,0,frames[0],bindings,code,cpu);witness.emitted(cap)
        order=[i for tag,i in witness.emitted_trace if tag=='root']
        require(index in order,'echo store not on actual emitted path')
        after=order[order.index(index)+1:]
        rereads=[i for i in after if any(v['space']=='ram' and v['offset']==0xc060 for v in ops[i]['inputs'])]
        require(rereads,'late-store control lacks still-dependent physical reread')
        # Follow actual local edges: operation array order is not execution order.
        after_read=after[after.index(rereads[0])+1:]
        later=next(i for i in after_read if ops[i]['mnemonic']=='COPY' and ops[i].get('output',{}).get('space')=='unique' and ops[i]['inputs'][0]['constant'])
        ops[later]=store
        try:run(changed,0,frames[0]);raise AssertionError('late-store mutation escaped')
        except core.Refusal:negatives['requested/late-store']='counterexample'
    return {'label':label,'mode':mode,'cases':cases,'negative_results':negatives,'nodes':len(cap.proof['nodes']),'origins':len(cap.proof['origins']),'proof_bytes':(root/f'{label}-proof.json').stat().st_size}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--label',required=True);p.add_argument('--mode',choices=['A','I1','I2'],required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--bindings',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=evaluate(a.root,a.label,a.mode,a.fixture.read_bytes(),core.read(a.bindings));a.output.write_text(json.dumps(result,indent=2)+'\n');print('W4_CHECK_PASS',json.dumps(result))
