#!/usr/bin/env python3
"""Conditional raw/emitted/native replay using the maintained p-code evaluator.
No provider evaluator or trusted target/result enters architectural execution.
"""
import argparse,json,collections
from pathlib import Path
import check_predicated_calls as core

class Machine(core.Machine):
    GLOBAL_RANGE=range(0xc000,0xffff)
    OUTPUT_RANGE=range(0xc000,0xffff)
    BYTE_A_CONTRACT=False
    def __init__(self,cap,image,a,u,flags,sp,pattern,matched):
        super().__init__(image,pattern[0],(sp,0x19a,flags,pattern[1],pattern[2],pattern[3]))
        request=cap.proof['callSite'];self.ROOT_CPU=int(request['site'].split('::')[-1],16)
        self.set_register(1,1,a);self.set_register(8,2,self.ROOT_CPU)
        self.bank=request['mapper']['low'];self.low=self.bank;self.high_bit=request['mapper']['high']
        self.conditional_site=True;self.matched_only=matched
        self.spaces={v&0xffffffff:k for k,v in core.read(cap.root/f'{cap.label}-before-identity.json')['spaces'].items()}
        self.initial_allowed=set();self.written=set();self.physical_reads=[];self.boundary_states=[];self.bus_reads=[];self.mapper_epoch=0
        for delta in request['incomingStackBytes']:self.initial_allowed.add(sp+delta)
        for at in list(self.mem):
            if at not in self.initial_allowed:del self.mem[at]
        for n in cap.proof['nodes']:
            for access in n['memoryAccesses']:
                at=int(access['storage'].split(':')[-1],16);self.mem.setdefault(at,0xa5^(at&255))
        for cell in cap.proof['memory']['inputs']:
            at=int(cell['storage'].split(':')[-1],16);self.initial_allowed.add(at);self.mem[at]=u
        self.mem[request['shadowCpu']]=request['shadowValue']
        self.initial_allowed.add(request['shadowCpu'])
        if matched:
            b=next(b for b in cap.proof['boundaries'] if b['kind']=='MATCHED_CALL_COMPLETION');self.emitted_return=b['cpu']
    def record_transfer(self,kind,target,source_cpu,source_bank):
        # CALL/BRANCH p-code carries intrinsic control. Its hardware PC is the
        # actual transfer operand, even when SLEIGH's PC temporary still holds Q.
        registers=dict(self.reg);registers[8]=target&255;registers[9]=target>>8
        self.boundary_states.append(dict(kind=kind,source=f'{source_cpu:04x}' if source_bank==0 else f'rom{source_bank}::{source_cpu:04x}',cpu=target,sp=self.register(10,2)-self.root_sp,reg=registers,mem=dict(self.mem),low=self.low,high=self.high_bit))
    @staticmethod
    def canonical(cpu):return cpu-0x2000 if 0xe000<=cpu<=0xefff else cpu
    def load(self,cpu,size,trace=True):
        cpu=self.canonical(cpu)
        for at in range(cpu,cpu+size):
            if at>=0x8000:core.require(at in self.initial_allowed or at in self.written,'undeclared entry memory read '+hex(at))
            elif trace:
                bank=0 if at<0x4000 else self.bank
                core.require(bank is not None and 0<=bank<len(self.image)//0x4000,'physical read outside image')
                self.physical_reads.append((bank,at))
                self.bus_reads.append((self.mapper_epoch,bank,at,self.image[bank*0x4000+(at&0x3fff)]))
        return super().load(cpu,size,trace)
    def store(self,cpu,size,value,trace=True):
        cpu=self.canonical(cpu)
        if 0x2000<=cpu<0x4000:
            core.require(size==1,'wide mapper write unsupported by oracle')
            if cpu<0x3000:self.low=value
            else:self.high_bit=value&1
            banks=len(self.image)//0x4000;core.require(banks&(banks-1)==0,'non-power-of-two fixture geometry')
            self.bank=((self.high_bit<<8)|self.low)&(banks-1);self.events.append(('mapper',cpu,value));self.mapper_epoch+=1;return
        core.require(0xc000<=cpu and cpu+size<=0xd000 or 0xff80<=cpu and cpu+size<=0xffff,'unsupported actual write storage')
        self.written.update(range(cpu,cpu+size));return super().store(cpu,size,value,trace)
    def get(self,v,env=None,entry=None):
        core.validate_storage(v)
        if v['constant'] or env is not None and v['id'] in env:return super().get(v,env,entry)
        if v['space'].startswith('rom'):
            bank=int(v['space'][3:]);core.require(bank==self.bank,'physical ROM operand disagrees with executed mapper');return self.load(v['offset'],v['size'])
        if v['space']=='ram':return self.load(v['offset'],v['size'])
        return super().get(v,env,entry)
    def ordinary(self,op,env=None,entry=None):
        for v in [op.get('output'),*op['inputs']]:core.validate_storage(v)
        code=op['mnemonic'];nodes=op['inputs']
        if env is not None and id(op) in self.forwarded_copies and code=='COPY':
            out=op['output'];core.require(core.same_storage(out,nodes[0]),'forwarding storage differs')
            at=self.canonical(out['offset']);value=env.get(nodes[0]['id'],self.mem.get(at))
            core.supported(value is not None,'uncaptured incoming storage preservation')
            self.put(out,value,env,write=value!=self.mem.get(at));return
        if code=='CALLOTHER':
            core.require(op.get('userop_name') in {'gb_direct_write8','gb_cartridge_write8'},'foreign native userop')
            core.require(len(nodes)==3 and nodes[1]['size']==2 and nodes[2]['size']==1,'unexpected bus effect widths')
            cpu=self.get(nodes[1],env,entry)
            # Raw direct bus writes lower to the cartridge userop for mapper ports.
            if env is not None and cpu<0x8000:core.require(op['userop_name']=='gb_cartridge_write8','wrong actual bus userop')
            self.store(cpu,nodes[2]['size'],self.get(nodes[2],env,entry));return
        if code in {'LOAD','STORE'}:
            space=self.spaces.get(self.get(nodes[0],env,entry)&0xffffffff)
            core.require(space is not None,'unbound actual address-space operand')
            if space.startswith('rom'):core.require(int(space[3:])==self.bank,'wrong physical LOAD bank')
            else:core.require(space=='ram','unsupported actual memory space')
        return super().ordinary(op,env,entry)

def validate_mapper_observation(raw,emitted,native):
    # Selector latches are hardware state even when unconnected address lines
    # make two values resolve to the same physical bank on this fixture board.
    state=lambda m:(m.low,m.high_bit,m.bank)
    core.require(state(raw)==state(emitted)==state(native),'mapper latch restoration differs')
    mapper=lambda m:[e for e in m.events if e[0]=='mapper']
    core.require(mapper(raw)==mapper(emitted)==mapper(native),'ordered mapper bus effects differ')
    # Native may fold immutable reads and eliminate disjoint local frame storage.
    # Every retained physical read must still occur in its source mapper epoch.
    core.require(not collections.Counter(native.bus_reads)-collections.Counter(raw.bus_reads),
                 'native physical read moved across mapper effect or selected wrong bytes')
    def writes(m):
        epoch=0;result=collections.Counter()
        for event in m.events:
            if event[0]=='mapper':epoch+=1
            elif event[0]=='write':result[(epoch,*event[1:])]+=1
        return result
    core.require(not writes(native)-writes(raw),'native write moved across mapper effect or extra actual write')

def evaluate(origin,initial,names,memo):
    key=id(origin)
    if key in memo:return memo[key]
    if origin['kind']=='CONSTANT':value=origin['constant']
    elif origin['kind']=='INPUT':
        text=origin['input']
        if ':entry-register-byte@' in text:value=initial.register(int(text.rsplit('@',1)[1]))
        elif ':incoming-frame-memory@' in text:value=initial.mem[initial.root_sp+int(text.rsplit('@',1)[1])]
        elif ':entry-memory:' in text:value=initial.mem[int(text.rsplit(':',1)[1].split('@')[0],16)]
        else:raise core.Refusal('foreign/unrecognized origin input '+text)
    else:
        values=[evaluate(v,initial,names,memo) for v in origin['inputs']]
        if origin['opcode']==-1:
            rows=[r for r in origin['table'] if r['keys']==values];core.require(len(rows)==1,'undefined immutable origin row');value=rows[0]['value']
        else:
            core.supported(origin['opcode'] in names,'unobserved origin opcode')
            value=core.arithmetic(names[origin['opcode']],[dict(size=v['width']) for v in origin['inputs']],values,origin['width'])
    memo[key]=value;return value

def validate_initial(proof):
    first=proof['boundaries'][0];core.require(first['kind']=='CALL_SITE_ENTRY' and first['spDelta']==0,'invented entry frame')
    regs={b['offset']:b['origin'] for b in first['registers']}
    for offset in [1,2,3,4,5,6,7,10,11]:
        o=regs[offset];core.require(o['kind']=='INPUT' and o['width']==1 and o['input'].endswith(':entry-register-byte@'+str(offset)),'entry register was concretized or replaced')
    core.require({b['delta'] for b in first['stack']}==set(proof['callSite']['incomingStackBytes']),'invented incoming stack bytes')
    for cell in proof['memory']['inputs']:
        fact=next(f for f in first['memory'] if f['physical']==cell['physical'])
        if cell['cpu']!=proof['callSite']['shadowCpu']:core.require(fact['value']['kind']=='INPUT','unknown RAM input was concretized')

def validate_boundary(boundary,observed,initial,names):
    memo={}
    if not all(evaluate(t['origin'],initial,names,memo)==t['value'] for t in boundary.get('predicate',{}).get('terms',[])):return False
    core.require(boundary['spDelta']==observed['sp'],'boundary SP differs from raw execution')
    if boundary.get('cpu') is not None:core.require(boundary['cpu']==observed['cpu'],'boundary CPU differs')
    core.require(boundary['mapper']['low']==observed['low'] and boundary['mapper']['high']==observed['high'],'boundary mapper differs')
    for b in boundary['registers']:
        core.require(evaluate(b['origin'],initial,names,memo)==observed['reg'][b['offset']],'boundary register origin differs at '+str(b['offset']))
    for b in boundary['stack']:
        core.require(evaluate(b['value'],initial,names,memo)==observed['mem'][initial.root_sp+b['delta']],'boundary residual stack origin differs')
    for fact in boundary['memory']:
        physical=fact['physical'];at=(0xff80 if physical['region']=='HRAM' else 0xc000)+physical['offset']
        core.require(evaluate(fact['value'],initial,names,memo)==observed['mem'][at],'boundary memory origin differs at '+hex(at))
    return True

def validate_post_link(proof):
    completed=next(b for b in proof['boundaries'] if b['kind']=='MATCHED_CALL_COMPLETION')
    post=next(b for b in proof['boundaries'] if b['kind']=='ANALYSIS_BOUNDARY')
    node=next(n for n in proof['nodes'] if n['id']==post['node']);reads=[a for a in node['memoryAccesses'] if a['kind']=='READ']
    core.require(len(reads)==1,'post-load relation lacks a unique actual memory read')
    memory=next(f for f in completed['memory'] if f['physical']==reads[0]['physical'])
    a=next(b for b in post['registers'] if b['offset']==1)
    core.require(a['origin']==reads[0]['value']==memory['value'],'post-load A is not linked to actual outgoing memory')
    entry=proof['boundaries'][0]
    for offset in range(2,8):
        original=next(b['origin'] for b in entry['registers'] if b['offset']==offset)
        core.require(next(b['origin'] for b in completed['registers'] if b['offset']==offset)==original,'private preserved register identity lost')
        core.require(next(b['origin'] for b in post['registers'] if b['offset']==offset)==original,'post-load preserved register identity lost')
    core.require(next(b['origin'] for b in post['registers'] if b['offset']==0)==next(b['origin'] for b in completed['registers'] if b['offset']==0),'post-load flags not linked')
    return post,node

def check(root,label='original',private=False,exhaust=True,delta=1,register_sweep=False):
    cap=core.Capture(root,label);image=(root/'fixture.gb').read_bytes();proof=cap.proof
    core.require(proof['version'] in {'conditional-call-site-1','conditional-call-site-2','conditional-call-site-3'} and proof['coverageComplete'] and not proof['frontier'],'incomplete conditional proof')
    validate_initial(proof)
    names={o['opcode']:o['mnemonic'] for ins in cap.raw.values() for o in ins['ops']};names.update({62:'PIECE',63:'SUBPIECE'})
    if private:validate_post_link(proof)
    complete=[b for b in proof['boundaries'] if b['kind']=='MATCHED_CALL_COMPLETION'];core.require(len(complete)==1,'ambiguous call completion')
    request=cap.requests['root'];core.require(request['completed'] and request['highfunction_available'],'actual native unavailable')
    native_hashes={'c5e9775345e6841c717995a85f0bc33a972acc84b0990ad0d6fbccd6db0ae77d','4a97ff9a3dbac5757c7240a664571e82345e4abc4f67cd211cd9d402abe4543d'}
    core.require(any(core.actual_native_process(p,request['owner_java_pid'],native_hashes) for p in request['processes_after']),'unverified actual native')
    spaces=core.read(root/f'{label}-before-identity.json')['spaces'];debug=root/f'{label}-root-debug.xml'
    core.require(core.sha(debug)==request['debug']['sha256'],'changed debug artifact');core.base.debug_identity(debug,cap.requested['root'],request['entry'],'gb_analysis_entry_v1',spaces)
    return replay(cap,image,private,exhaust,delta,register_sweep)


def replay(cap,image,private=False,exhaust=True,delta=1,register_sweep=False):
    """Shared semantic kernel; callers separately bind their actual native consumer evidence."""
    root=cap.root;label=cap.label;proof=cap.proof
    core.require(proof['version'] in {'conditional-call-site-1','conditional-call-site-2','conditional-call-site-3'} and proof['coverageComplete'] and not proof['frontier'],'incomplete conditional proof')
    validate_initial(proof)
    names={o['opcode']:o['mnemonic'] for ins in cap.raw.values() for o in ins['ops']};names.update({62:'PIECE',63:'SUBPIECE'})
    if private:validate_post_link(proof)
    core.require(len([b for b in proof["boundaries"] if b["kind"]=="MATCHED_CALL_COMPLETION"])==1,"ambiguous call completion")
    frames=[proof['callSite']['footprint']['stackMin'],0xc200,proof['callSite']['footprint']['stackMax']];patterns=[(0x12,0x34,0x56ab,0x89cd),(0xab,0xff,0x00ff,0xff00),(0xff,0,0xab55,0x1020)]
    rows=0
    contexts=[(index,sp,pattern) for index,sp in enumerate(frames) for pattern in (patterns+[(0,0,0,0),(255,255,65535,65535),(0x55,0xaa,0x8000,0x7fff),(0x80,0x7f,0xff00,0x00ff)] if register_sweep else [patterns[index]])]
    for index,sp,pattern in contexts:
        for flags in range(0,256,16):
            for u in range(256) if exhaust else [0,1,254,255]:
                a=[0,0x53,255][index] if private else u
                raw=Machine(cap,image,a,u,flags,sp,pattern,private);emitted=Machine(cap,image,a,u,flags,sp,pattern,private);native=Machine(cap,image,a,u,flags,sp,pattern,private)
                initial=Machine(cap,image,a,u,flags,sp,pattern,private)
                raw.raw(cap);emitted.emitted(cap);result=native.high(cap)
                for boundary in proof['boundaries'][1:]:
                    if boundary['kind']=='ANALYSIS_BOUNDARY':continue
                    source=next(n['source'] for n in proof['nodes'] if n['id']==boundary['node'])
                    memo={}
                    if not all(evaluate(t['origin'],initial,names,memo)==t['value'] for t in boundary.get('predicate',{}).get('terms',[])):continue
                    observed=[b for b in raw.boundary_states if b['source']==source and b['sp']==boundary['spDelta']]
                    core.require(len(observed)==1,'boundary lacks unique raw transfer witness')
                    validate_boundary(boundary,observed[0],initial,names)
                core.require(raw.reg==emitted.reg,'raw/emitted registers differ')
                effects=lambda m:[e for e in m.events if e[0] in {'read','write','mapper'}]
                core.require(effects(raw)==effects(emitted),'raw/emitted ordered memory differs')
                validate_mapper_observation(raw,emitted,native)
                core.require((raw.low,raw.high_bit)==(proof['callSite']['mapper']['low'],proof['callSite']['mapper']['high']),'mapper restoration differs')
                core.require(raw.physical_reads==emitted.physical_reads,'physical immutable read ordering differs')
                core.require(raw.mem==emitted.mem,'residual architectural stack/scratch differs')
                allowed=collections.Counter(e for e in raw.events if e[0]=='write');actual=collections.Counter(e for e in native.events if e[0]=='write')
                core.require(not actual-allowed,'extra native actual write '+str(actual-allowed))
                # Native frame locals may be optimized; the architectural ledger above
                # retains every byte. The required continuation is physically disjoint.
                for _,at,_ in allowed:
                    if not sp+proof['callSite']['footprint']['minDelta']<=at<sp:
                        core.require(raw.mem[at]==native.mem.get(at),'missing native scratch/data effect '+hex(at))
                core.require(result==raw.register(6,2),'native observed HL result differs')
                if private:
                    post=next(b for b in proof['boundaries'] if b['kind']=='ANALYSIS_BOUNDARY')
                    node=next(n for n in proof['nodes'] if n['id']==post['node']);ins=cap.raw[node['source']]
                    bank=node['fetch'][0]['physical']['bank'];offset=bank*0x4000+(node['cpu']&0x3fff)
                    core.require(bytes.fromhex(ins['bytes'])==image[offset:offset+len(ins['bytes'])//2],'continuation source bytes differ')
                    core.require(raw.register(1)==0 and raw.register(0)==0x80,'private matched A/F relation differs')
                    for op in ins['ops']:raw.ordinary(op)
                    core.require(raw.register(1)==u and raw.register(0)==0x80 and raw.register(10,2)==sp,'linked continuation load/flags/SP differ')
                    raw.set_register(8,2,(node['cpu']+len(ins['bytes'])//2)&65535)
                    observed=dict(cpu=raw.register(8,2),sp=raw.register(10,2)-sp,reg=raw.reg,mem=raw.mem,low=raw.low,high=raw.high_bit)
                    validate_boundary(post,observed,initial,names)
                else:
                    expected=(u+delta)&255
                    core.require(raw.mem[0xca20]==expected and raw.register(1)==expected,'nonconstant callee result differs')
                    # Independent SM83 INC/DEC specification: Z from the byte result,
                    # N for DEC, H from nibble carry/borrow; preceding ADC A,0 clears C.
                    expected_f=(0x80 if expected==0 else 0)|(0x40 if delta<0 else 0)|(0x20 if (u&15)==(0 if delta<0 else 15) else 0)
                    core.require(raw.register(0)==expected_f,'callee INC/DEC hardware flag relation differs')
                    if expected:core.require(raw.mem[0xca21]==expected,'returned flag/register continuation differs')
                rows+=1
    return dict(status='PASS',cases=rows,frames=frames,flags=list(range(0,256,16)),register_patterns=sorted(set(pattern for _,_,pattern in contexts)),independent_register_sweep=register_sweep,nodes=len(proof['nodes']),proof_bytes=(root/f'{label}-proof.json').stat().st_size)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('--private',action='store_true');p.add_argument('--register-sweep',action='store_true');p.add_argument('--quick',action='store_true');p.add_argument('--label',default='original');p.add_argument('--delta',type=int,choices=[-1,1],default=1);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:r=check(a.root,a.label,a.private,not a.quick,a.delta,a.register_sweep)
    except Exception as e:a.output.write_text(json.dumps(dict(status='FAIL',type=type(e).__name__,error=str(e)),indent=2));raise
    a.output.write_text(json.dumps(r,indent=2)+'\n');print('PASS',r['cases'])
