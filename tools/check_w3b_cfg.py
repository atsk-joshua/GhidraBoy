#!/usr/bin/env python3
"""Independent new W3b capture checks, reusing the bounded architectural/p-code/HighFunction checker."""
import argparse, copy, hashlib, json, re
from pathlib import Path
import check_predicated_calls as core
require, supported, read = core.require, core.supported, core.read
class LoopMachine(core.Machine):
    OUTPUT_RANGE=range(0xc064,0xc066)
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.global_definitions=[]
    def put(self,v,value,env=None,write=True):
        begin=len(self.events);super().put(v,value,env,write)
        if env is not None and v.get('high_global',{}).get('offset')==0xc064:
            self.global_definitions.append((len(self.high_trace),v['id'],value))
            if v['space']!='ram':
                for i in range(begin,len(self.events)):
                    if self.events[i][0]=='write':self.events[i]=('definition',*self.events[i][1:])
class DomainMachine(core.Machine):
    ROOT_CPU=0x200
    OUTPUT_RANGE=range(0xc210,0xc211)
    GLOBAL_RANGE=set(range(0xc0fe,0xc102))|{0xc210}
    BYTE_A_CONTRACT=False
    def __init__(self,image,flags,word):
        super().__init__(image,0,(0xc100,word,flags,0,0,0x4100))
        self.set_register(1,1,2);self.set_register(8,2,0x200);self.bank=1

    def require_indirect_preservation(self,out,raw_ops,child_ops):
        supported(out['space']=='ram' and out['size']==1 and out['offset'] in range(0xc0fe,0xc102),'unobserved configured frame INDIRECT')
        # Prove disjointness against actual requested and HighFunction effects, per cell.
        for op in raw_ops+child_ops:
            supported(op['mnemonic']!='CALL','nested domain call not admitted by this checker')
            if op['mnemonic']=='STORE':supported(op['inputs'][1]['constant'] and op['inputs'][1]['offset']==0xc210 and op['inputs'][2]['size']==1,'callee may clobber preserved frame')
            if op['mnemonic']=='CALLOTHER':supported(op.get('userop_name') in {'gb_direct_write8','gb_cartridge_write8'} and op['inputs'][1]['constant'] and op['inputs'][1]['offset']==0x2000,'unproved configured callee device effect')
            result=op.get('output')
            if result is not None and result['space']=='ram':
                supported(result['offset']==0xc210 and result['size']==1,'callee may change actual frame/memory storage')
            if result is not None and result.get('high_global'):
                storage=result['high_global']
                supported(storage['space']=='ram' and storage['offset']==0xc210 and storage['size']==result['size']==1,'callee may change global outside its output cell')
    def native_arguments(self,cap,tag,parameters,declared):
        if len(parameters)==len(declared):return parameters
        # Exact state-entry initializes its inputs. Ghidra can retain unused register actuals
        # on a caller before separately recovering the callee's empty input list.
        supported(not declared and len(cap.high[tag])==1,'unexplained native argument/prototype mismatch')
        defined=set()
        for op in cap.high[tag][0]['ops']:
            supported(all(v['constant'] or v['id'] in defined for v in op['inputs']),'extra arguments cannot be discarded from a live-input callee')
            if op.get('output') is not None:defined.add(op['output']['id'])
        return []

def native_identity(cap):
    for view in cap.views:
        tag=view['tag'];req=cap.requests[tag]
        require(req['completed'] and req['highfunction_available'] and not req['error'],'native request failed '+tag+': '+str(req.get('error')))
        require(req['entry']==view['view']['entry'],'foreign native entry')
        cap.verify_native(tag)

def is_ram(v,cpu):return v is not None and v['space']=='ram' and v['offset']==cpu and v['size']==1

def loop_high_sinks(cap):
    """Bind coalesced globals to real memory varnodes and the actual CALL preservation chain."""
    sinks={}
    for block in cap.high['root']:
        for call in [o for o in block['ops'] if o['mnemonic']=='CALL']:
            reference=int(re.search(r', (\d+), \d+\)',call['sequence'])[1])
            indirect=[o for o in block['ops'] if o['mnemonic']=='INDIRECT' and is_ram(o.get('output'),0xc064) and o['inputs'][1]['offset']==reference]
            require(len(indirect)==1,'missing actual C064 CALL-bound INDIRECT')
            preserved=indirect[0];source=preserved['inputs'][0]
            require(source.get('high_global',{}).get('offset')==0xc064,'misbound C064 accumulator/global source')
            require(any(o['mnemonic']=='COPY' and is_ram(o.get('output'),0xc064) and o['inputs'][0]['id']==preserved['output']['id'] for o in block['ops']),'missing actual ram C064 preservation sink')
            require(call.get('output') is not None and any(o['mnemonic']=='COPY' and is_ram(o.get('output'),0xc065) and o['inputs'][0]['id']==call['output']['id'] for o in block['ops']),'missing real C065 sink for native CALL result')
            child=cap.target(call['inputs'][0]);ops=[o for b in cap.high[child['tag']] for o in b['ops']]
            require(all(o['mnemonic'] not in {'LOAD','STORE','CALLOTHER','CALL'} and not (o.get('output') or {}).get('space')=='ram' for o in ops),'callee can observe or clobber coalesced output memory')
            sinks[block['index']]=source['id']
    require(bool(sinks),'missing native physical calls');return sinks

def loop_observations(machine,cap,acc,bank,value):
    # HighVariable instances can reside in register/unique storage; these definitions are not
    # architectural WRAM write counts. Only this pure prefix may coalesce, under no async/DMA.
    prefix=[];events=list(machine.events)
    while events and events[0][0] in {'write','definition'} and events[0][1]==0xc064:prefix.append(events.pop(0))
    require(prefix and prefix[-1][2]==acc,'C064 final definition does not precede mapper')
    require(events==[('mapper',0x2000,bank),('call',bank,0x4000),('write',0xc065,value)],'native observable mapper/CALL/C065 order differs')
    boundary=None;call_block=None
    for index,(tag,block,op) in enumerate(machine.high_trace,1):
        if tag!='root':continue
        if op['mnemonic']=='CALLOTHER':
            require(op.get('userop_name') in {'gb_direct_write8','gb_cartridge_write8'} and op['inputs'][1]['constant'] and op['inputs'][1]['offset']==0x2000,'coalesced prefix crosses an observer/userop')
            boundary=index;break
        require(op['mnemonic'] not in {'LOAD','CALL','INDIRECT'},'coalesced prefix contains memory observer/barrier')
        if op['mnemonic']=='STORE':require(op['inputs'][1]['constant'] and op['inputs'][1]['offset']==0xc064,'coalesced prefix writes other memory')
        out=op.get('output');require(out is None or out['space']!='ram' or is_ram(out,0xc064),'coalesced prefix defines other memory')
    require(boundary is not None,'missing actual mapper boundary')
    for tag,block,op in machine.high_trace:
        if tag=='root' and op['mnemonic']=='CALL':call_block=block;break
    definitions=[d for d in machine.global_definitions if d[0]<boundary]
    require(definitions and definitions[-1][2]==acc and loop_high_sinks(cap)[call_block]==definitions[-1][1],'C064 sink is not the actual pre-mapper accumulator definition')

def loop_structure(cap,native=True):
    p=cap.proof;require(p['version'] in {'predicated-ordinary-graph-3','predicated-ordinary-graph-4'} and p['coverageComplete'] and not p['frontier'],'incomplete cyclic proof')
    c=p['convergence'];require(c['postFixedPoint'] and c['transfers']==c['replayTransfers']==len(p['joins']) and not c['possibleNontermination'],'unchecked fixed point or possible divergence')
    nodes={n['id']:n for n in p['nodes']};require(len(nodes)==len(p['nodes']),'duplicate graph identity')
    require(any(n['cpu']==0x15b and any(e['kind']=='TAKEN' and nodes[e['target']]['cpu']==0x159 for e in n['edges']) for n in nodes.values()),'dropped actual graph backedge')
    require(any(o['mnemonic'] in {'BRANCH','CBRANCH'} and o['inputs'][0]['constant'] and o['inputs'][0]['offset']&0x80000000 for o in cap.requested['root']),'emitted loop backedge absent')
    row_ids={r['id'] for r in p['joins']};require(len(row_ids)==len(p['joins']),'duplicate joined row')
    for row in p['joins']:
        require(row['node'] in nodes and all(target in row_ids for target in row['successors']),'missing predecessor/successor row obligation')
        require(0<=row['domain']<len(p['joinDomains']),'foreign joined incoming domain')
    calls=[n for n in nodes.values() if n['transfer']=='CALL']
    require(calls and {n['cpu'] for n in calls}=={0x16e},'wrong post-loop CALL site')
    for n in calls:
        require([a['delta'] for a in n['frameAccesses']]==[-1,-2] and [a['value'] for a in n['frameAccesses']]==[1,0x71],'lost real CALL push')
        require({e['kind'] for e in n['edges']}=={'CALL','RESUME'},'lost matched return/continuation')
    require({i['target'] for i in p['invocations']}=={'rom1::4000','rom2::4000'},'merged physical callees')
    for i in p['invocations']:
        require(i['returnCpu']==0x171 and nodes[i['continuation']]['cpu']==0x171 and i['byteAContract'],'wrong physical continuation/frame')
    if native:native_identity(cap);loop_high_sinks(cap)

def loop_stage(cap,image,mutated=False,native=True):
    loop_structure(cap,native);digest=hashlib.sha256();cases=0
    for b in range(256):
        n=b&7;acc=(-n)&255 if mutated else n;bank=1+(n&1);value=0x31 if bank==1 else 0xa7
        for frame in core.FRAMES:
            raw=LoopMachine(image,b,frame);raw.raw(cap);emitted=LoopMachine(image,b,frame);emitted.emitted(cap)
            require((raw.reg,raw.mem,raw.events)==(emitted.reg,emitted.mem,emitted.events),'raw/emitted full effects/flags/frame differ B='+str(b))
            require(raw.outputs=={0xc064:acc,0xc065:value} and raw.bank==bank,'wrong full loop relation B='+str(b))
            require(raw.fetches.count((0,0x159))==n and raw.fetches.count((0,0x15b))==n,'wrong real iteration count')
            require(raw.reg[3]==b and raw.reg[2]==0 and raw.reg[5]==acc,'wrong counter/accumulator/input register effects')
            require(raw.calls==[(0x16e,bank,0x4000,0x171)],'wrong loop-to-physical-callee association')
            require(raw.register(10,2)==frame[0]+2 and raw.register(8,2)==frame[1],'wrong architectural SP/PC/outer RET')
            effects=[e for e in raw.events if e[0]=='mapper' or e[0]=='call' or (e[0]=='write' and e[1] in raw.OUTPUT_RANGE)]
            require(effects[0]==('write',0xc064,acc) and effects[1]==('mapper',0x2000,bank) and effects[2][0]=='call' and effects[3]==('write',0xc065,value),'loop/store/mapper/CALL/result effect order')
            if native:
                observed=LoopMachine(image,b,frame);observed.high(cap)
                require(observed.outputs==raw.outputs and observed.bank==bank,'native rooted loop relation differs B='+str(b))
                loop_observations(observed,cap,acc,bank,value)
            cases+=1
        digest.update(f'{b}:{acc}:{bank}:{value};'.encode())
    return {'status':'PASS','B_inputs':256,'frame_variants':3,'cases':cases,'relation_sha256':digest.hexdigest(),'n_controls':[0,1,7],'native_observation':'HighVariable definitions with actual RAM sinks and ordered mapper/CALL boundaries; not architectural write counts' if native else 'NOT_RUN'}

def loop_negatives(cap,image):
    results=[]
    def reject(name,fn):
        try:fn()
        except core.Refusal as error:results.append({'name':name,'status':'REJECTED','reason':str(error)})
        else:raise core.Refusal('negative escaped '+name)
    altered=copy.deepcopy(cap)
    n=next(n for n in altered.proof['nodes'] if n['cpu']==0x15b);n['edges']=[e for e in n['edges'] if e['kind']!='TAKEN']
    reject('dropped-graph-backedge',lambda:loop_structure(altered))
    altered=copy.deepcopy(cap);altered.proof['convergence']['replayTransfers']=0
    reject('premature-fixed-point',lambda:loop_structure(altered))
    altered=copy.deepcopy(cap);altered.proof['joins'][0]['successors']=['unexplored']
    reject('lost-reachable-row',lambda:loop_structure(altered))
    altered=copy.deepcopy(cap)
    phis=[o for block in altered.high['root'] for o in block['ops'] if o['mnemonic']=='MULTIEQUAL' and len(o['inputs'])==2]
    if phis:
        block=next(b for b in altered.high['root'] if phis[0] in b['ops']);back=block['in'].index(block['index']);entry=1-back
        phis[0]['inputs'][back]=copy.deepcopy(phis[0]['inputs'][entry]);reject('wrong-native-phi-predecessor',lambda:loop_stage(altered,image))
    else:
        # Native may replace the loop with an equivalent form; mutate its actual rooted predicate input.
        branch=next(o for block in altered.high['root'] for o in block['ops'] if o['mnemonic']=='CBRANCH')
        branch['inputs'][1].update(constant=True,offset=0)
        reject('wrong-native-branch-domain',lambda:loop_stage(altered,image))
    for kind in ['missing-ram-sink','misbound-call-preservation','definition-after-mapper','memory-observer-in-prefix']:
        altered=copy.deepcopy(cap);block=next(b for b in altered.high['root'] if any(o['mnemonic']=='CALL' for o in b['ops']))
        indirect=next(o for o in block['ops'] if o['mnemonic']=='INDIRECT' and is_ram(o.get('output'),0xc064))
        if kind=='missing-ram-sink':block['ops']=[o for o in block['ops'] if not (o['mnemonic']=='COPY' and is_ram(o.get('output'),0xc064) and o['inputs'][0]['id']==indirect['output']['id'])]
        elif kind=='misbound-call-preservation':indirect['inputs'][0]['high_global']['offset']=0xc065
        elif kind=='definition-after-mapper':
            initial=next(o for o in altered.high['root'][0]['ops'] if o.get('output',{}).get('high_global',{}).get('offset')==0xc064)
            altered.high['root'][0]['ops'].remove(initial);index=next(i for i,o in enumerate(block['ops']) if o['mnemonic']=='CALLOTHER');block['ops'].insert(index+1,initial)
        else:
            index=next(i for i,o in enumerate(block['ops']) if o['mnemonic']=='CALLOTHER')
            block['ops'].insert(index,{'mnemonic':'LOAD','inputs':[{'id':9001,'space':'const','size':4,'offset':0,'constant':True},{'id':9002,'space':'const','size':2,'offset':0xc064,'constant':True}], 'output':{'id':9003,'space':'unique','size':1,'offset':0xdeadbeef,'constant':False}})
        reject(kind,lambda:loop_stage(altered,image))
    return results

def domains_stage(cap,image,native=True):
    if native:native_identity(cap)
    proof=cap.proof;require(proof['version']=='software-call-domains-2' and len(proof['domains'])==2,'wrong domain proof')
    require(len({d['id'] for d in proof['domains']})==2,'duplicate domain identity')
    require({d['configuration']['registers']['f'] for d in proof['domains']}=={0,0x80},'missing configured flag domain')
    require({d['physicalSite'] for d in proof['domains']}=={'0200'},'configured physical site differs')
    results=[]
    for domain in proof['domains']:
        flags=domain['configuration']['registers']['f'];value=0x22 if flags==0x80 else 0x33;bank=2 if flags==0x80 else 3
        roots=[v for v in cap.views if v['view']['domain']==domain['id'] and v['view']['kind']=='root'];require(len(roots)==1,'ambiguous domain root')
        for word in [0x190,0x3a01,0x10]:
            raw=DomainMachine(image,flags,word);raw.raw(cap);emitted=DomainMachine(image,flags,word);emitted.emitted(cap,roots[0]['tag'])
            require(raw.reg==emitted.reg and raw.mem==emitted.mem,'configured raw/emitted registers or real frame differ')
            require([e for e in raw.events if e[0]!='call']==[e for e in emitted.events if e[0]!='call'],'configured push/helper/RET effect order differs')
            require(raw.outputs=={0xc210:value} and raw.bank==bank,'wrong incoming-domain relationship')
            require(raw.calls==[(0x200,1,0x28,0x201)],'configured RST was replaced by ordinary CALL fixture')
            require(raw.register(10,2)==0xc102 and raw.register(8,2)==word,'configured real SP/outer RET differs')
            if native:
                observed=DomainMachine(image,flags,word);observed.high(cap,roots[0]['tag'])
                require(observed.outputs=={0xc210:value} and observed.bank==bank,'native domain selected wrong physical/state effect')
                effects=[e for e in observed.events if e[0] in {'mapper','call'} or (e[0]=='write' and e[1]==0xc210)]
                require(effects==[('mapper',0x2000,2),('call',2,0x4100),('mapper',0x2000,bank),('write',0xc210,value)],'native configured-domain effect order differs')
        results.append({'domain':domain['id'],'flags':flags,'C210':value,'bank':bank,'outer_return_words':3})
    return {'status':'PASS','same_physical_site':'0200','domains':results}

def domain_relation(stage):
    rows=stage['domains'];relation={row['domain']:row for row in rows}
    require(len(rows)==len(relation)==2,'missing or duplicate checked domain')
    return relation

def domains_persistence(root,domain_ids):
    require((root/'persisted-registration.json').read_bytes()==(root/'reopened-registration.json').read_bytes(),'separate-process saved domain registration changed')
    saved=read(root/'persisted-identity.json');opened=read(root/'reopen-compatibility.json')
    require(opened['readOnly'] is True and opened['registrationUnchanged'] is True,'domain reopen changed saved authority')
    require(opened['version']=='software-call-domains-2','unsupported reopened domain authority')
    require(saved['programId']==opened['programId'],'domain reopen used a different Program')
    require(all(type(record['javaPid']) is int and record['javaPid']>0 for record in [saved,opened]),'invalid saving/reopened JVM identity')
    require(saved['javaPid']!=opened['javaPid'],'saving process did not exit before domain reopen')
    refusals=read(root/'stale-domains.json')
    require(len(refusals)==2 and {r['domain'] for r in refusals}==domain_ids,'missing distinct stale domain controls')
    require(len({domain[:12] for domain in domain_ids})==2,'ambiguous stale request artifact identity')
    for refusal in refusals:
        require('Stale' in refusal['reason'],'stale domain proof consumed')
        request=read(root/f"stale-{refusal['domain'][:12]}-request.json")
        require(not request['completed'] and not request['highfunction_available'] and 'Stale' in request['error'],'native stale domain proof accepted '+refusal['domain'])
    return {'status':'PASS','saved_java_pid':saved['javaPid'],'reopened_java_pid':opened['javaPid'],'registration_unchanged':True,'read_only':True}

class RawCapture(core.Capture):
    def __init__(self,root,label):
        self.root=root;self.label=label;self.proof=read(root/f'{label}-proof.json');self.raw=read(root/f'{label}-raw.json')
        self.views=read(root/f'{label}-views.json');self.by_entry={i['view']['entry']:i for i in self.views}
        self.requested={i['tag']:read(root/f"{label}-{i['tag']}-requested.json") for i in self.views}

def run(root,kind,raw=False):
    if raw:
        cap=RawCapture(root,'original');image=(root/'image.gb').read_bytes()
        return {'scope':'RAW_AND_EMITTED_ONLY','native':'NOT_RUN','checks':loop_stage(cap,image,native=False) if kind=='loops' else domains_stage(cap,image,native=False)}
    if kind=='loops':
        result={}
        for stage in ['original','refreshed','reopened']:
            cap=core.Capture(root,stage);image=(root/('refreshed-image.gb' if stage=='refreshed' else 'original-image.gb')).read_bytes()
            result[stage]=loop_stage(cap,image,stage=='refreshed')
        cap=core.Capture(root,'original');result['negatives']=loop_negatives(cap,(root/'original-image.gb').read_bytes())
        stale=read(root/'stale-root-request.json');require(not stale['completed'] and not stale['highfunction_available'] and 'Stale' in stale['error'],'native stale loop proof accepted')
        require((root/'saved-registration.json').read_bytes()==(root/'reopened-registration.json').read_bytes(),'separate-process saved registration changed')
        saved=read(root/'saved-identity.json');opened=read(root/'reopened-before-identity.json')
        for field in ['program_id','domain_file','current_image_sha256','provider_jar_sha256','views']:require(saved[field]==opened[field],'reopen identity changed '+field)
        if saved.get('domain_file_id') is not None:require(saved['domain_file_id']==opened.get('domain_file_id'),'reopen DomainFile ID changed')
        require(opened.get('domain_file_id') is not None,'reopen did not resolve a saved DomainFile')
        require(saved['java_pid']!=opened['java_pid'],'saving process did not exit before reopen')
        result['persistence']={'status':'PASS','saved_java_pid':saved['java_pid'],'reopened_java_pid':opened['java_pid']}
        return result
    image=(root/'original-image.gb').read_bytes();forward=domains_stage(core.Capture(root,'forward'),image);reverse=domains_stage(core.Capture(root,'reverse'),image)
    reopened=domains_stage(core.Capture(root,'reopened'),image)
    relation=domain_relation(forward)
    require(relation==domain_relation(reverse),'request/display order altered domain identity')
    require(relation==domain_relation(reopened),'saved/reopened domain semantics differ')
    require(read(root/'site-only-negative.json')['rejected'],'site-only cache negative missing')
    persistence=domains_persistence(root,set(relation))
    return {'forward':forward,'reverse':reverse,'reopened':reopened,'persistence':persistence,'site_only_lookup':'REJECTED','stale_domains':'REJECTED'}
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('kind',choices=['loops','domains']);parser.add_argument('root',type=Path);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--raw-only',action='store_true');args=parser.parse_args()
    try:result={'status':'PASS','checks':run(args.root,args.kind,args.raw_only)}
    except core.Refusal as error:result={'status':'FAIL','reason':str(error)}
    except core.Insufficient as error:result={'status':'ORACLE_INSUFFICIENT','reason':str(error)}
    args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));raise SystemExit(0 if result['status']=='PASS' else 1)
