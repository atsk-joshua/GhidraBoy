#!/usr/bin/env python3
"""Independent W2g capture checker; scalar execution retained from W2f with C050/51 roots.
No provider value/mapper code imported. Only the actual observed straight-line fragment
is supported; unsupported forms return ORACLE_INSUFFICIENT.
"""
import argparse
import collections
import copy
import hashlib
import json
import re
import zipfile
from pathlib import Path
import check_w2e_native as native
require, read, sha, flatten = native.require, native.read, native.sha, native.flatten
Refusal, Insufficient = native.Refusal, native.Insufficient
CODES = {'independent':'78e6013cea50c0ea00207ae6016f26607eea51c0c9',
         'same':'78e6013cea50c0ea002078e6016f26607eea51c0c9'}

def supported(ok, message):
    if not ok: raise Insufficient(message)

def run_ops(ops, b, d, high=False, image=None):
    # Register offsets are pinned compiled SM83 language storage, checked by raw structured capture.
    entry = {0:0xf0, 1:0x95, 2:0x53, 3:b, 4:0xa6, 5:d, 6:0xef, 7:0xbe, 8:0x50, 9:1, 10:0xfc, 11:0xcf}
    storage = {('register', k):v for k,v in entry.items()}
    storage.update({('ram',0xcffc):0x90, ('ram',0xcffd):1})
    values = {}; outputs = {}; effects = []; returns = 0; bank = None; reads = []
    def get(v):
        if v['constant']: return v['offset'] & ((1 << (v['size']*8))-1)
        if high and v['id'] in values: return values[v['id']]
        if high and v['space'] == 'register':
            octets = [entry.get(v['offset']+i) for i in range(v['size'])]
        else: octets = [storage.get((v['space'],v['offset']+i)) for i in range(v['size'])]
        return None if any(x is None for x in octets) else sum(x << (8*i) for i,x in enumerate(octets))
    def put(v, value):
        if value is not None: value &= (1 << (v['size']*8))-1
        if high: values[v['id']] = value
        else:
            for i in range(v['size']): storage[(v['space'],v['offset']+i)] = None if value is None else (value >> (8*i)) & 255
        if v.get('address'):
            require(v['space']=='ram' and v['offset'] in {0xc050,0xc051} and v['size']==1, 'unexpected rooted memory write')
            # Native final SSA copies may repeat a rooted cell after its actual earlier definition.
            if outputs.get(v['offset']) != value or v['offset'] not in outputs:
                effects.append(['write',v['offset'],value])
            outputs[v['offset']] = value
    for index, op in enumerate(ops):
        code=op['mnemonic']; nodes=op['inputs']; args=[get(v) for v in nodes]; out=op.get('output'); result=None
        if code in {'COPY','CAST'}:
            if code=='CAST': supported(high and out['size']==nodes[0]['size'], 'unsupported cast width')
            result=args[0]
        elif code == 'CALLOTHER':
            supported(op.get('userop_name') in {'gb_direct_write8','gb_cartridge_write8'}, 'unknown userop')
            require(len(args)==3 and args[1] is not None and args[2] is not None, 'unconstrained effect')
            cpu,value=args[1:]
            if cpu==0x2000:
                bank = value & 7; effects.append(['mapper',cpu,value])
            else:
                require(not high and cpu in {0xc050,0xc051}, 'unexpected native/device write')
                outputs[cpu]=value; effects.append(['write',cpu,value])
        elif code == 'STORE':
            supported(high and len(args)==3 and nodes[0]['constant'] and nodes[1]['size']==2 and nodes[2]['size']==1, 'unsupported store shape')
            require(args[1] in {0xc050,0xc051} and args[2] is not None, 'unproved store address/value')
            outputs[args[1]]=args[2];effects.append(['write',args[1],args[2]])
        elif code == 'LOAD':
            supported(len(args)==2 and nodes[1]['size']==2 and out['size']==1, 'unsupported load width')
            cpu=args[1]
            if cpu in {0xcffc,0xcffd}: result=0x90 if cpu==0xcffc else 1
            elif image is not None and cpu is not None and 0 <= cpu < 0x8000:
                require(bank is not None, 'ROM read without established mapper')
                physical_bank=0 if cpu < 0x4000 else bank
                offset=cpu & 0x3fff; result=image[physical_bank*0x4000+offset]
                reads.append(dict(cpu=cpu,bank=physical_bank,offset=offset,value=result))
            else: raise Insufficient('non-stack or unproved ROM load remains')
        elif code == 'RETURN':
            require(index==len(ops)-1, 'unreachable operations after return')
            returns += 1
            if not high: require(args==[0x190], 'raw symbolic stack return lost')
        elif code in {'INT_ADD','INT_SUB','INT_MULT','INT_AND','INT_OR','INT_XOR','INT_LEFT','INT_RIGHT','INT_EQUAL',
                      'INT_NOTEQUAL','INT_LESS','INT_LESSEQUAL','BOOL_NEGATE','BOOL_AND','BOOL_OR','BOOL_XOR',
                      'INT_ZEXT','INT_SEXT','INT_NEGATE','PIECE','SUBPIECE','INT_CARRY'}:
            if all(x is not None for x in args):
                a=args[0]; z=args[1] if len(args)>1 else None
                if code=='INT_ADD': result=a+z
                elif code=='INT_SUB': result=a-z
                elif code=='INT_MULT': result=a*z
                elif code in {'INT_AND','BOOL_AND'}: result=a&z
                elif code in {'INT_OR','BOOL_OR'}: result=a|z
                elif code in {'INT_XOR','BOOL_XOR'}: result=a^z
                elif code=='INT_LEFT': result=a<<z
                elif code=='INT_RIGHT': result=a>>z
                elif code=='INT_EQUAL': result=int(a==z)
                elif code=='INT_NOTEQUAL': result=int(a!=z)
                elif code=='INT_LESS': result=int(a<z)
                elif code=='INT_LESSEQUAL': result=int(a<=z)
                elif code=='BOOL_NEGATE': result=int(not a)
                elif code=='INT_ZEXT': result=a
                elif code=='INT_SEXT': result=a-(1 << (8*nodes[0]['size'])) if a & (1 << (8*nodes[0]['size']-1)) else a
                elif code=='INT_NEGATE': result=~a
                elif code=='PIECE': result=(a << (8*nodes[1]['size'])) | z
                elif code=='SUBPIECE': result=a >> (8*z)
                elif code=='INT_CARRY': result=int(a+z >= 1 << (8*nodes[0]['size']))
        else: raise Insufficient('unsupported observed operator '+code)
        if out is not None: put(out,result)
    require(returns==1, 'missing return')
    require(set(outputs)=={0xc050,0xc051}, 'missing rooted outputs')
    return {'outputs':[outputs[k] for k in (0xc050,0xc051)], 'effects':effects, 'reads':reads,
            'registers':{str(k):storage.get(('register',k)) for k in entry} if not high else None}
def inputs(case):
    return ((b,d) for b in range(256) for d in (range(256) if case=='independent' else [0xa3]))

def origin_value(origin,b,d,names):
    kind=origin['kind'];width=origin['width']
    if kind=='CONSTANT':return origin['constant']
    if kind=='INPUT':
        match=re.search(r':entry-register-byte@(3|5)$',origin['input'])
        if not match or width!=1:raise Insufficient('unrecognized origin input '+origin['input'])
        return b if match[1]=='3' else d
    if kind!='OPERATION':raise Insufficient('unrecognized origin kind')
    op=names.get(origin['opcode']);args=[origin_value(o,b,d,names) for o in origin['inputs']]
    if op=='COPY':v=args[0]
    elif op=='INT_AND':v=args[0]&args[1]
    elif op=='INT_ADD':v=args[0]+args[1]
    elif op=='PIECE':v=(args[0]<<(8*origin['inputs'][1]['width']))|args[1]
    elif op=='SUBPIECE':v=args[0]>>(8*args[1])
    else:raise Insufficient('unrecognized observed origin operation '+str(origin['opcode']))
    return v&((1<<(8*width))-1)

def proof_check(proof,case,image,names):
    require(proof['version']=='ordinary-entry-access-experiment-5-abstract-joint','foreign proof version')
    require(proof['entry']=='0150' and proof['end']=='0164' and not proof.get('invocation')
            and not proof['analysis'].get('assumption'),'foreign or specialized proof')
    require(''.join(i['bytes'] for i in proof['instructions'])==CODES[case],'foreign actual code')
    finite=proof['finite'];require(finite['version']=='finite-entry-producer-w2g-joint-3','foreign producer')
    require(len(finite['choices'])==2 and len(finite['reads'])==1,'wrong choice/read coverage')
    selector,pointer=finite['choices'];read_item=finite['reads'][0];joint=read_item['joint']
    require(selector['kind']=='MAPPER_SELECTOR' and selector['instruction']=='0157' and selector['width']==1
            and selector['input']==2 and selector['mapperCpu']==0x2000 and selector['values']==[1,2], 'wrong mapper capture')
    require(pointer['kind']=='CPU_POINTER' and pointer['instruction']=='0160' and pointer['width']==2
            and pointer['input']==1 and pointer['values']==[0x6000,0x6001], 'wrong pointer capture')
    require(joint['complete'] and joint['selector']==selector and joint['pointer']==pointer
            and read_item['choice']==pointer and read_item['alternatives']==[], 'wrong joint authority')
    expected=[(1,0x6000),(1,0x6001),(2,0x6000),(2,0x6001)]
    def pair(endpoint):return endpoint['selector'],endpoint['pointer']
    require([pair(c) for c in joint['candidateCover']]==expected,'wrong conservative endpoint cover')
    for c in joint['candidateCover']:
        bank,ptr=pair(c);value=image[bank*0x4000+(ptr&0x3fff)]
        source={'byteIndex':0,'address':f'rom{bank}::{ptr:04x}',
                'physical':{'region':'ROM','bank':bank,'offset':ptr&0x3fff},'value':value}
        require(c['value']==value and c['sources']==[source],'wrong physical endpoint byte')
    reachable=expected if case=='independent' else [expected[0],expected[3]]
    require([pair(g['endpoint']) for g in joint['reachable']]==reachable,'unreachable or missing published pairs')
    for g in joint['reachable']:
        c=g['endpoint']
        require(c in joint['candidateCover'] and g['condition']=={'terms':[
            {'origin':selector['origin'],'value':c['selector']},
            {'origin':pointer['origin'],'value':c['pointer']}]}, 'forged structural guards')
    return joint

def stage(root,label,case,image,raw):
    emitted=read(root/f'{label}-requested-entry-pcode.json');high=flatten(read(root/f'{label}-high.json'))
    names={o['opcode']:o['mnemonic'] for o in raw+emitted+high}
    joint=proof_check(read(root/f'{label}-proof.json'),case,image,names)
    req=read(root/f'{label}-request.json')
    require(req['completed'] and req['highfunction_available'] and not req['error'],'native did not complete')
    companions=[p for p in req['processes_after'] if p.get('binary_sha256')==native.NATIVE and p.get('parent')==req['owner_java_pid']]
    require(len(companions)==1,'wrong actual native companion/owner')
    debug=root/f'{label}-debug.xml';require(sha(debug)==req['debug']['sha256'],'changed debug capture')
    binding=native.debug_identity(debug,emitted,req['entry'])
    counts=collections.Counter();digest=hashlib.sha256();n=0
    for b,d in inputs(case):
        selector=(b&1)+1;pointer=0x6000+((d if case=='independent' else b)&1)
        value=image[selector*0x4000+(pointer&0x3fff)]
        matching=[]
        for guard in joint['reachable']:
            if all(origin_value(t['origin'],b,d,names)==t['value'] for t in guard['condition']['terms']):matching.append(guard['endpoint'])
        require(len(matching)==1 and (matching[0]['selector'],matching[0]['pointer'],matching[0]['value'])==(selector,pointer,value),
                f'wrong actual guard B={b} D={d}')
        expected=[['write',0xc050,selector],['mapper',0x2000,selector],['write',0xc051,value]]
        original=run_ops(raw,b,d,image=image);requested=run_ops(emitted,b,d);actual=run_ops(high,b,d,True)
        for surface,result in [('raw',original),('emitted',requested),('native',actual)]:
            require(result['outputs']==[selector,value] and result['effects']==expected,f'{surface} relation/order B={b} D={d}: {result}')
        require(original['reads']==[dict(cpu=pointer,bank=selector,offset=pointer&0x3fff,value=value)],'wrong raw physical pointer/read')
        require(original['registers']==requested['registers'],'raw/emitted flags/registers/stack mismatch')
        counts[(selector,pointer,value)]+=1;digest.update(f'{b},{d},{selector},{pointer},{value};'.encode());n+=1
    return {'status':'PASS','inputs':n,'relations':[dict(selector=s,pointer=p,value=v,count=n) for (s,p,v),n in sorted(counts.items())],
            'enumeration_sha256':digest.hexdigest(),'native_binding':binding,'java_pid':req['owner_java_pid'],'native_pid':companions[0]['pid']}

def negatives(root,case,image,raw):
    proof=read(root/'original-proof.json');ops=read(root/'original-requested-entry-pcode.json');high=flatten(read(root/'original-high.json'))
    names={o['opcode']:o['mnemonic'] for o in raw+ops+high};results=[]
    def reject(name,action):
        try:action()
        except Refusal as e:results.append(dict(name=name,status='REJECTED',reason=str(e)))
        else:raise Refusal('negative escaped '+name)
    for name in ['missing','forged-guard','unreachable']:
        p=copy.deepcopy(proof);j=p['finite']['reads'][0]['joint']
        if name=='missing':j['reachable'].pop()
        elif name=='forged-guard':j['reachable'][0]['condition']['terms'][0]['value']=9
        else:j['reachable'].append(copy.deepcopy(j['reachable'][0]))
        reject(name,lambda p=p:proof_check(p,case,image,names))
    mutated=copy.deepcopy(ops)
    guard=next(o for o in mutated if o['mnemonic']=='INT_EQUAL' and o['inputs'][1]['offset']==0x6001)
    guard['inputs'][1]['offset']=0x6000
    def check_wrong():
        for b,d in inputs(case):
            s=(b&1)+1;p=0x6000+((d if case=='independent' else b)&1);v=image[s*0x4000+(p&0x3fff)]
            require(run_ops(mutated,b,d)['outputs']==[s,v],'wrong-pointer mutation detected')
    reject('wrong-runtime-pointer',check_wrong)
    return results

def persistence(root,receipts,image,raw):
    before=read(root/'saved-before-identity.json');after=read(root/'reopened-before-identity.json')
    for label in ['saved','reopened']:
        identity=read(root/f'{label}-before-identity.json')
        require(identity==read(root/f'{label}-after-identity.json'),'read-only invocation mutated Program')
        require((root/f'{label}-registration.json').read_bytes()==(root/f'{label}-registration-after.json').read_bytes(),'registration changed during invocation')
        require(read(root/f'{label}-proof.json')==read(root/'refreshed-proof.json'),'stored refreshed proof changed')
        command=read(receipts/label/'result.json');argv=command['argv']
        require(command['exit_code']==0 and command['completion_marker'] and '-process' in argv and '-noanalysis' in argv
                and '-import' not in argv and (('-readOnly' in argv)==(label=='reopened')),'invalid reopen command')
        require(identity['current_export_sha256']==hashlib.sha256(image).hexdigest(),'wrong persisted image')
        require(len(identity['physical_sources'])==4,'lost physical candidates')
        for c in identity['physical_sources']:
            source=c['stored_source'];require(c['actual_value']==source['value'] and c['actual_physical']==[source['physical']]
                and not c['block_writable'],'changed persistent source')
        require(read(root/f'{label}-requested-entry-pcode.json')==read(root/'refreshed-requested-entry-pcode.json'),'emitted persisted semantics changed')
    require('Save succeeded for processed file: /JOINT_INDEPENDENT.gb' in (receipts/'saved/output.log').read_text(),'save not established')
    require(read(receipts/'saved/result.json')['end_utc']<read(receipts/'reopened/result.json')['start_utc'],'processes not sequential')
    require(before['java_pid']!=after['java_pid'] and before['java_start']!=after['java_start'],'same Java process')
    require((root/'saved-registration.json').read_bytes()==(root/'reopened-registration.json').read_bytes(),'stored registration changed')
    for key in ['program_id','domain_file_id','original_image_sha256','current_export_sha256','stored_program_instance','stored_revision','physical_sources','provider_jar_sha256']:
        require(before[key]==after[key],'persistent identity mismatch '+key)
    stages={label:stage(root,label,'independent',image,raw) for label in ['saved','reopened']}
    require(stages['saved']['native_pid']!=stages['reopened']['native_pid'],'same native process')
    return dict(status='PASS',stages=stages,identities=[before,after],registration_sha256=sha(root/'saved-registration.json'))

def check(args):
    with zipfile.ZipFile(args.extension) as z:
        jars=[n for n in z.namelist() if re.search(r'/lib/GhidraBoy(?:-[^/]+)?\.jar$',n)];require(len(jars)==1,'ambiguous provider jar')
        jar_hash=hashlib.sha256(z.read(jars[0])).hexdigest()
    result={'status':'PASS','extension_sha256':sha(args.extension),'provider_jar_sha256':jar_hash,'checker_sha256':sha(Path(__file__)),
            'retained_executor_sha256':sha(Path(__file__).with_name('check_w2f_rom_index.py')),'cases':{}}
    for case in ['independent','same']:
        root=args.capture/case;image=(args.fixtures/('JOINT_'+case.upper()+'.gb')).read_bytes();program=read(root/'program.json')
        require(program['provider_jar_sha256']==jar_hash and program['image_sha256']==hashlib.sha256(image).hexdigest(),'wrong invoked artifact/fixture')
        require(image[0x150:0x165].hex()==CODES[case] and image[0x147]==0x19 and len(image)==8*0x4000,'wrong fixture code/geometry')
        canonical=read(root/'canonical-before.json');require(canonical==read(root/'canonical-after-install.json'),'canonical changed')
        raw=[op for ins in canonical['instructions'] for op in ins['raw']]
        require(''.join(ins['bytes'] for ins in canonical['instructions'])==CODES[case],'wrong raw instructions')
        changed=bytearray(image);changed[0x6001]=0x6e
        mutation=read(root/'mutation.json');stale=read(root/'stale-request.json')
        require(mutation['changed_file_offsets']==[0x6001] and mutation['old']==0x5d and mutation['new']==0x6e and mutation['old_registration_retained'],'wrong consumed mutation')
        require(not stale['completed'] and not stale['highfunction_available'] and 'Stale ordinary-entry registration' in stale['error'],'stale native proof accepted')
        stages={label:stage(root,label,case,img,raw) for label,img in [('original',image),('refreshed',changed)]}
        require(read(root/'original-proof.json')['dependencies']!=read(root/'refreshed-proof.json')['dependencies'],'lost consumed dependency')
        if case=='same':require(stages['original']['relations']==stages['refreshed']['relations'],'unreachable off-diagonal changed same-input outputs')
        result['cases'][case]=dict(stages=stages,negatives=negatives(root,case,image,raw),fixture_sha256=hashlib.sha256(image).hexdigest())
        if case=='independent':result['persistence']=persistence(root,args.receipts/case,changed,raw)
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['capture','fixtures','receipts','extension','out']:parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    try:result=check(args)
    except Insufficient as e:result=dict(status='ORACLE_INSUFFICIENT',reason=str(e))
    except (Refusal,KeyError,ValueError) as e:result=dict(status='FAIL',reason=str(e))
    args.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k in ['status','reason','extension_sha256']}))
    raise SystemExit(0 if result['status']=='PASS' else 1)

if __name__=='__main__':main()
