#!/usr/bin/env python3
"""Independent W2f raw/requested/native/persistence check, one unknown-input Program.
The scalar executor below extends check_w2e_native.py only for C040/C041 roots,
ROM fixture loads and two ordered mapper writes. It never imports provider transfer
code. The fixture's physical bytes are independently indexed with the witnessed
MBC5 established-bank semantics; unsupported forms yield ORACLE_INSUFFICIENT.
"""
import argparse
import copy
import hashlib
import json
import re
import subprocess
import tempfile
import zipfile
from urllib.parse import urlparse, unquote
from pathlib import Path
import check_w2e_native as native

Refusal, Insufficient = native.Refusal, native.Insufficient
require, read, sha, flatten = native.require, native.read, native.sha, native.flatten
CODE = '3e02ea002078e6036f26607eea40c0ea00202100617eea41c0c9'
MARKERS = {1:0x31,2:0xa7,3:0xd3,4:0x5c}

def supported(ok,message):
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
            require(v['space']=='ram' and v['offset'] in {0xc040,0xc041} and v['size']==1, 'unexpected rooted memory write')
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
                require(not high and cpu in {0xc040,0xc041}, 'unexpected native/device write')
                outputs[cpu]=value; effects.append(['write',cpu,value])
        elif code == 'STORE':
            supported(high and len(args)==3 and nodes[0]['constant'] and nodes[1]['size']==2 and nodes[2]['size']==1, 'unsupported store shape')
            require(args[1] in {0xc040,0xc041} and args[2] is not None, 'unproved store address/value')
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
    require(set(outputs)=={0xc040,0xc041}, 'missing rooted outputs')
    return {'outputs':[outputs[k] for k in (0xc040,0xc041)], 'effects':effects, 'reads':reads,
            'registers':{str(k):storage.get(('register',k)) for k in entry} if not high else None}
def check_proof(proof, image):
    require(proof['version']=='ordinary-entry-access-experiment-4-rom-index', 'wrong proof engine')
    require(proof['entry']=='0150' and proof['end']=='0169'
            and proof['analysis'].get('assumption') is None and proof.get('invocation') is None,
            'foreign or concretely selected entry premise')
    require('incoming mapper and CPU registers unknown' in proof['domain']['scope'], 'unknown-input domain missing')
    require(re.fullmatch('[0-9a-f]{64}',proof.get('dependencies','')) is not None, 'lost dependency fingerprint')
    require(''.join(i['bytes'] for i in proof['instructions'])==CODE, 'foreign pointer producer code')
    finite=proof['finite']; choices=finite['choices']
    require(finite['version']=='finite-entry-producer-w2f-rom-index-2' and len(choices)==2, 'wrong finite engine or choices')
    pointer,mapper=choices
    require(pointer['kind']=='CPU_POINTER' and pointer['instruction']=='015b'
            and pointer['width']==2 and pointer.get('mapperCpu') is None
            and pointer['values']==list(range(0x6000,0x6004))
            and 'entry-register-byte@3' in pointer['expression'], 'unproduced/incomplete CPU pointer')
    table=list(image[0xa000:0xa004]); selectors=sorted(set(table))
    require(mapper['kind']=='MAPPER_SELECTOR' and mapper['instruction']=='015f'
            and mapper['width']==1 and mapper['mapperCpu']==0x2000 and mapper['values']==selectors,
            'unproduced downstream mapper selection')
    reads=finite['reads']
    require(len(reads)==2 and reads[0]['choice']==pointer and reads[1]['choice']==mapper,
            'uncorrelated read choices')
    for read_item,keys,offsets,banks,values in (
        (reads[0],list(range(0x6000,0x6004)),list(range(0x2000,0x2004)),[2]*4,table),
        (reads[1],selectors,[0x2100]*len(selectors),selectors,[MARKERS[s] for s in selectors]),
    ):
        alternatives=read_item['alternatives']
        require([a['key'] for a in alternatives]==keys, 'omitted, duplicated, forged, or reordered address alternatives')
        for alternative,offset,bank,value in zip(alternatives,offsets,banks,values):
            require(alternative['value']==value and len(alternative['sources'])==1, 'wrong choice value/source count')
            source=alternative['sources'][0]; physical={'region':'ROM','bank':bank,'offset':offset}
            require(source['byteIndex']==0 and source['physical']==physical and source['value']==value
                    and source['address']==f'rom{bank}::{offset+0x4000:04x}', 'wrong CPU-pointer/physical-byte association')
            require(image[bank*0x4000+offset]==value, 'source does not bind current immutable image')
    return {'status':'PASS','cpu_pointers':pointer['values'],'table_bytes':table,
            'selectors':selectors,'physical_sources':sum(len(r['alternatives']) for r in reads)}


def check_domain(ops,image,high=False,raw=False):
    rows=[]
    for b in range(256):
        index=b&3; pointer=0x6000+index; selector=image[0xa000+index]; marker=MARKERS[selector]
        result=run_ops(ops,b,0xa3,high,image if raw else None)
        expected=[['mapper',0x2000,2],['write',0xc040,selector],
                  ['mapper',0x2000,selector],['write',0xc041,marker]]
        require(result['outputs']==[selector,marker] and result['effects']==expected,
                f'wrong input/pointer/selector/output or ordered effects B={b}: {result}')
        if raw:
            require(result['reads']==[dict(cpu=pointer,bank=2,offset=0x2000+index,value=selector),
                                     dict(cpu=0x6100,bank=selector,offset=0x2100,value=marker)],
                    f'wrong runtime pointer or physical source B={b}')
        rows.append(dict(B=b,pointer=pointer,table_file_offset=0xa000+index,C040=selector,
                         output_file_offset=selector*0x4000+0x2100,C041=marker))
    return {'status':'PASS','inputs':256,'relationship':rows}


def check_c(path,image):
    source=path.read_text()
    supported(re.search(r'gb_ordinary_150_conditional\(undefined2 param_1\)',source), 'unsupported C ABI')
    header='''#include <stdio.h>
#include <stdint.h>
typedef uint8_t byte, undefined1; typedef uint16_t undefined2; typedef unsigned int uint;
#define __ghidraboy_state_entry_v1
static uint16_t CONCAT11(uint8_t high, uint8_t low) { return ((uint16_t)high << 8) | low; }
byte DAT_c040, DAT_c041; int mapper_count, mapper_selector, early;
void gb_cartridge_write8(unsigned cpu, unsigned value) {
  if (cpu != 0x2000 || DAT_c041 != 0) early=1;
  if (mapper_count==0 && (value!=2 || DAT_c040!=0)) early=1;
  if (mapper_count==1 && DAT_c040!=(byte)value) early=1;
  mapper_count++; mapper_selector=(byte)value;
}
'''
    driver='''int main(void) { for (int b=0;b<256;b++) {
  DAT_c040=DAT_c041=mapper_count=mapper_selector=early=0;
  gb_ordinary_150_conditional((b<<8)|0x53);
  printf("%d %d %d %d %d %d\\n",b,DAT_c040,DAT_c041,mapper_count,mapper_selector,early);
} return 0; }
'''
    with tempfile.TemporaryDirectory(prefix='w2f-rooted-c-') as tmp:
        c=Path(tmp)/'capture.c';exe=Path(tmp)/'capture';c.write_text(header+source+driver)
        build=subprocess.run(['cc','-std=c11','-O0',str(c),'-o',str(exe)],capture_output=True,text=True)
        if build.returncode: raise Insufficient('captured C compile unsupported: '+build.stderr)
        run=subprocess.run([str(exe)],capture_output=True,text=True,check=True)
    rows=[list(map(int,line.split())) for line in run.stdout.splitlines()]
    require(len(rows)==256, 'C enumeration incomplete')
    for b,selector,marker,count,mapper,early in rows:
        s=image[0xa000+(b&3)]
        require([selector,marker,count,mapper,early]==[s,MARKERS[s],2,s,0],f'wrong C relation/order B={b}')
    return {'status':'PASS','inputs':256,'c_sha256':sha(path),'compiler':'cc -std=c11 -O0'}


def negatives(emitted,proof,image):
    results=[]
    def reject(name, action):
        try: action()
        except Refusal as exc: results.append(dict(name=name,status='REJECTED',reason=str(exc)))
        except Insufficient as exc: raise Insufficient(f'negative {name} oracle insufficient: {exc}')
        else: raise Refusal('negative control escaped: '+name)
    for name,change in (
        ('omitted-address',lambda p:p['finite']['reads'][0]['alternatives'].pop()),
        ('forged-address',lambda p:p['finite']['reads'][0]['alternatives'][0].update(key=0x6004)),
        ('wrong-physical-source',lambda p:p['finite']['reads'][0]['alternatives'][1]['sources'][0]['physical'].update(bank=3)),
        ('lost-dependency',lambda p:p.pop('dependencies')),
        ('foreign-entry',lambda p:p.update(entry='0151')),
    ):
        mutant=copy.deepcopy(proof);change(mutant);reject(name,lambda m=mutant:check_proof(m,image))
    guards=[i for i,op in enumerate(emitted) if op['mnemonic']=='INT_EQUAL' and op['inputs'][1]['constant']
            and op['inputs'][1]['offset'] in {0x6001,0x6002,0x6003}]
    require(len(guards)==3,'unexpected actual pointer guard shape')
    mutant=copy.deepcopy(emitted)
    for i in guards:
        mutant[i]['inputs'][0]=dict(mutant[i]['inputs'][0],constant=True,space='const',offset=0x6000,
                                     address=False,register=False)
    reject('runtime-pointer-dependency-lost',lambda:check_domain(mutant,image))
    mutant=copy.deepcopy(emitted)
    mutant[guards[0]]['inputs'][1]['offset']=0x6002;mutant[guards[1]]['inputs'][1]['offset']=0x6001
    reject('runtime-pointer-source-association-swapped',lambda:check_domain(mutant,image))
    mutant=copy.deepcopy(emitted)
    write=next(i for i,o in enumerate(mutant) if o['mnemonic']=='CALLOTHER' and o['inputs'][1]['offset']==0x2000)
    del mutant[write];reject('initial-mapper-write-lost',lambda:check_domain(mutant,image))
    return results


def check_stage(root,label,image):
    proof=read(root/f'{label}-proof.json');proof_result=check_proof(proof,image)
    emitted=read(root/f'{label}-requested-entry-pcode.json');request=read(root/f'{label}-request.json')
    require(request['completed'] and request['highfunction_available'] and not request['error'], 'native request failed')
    companions=[p for p in request['processes_after'] if p.get('binary_sha256')==native.NATIVE
                and p.get('parent')==request['owner_java_pid']]
    require(len(companions)==1,'wrong pinned native binary/Java owner')
    debug=root/f'{label}-debug.xml';require(sha(debug)==request['debug']['sha256'],'debug hash mismatch')
    high=flatten(read(root/f'{label}-high.json'))
    stage=dict(proof=proof_result,requested=check_domain(emitted,image),native_high=check_domain(high,image,True),
               actual_requested_binding=native.debug_identity(debug,emitted,request['entry']),
               native_c=check_c(root/f'{label}.c',image),java_pid=request['owner_java_pid'],native_pid=companions[0]['pid'])
    return stage


def check_persistence(root,receipts,image):
    registrations=[];identities=[];stages={};historical=read(root/'refreshed-proof.json')
    for label in ('saved','reopened'):
        command=read(receipts/label/'result.json');argv=command['argv']
        require(command['exit_code']==0 and command['completion_marker'],'persistence capture process failed')
        require('-process' in argv and '-noanalysis' in argv and '-import' not in argv,'not existing Program/noanalysis')
        require(('-readOnly' in argv)==(label=='reopened'),'wrong save/reopen mode')
        if label=='saved': require('Save succeeded for processed file: /ROM_INDEX.gb' in (receipts/label/'output.log').read_text(),
                                   'actual save not established')
        registration=(root/f'{label}-registration.json').read_bytes()
        require(registration==(root/f'{label}-registration-after.json').read_bytes(),'registration changed on native read')
        stored=json.loads(registration);proof=read(root/f'{label}-proof.json')
        require(stored['proof']==proof==historical,'persistent stored proof differs from actual refreshed authority')
        require(stored['alias']=='gb_ordinary_150::0150','wrong saved alias')
        before=read(root/f'{label}-before-identity.json');after=read(root/f'{label}-after-identity.json')
        require(before==after,'capture changed live Program state')
        require(before['program_id']==stored['programId'],'persistent Program identity mismatch')
        require(before['stored_program_instance']==proof['programInstance'] and before['stored_revision']==proof['revision'],
                'stored proof identity differs')
        require(before['current_export_sha256']==hashlib.sha256(image).hexdigest(),'different reopened image revision')
        sources=before['physical_sources']
        expected=[(r,a,s) for r in proof['finite']['reads'] for a in r['alternatives'] for s in a['sources']]
        require(len(sources)==len(expected),'physical source coverage incomplete')
        for actual,(r,a,s) in zip(sources,expected):
            require(actual['key']==a['key'] and actual['choice']==r['choice'] and actual['read_instruction']==r['instruction']
                    and actual['stored_source']==s and actual['actual_value']==s['value'] and not actual['block_writable']
                    and actual['actual_physical']==[s['physical']],'actual persisted source association changed')
        require(read(root/f'{label}-canonical.json')==read(root/'canonical-before.json'),'canonical changed')
        require(read(root/f'{label}-requested-entry-pcode.json')==read(root/'refreshed-requested-entry-pcode.json'),
                'saved requested payload changed')
        stage=check_stage(root,label,image)
        require(stage['java_pid']==before['java_pid'],'wrong native callback Java owner')
        stages[label]=stage;registrations.append(registration);identities.append(before)
    require(registrations[0]==registrations[1],'serialized registration changed across processes')
    for key in ('program_id','domain_file','domain_file_id','stored_program_instance','stored_revision',
                'original_image_sha256','current_export_sha256','physical_sources','provider_location','provider_jar_sha256'):
        require(identities[0][key]==identities[1][key],'persistent identity changed: '+key)
    require(identities[0]['java_pid']!=identities[1]['java_pid'] and identities[0]['java_start']!=identities[1]['java_start']
            and stages['saved']['native_pid']!=stages['reopened']['native_pid'],'not separate Java/native processes')
    require(read(receipts/'saved/result.json')['end_utc'] < read(receipts/'reopened/result.json')['start_utc'],
            'reopened before saving process exited')
    return dict(status='PASS',stages=stages,registration_sha256=hashlib.sha256(registrations[0]).hexdigest(),
                identities=identities,identity_note='Persistent fields are compared exactly; live object identity and session counters are independently reported, never normalized.')


def check(capture,fixture,receipts,extension):
    image=fixture.read_bytes();program=read(capture/'program.json')
    with zipfile.ZipFile(extension) as archive:
        jars=[name for name in archive.namelist() if re.search(r'/lib/GhidraBoy(?:-[^/]+)?\.jar$',name)]
        require(len(jars)==1,'extension provider JAR ambiguous')
        jar_hash=hashlib.sha256(archive.read(jars[0])).hexdigest()
    require(program['provider_jar_sha256']==jar_hash,'invoked provider differs from newly built extension')
    installed_jar=Path(unquote(urlparse(program['provider_location']).path))
    require(sha(installed_jar)==jar_hash,'captured installed provider artifact changed')
    require(sha(fixture)==program['image_sha256'] and program['fresh_setup'],'foreign or undisclosed fixture setup')
    require(image[0x150:0x16a].hex()==CODE and image[0xa000:0xa004]==bytes([1,3,2,4]),'wrong fixture bytes')
    require(image[0x147]==0x19 and len(image)==8*0x4000,'wrong MBC5 eight-bank infrastructure')
    for bank,value in MARKERS.items():require(image[bank*0x4000+0x2100]==value,'wrong authored marker')
    canonical=read(capture/'canonical-before.json')
    require(canonical==read(capture/'canonical-after-install.json'),'canonical changed during installation')
    require(''.join(i['bytes'] for i in canonical['instructions'])==CODE,'wrong captured actual code')
    raw=[op for instruction in canonical['instructions'] for op in instruction['raw']]
    raw_result=check_domain(raw,image,raw=True)
    emitted=read(capture/'original-requested-entry-pcode.json')
    for b in range(256):
        original=run_ops(raw,b,0xa3,image=image);lowered=run_ops(emitted,b,0xa3)
        require(original['registers']==lowered['registers'],f'raw/emitted register, flags or stack difference B={b}')
    result=dict(status='PASS',fixture_sha256=sha(fixture),checker_sha256=sha(Path(__file__)),
                retained_debug_executor_sha256=sha(Path(native.__file__)),raw=raw_result,stages={},
                invoked_artifact=dict(extension_sha256=sha(extension),provider_jar_sha256=jar_hash,provider_location=program['provider_location']))
    result['stages']['original']=check_stage(capture,'original',image)
    result['negative_controls']=negatives(emitted,read(capture/'original-proof.json'),image)
    mutation=read(capture/'mutation.json');stale=read(capture/'stale-request.json')
    require(mutation['changed_file_offsets']==[0xa001] and mutation['old']==3 and mutation['new']==4
            and mutation['old_registration_retained'] and mutation['read_only_ROM'],'not exact immutable consumed table mutation')
    require(not stale['completed'] and not stale['highfunction_available'] and 'Stale ordinary-entry registration' in stale['error'],
            'old dependency proof generated native semantics')
    changed=bytearray(image);changed[0xa001]=4
    require(read(capture/'original-proof.json')['dependencies']!=read(capture/'refreshed-proof.json')['dependencies'],
            'actual consumed byte absent from refreshed broad dependency')
    result['stages']['refreshed']=check_stage(capture,'refreshed',changed)
    result['raw_refreshed']=check_domain(raw,changed,raw=True)
    result['persistence']=check_persistence(capture,receipts,changed)
    for identity in result['persistence']['identities']:
        require(identity['provider_jar_sha256']==jar_hash and identity['provider_location']==program['provider_location']
                and identity['program_id']==program['program_id'] and identity['original_image_sha256']==program['image_sha256'],
                'persistence used foreign provider, Program or original image')
    require(result['stages']['original']['java_pid']==result['stages']['refreshed']['java_pid']
            and result['stages']['original']['native_pid']==result['stages']['refreshed']['native_pid'],
            'native owner changed during stale/refresh control')
    result['scope']='One provider-owned unknown-B entry, independently enumerated for all 256 B values; original table 01/03/02/04 and persisted refreshed table 01/04/02/04.'
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('capture','fixture','receipts','extension','out'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    try: result=check(args.capture,args.fixture,args.receipts,args.extension)
    except Insufficient as exc:result=dict(status='ORACLE_INSUFFICIENT',reason=str(exc))
    except (Refusal,KeyError,ValueError) as exc:result=dict(status='FAIL',reason=str(exc))
    args.out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k in {'status','reason','fixture_sha256','checker_sha256','scope'}}))
    raise SystemExit(0 if result['status']=='PASS' else 1)


if __name__=='__main__':main()
